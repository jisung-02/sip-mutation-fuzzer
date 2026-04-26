"""Deprecated legacy sender for Docker container network namespaces.

This module remains as a compatibility fallback for older ``bind_container``-based
real-UE workflows.  The preferred path is host-side source-IP binding via
``TargetEndpoint.source_ip`` with ``net.ipv4.ip_nonlocal_bind=1``.

The legacy :func:`send_via_container` helper delegates UDP/TCP SIP transmission to a
minimal Python driver that runs inside the target container via ``docker exec -i``.

The driver script is passed as a ``-c`` argument to ``python3`` so no file needs to
be copied into the container.  The raw SIP payload bytes are passed on stdin with a
4-byte big-endian length prefix.  Response observations are returned as JSON lines on
stdout, one object per SIP response received, then parsed by the parent process.
"""

from __future__ import annotations

import base64
import json
import subprocess
from dataclasses import dataclass
from typing import Final, Literal

# Minimal Python driver executed inside the container via "python3 -c <SCRIPT>".
# Receives: bind_host, remote_host, remote_port, transport, timeout_secs,
#           collect_all (0/1) as argv[1..6].
# Reads stdin: 4-byte big-endian payload length, then raw payload bytes.
# Writes stdout: one JSON object per SIP response received.
_DRIVER_SCRIPT: Final[str] = r"""
import socket, sys, json, base64, struct
bind_host = sys.argv[1]
bind_port = int(sys.argv[2])
remote_host = sys.argv[3]
remote_port = int(sys.argv[4])
transport = sys.argv[5].upper()
timeout_secs = float(sys.argv[6])
collect_all = sys.argv[7] == "1"

length_bytes = sys.stdin.buffer.read(4)
if len(length_bytes) < 4:
    sys.exit(1)
payload_len = struct.unpack(">I", length_bytes)[0]
payload = sys.stdin.buffer.read(payload_len)

MAX_RESPONSES = 8

if transport == "TCP":
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_secs)
    if bind_port > 0:
        sock.bind((bind_host, bind_port))
    sock.connect((remote_host, remote_port))
    sock.sendall(payload)
    chunks = []
    while True:
        try:
            chunk = sock.recv(65535)
        except (socket.timeout, TimeoutError):
            break
        if not chunk:
            break
        chunks.append(chunk)
    sock.close()
    if chunks:
        raw = b"".join(chunks)
        print(json.dumps({"raw_b64": base64.b64encode(raw).decode(), "host": remote_host, "port": remote_port}), flush=True)
else:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (OSError, AttributeError):
        pass
    sock.bind((bind_host, bind_port))
    sock.settimeout(timeout_secs)
    # connect() so the kernel scores this socket above any wildcard listener
    # (e.g. kamailio on :5060) when routing inbound replies from this UE peer.
    # Without it, replies race into the unconnected listener and recvfrom()
    # times out even when the UE responded.
    try:
        sock.connect((remote_host, remote_port))
    except OSError as exc:
        sys.stderr.write(f"connect({remote_host}:{remote_port}) failed: {exc}\n")
    sock.send(payload)
    count = 0
    while count < MAX_RESPONSES:
        try:
            data, addr = sock.recvfrom(65535)
        except (socket.timeout, TimeoutError):
            break
        raw_b64 = base64.b64encode(data).decode()
        print(json.dumps({"raw_b64": raw_b64, "host": addr[0], "port": addr[1]}), flush=True)
        count += 1
        first_line = data.decode("utf-8", errors="replace").split("\r\n", 1)[0]
        code = 0
        parts = first_line.split(None, 2)
        if len(parts) >= 2:
            try:
                code = int(parts[1])
            except ValueError:
                pass
        if not collect_all and code >= 200:
            break
    sock.close()
"""

_MAX_DRIVER_TIMEOUT_EXTRA_S: Final[float] = 5.0


@dataclass(frozen=True)
class ContainerSendResult:
    """Result of a ``send_via_container`` call."""

    payload_size: int
    raw_responses: tuple[tuple[bytes, tuple[str, int]], ...]
    observer_events: tuple[str, ...]


def send_via_container(
    *,
    container: str,
    bind_host: str,
    bind_port: int = 0,
    remote_host: str,
    remote_port: int,
    transport: Literal["UDP", "TCP"],
    payload: bytes,
    timeout_seconds: float,
    collect_all_responses: bool,
) -> ContainerSendResult:
    """Send *payload* from inside *container*'s network namespace and collect responses.

    The payload is sent to ``(remote_host, remote_port)`` using *transport*.  The
    container-side socket is bound to ``(bind_host, bind_port)``.  Passing
    ``bind_port=0`` lets the kernel pick a random source port; passing a non-zero
    value is required when the caller wants incoming responses (e.g. 100 Trying,
    180 Ringing) to arrive back on a specific known port that matches the SIP
    ``Via`` sent-by header value.

    Returns a :class:`ContainerSendResult` whose ``raw_responses`` tuples carry raw
    SIP bytes and the sender address.  The caller is responsible for converting these
    to :class:`~volte_mutation_fuzzer.sender.contracts.SocketObservation` using e.g.
    :func:`~volte_mutation_fuzzer.sender.core.parse_sip_response`.
    """
    length_prefix = len(payload).to_bytes(4, "big")
    stdin_data = length_prefix + payload

    cmd = [
        "docker",
        "exec",
        "-i",
        container,
        "python3",
        "-c",
        _DRIVER_SCRIPT,
        bind_host,
        str(bind_port),
        remote_host,
        str(remote_port),
        transport,
        str(timeout_seconds),
        "1" if collect_all_responses else "0",
    ]

    process_timeout = timeout_seconds + _MAX_DRIVER_TIMEOUT_EXTRA_S
    observer_events: list[str] = [
        f"container-send:exec:{container}",
        f"container-send:bind:{bind_host}:{bind_port}",
    ]

    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            timeout=process_timeout,
        )
    except subprocess.TimeoutExpired as exc:
        observer_events.append(f"container-send:timeout:{exc}")
        return ContainerSendResult(
            payload_size=len(payload),
            raw_responses=(),
            observer_events=tuple(observer_events),
        )
    except (FileNotFoundError, OSError) as exc:
        observer_events.append(f"container-send:error:{exc}")
        return ContainerSendResult(
            payload_size=len(payload),
            raw_responses=(),
            observer_events=tuple(observer_events),
        )

    if proc.returncode != 0:
        stderr_snippet = (proc.stderr or b"").decode("utf-8", errors="replace")[:200]
        observer_events.append(f"container-send:exit:{proc.returncode}:{stderr_snippet}")

    raw_responses: list[tuple[bytes, tuple[str, int]]] = []
    stdout = (proc.stdout or b"").decode("utf-8", errors="replace")
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            raw = base64.b64decode(obj["raw_b64"])
            addr = (str(obj["host"]), int(obj["port"]))
            raw_responses.append((raw, addr))
        except (ValueError, KeyError):
            observer_events.append(f"container-send:malformed-line:{line[:80]}")

    observer_events.append(f"container-send:responses:{len(raw_responses)}")

    return ContainerSendResult(
        payload_size=len(payload),
        raw_responses=tuple(raw_responses),
        observer_events=tuple(observer_events),
    )


__all__ = [
    "ContainerSendResult",
    "send_via_container",
]
