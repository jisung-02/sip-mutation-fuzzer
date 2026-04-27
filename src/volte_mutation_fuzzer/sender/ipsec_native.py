from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass
from typing import Final, Literal

from volte_mutation_fuzzer.sender.contracts import ObservationClass, SendArtifact, SocketObservation
from volte_mutation_fuzzer.sender.real_ue import (
    RealUEDirectResolutionError,
    ResolvedNativeIPsecSession,
)

_CRLF: Final[str] = "\r\n"
_SIP_STATUS_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^SIP/2\.0\s+(\d{3})\s*(.*)$"
)
_CALL_ID_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"Call-ID:\s*([^\r\n]+)", re.IGNORECASE
)
_CSEQ_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"CSeq:\s*(\d+)\s+([A-Z][A-Z0-9_-]*)",
    re.IGNORECASE,
)
_VIA_BRANCH_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"Via:\s.*?branch=([^;\s]+)", re.IGNORECASE
)
_LINE_BRANCH_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"branch=([^;\s]+)", re.IGNORECASE
)
_DEFAULT_POLL_INTERVAL_SECONDS: Final[float] = 0.25
_LOG_HEADER_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b(Call-ID|CSeq|Via):\s*(.*?)(?=\s+(?:Call-ID|CSeq|Via):|$)",
    re.IGNORECASE,
)
# Earlier iterations of this module used SOCK_RAW + IP_HDRINCL to spoof the
# protected source port. That path silently *bypasses* Linux xfrm output
# processing, so "native IPsec" was in fact shipping plaintext UDP on the
# wire — it only appeared to work against lenient UEs (e.g. the original
# Galaxy A31) that also accepted plaintext on the protected ports. Spec-strict
# UEs (Galaxy A16, Pixel) drop those plaintext datagrams and every case times
# out.
#
# The correct approach is to use a normal kernel UDP socket inside the P-CSCF
# netns with an explicit bind to the protected source port. The installed
# xfrm OUT policy then auto-encapsulates outbound traffic as ESP, which is
# what the UE actually expects. SO_REUSEPORT lets us share the port with
# kamailio when its own UDP listener has already bound it.
_UDP_DGRAM_PROBE_SCRIPT: Final[str] = (
    "import socket\n"
    "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
    "sock.close()\n"
    "print('ok')\n"
)

# TCP native path uses kernel SOCK_STREAM inside the P-CSCF netns so the
# installed xfrm SA encrypts outbound traffic automatically. Raw TCP with a
# manual 3-way handshake is technically possible but the kernel RST on
# source-host would fight us; reusing the kernel TCP stack side-steps that.
# SO_REUSEPORT is attempted so we can share the protected source port with
# kamailio when it already has a listener bound there.
_TCP_STREAM_PROBE_SCRIPT: Final[str] = (
    "import socket\n"
    "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
    "sock.close()\n"
    "print('ok')\n"
)
_UDP_DRIVER_SCRIPT: Final[str] = r"""
import socket
import struct
import sys
import time
import select as select_mod


src_ip = sys.argv[1]
src_port = int(sys.argv[2])
dst_ip = sys.argv[3]
dst_port = int(sys.argv[4])
timeout_seconds = float(sys.argv[5])
# Optional secondary 4-tuple — needed because the IMS IPsec spec
# (3GPP TS 33.203) negotiates four SAs (UE/P-CSCF × client/server) and the
# kernel's xfrm output policy may match either the server-side SA
# (6109<->9901) or the client-side SA (5109<->9900) depending on which
# pair is currently active. Replies come back on whichever SA the UE
# happened to use; binding both so we don't miss the ones that land on
# the unattended port. Pass 0 for both to disable secondary.
alt_src_port = int(sys.argv[6]) if len(sys.argv) > 6 else 0
alt_dst_port = int(sys.argv[7]) if len(sys.argv) > 7 else 0

length_bytes = sys.stdin.buffer.read(4)
if len(length_bytes) < 4:
    sys.exit(1)
payload_len = struct.unpack(">I", length_bytes)[0]
payload = sys.stdin.buffer.read(payload_len)


sock_primary = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock_primary.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    sock_primary.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
except (OSError, AttributeError):
    pass
sock_primary.settimeout(timeout_seconds)
try:
    sock_primary.bind((src_ip, src_port))
except OSError as exc:
    sys.stderr.write(f"bind({src_ip}:{src_port}) failed: {exc}\n")
    sys.exit(2)
# connect() the UDP socket so the kernel prefers it over kamailio's
# unconnected listener when routing inbound packets from this UE peer.
# Linux's UDP socket lookup scores connected sockets higher than
# wildcard-bound ones, regardless of SO_REUSEPORT hashing — without this,
# every reply from A16 races into kamailio and gets dropped as a stray.
try:
    sock_primary.connect((dst_ip, dst_port))
except OSError as exc:
    sys.stderr.write(f"connect({dst_ip}:{dst_port}) failed: {exc}\n")
    sys.exit(3)

# Optional alt socket on the alternate IPsec SA pair (server vs client).
# Only created when both alt ports were supplied — silently no-op
# otherwise to preserve the original single-socket behaviour.
sock_alt = None
if alt_src_port and alt_dst_port and alt_src_port != src_port:
    try:
        sock_alt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_alt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock_alt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (OSError, AttributeError):
            pass
        sock_alt.settimeout(timeout_seconds)
        sock_alt.bind((src_ip, alt_src_port))
        sock_alt.connect((dst_ip, alt_dst_port))
    except OSError as exc:
        # Best-effort: log and fall back to primary only. The original
        # path (single socket) still works.
        sys.stderr.write(f"alt bind/connect {src_ip}:{alt_src_port} -> {dst_ip}:{alt_dst_port} failed: {exc}\n")
        if sock_alt is not None:
            try: sock_alt.close()
            except OSError: pass
        sock_alt = None

sock_primary.send(payload)

socks = [sock_primary] + ([sock_alt] if sock_alt else [])
# RFC 5626 (and 3GPP TS 33.203 IMS profile) UEs send CRLF / CRLFCRLF
# keepalives on the protected port. Without filtering, the very first
# datagram on this socket is often a keepalive that arrives a few ms
# before the real SIP response — recvfrom() returns it, the parent
# parses it as an empty SIP message, and the case is mis-classified as
# timeout. Loop past these until a real SIP-shaped datagram arrives or
# the budget expires. Confirmed against the 2026-04-27 INVITE Pixel
# campaign where 12/13 timeouts had substantial UE → fuzzer ESP
# responses 15 ms after a 78-byte keepalive ESP.
deadline = time.monotonic() + timeout_seconds
result_data = None
result_peer = None
try:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        ready, _, _ = select_mod.select(socks, [], [], remaining)
        if not ready:
            break
        data, peer = ready[0].recvfrom(65535)
        # Empty / whitespace-only datagram is a keepalive, skip it.
        if not data.strip(b"\r\n\t "):
            continue
        result_data, result_peer = data, peer
        break

    if result_data is None:
        sys.stdout.buffer.write((0).to_bytes(4, "big"))
    else:
        sys.stdout.buffer.write(len(result_data).to_bytes(4, "big"))
        sys.stdout.buffer.write(result_peer[0].encode("ascii"))
        sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.write(result_peer[1].to_bytes(2, "big"))
        sys.stdout.buffer.write(result_data)
    sys.stdout.buffer.flush()
finally:
    sock_primary.close()
    if sock_alt is not None:
        sock_alt.close()
"""

_TCP_DRIVER_SCRIPT: Final[str] = r"""
import socket
import struct
import sys


src_ip = sys.argv[1]
src_port = int(sys.argv[2])
dst_ip = sys.argv[3]
dst_port = int(sys.argv[4])
timeout_seconds = float(sys.argv[5])

length_bytes = sys.stdin.buffer.read(4)
if len(length_bytes) < 4:
    sys.exit(1)
payload_len = struct.unpack(">I", length_bytes)[0]
payload = sys.stdin.buffer.read(payload_len)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
except (OSError, AttributeError):
    pass
sock.settimeout(timeout_seconds)
try:
    sock.bind((src_ip, src_port))
except OSError as exc:
    sys.stderr.write(f"bind({src_ip}:{src_port}) failed: {exc}\n")
    sys.exit(2)
try:
    sock.connect((dst_ip, dst_port))
    sock.sendall(payload)
finally:
    try:
        sock.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    sock.close()
"""


@dataclass(frozen=True)
class ArtifactCorrelation:
    call_id: str | None
    cseq_method: str | None
    cseq_sequence: int | None
    via_branch: str | None
    confidence: Literal["high", "low"]


@dataclass(frozen=True)
class NativeIPsecSendResult:
    payload_size: int
    observer_events: tuple[str, ...]
    # Best-effort response captured on the same bound UDP socket inside the
    # P-CSCF netns. None when the driver timed out waiting, when the UE
    # didn't reply, or when SO_REUSEPORT hashed the reply to kamailio.
    response_bytes: bytes | None = None
    response_peer_host: str | None = None
    response_peer_port: int | None = None


@dataclass(frozen=True)
class NativeIPsecPreflight:
    pcscf_port: int
    observer_events: tuple[str, ...]


class NativeIPsecError(RealUEDirectResolutionError):
    """Domain-specific real-UE error for native IPsec send failures."""


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _extract_log_headers(line: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    header_names = ("Call-ID", "CSeq", "Via")
    for header_name in header_names:
        start_match = re.search(
            rf"(?:^|\s){re.escape(header_name)}:\s*",
            line,
            re.IGNORECASE,
        )
        if start_match is None:
            continue
        value_start = start_match.end()
        next_start = len(line)
        for candidate in header_names:
            if candidate.lower() == header_name.lower():
                continue
            candidate_match = re.search(
                rf"\s{re.escape(candidate)}:\s*",
                line[value_start:],
                re.IGNORECASE,
            )
            if candidate_match is not None:
                next_start = min(next_start, value_start + candidate_match.start())
        headers[header_name.casefold()] = _normalize_optional_text(
            line[value_start:next_start]
        ) or ""
    return headers


def _extract_wire_headers(text: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in text.splitlines():
        for header_name in ("Call-ID", "CSeq", "Via"):
            prefix = f"{header_name}:"
            if not line.lower().startswith(prefix.lower()):
                continue
            headers[header_name.casefold()] = _normalize_optional_text(
                line[len(prefix) :]
            ) or ""
    return headers


def _parse_headers_to_correlation(headers: dict[str, str]) -> ArtifactCorrelation:
    call_id = _normalize_optional_text(headers.get("call-id"))
    cseq_method = None
    cseq_sequence = None
    cseq_text = headers.get("cseq")
    if cseq_text:
        cseq_match = re.match(r"(\d+)\s+([A-Z][A-Z0-9_-]*)", cseq_text, re.IGNORECASE)
        if cseq_match is not None:
            cseq_sequence = int(cseq_match.group(1))
            cseq_method = cseq_match.group(2).upper()
    via_branch = None
    via_text = headers.get("via")
    if via_text:
        via_match = re.search(r"branch=([^;\s]+)", via_text, re.IGNORECASE)
        via_branch = _normalize_optional_text(via_match.group(1) if via_match else None)

    confidence = (
        "high"
        if any((call_id, cseq_method, cseq_sequence is not None, via_branch))
        else "low"
    )
    return ArtifactCorrelation(
        call_id=call_id,
        cseq_method=cseq_method,
        cseq_sequence=cseq_sequence,
        via_branch=via_branch,
        confidence=confidence,
    )


def _parse_correlation_text(text: str) -> ArtifactCorrelation:
    return _parse_headers_to_correlation(_extract_wire_headers(text))


def extract_correlation_from_artifact(artifact: SendArtifact) -> ArtifactCorrelation:
    if artifact.packet is not None:
        cseq = getattr(artifact.packet, "cseq", None)
        via = getattr(artifact.packet, "via", ())
        top_via = via[0] if via else None
        cseq_method = None
        if cseq is not None:
            raw_method = getattr(cseq, "method", None)
            cseq_method = None if raw_method is None else str(raw_method)
        call_id = getattr(artifact.packet, "call_id", None)
        cseq_sequence = getattr(cseq, "sequence", None)
        via_branch = getattr(top_via, "branch", None)
        confidence: Literal["high", "low"] = (
            "high"
            if any((call_id, cseq_method, cseq_sequence is not None, via_branch))
            else "low"
        )
        return ArtifactCorrelation(
            call_id=call_id,
            cseq_method=cseq_method,
            cseq_sequence=cseq_sequence,
            via_branch=via_branch,
            confidence=confidence,
        )

    if artifact.wire_text is not None:
        correlation = _parse_correlation_text(artifact.wire_text)
        if correlation.confidence == "low":
            return correlation
        return correlation

    if artifact.packet_bytes is not None:
        return _parse_correlation_text(artifact.packet_bytes.decode("utf-8", errors="replace"))

    return ArtifactCorrelation(None, None, None, None, "low")


def preflight_native_ipsec_target(
    *,
    session: ResolvedNativeIPsecSession,
    ue_ip: str,
    ue_port: int,
    container: str,
    transport: Literal["UDP", "TCP"] = "UDP",
) -> NativeIPsecPreflight:
    if ue_ip != session.ue_ip:
        raise RealUEDirectResolutionError(
            f"native IPsec preflight UE mismatch: expected {session.ue_ip}, got {ue_ip}"
        )
    if ue_port not in session.port_map:
        raise RealUEDirectResolutionError(
            f"native IPsec preflight could not map UE protected port {ue_port}"
        )

    probe_script = (
        _UDP_DGRAM_PROBE_SCRIPT if transport == "UDP" else _TCP_STREAM_PROBE_SCRIPT
    )
    probe_label = "raw socket" if transport == "UDP" else "stream socket"
    try:
        probe = subprocess.run(
            [
                "docker",
                "exec",
                container,
                "python3",
                "-c",
                probe_script,
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        raise RealUEDirectResolutionError(
            f"native IPsec preflight failed: {probe_label} unavailable in {container}: {exc}"
        ) from exc
    if probe.returncode != 0:
        stderr_text = _normalize_optional_text((probe.stderr or probe.stdout)[:200])
        raise RealUEDirectResolutionError(
            f"native IPsec preflight failed: {probe_label} unavailable in {container}: {stderr_text or 'unknown error'}"
        )

    pcscf_port = session.pcscf_port_for(ue_port)
    return NativeIPsecPreflight(
        pcscf_port=pcscf_port,
        observer_events=(
            f"native-ipsec:preflight:ok:{container}",
            f"native-ipsec:preflight:transport:{transport.lower()}",
            f"native-ipsec:tuple:{session.pcscf_ip}:{pcscf_port}->{ue_ip}:{ue_port}",
        ),
    )


def send_via_native_ipsec(
    *,
    container: str,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    payload: bytes,
    timeout_seconds: float,
    transport: Literal["UDP", "TCP"] = "UDP",
    alt_src_port: int = 0,
    alt_dst_port: int = 0,
) -> NativeIPsecSendResult:
    driver_script = _UDP_DRIVER_SCRIPT if transport == "UDP" else _TCP_DRIVER_SCRIPT
    driver = [
        "docker",
        "exec",
        "-i",
        container,
        "python3",
        "-c",
        driver_script,
        src_ip,
        str(src_port),
        dst_ip,
        str(dst_port),
        str(timeout_seconds),
    ]
    # Append alt-pair argv only when supplied (UDP path only — TCP driver
    # ignores extra args). Keeps the original 5-arg call signature
    # backward-compatible: callers that don't supply alts get the
    # original single-socket behaviour.
    if transport == "UDP" and (alt_src_port or alt_dst_port):
        driver.extend([str(alt_src_port), str(alt_dst_port)])
    stdin_data = len(payload).to_bytes(4, "big") + payload
    try:
        proc = subprocess.run(
            driver,
            input=stdin_data,
            capture_output=True,
            # Grace over the socket-level timeout so the driver can finish
            # recvfrom + frame output before subprocess reaps it.
            timeout=timeout_seconds + 1.5,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        raise NativeIPsecError(
            f"native IPsec injector failed: {exc}",
            observer_events=(f"native-ipsec:send:failed:{type(exc).__name__}",),
        ) from exc
    if proc.returncode != 0:
        stderr_text = _normalize_optional_text((proc.stderr or b"").decode("utf-8", errors="replace")[:200])
        raise NativeIPsecError(
            f"native IPsec injector failed: {stderr_text or 'unknown error'}",
            observer_events=("native-ipsec:send:failed:returncode",),
        )

    response_bytes, peer_host, peer_port = _parse_driver_response(proc.stdout or b"")
    observer_events = [
        "native-ipsec:send:ok",
        f"native-ipsec:send:transport:{transport.lower()}",
        f"native-ipsec:tuple:{src_ip}:{src_port}->{dst_ip}:{dst_port}",
    ]
    if response_bytes is not None:
        observer_events.append(
            f"native-ipsec:recv:ok:{peer_host}:{peer_port}:{len(response_bytes)}B"
        )

    return NativeIPsecSendResult(
        payload_size=len(payload),
        observer_events=tuple(observer_events),
        response_bytes=response_bytes,
        response_peer_host=peer_host,
        response_peer_port=peer_port,
    )


def _parse_driver_response(
    stdout: bytes,
) -> tuple[bytes | None, str | None, int | None]:
    """Decode the length-prefixed response frame emitted by _UDP_DRIVER_SCRIPT.

    Frame layout when a reply was received:
        uint32 length_big_endian
        ascii peer_host + b"\n"
        uint16 peer_port_big_endian
        bytes  payload
    Frame layout on timeout: uint32 length=0 (no peer, no payload).
    Returns (None, None, None) on any parse issue.
    """
    if len(stdout) < 4:
        return None, None, None
    length = int.from_bytes(stdout[:4], "big")
    if length == 0:
        return None, None, None
    rest = stdout[4:]
    nl = rest.find(b"\n")
    if nl < 0 or len(rest) < nl + 1 + 2 + length:
        return None, None, None
    peer_host = rest[:nl].decode("ascii", errors="replace")
    peer_port = int.from_bytes(rest[nl + 1 : nl + 3], "big")
    payload = rest[nl + 3 : nl + 3 + length]
    if len(payload) != length:
        return None, None, None
    return payload, peer_host, peer_port


def _parse_pcscf_log_observation(
    line: str,
    *,
    ue_ip: str,
    ue_port: int,
) -> SocketObservation | None:
    status_match = _SIP_STATUS_PATTERN.search(line)
    if status_match is None:
        return None

    code = int(status_match.group(1))
    reason = _normalize_optional_text(status_match.group(2)) or ""
    headers = _extract_log_headers(line)

    return SocketObservation(
        source="pcscf-log",
        remote_host=ue_ip,
        remote_port=ue_port,
        status_code=code,
        reason_phrase=reason,
        headers=headers,
        raw_text=line,
        raw_size=len(line.encode("utf-8")),
        classification=_classify_status_code(code),
    )


def _classify_status_code(status_code: int) -> ObservationClass:
    if 100 <= status_code < 200:
        return "provisional"
    if 200 <= status_code < 300:
        return "success"
    if 300 <= status_code < 400:
        return "redirection"
    if 400 <= status_code < 500:
        return "client_error"
    if 500 <= status_code < 600:
        return "server_error"
    if 600 <= status_code < 700:
        return "global_error"
    return "invalid"


def _matches_correlation(line: str, correlation: ArtifactCorrelation) -> bool:
    headers = _extract_log_headers(line)
    if correlation.call_id is not None:
        call_id = headers.get("call-id")
        if call_id is None or call_id != correlation.call_id:
            return False
    if correlation.cseq_method is not None:
        cseq_text = headers.get("cseq") or ""
        cseq_match = re.match(r"(\d+)\s+([A-Z][A-Z0-9_-]*)", cseq_text, re.IGNORECASE)
        if cseq_match is None or cseq_match.group(2).upper() != correlation.cseq_method.upper():
            return False
    if correlation.cseq_sequence is not None:
        cseq_text = headers.get("cseq") or ""
        cseq_match = re.match(r"(\d+)\s+([A-Z][A-Z0-9_-]*)", cseq_text, re.IGNORECASE)
        if cseq_match is None or int(cseq_match.group(1)) != correlation.cseq_sequence:
            return False
    if correlation.via_branch is not None:
        via_text = headers.get("via") or ""
        via_match = re.search(r"branch=([^;\s]+)", via_text, re.IGNORECASE)
        if via_match is None or via_match.group(1) != correlation.via_branch:
            return False
    return True


def _matches_tuple_hint(line: str, *, ue_ip: str, ue_port: int) -> bool:
    if ue_ip not in line:
        return False
    return re.search(rf"(?<!\d){ue_port}(?!\d)", line) is not None


def observe_pcscf_log_responses(
    *,
    container: str,
    since: str,
    ue_ip: str,
    ue_port: int,
    correlation: ArtifactCorrelation,
    timeout_seconds: float,
    poll_interval_seconds: float,
    collect_all_responses: bool,
    observer_events: list[str] | None = None,
) -> tuple[SocketObservation, ...]:
    observations: list[SocketObservation] = []
    seen_lines: set[str] = set()
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            result = subprocess.run(
                ["docker", "logs", container, "--since", since],
                capture_output=True,
                text=True,
                timeout=min(timeout_seconds, max(poll_interval_seconds, 0.2)),
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            if observer_events is not None:
                observer_events.append(
                    f"native-ipsec:observe:docker-logs-error:{type(exc).__name__}"
                )
            break
        for line in (result.stdout + result.stderr).splitlines():
            if not line or line in seen_lines:
                continue
            seen_lines.add(line)
            if correlation.confidence == "low":
                if not _matches_tuple_hint(line, ue_ip=ue_ip, ue_port=ue_port):
                    continue
            elif not _matches_correlation(line, correlation):
                continue
            observation = _parse_pcscf_log_observation(line, ue_ip=ue_ip, ue_port=ue_port)
            if observation is None:
                continue
            observations.append(observation)
            if not collect_all_responses and observation.classification != "provisional":
                return tuple(observations)
        time.sleep(poll_interval_seconds)
    return tuple(observations)


__all__ = [
    "ArtifactCorrelation",
    "NativeIPsecPreflight",
    "NativeIPsecError",
    "NativeIPsecSendResult",
    "extract_correlation_from_artifact",
    "observe_pcscf_log_responses",
    "preflight_native_ipsec_target",
    "send_via_native_ipsec",
]
