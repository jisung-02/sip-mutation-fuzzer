from __future__ import annotations

import logging
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Final, Literal

from volte_mutation_fuzzer.sender.contracts import (
    ObservationClass,
    SendArtifact,
    SocketObservation,
)
from volte_mutation_fuzzer.sender.real_ue import (
    RealUEDirectResolutionError,
    ResolvedNativeIPsecSession,
)

logger = logging.getLogger(__name__)

_SIP_STATUS_PATTERN: Final[re.Pattern[str]] = re.compile(r"^SIP/2\.0\s+(\d{3})\s*(.*)$")
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
        headers[header_name.casefold()] = (
            _normalize_optional_text(line[value_start:next_start]) or ""
        )
    return headers


def _extract_wire_headers(text: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in text.splitlines():
        for header_name in ("Call-ID", "CSeq", "Via"):
            prefix = f"{header_name}:"
            if not line.lower().startswith(prefix.lower()):
                continue
            headers[header_name.casefold()] = (
                _normalize_optional_text(line[len(prefix) :]) or ""
            )
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
        return _parse_correlation_text(
            artifact.packet_bytes.decode("utf-8", errors="replace")
        )

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
    ipsec_mode: Literal["native", "null"] = "native",
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

    # null mode: temporarily switch outbound SA encryption to NULL so the
    # packet travels inside a well-formed ESP header (honoring SPD/xfrm
    # policy) but the payload is plaintext — observable in pcap. The swap
    # records the exact SPI and the original ``enc`` tail (algorithm name
    # plus key hex when the dump exposes it) so the restore after the send
    # re-encrypts the same SA instead of an arbitrary one.
    null_swap: NullEalgSwap | None = None
    if ipsec_mode == "null":
        null_swap = _save_and_null_outbound_ealg(
            container=container,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
        )
    restore_events: list[str] = []

    def _restore_null_swap() -> None:
        if null_swap is None:
            return
        restored = _restore_outbound_ealg(
            container=container, src_ip=src_ip, dst_ip=dst_ip, swap=null_swap
        )
        if restored:
            restore_events.append(f"native-ipsec:null-mode:restore-ok:{null_swap.spi}")
        else:
            restore_events.append(
                f"native-ipsec:null-mode:restore-failed:{null_swap.spi}"
            )

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
        _restore_null_swap()
        raise NativeIPsecError(
            f"native IPsec injector failed: {exc}",
            observer_events=(
                f"native-ipsec:send:failed:{type(exc).__name__}",
                *restore_events,
            ),
        ) from exc

    _restore_null_swap()

    if proc.returncode != 0:
        stderr_text = _normalize_optional_text(
            (proc.stderr or b"").decode("utf-8", errors="replace")[:200]
        )
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
    if ipsec_mode == "null":
        if null_swap is not None:
            observer_events.append(
                "native-ipsec:null-mode:ealg-saved:"
                f"{null_swap.original_enc_tail.split()[0]}:{null_swap.spi}"
            )
        else:
            observer_events.append("native-ipsec:null-mode:no-ealg-found")
        observer_events.extend(restore_events)
    if response_bytes is not None:
        observer_events.append(
            f"native-ipsec:recv:ok:{peer_host}:{peer_port}:{len(response_bytes)}B"
        )

    return NativeIPsecSendResult(
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
        if (
            cseq_match is None
            or cseq_match.group(2).upper() != correlation.cseq_method.upper()
        ):
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
            observation = _parse_pcscf_log_observation(
                line, ue_ip=ue_ip, ue_port=ue_port
            )
            if observation is None:
                continue
            observations.append(observation)
            if (
                not collect_all_responses
                and observation.classification != "provisional"
            ):
                return tuple(observations)
        time.sleep(poll_interval_seconds)
    return tuple(observations)


@dataclass(frozen=True)
class NullEalgSwap:
    """State needed to undo a null-encryption swap on one outbound SA.

    ``original_enc_tail`` is the full text after ``enc`` in the xfrm state
    dump — the algorithm name plus the key hex when the dump exposes it
    (e.g. ``cbc(aes) 0x44556677``). Keeping the whole tail lets the restore
    re-specify the key, which ``ip xfrm state update`` requires for
    non-null algorithms.
    """

    spi: str
    original_enc_tail: str


@dataclass(frozen=True)
class _OutboundSa:
    spi: str
    enc_tail: str | None
    sel_sport: str | None
    sel_dport: str | None


def _collect_outbound_sas(stdout: str, src_ip: str, dst_ip: str) -> list[_OutboundSa]:
    """Parse ``ip xfrm state`` blocks for ESP SAs with src→dst direction.

    Real iproute2 output puts the SPI on the ``proto esp spi 0x… reqid …``
    line (not on a standalone ``spi`` line), so both shapes are accepted.
    The selector line (``sel src … sport X dport Y``) is captured when
    present — IMS installs several SAs with the same src/dst pair and only
    the selector's ports distinguish them.
    """
    sas: list[_OutboundSa] = []
    block: list[str] = []
    blocks: list[list[str]] = []
    for line in stdout.splitlines():
        if not line.strip():
            if block:
                blocks.append(block)
                block = []
            continue
        block.append(line.strip())
    if block:
        blocks.append(block)

    for blk in blocks:
        header = blk[0].split()
        if len(header) < 4 or header[0] != "src" or header[2] != "dst":
            continue
        if header[1] != src_ip or header[3] != dst_ip:
            continue
        spi: str | None = None
        enc_tail: str | None = None
        sel_sport: str | None = None
        sel_dport: str | None = None
        for line in blk[1:]:
            tokens = line.split()
            if line.startswith("sel "):
                if "sport" in tokens:
                    sel_sport = tokens[tokens.index("sport") + 1]
                if "dport" in tokens:
                    sel_dport = tokens[tokens.index("dport") + 1]
            if spi is None:
                if line.startswith("spi "):
                    spi = tokens[1].split("(")[0]
                elif line.startswith("proto ") and "spi" in tokens:
                    spi = tokens[tokens.index("spi") + 1].split("(")[0]
            if enc_tail is None and (
                line.startswith("ealg ") or line.startswith("enc ")
            ):
                enc_tail = line.split(None, 1)[1].strip()
        if spi is not None:
            sas.append(
                _OutboundSa(
                    spi=spi,
                    enc_tail=enc_tail,
                    sel_sport=sel_sport,
                    sel_dport=sel_dport,
                )
            )
    return sas


def _selector_port_matches(port_text: str | None, port: int) -> bool | None:
    """Return whether the selector covers ``port``; None when it can't tell."""
    if port_text is None:
        return None
    range_text = port_text.split("(")[0]
    lo, _, hi = range_text.partition("-")
    try:
        if hi:
            return int(lo) <= port <= int(hi)
        return int(lo) == port
    except ValueError:
        return None


def _save_and_null_outbound_ealg(
    *,
    container: str,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
) -> NullEalgSwap | None:
    """Temporarily set the P-CSCF→UE outbound SA encryption to NULL.

    Queries ``ip xfrm state`` for ESP SAs with direction ``src <src_ip> dst
    <dst_ip>``, picks the one whose selector matches the send tuple
    (``src_port``→``dst_port``) — IMS installs two outbound SAs per UE with
    identical src/dst and different ports — captures its ``enc`` tail, then
    switches it to ``enc null`` via ``ip xfrm state update``.

    Returns the swap handle for :func:`_restore_outbound_ealg`, or ``None``
    when no SA could be selected unambiguously or the null update failed
    (nothing was nulled, so there is nothing to restore).
    """
    try:
        result = subprocess.run(
            ["docker", "exec", container, "ip", "xfrm", "state"],
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None

    candidates = [
        sa for sa in _collect_outbound_sas(result.stdout, src_ip, dst_ip) if sa.enc_tail
    ]
    if not candidates:
        return None
    exact = [
        sa
        for sa in candidates
        if _selector_port_matches(sa.sel_sport, src_port) is True
        and _selector_port_matches(sa.sel_dport, dst_port) is True
    ]
    if len(exact) == 1:
        target = exact[0]
    elif len(candidates) == 1:
        target = candidates[0]
    else:
        logger.warning(
            "null mode: %d outbound SAs match %s->%s and the send tuple "
            "%d->%d does not disambiguate them; refusing to null an arbitrary SA",
            len(candidates),
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        )
        return None

    try:
        null_result = subprocess.run(
            [
                "docker",
                "exec",
                container,
                "ip",
                "xfrm",
                "state",
                "update",
                "src",
                src_ip,
                "dst",
                dst_ip,
                "proto",
                "esp",
                "spi",
                target.spi,
                "enc",
                "null",
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("null mode: ealg swap failed for spi %s: %s", target.spi, exc)
        return None
    if null_result.returncode != 0:
        stderr_text = (null_result.stderr or null_result.stdout or "").strip()[:200]
        logger.warning(
            "null mode: ealg swap failed for spi %s: %s",
            target.spi,
            stderr_text or "unknown error",
        )
        return None
    return NullEalgSwap(spi=target.spi, original_enc_tail=target.enc_tail or "null")


def _restore_outbound_ealg(
    *,
    container: str,
    src_ip: str,
    dst_ip: str,
    swap: NullEalgSwap,
) -> bool:
    """Restore the original encryption on the SA the swap nulled.

    The update targets the SPI saved in ``swap`` — re-querying by src/dst
    could pick a different (e.g. rekeyed) SA and leave the nulled one
    permanently null-encrypted. The saved ``enc`` tail is split so the
    algorithm name and key hex become separate argv tokens, as iproute2
    expects. Returns True only when the update succeeded.
    """
    cmd = [
        "docker",
        "exec",
        container,
        "ip",
        "xfrm",
        "state",
        "update",
        "src",
        src_ip,
        "dst",
        dst_ip,
        "proto",
        "esp",
        "spi",
        swap.spi,
        "enc",
        *swap.original_enc_tail.split(),
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        logger.error(
            "null mode: ealg restore failed for spi %s — SA may remain "
            "null-encrypted; manual fix: %s (error: %s)",
            swap.spi,
            " ".join(cmd),
            exc,
        )
        return False
    if result.returncode != 0:
        stderr_text = (result.stderr or result.stdout or "").strip()[:200]
        logger.error(
            "null mode: ealg restore failed for spi %s — SA may remain "
            "null-encrypted; manual fix: %s (stderr: %s)",
            swap.spi,
            " ".join(cmd),
            stderr_text or "unknown error",
        )
        return False
    return True


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
