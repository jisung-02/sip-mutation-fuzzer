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
_RAW_SOCKET_PROBE_SCRIPT: Final[str] = (
    "import socket\n"
    "sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)\n"
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
_RAW_DRIVER_SCRIPT: Final[str] = r"""
import base64
import socket
import struct
import sys


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


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

udp_length = 8 + len(payload)
udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)

version_ihl = (4 << 4) | 5
tos = 0
total_length = 20 + udp_length
identification = 0
flags_fragment = 0
ttl = 64
protocol = socket.IPPROTO_UDP
header_checksum = 0
src_addr = socket.inet_aton(src_ip)
dst_addr = socket.inet_aton(dst_ip)
ip_header = struct.pack(
    "!BBHHHBBH4s4s",
    version_ihl,
    tos,
    total_length,
    identification,
    flags_fragment,
    ttl,
    protocol,
    header_checksum,
    src_addr,
    dst_addr,
)
header_checksum = _checksum(ip_header)
ip_header = struct.pack(
    "!BBHHHBBH4s4s",
    version_ihl,
    tos,
    total_length,
    identification,
    flags_fragment,
    ttl,
    protocol,
    header_checksum,
    src_addr,
    dst_addr,
)

pseudo_header = struct.pack("!4s4sBBH", src_addr, dst_addr, 0, protocol, udp_length)
udp_checksum = _checksum(pseudo_header + udp_header + payload)
udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, udp_checksum)

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sock.settimeout(timeout_seconds)
sock.sendto(ip_header + udp_header + payload, (dst_ip, dst_port))
sock.close()
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
        _RAW_SOCKET_PROBE_SCRIPT if transport == "UDP" else _TCP_STREAM_PROBE_SCRIPT
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
) -> NativeIPsecSendResult:
    driver_script = _RAW_DRIVER_SCRIPT if transport == "UDP" else _TCP_DRIVER_SCRIPT
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
    stdin_data = len(payload).to_bytes(4, "big") + payload
    try:
        proc = subprocess.run(
            driver,
            input=stdin_data,
            capture_output=True,
            timeout=timeout_seconds,
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
    return NativeIPsecSendResult(
        payload_size=len(payload),
        observer_events=(
            "native-ipsec:send:ok",
            f"native-ipsec:send:transport:{transport.lower()}",
            f"native-ipsec:tuple:{src_ip}:{src_port}->{dst_ip}:{dst_port}",
        ),
    )


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
