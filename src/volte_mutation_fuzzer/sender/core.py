import os
import re
import socket
import time
from collections.abc import Sequence
from typing import Final

from volte_mutation_fuzzer.sender.contracts import (
    CorrelationKey,
    DeliveryOutcome,
    ObservationClass,
    SendArtifact,
    SendReceiveResult,
    SocketObservation,
    TargetEndpoint,
)
from volte_mutation_fuzzer.sender.real_ue import (
    RealUEDirectError,
    RealUEDirectResolver,
    RealUEDirectRouteError,
    check_route_to_target,
    prepare_real_ue_direct_payload,
    setup_route_to_target,
)
from volte_mutation_fuzzer.sip.render import PacketModel, render_packet_bytes

_STATUS_LINE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^SIP/2\.0\s+(\d{3})\s*(.*)$"
)
_MAX_UDP_RESPONSES: Final[int] = 8
_TCP_READ_SIZE: Final[int] = 65535
_CRLF = "\r\n"


# ---------------------------------------------------------------------------
# Module-level helpers (reusable by dialog orchestrator etc.)
# ---------------------------------------------------------------------------


def classify_status_code(status_code: int) -> ObservationClass:
    """Map a numeric SIP status code to its ObservationClass."""
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


def parse_sip_response(
    data: bytes,
    remote_addr: tuple[str, int] | Sequence[object] | None,
) -> SocketObservation:
    """Parse raw UDP/TCP bytes into a SocketObservation."""
    raw_text = data.decode("utf-8", errors="replace")
    lines = raw_text.split(_CRLF)
    headers: dict[str, str] = {}
    body = ""
    status_code: int | None = None
    reason_phrase: str | None = None
    classification: ObservationClass = "invalid"

    if lines and (match := _STATUS_LINE_PATTERN.match(lines[0])):
        status_code = int(match.group(1))
        reason_phrase = match.group(2).strip() or None
        classification = classify_status_code(status_code)

        header_end = len(lines)
        for index, line in enumerate(lines[1:], start=1):
            if line == "":
                header_end = index
                break
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip().casefold()] = value.strip()

        if header_end < len(lines) - 1:
            body = _CRLF.join(lines[header_end + 1 :])

    remote_host: str | None = None
    remote_port: int | None = None
    if remote_addr is not None and len(remote_addr) >= 2:  # type: ignore[arg-type]
        remote_host = str(remote_addr[0])
        remote_port_candidate = remote_addr[1]
        if isinstance(remote_port_candidate, int):
            remote_port = remote_port_candidate

    return SocketObservation(
        remote_host=remote_host,
        remote_port=remote_port,
        status_code=status_code,
        reason_phrase=reason_phrase,
        headers=headers,
        body=body,
        raw_text=raw_text,
        raw_size=len(data),
        classification=classification,
    )


def read_udp_observations(
    sock: socket.socket,
    *,
    collect_all_responses: bool,
) -> list[SocketObservation]:
    """Read SIP responses from a UDP socket until timeout or final response."""
    observations: list[SocketObservation] = []
    while len(observations) < _MAX_UDP_RESPONSES:
        try:
            data, addr = sock.recvfrom(_TCP_READ_SIZE)
        except TimeoutError:
            break

        observation = parse_sip_response(data, addr)
        observations.append(observation)
        if not collect_all_responses and observation.classification != "provisional":
            break
    return observations


class SIPSenderReactor:
    """Sender/Reactor that can target softphones and real-ue-direct dumpipe flows."""

    def __init__(
        self,
        *,
        auto_setup_route: bool = True,
        env: dict[str, str] | None = None,
    ) -> None:
        self._auto_setup_route = auto_setup_route
        self._env = os.environ if env is None else env

    def send_artifact(
        self,
        artifact: SendArtifact,
        target: TargetEndpoint,
        *,
        collect_all_responses: bool = False,
    ) -> SendReceiveResult:
        correlation_key = self._build_correlation_key(artifact.packet)
        started_at = time.time()
        observer_events: list[str] = []
        resolved_target = target
        payload = b""

        try:
            if target.mode == "real-ue-direct":
                (
                    resolved_target,
                    payload,
                    observations,
                    direct_events,
                ) = self._send_real_ue_direct(
                    artifact,
                    target,
                    collect_all_responses=collect_all_responses,
                )
                observer_events.extend(direct_events)
            else:
                payload = self._build_payload(artifact)
                if target.transport == "UDP":
                    observations = self._send_udp(
                        payload,
                        target,
                        collect_all_responses=collect_all_responses,
                    )
                else:
                    observations = self._send_tcp(payload, target)
        except (OSError, RealUEDirectError) as exc:
            if isinstance(exc, RealUEDirectError):
                observer_events.extend(exc.observer_events)
                if exc.resolved_target is not None:
                    resolved_target = exc.resolved_target
            finished_at = time.time()
            return SendReceiveResult(
                target=resolved_target,
                artifact_kind=artifact.artifact_kind,
                correlation_key=correlation_key,
                bytes_sent=len(payload),
                outcome="send_error",
                responses=(),
                send_started_at=started_at,
                send_completed_at=finished_at,
                error=str(exc),
                observer_events=tuple(observer_events),
            )

        finished_at = time.time()
        return SendReceiveResult(
            target=resolved_target,
            artifact_kind=artifact.artifact_kind,
            correlation_key=correlation_key,
            bytes_sent=len(payload),
            outcome=self._resolve_outcome(observations),
            responses=tuple(observations),
            send_started_at=started_at,
            send_completed_at=finished_at,
            observer_events=tuple(observer_events),
        )

    def send_packet(
        self,
        packet: PacketModel,
        target: TargetEndpoint,
        *,
        collect_all_responses: bool = False,
    ) -> SendReceiveResult:
        return self.send_artifact(
            SendArtifact.from_packet(packet),
            target,
            collect_all_responses=collect_all_responses,
        )

    def send_wire_text(
        self,
        wire_text: str,
        target: TargetEndpoint,
        *,
        collect_all_responses: bool = False,
    ) -> SendReceiveResult:
        return self.send_artifact(
            SendArtifact.from_wire_text(wire_text),
            target,
            collect_all_responses=collect_all_responses,
        )

    def send_packet_bytes(
        self,
        packet_bytes: bytes,
        target: TargetEndpoint,
        *,
        collect_all_responses: bool = False,
    ) -> SendReceiveResult:
        return self.send_artifact(
            SendArtifact.from_packet_bytes(packet_bytes),
            target,
            collect_all_responses=collect_all_responses,
        )

    def _build_payload(self, artifact: SendArtifact) -> bytes:
        if artifact.packet is not None:
            return render_packet_bytes(artifact.packet)
        if artifact.wire_text is not None:
            return artifact.wire_text.encode("utf-8")
        assert artifact.packet_bytes is not None
        return artifact.packet_bytes

    def _build_correlation_key(self, packet: PacketModel | None) -> CorrelationKey:
        if packet is None:
            return CorrelationKey()

        cseq = getattr(packet, "cseq", None)
        return CorrelationKey(
            call_id=getattr(packet, "call_id", None),
            cseq_method=getattr(cseq, "method", None),
            cseq_sequence=getattr(cseq, "sequence", None),
        )

    def _send_real_ue_direct(
        self,
        artifact: SendArtifact,
        target: TargetEndpoint,
        *,
        collect_all_responses: bool,
    ) -> tuple[TargetEndpoint, bytes, list[SocketObservation], tuple[str, ...]]:
        resolved = RealUEDirectResolver(env=self._env).resolve(target)
        resolved_target = target.model_copy(
            update={
                "host": resolved.host,
                "port": resolved.port,
                "label": resolved.label,
            },
            deep=True,
        )

        route_result = check_route_to_target(resolved.host)
        observer_events = [*resolved.observer_events]
        if route_result.ok:
            observer_events.append(f"route-check:ok:{route_result.detail}")
        else:
            observer_events.append(f"route-check:missing:{route_result.detail}")
            if self._auto_setup_route:
                setup_result = setup_route_to_target(resolved.host, env=self._env)
                if setup_result.ok:
                    observer_events.append(f"route-setup:ok:{setup_result.detail}")
                else:
                    observer_events.append(f"route-setup:failed:{setup_result.detail}")
                    raise RealUEDirectRouteError(
                        "real-ue-direct route check failed for "
                        f"{resolved.host}: {setup_result.detail}. "
                        "add a host or UE IMS subnet route before retrying",
                        observer_events=tuple(observer_events),
                        resolved_target=resolved_target,
                    )
            else:
                raise RealUEDirectRouteError(
                    "real-ue-direct route check failed for "
                    f"{resolved.host}: {route_result.detail}. "
                    "add a host or UE IMS subnet route before retrying",
                    observer_events=tuple(observer_events),
                    resolved_target=resolved_target,
                )

        observations: list[SocketObservation] = []
        payload = b""
        if target.transport.upper() == "TCP":
            with socket.create_connection(
                (resolved.host, resolved.port), timeout=target.timeout_seconds
            ) as sock:
                sock.settimeout(target.timeout_seconds)
                local_host, local_port = sock.getsockname()
                observer_events.append(f"direct-local:{local_host}:{local_port}")
                payload, normalization_events = prepare_real_ue_direct_payload(
                    artifact,
                    local_host=local_host,
                    local_port=int(local_port),
                )
                observer_events.extend(normalization_events)
                sock.sendall(payload)
                chunks: list[bytes] = []
                while True:
                    try:
                        chunk = sock.recv(_TCP_READ_SIZE)
                    except TimeoutError:
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
                if chunks:
                    observations = [
                        self._parse_response(
                            b"".join(chunks), (resolved.host, resolved.port)
                        )
                    ]
        else:
            # local_host 결정: connect()로 라우팅 조회만 하고 즉시 닫음
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as _probe:
                _probe.connect((resolved.host, resolved.port))
                local_host, _ = _probe.getsockname()
            # 실제 송수신 소켓: unconnected로 유지해야 A31이 다른 포트(port_ps)로
            # 응답할 때도 recvfrom()이 받을 수 있음
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(target.timeout_seconds)
                sock.bind((local_host, 0))
                _, local_port = sock.getsockname()
                observer_events.append(f"direct-local:{local_host}:{local_port}")
                payload, normalization_events = prepare_real_ue_direct_payload(
                    artifact,
                    local_host=local_host,
                    local_port=int(local_port),
                )
                observer_events.extend(normalization_events)
                sock.sendto(payload, (resolved.host, resolved.port))
                observations = self._read_udp_observations(
                    sock,
                    collect_all_responses=collect_all_responses,
                )

        return resolved_target, payload, observations, tuple(observer_events)

    def _send_udp(
        self,
        payload: bytes,
        target: TargetEndpoint,
        *,
        collect_all_responses: bool,
    ) -> list[SocketObservation]:
        assert target.host is not None
        assert target.port is not None
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(target.timeout_seconds)
            sock.sendto(payload, (target.host, target.port))
            return self._read_udp_observations(
                sock,
                collect_all_responses=collect_all_responses,
            )

    def _read_udp_observations(
        self,
        sock: socket.socket,
        *,
        collect_all_responses: bool,
    ) -> list[SocketObservation]:
        return read_udp_observations(sock, collect_all_responses=collect_all_responses)

    def _send_tcp(
        self, payload: bytes, target: TargetEndpoint
    ) -> list[SocketObservation]:
        assert target.host is not None
        assert target.port is not None
        chunks: list[bytes] = []
        with socket.create_connection(
            (target.host, target.port), timeout=target.timeout_seconds
        ) as sock:
            sock.settimeout(target.timeout_seconds)
            sock.sendall(payload)

            while True:
                try:
                    chunk = sock.recv(_TCP_READ_SIZE)
                except TimeoutError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)

        if not chunks:
            return []

        return [self._parse_response(b"".join(chunks), (target.host, target.port))]

    def _parse_response(
        self,
        data: bytes,
        remote_addr: tuple[str, int] | Sequence[object] | None,
    ) -> SocketObservation:
        return parse_sip_response(data, remote_addr)

    def _classify_status_code(self, status_code: int) -> ObservationClass:
        return classify_status_code(status_code)

    def _resolve_outcome(
        self,
        observations: Sequence[SocketObservation],
    ) -> DeliveryOutcome:
        if not observations:
            return "timeout"

        selected = next(
            (
                observation
                for observation in reversed(observations)
                if observation.classification != "provisional"
            ),
            observations[-1],
        )
        if selected.classification == "success":
            return "success"
        if selected.classification == "provisional":
            return "provisional"
        if selected.classification == "invalid":
            return "invalid_response"
        return "error"


__all__ = [
    "SIPSenderReactor",
    "classify_status_code",
    "parse_sip_response",
    "read_udp_observations",
]
