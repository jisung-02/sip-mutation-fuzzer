from ipaddress import ip_address
from typing import Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)

from volte_mutation_fuzzer.sip.common import SIPMethod
from volte_mutation_fuzzer.sip.render import PacketModel

TargetMode = Literal["softphone", "real-ue-direct"]
TransportProtocol = Literal["UDP", "TCP"]
ArtifactKind = Literal["packet", "wire", "bytes"]
ObservationSource = Literal["socket", "pcscf-log", "native-ipsec-socket"]
ObservationClass = Literal[
    "provisional",
    "success",
    "redirection",
    "client_error",
    "server_error",
    "global_error",
    "invalid",
]
DeliveryOutcome = Literal[
    "provisional",
    "success",
    "error",
    "timeout",
    "send_error",
    "invalid_response",
]


class CorrelationKey(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    call_id: str | None = None
    cseq_method: SIPMethod | None = None
    cseq_sequence: int | None = Field(default=None, ge=0)


class TargetEndpoint(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    mode: TargetMode = "softphone"
    host: str | None = Field(default=None, min_length=1)
    port: int | None = Field(default=None, ge=1, le=65535)
    msisdn: str | None = Field(default=None, min_length=1)
    transport: TransportProtocol = "UDP"
    timeout_seconds: float = Field(default=2.0, gt=0.0, le=60.0)
    label: str | None = None
    ipsec_mode: Literal["null", "bypass", "native", "ipsec"] | None = None
    source_ip: str | None = Field(default=None, min_length=1)
    # Deprecated compatibility path for Docker netns sending.
    bind_container: str | None = Field(default=None, min_length=1)
    bind_port: int | None = Field(default=None, ge=1, le=65535)

    @field_validator(
        "host",
        "label",
        "ipsec_mode",
        "msisdn",
        "source_ip",
        "bind_container",
        mode="before",
    )
    @classmethod
    def _normalize_text(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        return stripped or None

    @field_validator("transport", mode="before")
    @classmethod
    def _normalize_transport(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        return value.strip().upper()

    @model_validator(mode="after")
    def _validate_target_shape(self) -> Self:
        if self.ipsec_mode == "ipsec":
            object.__setattr__(self, "ipsec_mode", "native")

        if self.mode == "real-ue-direct":
            if self.host is None and self.msisdn is None:
                raise ValueError(
                    "real-ue-direct requires at least one of host or msisdn"
                )
            if self.ipsec_mode == "native" and self.msisdn is None:
                raise ValueError(
                    "real-ue-direct native ipsec_mode requires msisdn"
                )

            # host=None 허용 — RealUEDirectResolver가 msisdn으로 동적 resolve
            if self.transport not in ("UDP", "TCP"):
                raise ValueError("real-ue-direct supports UDP or TCP")
            if self.host is not None:
                try:
                    parsed = ip_address(self.host)
                except ValueError as exc:
                    raise ValueError(
                        "real-ue-direct target host must be an IPv4 address"
                    ) from exc
                if parsed.version != 4:
                    raise ValueError(
                        "real-ue-direct target host must be an IPv4 address"
                    )
                if self.port is None:
                    object.__setattr__(self, "port", 5060)
            if self.source_ip is not None:
                try:
                    parsed_source = ip_address(self.source_ip)
                except ValueError as exc:
                    raise ValueError(
                        "real-ue-direct source_ip must be an IPv4 address"
                    ) from exc
                if parsed_source.version != 4:
                    raise ValueError(
                        "real-ue-direct source_ip must be an IPv4 address"
                    )
            return self

        if self.msisdn is not None:
            raise ValueError("msisdn is only supported in real-ue-direct mode")
        if self.source_ip is not None:
            raise ValueError("source_ip is only supported in real-ue-direct mode")
        if self.bind_container is not None:
            raise ValueError("bind_container is only supported in real-ue-direct mode")
        if self.bind_port is not None:
            raise ValueError("bind_port is only supported in real-ue-direct mode")
        if self.host is None:
            raise ValueError("host must be set")
        if self.port is None:
            object.__setattr__(self, "port", 5060)
        return self


class SendArtifact(BaseModel):
    model_config = ConfigDict(
        extra="forbid", validate_assignment=True, arbitrary_types_allowed=True
    )

    packet: PacketModel | None = None
    wire_text: str | None = None
    packet_bytes: bytes | None = None
    preserve_via: bool = False
    preserve_contact: bool = False

    @classmethod
    def from_packet(cls, packet: PacketModel) -> Self:
        return cls(packet=packet)

    @classmethod
    def from_wire_text(
        cls,
        wire_text: str,
        *,
        preserve_via: bool = False,
        preserve_contact: bool = False,
    ) -> Self:
        return cls(wire_text=wire_text, preserve_via=preserve_via, preserve_contact=preserve_contact)

    @classmethod
    def from_packet_bytes(
        cls,
        packet_bytes: bytes,
        *,
        preserve_via: bool = False,
        preserve_contact: bool = False,
    ) -> Self:
        return cls(packet_bytes=packet_bytes, preserve_via=preserve_via, preserve_contact=preserve_contact)

    @computed_field
    @property
    def artifact_kind(self) -> ArtifactKind:
        if self.packet is not None:
            return "packet"
        if self.wire_text is not None:
            return "wire"
        return "bytes"

    @model_validator(mode="after")
    def _ensure_exactly_one_artifact(self) -> Self:
        artifact_count = sum(
            1
            for item in (self.packet, self.wire_text, self.packet_bytes)
            if item is not None
        )
        if artifact_count != 1:
            raise ValueError(
                "exactly one of packet, wire_text, packet_bytes must be set"
            )
        return self


class SocketObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    source: ObservationSource = "socket"
    remote_host: str | None = None
    remote_port: int | None = Field(default=None, ge=0, le=65535)
    status_code: int | None = Field(default=None, ge=100, le=699)
    reason_phrase: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    raw_text: str = ""
    raw_size: int = Field(default=0, ge=0)
    classification: ObservationClass

    @field_validator("reason_phrase", "remote_host", mode="before")
    @classmethod
    def _normalize_optional_text(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        return stripped or None


class SendReceiveResult(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    target: TargetEndpoint
    artifact_kind: ArtifactKind
    correlation_key: CorrelationKey = Field(default_factory=CorrelationKey)
    bytes_sent: int = Field(ge=0)
    outcome: DeliveryOutcome
    responses: tuple[SocketObservation, ...] = Field(default_factory=tuple)
    send_started_at: float
    send_completed_at: float = Field(ge=0.0)
    error: str | None = None
    observer_events: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("error", mode="before")
    @classmethod
    def _normalize_error(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        return stripped or None

    @computed_field
    @property
    def duration_ms(self) -> float:
        return max((self.send_completed_at - self.send_started_at) * 1000.0, 0.0)

    @computed_field
    @property
    def final_response(self) -> SocketObservation | None:
        return self.responses[-1] if self.responses else None


__all__ = [
    "ArtifactKind",
    "CorrelationKey",
    "DeliveryOutcome",
    "ObservationClass",
    "ObservationSource",
    "SendArtifact",
    "SendReceiveResult",
    "SocketObservation",
    "TargetEndpoint",
    "TargetMode",
    "TransportProtocol",
]
