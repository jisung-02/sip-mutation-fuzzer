from __future__ import annotations

from enum import IntEnum, StrEnum
from types import UnionType
from typing import Any, Literal, TypeAlias, get_args, get_origin

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, model_validator


class SIPMethod(StrEnum):
    ACK = "ACK"
    BYE = "BYE"
    CANCEL = "CANCEL"
    INFO = "INFO"
    INVITE = "INVITE"
    MESSAGE = "MESSAGE"
    NOTIFY = "NOTIFY"
    OPTIONS = "OPTIONS"
    PRACK = "PRACK"
    PUBLISH = "PUBLISH"
    REFER = "REFER"
    REGISTER = "REGISTER"
    SUBSCRIBE = "SUBSCRIBE"
    UPDATE = "UPDATE"


class SIPDirection(StrEnum):
    INCOMING_TO_UE = "incoming_to_ue"


class UERole(StrEnum):
    UAS = "UAS"
    UAC = "UAC"


class StatusClass(IntEnum):
    INFORMATIONAL = 1
    SUCCESS = 2
    REDIRECTION = 3
    CLIENT_ERROR = 4
    SERVER_ERROR = 5
    GLOBAL_FAILURE = 6


class RequestReceptionProfile(StrEnum):
    CORE = "core_direct"
    CONDITIONAL = "conditional"
    ATYPICAL = "atypical"


class SIPFieldLocation(StrEnum):
    START_LINE = "start_line"
    HEADER = "header"
    BODY = "body"


class FieldDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    python_name: str
    wire_name: str
    location: SIPFieldLocation
    required: bool
    repeatable: bool
    fixed_value: str | int | None = None


class SIPURI(BaseModel):
    """Structured SIP/SIPS/TEL URI used by request lines and address headers."""

    model_config = ConfigDict(extra="forbid")

    scheme: Literal["sip", "sips", "tel"] = "sip"
    user: str | None = None
    password: str | None = None
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    parameters: dict[str, str | None] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_scheme_specific_requirements(self) -> "SIPURI":
        if self.scheme in {"sip", "sips"} and not self.host:
            raise ValueError("host is required for sip/sips URIs")
        if self.scheme == "tel" and not self.user:
            raise ValueError("user is required for tel URIs")
        if self.scheme == "tel" and self.password is not None:
            raise ValueError("password is not valid for tel URIs")
        return self


class AbsoluteURI(BaseModel):
    """Generic RFC 3261 absoluteURI form for non-SIP URI schemes."""

    model_config = ConfigDict(extra="forbid")

    uri: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_absolute_uri(self) -> "AbsoluteURI":
        scheme, separator, _rest = self.uri.partition(":")
        if not separator or not scheme:
            raise ValueError("absolute URI must contain a scheme")
        if scheme.lower() in {"sip", "sips", "tel"}:
            raise ValueError("use SIPURI for sip, sips, or tel URIs")
        return self


URIReference: TypeAlias = SIPURI | AbsoluteURI


class NameAddress(BaseModel):
    """SIP name-addr form used by From/To/Contact and similar headers."""

    model_config = ConfigDict(extra="forbid")

    display_name: str | None = None
    uri: URIReference
    parameters: dict[str, str | None] = Field(default_factory=dict)


class ViaHeader(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transport: str = Field(default="UDP", min_length=1)
    host: str = Field(min_length=1)
    port: int | None = Field(default=None, ge=1, le=65535)
    branch: str = Field(min_length=1)
    received: str | None = None
    rport: int | bool | None = None
    maddr: str | None = None
    ttl: int | None = Field(default=None, ge=0, le=255)
    parameters: dict[str, str | None] = Field(default_factory=dict)


class CSeqHeader(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sequence: int = Field(ge=0, lt=2**31)
    method: SIPMethod


class EventHeader(BaseModel):
    model_config = ConfigDict(extra="forbid")

    package: str = Field(min_length=1)
    parameters: dict[str, str | None] = Field(default_factory=dict)


class SubscriptionStateHeader(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: Literal["active", "pending", "terminated"] | str
    expires: int | None = Field(default=None, ge=0)
    reason: str | None = None
    retry_after: int | None = Field(default=None, ge=0)
    parameters: dict[str, str | None] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_expires_requirements(self) -> "SubscriptionStateHeader":
        if self.state in {"active", "pending"} and self.expires is None:
            raise ValueError(
                "Subscription-State for active/pending notifications must include expires"
            )
        if self.state == "terminated" and self.expires is not None:
            raise ValueError(
                "Subscription-State for terminated notifications must not include expires"
            )
        return self


class RAckHeader(BaseModel):
    model_config = ConfigDict(extra="forbid")

    response_num: int = Field(ge=0, lt=2**31)
    cseq_num: int = Field(ge=0, lt=2**31)
    method: SIPMethod


class AuthChallenge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scheme: str = Field(default="Digest", min_length=1)
    realm: str = Field(min_length=1)
    nonce: str = Field(min_length=1)
    algorithm: str | None = None
    opaque: str | None = None
    qop: tuple[str, ...] | None = None
    stale: bool | None = None
    parameters: dict[str, str] = Field(default_factory=dict)


class RetryAfterHeader(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seconds: int = Field(ge=0)
    comment: str | None = None
    duration: int | None = Field(default=None, ge=0)
    parameters: dict[str, str | None] = Field(default_factory=dict)


class ConditionalFieldRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field_name: str
    condition: str
    reference_rfcs: tuple[str, ...] = ()
    note: str | None = None


class PacketDefinitionBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    direction: SIPDirection
    ue_role: UERole
    description: str
    typical_scenario: str
    preconditions: tuple[str, ...] = ()
    reference_rfcs: tuple[str, ...]
    required_fields: tuple[str, ...]
    optional_fields: tuple[str, ...]
    forbidden_fields: tuple[str, ...] = ()
    field_descriptors: tuple[FieldDescriptor, ...] = ()
    conditional_required_fields: tuple[ConditionalFieldRule, ...] = ()


class SIPPacketBase(BaseModel):
    """Common validation behavior shared by request/response wire models."""

    model_config = ConfigDict(
        extra="forbid", populate_by_name=True, use_enum_values=True
    )


FromField = Field(
    validation_alias=AliasChoices("from", "from_"),
    serialization_alias="from",
)

EXCLUDED_MODEL_FIELDS = frozenset({"extension_headers"})

WIRE_NAME_OVERRIDES = {
    "allow_events": "Allow-Events",
    "authentication_info": "Authentication-Info",
    "call_id": "Call-ID",
    "call_info": "Call-Info",
    "content_disposition": "Content-Disposition",
    "content_encoding": "Content-Encoding",
    "content_language": "Content-Language",
    "content_length": "Content-Length",
    "content_type": "Content-Type",
    "cseq": "CSeq",
    "error_info": "Error-Info",
    "from_": "From",
    "from": "From",
    "geolocation_error": "Geolocation-Error",
    "info_package": "Info-Package",
    "max_forwards": "Max-Forwards",
    "min_expires": "Min-Expires",
    "min_se": "Min-SE",
    "permission_missing": "Permission-Missing",
    "path": "Path",
    "p_asserted_identity": "P-Asserted-Identity",
    "proxy_authenticate": "Proxy-Authenticate",
    "proxy_require": "Proxy-Require",
    "rack": "RAck",
    "record_route": "Record-Route",
    "recv_info": "Recv-Info",
    "refer_sub": "Refer-Sub",
    "refer_to": "Refer-To",
    "referred_by": "Referred-By",
    "request_uri": "Request-URI",
    "session_expires": "Session-Expires",
    "security_server": "Security-Server",
    "service_route": "Service-Route",
    "sip_etag": "SIP-ETag",
    "sip_if_match": "SIP-If-Match",
    "subscription_state": "Subscription-State",
    "target_dialog": "Target-Dialog",
    "user_agent": "User-Agent",
    "www_authenticate": "WWW-Authenticate",
    "alert_msg_error": "AlertMsg-Error",
}


def wire_field_name(python_name: str) -> str:
    if python_name in WIRE_NAME_OVERRIDES:
        return WIRE_NAME_OVERRIDES[python_name]
    return "-".join(part.capitalize() for part in python_name.rstrip("_").split("_"))


def field_location(python_name: str) -> SIPFieldLocation:
    if python_name in {
        "method",
        "request_uri",
        "status_code",
        "reason_phrase",
        "sip_version",
    }:
        return SIPFieldLocation.START_LINE
    if python_name == "body":
        return SIPFieldLocation.BODY
    return SIPFieldLocation.HEADER


def is_repeatable(annotation: object) -> bool:
    origin = get_origin(annotation)
    if origin in {list, tuple}:
        return True
    if origin in {UnionType}:
        return any(
            is_repeatable(arg) for arg in get_args(annotation) if arg is not type(None)
        )
    if str(origin) == "typing.Union":
        return any(
            is_repeatable(arg) for arg in get_args(annotation) if arg is not type(None)
        )
    return False


def is_catalog_excluded(name: str, info: Any) -> bool:
    if name in EXCLUDED_MODEL_FIELDS:
        return True
    extra = info.json_schema_extra if isinstance(info.json_schema_extra, dict) else {}
    return bool(extra.get("catalog_exclude"))


def build_field_descriptors(model_type: type[BaseModel]) -> tuple[FieldDescriptor, ...]:
    descriptors: list[FieldDescriptor] = []
    for name, info in model_type.model_fields.items():
        if is_catalog_excluded(name, info):
            continue
        python_name = name
        fixed_value = info.default if isinstance(info.default, (str, int)) else None
        descriptors.append(
            FieldDescriptor(
                python_name=python_name,
                wire_name=wire_field_name(info.serialization_alias or name),
                location=field_location(python_name),
                required=info.is_required(),
                repeatable=is_repeatable(info.annotation),
                fixed_value=fixed_value,
            )
        )
    return tuple(descriptors)


def classify_status(status_code: int) -> StatusClass:
    return StatusClass(status_code // 100)


def model_field_partition(
    model_type: type[BaseModel],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    required: list[str] = []
    optional: list[str] = []

    for name, info in model_type.model_fields.items():
        if is_catalog_excluded(name, info):
            continue
        field_name = info.serialization_alias or name
        if info.is_required():
            required.append(field_name)
        else:
            optional.append(field_name)

    return tuple(required), tuple(optional)


__all__ = [
    "AbsoluteURI",
    "AuthChallenge",
    "CSeqHeader",
    "EventHeader",
    "SubscriptionStateHeader",
    "RAckHeader",
    "ConditionalFieldRule",
    "FieldDescriptor",
    "FromField",
    "NameAddress",
    "PacketDefinitionBase",
    "RequestReceptionProfile",
    "SIPFieldLocation",
    "RetryAfterHeader",
    "SIPDirection",
    "SIPMethod",
    "SIPPacketBase",
    "SIPURI",
    "URIReference",
    "StatusClass",
    "UERole",
    "ViaHeader",
    "build_field_descriptors",
    "classify_status",
    "model_field_partition",
    "wire_field_name",
]
