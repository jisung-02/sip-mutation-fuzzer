from __future__ import annotations

from typing import Any, Literal, NotRequired, TypedDict

from pydantic import Field, model_validator

from volte_mutation_fuzzer.sip.common import (
    CSeqHeader,
    EventHeader,
    RAckHeader,
    SubscriptionStateHeader,
    URIReference,
    ConditionalFieldRule,
    FromField,
    NameAddress,
    PacketDefinitionBase,
    RequestReceptionProfile,
    SIPDirection,
    SIPMethod,
    SIPPacketBase,
    UERole,
    ViaHeader,
    build_field_descriptors,
    model_field_partition,
)


class SIPRequest(SIPPacketBase):
    """Generic incoming SIP request to the UE."""

    method: SIPMethod
    request_uri: URIReference
    sip_version: Literal["SIP/2.0"] = "SIP/2.0"
    via: list[ViaHeader] = Field(min_length=1)
    max_forwards: int = Field(ge=0, le=255)
    from_: NameAddress = FromField
    to: NameAddress
    call_id: str = Field(min_length=1)
    cseq: CSeqHeader
    contact: list[NameAddress] | None = None
    route: list[NameAddress | URIReference] | None = None
    record_route: list[NameAddress | URIReference] | None = None
    supported: tuple[str, ...] | None = None
    require: tuple[str, ...] | None = None
    proxy_require: tuple[str, ...] | None = None
    allow: tuple[SIPMethod, ...] | None = None
    allow_events: tuple[str, ...] | None = None
    accept: tuple[str, ...] | None = None
    accept_encoding: tuple[str, ...] | None = None
    accept_language: tuple[str, ...] | None = None
    alert_info: tuple[str, ...] | None = None
    call_info: tuple[str, ...] | None = None
    event: EventHeader | None = None
    expires: int | None = Field(default=None, ge=0)
    subject: str | None = None
    organization: str | None = None
    priority: str | None = None
    user_agent: str | None = None
    content_type: str | None = None
    content_disposition: str | None = None
    content_encoding: tuple[str, ...] | None = None
    content_language: tuple[str, ...] | None = None
    content_length: int = Field(default=0, ge=0)
    body: str | None = None
    extension_headers: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_cseq_method(self) -> "SIPRequest":
        if self.cseq.method != self.method:
            raise ValueError("cseq.method must match request method")
        return self

    @model_validator(mode="after")
    def validate_message_body(self) -> "SIPRequest":
        if self.body is not None and self.content_type is None:
            raise ValueError("content_type is required when body is present")
        if self.content_length == 0 and self.body:
            object.__setattr__(self, "content_length", len(self.body.encode("utf-8")))
        return self


class AckRequest(SIPRequest):
    method: Literal[SIPMethod.ACK] = SIPMethod.ACK


class ByeRequest(SIPRequest):
    method: Literal[SIPMethod.BYE] = SIPMethod.BYE


class CancelRequest(SIPRequest):
    method: Literal[SIPMethod.CANCEL] = SIPMethod.CANCEL
    reason: str | None = None

    @model_validator(mode="after")
    def validate_cancel_extension_rules(self) -> "CancelRequest":
        if self.require is not None:
            raise ValueError("CANCEL must not include Require")
        if self.proxy_require is not None:
            raise ValueError("CANCEL must not include Proxy-Require")
        return self


class InfoRequest(SIPRequest):
    method: Literal[SIPMethod.INFO] = SIPMethod.INFO
    info_package: str | None = None


class InviteRequest(SIPRequest):
    method: Literal[SIPMethod.INVITE] = SIPMethod.INVITE
    contact: list[NameAddress] = Field(min_length=1)
    recv_info: tuple[str, ...] | None = None
    session_expires: int | None = Field(default=None, ge=0)
    min_se: int | None = Field(default=None, ge=0)
    privacy: tuple[str, ...] | None = None
    p_asserted_identity: tuple[NameAddress, ...] | None = None


class MessageRequest(SIPRequest):
    method: Literal[SIPMethod.MESSAGE] = SIPMethod.MESSAGE
    contact: None = Field(default=None, json_schema_extra={"catalog_exclude": True})


class NotifyRequest(SIPRequest):
    method: Literal[SIPMethod.NOTIFY] = SIPMethod.NOTIFY
    contact: list[NameAddress] = Field(min_length=1)
    event: EventHeader
    subscription_state: SubscriptionStateHeader


class OptionsRequest(SIPRequest):
    method: Literal[SIPMethod.OPTIONS] = SIPMethod.OPTIONS


class PrackRequest(SIPRequest):
    method: Literal[SIPMethod.PRACK] = SIPMethod.PRACK
    rack: RAckHeader
    recv_info: tuple[str, ...] | None = None


class PublishRequest(SIPRequest):
    method: Literal[SIPMethod.PUBLISH] = SIPMethod.PUBLISH
    event: EventHeader
    sip_if_match: str | None = None

    @model_validator(mode="after")
    def validate_publish_initial_request_rules(self) -> "PublishRequest":
        if self.sip_if_match is None and self.body is None:
            raise ValueError("initial PUBLISH requests must contain a body")
        return self


class ReferRequest(SIPRequest):
    method: Literal[SIPMethod.REFER] = SIPMethod.REFER
    contact: list[NameAddress] = Field(min_length=1)
    refer_to: NameAddress | URIReference
    referred_by: NameAddress | None = None
    refer_sub: bool | None = None
    target_dialog: str | None = None
    replaces: str | None = None


class RegisterRequest(SIPRequest):
    method: Literal[SIPMethod.REGISTER] = SIPMethod.REGISTER
    path: tuple[str, ...] | None = None
    recv_info: tuple[str, ...] | None = None


class SubscribeRequest(SIPRequest):
    method: Literal[SIPMethod.SUBSCRIBE] = SIPMethod.SUBSCRIBE
    contact: list[NameAddress] = Field(min_length=1)
    event: EventHeader


class UpdateRequest(SIPRequest):
    method: Literal[SIPMethod.UPDATE] = SIPMethod.UPDATE
    contact: list[NameAddress] = Field(min_length=1)
    recv_info: tuple[str, ...] | None = None
    session_expires: int | None = Field(default=None, ge=0)
    min_se: int | None = Field(default=None, ge=0)


REQUEST_MODELS_BY_METHOD: dict[SIPMethod, type[SIPRequest]] = {
    SIPMethod.ACK: AckRequest,
    SIPMethod.BYE: ByeRequest,
    SIPMethod.CANCEL: CancelRequest,
    SIPMethod.INFO: InfoRequest,
    SIPMethod.INVITE: InviteRequest,
    SIPMethod.MESSAGE: MessageRequest,
    SIPMethod.NOTIFY: NotifyRequest,
    SIPMethod.OPTIONS: OptionsRequest,
    SIPMethod.PRACK: PrackRequest,
    SIPMethod.PUBLISH: PublishRequest,
    SIPMethod.REFER: ReferRequest,
    SIPMethod.REGISTER: RegisterRequest,
    SIPMethod.SUBSCRIBE: SubscribeRequest,
    SIPMethod.UPDATE: UpdateRequest,
}


class SIPRequestDefinition(PacketDefinitionBase):
    method: SIPMethod
    model_name: str
    reception_profile: RequestReceptionProfile


class RequestMetadata(TypedDict):
    description: str
    typical_scenario: str
    reference_rfcs: tuple[str, ...]
    reception_profile: RequestReceptionProfile
    preconditions: NotRequired[tuple[str, ...]]
    forbidden_fields: NotRequired[tuple[str, ...]]
    conditional_required_fields: NotRequired[tuple[ConditionalFieldRule, ...]]


_REQUEST_METADATA: dict[SIPMethod, RequestMetadata] = {
    SIPMethod.ACK: {
        "description": "Acknowledges the final response to an INVITE transaction.",
        "typical_scenario": "UE acted as UAS for INVITE and receives ACK after sending a final response.",
        "preconditions": ("Matching INVITE transaction exists.",),
        "reference_rfcs": ("RFC3261",),
        "reception_profile": RequestReceptionProfile.CORE,
        "conditional_required_fields": (
            ConditionalFieldRule(
                field_name="route",
                condition="Populate when the INVITE dialog established a route set.",
                reference_rfcs=("RFC3261",),
            ),
        ),
    },
    SIPMethod.BYE: {
        "description": "Terminates an established SIP dialog/session.",
        "typical_scenario": "Remote endpoint ends an active call or session with the UE.",
        "preconditions": ("Confirmed dialog exists.",),
        "reference_rfcs": ("RFC3261",),
        "reception_profile": RequestReceptionProfile.CORE,
    },
    SIPMethod.CANCEL: {
        "description": "Cancels a pending INVITE transaction before final response.",
        "typical_scenario": "Caller aborts an inbound ringing INVITE before the UE answers.",
        "preconditions": ("Matching INVITE server transaction is still proceeding.",),
        "reference_rfcs": ("RFC3261",),
        "reception_profile": RequestReceptionProfile.CORE,
        "conditional_required_fields": (
            ConditionalFieldRule(
                field_name="route",
                condition="If the original request established a route set, CANCEL follows the same route set.",
                reference_rfcs=("RFC3261",),
            ),
            ConditionalFieldRule(
                field_name="reason",
                condition="Include when cancellation cause should be conveyed explicitly.",
                reference_rfcs=("RFC3326",),
                note="Reason is not mandatory in base RFC3261 but is common in modern deployments.",
            ),
        ),
        "forbidden_fields": ("require", "proxy_require"),
    },
    SIPMethod.INFO: {
        "description": "Carries mid-dialog application information using the INFO framework.",
        "typical_scenario": "UE receives DTMF or application signaling during an active dialog.",
        "preconditions": ("Existing dialog exists.",),
        "reference_rfcs": ("RFC6086",),
        "reception_profile": RequestReceptionProfile.CONDITIONAL,
        "conditional_required_fields": (
            ConditionalFieldRule(
                field_name="info_package",
                condition="Required when the INFO package framework is used for a named package.",
                reference_rfcs=("RFC6086",),
            ),
        ),
    },
    SIPMethod.INVITE: {
        "description": "Creates a new session or modifies an existing dialog via re-INVITE.",
        "typical_scenario": "UE receives an initial incoming call or an in-dialog session renegotiation.",
        "preconditions": (),
        "reference_rfcs": ("RFC3261", "RFC6026"),
        "reception_profile": RequestReceptionProfile.CORE,
        "conditional_required_fields": (
            ConditionalFieldRule(
                field_name="body",
                condition="Often carries SDP offer/answer, but offerless INVITE is also valid.",
                reference_rfcs=("RFC3261",),
            ),
            ConditionalFieldRule(
                field_name="recv_info",
                condition="Include in an initial INVITE when advertising supported INFO packages; an empty Recv-Info value is valid.",
                reference_rfcs=("RFC6086",),
            ),
        ),
    },
    SIPMethod.MESSAGE: {
        "description": "Transports pager-mode instant messages to the UE.",
        "typical_scenario": "Remote endpoint sends a SIP MESSAGE text or signaling payload.",
        "preconditions": (),
        "reference_rfcs": ("RFC3428",),
        "reception_profile": RequestReceptionProfile.CONDITIONAL,
        "forbidden_fields": ("contact",),
        "conditional_required_fields": (
            ConditionalFieldRule(
                field_name="body",
                condition="MESSAGE usually carries an instant-message payload, but the model keeps the body optional for RFC-tolerant parsing/fuzzing.",
                reference_rfcs=("RFC3428",),
            ),
        ),
    },
    SIPMethod.NOTIFY: {
        "description": "Delivers subscription state or REFER progress notifications.",
        "typical_scenario": "UE previously subscribed to an event package or created an implicit REFER subscription.",
        "preconditions": (
            "Active subscription or implicit REFER subscription exists.",
        ),
        "reference_rfcs": ("RFC6665",),
        "reception_profile": RequestReceptionProfile.CONDITIONAL,
        "conditional_required_fields": (
            ConditionalFieldRule(
                field_name="event",
                condition="The NOTIFY Event package must match the subscription or implicit REFER subscription it is reporting on.",
                reference_rfcs=("RFC6665",),
            ),
            ConditionalFieldRule(
                field_name="subscription_state",
                condition="Subscription-State drives whether expires is required (active/pending) or forbidden (terminated).",
                reference_rfcs=("RFC6665",),
            ),
            ConditionalFieldRule(
                field_name="body",
                condition="If a body is present, its format must be acceptable to the subscriber; many event packages send a body, but empty NOTIFY is possible for some terminal states.",
                reference_rfcs=("RFC6665",),
            ),
        ),
    },
    SIPMethod.OPTIONS: {
        "description": "Queries UE capabilities and reachability.",
        "typical_scenario": "Network or peer probes the UE's supported SIP features.",
        "preconditions": (),
        "reference_rfcs": ("RFC3261",),
        "reception_profile": RequestReceptionProfile.CORE,
    },
    SIPMethod.PRACK: {
        "description": "Acknowledges a reliable provisional response (100rel).",
        "typical_scenario": "UE sent a reliable provisional INVITE response and receives PRACK in return.",
        "preconditions": ("Reliable provisional response was sent.",),
        "reference_rfcs": ("RFC3262",),
        "reception_profile": RequestReceptionProfile.CONDITIONAL,
        "conditional_required_fields": (
            ConditionalFieldRule(
                field_name="recv_info",
                condition="May be included when the UA advertises support for INFO packages during dialog establishment.",
                reference_rfcs=("RFC6086",),
            ),
        ),
    },
    SIPMethod.PUBLISH: {
        "description": "Publishes event state to an event state compositor.",
        "typical_scenario": "Only meaningful when the UE exposes publication-server-like behavior.",
        "preconditions": ("UE acts as a publication target/service.",),
        "reference_rfcs": ("RFC3903",),
        "reception_profile": RequestReceptionProfile.ATYPICAL,
        "conditional_required_fields": (
            ConditionalFieldRule(
                field_name="expires",
                condition="Typically supplied to define publication lifetime.",
                reference_rfcs=("RFC3903",),
            ),
            ConditionalFieldRule(
                field_name="body",
                condition="Initial PUBLISH requests MUST carry the publication state in the message body.",
                reference_rfcs=("RFC3903",),
            ),
            ConditionalFieldRule(
                field_name="sip_if_match",
                condition="Used for refresh/modify/remove of an existing publication and MUST NOT appear on an initial PUBLISH.",
                reference_rfcs=("RFC3903",),
            ),
        ),
    },
    SIPMethod.REFER: {
        "description": "Requests that the UE contact a third party, typically for call transfer.",
        "typical_scenario": "Remote endpoint instructs the UE to transfer or initiate another SIP request.",
        "preconditions": (),
        "reference_rfcs": ("RFC3515",),
        "reception_profile": RequestReceptionProfile.CONDITIONAL,
    },
    SIPMethod.REGISTER: {
        "description": "Registers or refreshes AOR bindings with a registrar.",
        "typical_scenario": "Rare for handset UE because the UE is normally the REGISTER sender, not receiver.",
        "preconditions": ("UE acts like a registrar or registration service.",),
        "reference_rfcs": ("RFC3261",),
        "reception_profile": RequestReceptionProfile.ATYPICAL,
        "conditional_required_fields": (
            ConditionalFieldRule(
                field_name="contact",
                condition="Needed for normal binding add/update flows; omitted or specialized in query variants.",
                reference_rfcs=("RFC3261",),
            ),
            ConditionalFieldRule(
                field_name="recv_info",
                condition="May be included to advertise INFO-package support as allowed by RFC6086.",
                reference_rfcs=("RFC6086",),
            ),
        ),
    },
    SIPMethod.SUBSCRIBE: {
        "description": "Creates or refreshes a subscription to an event package.",
        "typical_scenario": "Peer subscribes to presence, dialog, or another UE-hosted event package.",
        "preconditions": ("UE supports the targeted event package.",),
        "reference_rfcs": ("RFC6665",),
        "reception_profile": RequestReceptionProfile.CONDITIONAL,
        "conditional_required_fields": (
            ConditionalFieldRule(
                field_name="expires",
                condition="SUBSCRIBE requests SHOULD include Expires; Expires: 0 is used to fetch or terminate a subscription depending on context.",
                reference_rfcs=("RFC6665",),
            ),
        ),
    },
    SIPMethod.UPDATE: {
        "description": "Updates session parameters without creating a new dialog.",
        "typical_scenario": "UE receives in-dialog or early-dialog SDP/session refresh adjustments.",
        "preconditions": ("Early or confirmed dialog exists.",),
        "reference_rfcs": ("RFC3311",),
        "reception_profile": RequestReceptionProfile.CONDITIONAL,
        "conditional_required_fields": (
            ConditionalFieldRule(
                field_name="body",
                condition="Required when the UPDATE carries SDP or another message body.",
                reference_rfcs=("RFC3311",),
            ),
            ConditionalFieldRule(
                field_name="recv_info",
                condition="May be included when the UA refreshes advertised INFO-package support in-dialog.",
                reference_rfcs=("RFC6086",),
            ),
        ),
    },
}


REQUEST_DEFINITIONS: tuple[SIPRequestDefinition, ...] = tuple(
    SIPRequestDefinition(
        method=method,
        model_name=model_type.__name__,
        direction=SIPDirection.INCOMING_TO_UE,
        ue_role=UERole.UAS,
        description=metadata["description"],
        typical_scenario=metadata["typical_scenario"],
        preconditions=tuple(metadata.get("preconditions", ())),
        reference_rfcs=tuple(metadata["reference_rfcs"]),
        required_fields=model_field_partition(model_type)[0],
        optional_fields=model_field_partition(model_type)[1],
        forbidden_fields=tuple(metadata.get("forbidden_fields", ())),
        field_descriptors=build_field_descriptors(model_type),
        conditional_required_fields=tuple(
            metadata.get("conditional_required_fields", ())
        ),
        reception_profile=metadata["reception_profile"],
    )
    for method, model_type in REQUEST_MODELS_BY_METHOD.items()
    for metadata in (_REQUEST_METADATA[method],)
)


__all__ = [
    "AckRequest",
    "ByeRequest",
    "CancelRequest",
    "InfoRequest",
    "InviteRequest",
    "MessageRequest",
    "NotifyRequest",
    "OptionsRequest",
    "PrackRequest",
    "PublishRequest",
    "ReferRequest",
    "RegisterRequest",
    "REQUEST_DEFINITIONS",
    "REQUEST_MODELS_BY_METHOD",
    "SIPRequest",
    "SIPRequestDefinition",
    "SubscribeRequest",
    "UpdateRequest",
]
