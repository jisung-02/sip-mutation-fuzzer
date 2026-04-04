from typing import Any, Literal, Self

from pydantic import BaseModel, Field, computed_field, create_model, model_validator

from volte_mutation_fuzzer.sip.common import (
    AuthChallenge,
    CSeqHeader,
    ConditionalFieldRule,
    FromField,
    NameAddress,
    PacketDefinitionBase,
    RetryAfterHeader,
    SIPDirection,
    SIPMethod,
    SIPPacketBase,
    URIReference,
    StatusClass,
    UERole,
    ViaHeader,
    classify_status,
    build_field_descriptors,
    model_field_partition,
)


class SIPResponse(SIPPacketBase):
    """Generic incoming SIP response to a UE-originated request."""

    status_code: int = Field(ge=100, le=699)
    reason_phrase: str = Field(min_length=1)
    sip_version: Literal["SIP/2.0"] = "SIP/2.0"
    via: list[ViaHeader] = Field(min_length=1)
    from_: NameAddress = FromField
    to: NameAddress
    call_id: str = Field(min_length=1)
    cseq: CSeqHeader
    contact: list[NameAddress] | None = None
    path: tuple[NameAddress | URIReference, ...] | None = None
    record_route: list[NameAddress | URIReference] | None = None
    allow: tuple[SIPMethod, ...] | None = None
    allow_events: tuple[str, ...] | None = None
    supported: tuple[str, ...] | None = None
    require: tuple[str, ...] | None = None
    unsupported: tuple[str, ...] | None = None
    accept: tuple[str, ...] | None = None
    accept_encoding: tuple[str, ...] | None = None
    accept_language: tuple[str, ...] | None = None
    call_info: tuple[str, ...] | None = None
    warning: tuple[str, ...] | None = None
    retry_after: RetryAfterHeader | None = None
    proxy_authenticate: tuple[AuthChallenge, ...] | None = None
    www_authenticate: tuple[AuthChallenge, ...] | None = None
    authentication_info: dict[str, str] | None = None
    expires: int | None = Field(default=None, ge=0)
    session_expires: int | None = Field(default=None, ge=0)
    min_expires: int | None = Field(default=None, ge=0)
    min_se: int | None = Field(default=None, ge=0)
    recv_info: tuple[str, ...] | None = None
    rseq: int | None = Field(default=None, ge=1)
    sip_etag: str | None = None
    security_server: tuple[str, ...] | None = None
    service_route: tuple[NameAddress | URIReference, ...] | None = None
    error_info: tuple[str, ...] | None = None
    geolocation_error: str | None = None
    alert_msg_error: str | None = None
    permission_missing: tuple[NameAddress | URIReference, ...] | None = None
    timestamp: float | None = None
    server: str | None = None
    reason: str | None = None
    content_type: str | None = None
    content_disposition: str | None = None
    content_encoding: tuple[str, ...] | None = None
    content_language: tuple[str, ...] | None = None
    content_length: int = Field(default=0, ge=0)
    body: str | None = None
    extension_headers: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_body_headers(self) -> Self:
        if self.body is not None and self.content_type is None:
            raise ValueError("content_type is required when body is present")
        if self.content_length == 0 and self.body:
            object.__setattr__(self, "content_length", len(self.body.encode("utf-8")))
        if self.status_code != 100 and "tag" not in self.to.parameters:
            raise ValueError("responses other than 100 Trying must include a To tag")
        if self.cseq.method == SIPMethod.INVITE and (
            101 <= self.status_code < 199 or 200 <= self.status_code < 300
        ):
            if self.contact is None:
                raise ValueError(
                    "dialog-establishing INVITE responses must include contact"
                )
        if 200 <= self.status_code < 300 and self.cseq.method == SIPMethod.SUBSCRIBE:
            if self.expires is None:
                raise ValueError("2xx to SUBSCRIBE must include expires")
        if 200 <= self.status_code < 300 and self.cseq.method == SIPMethod.REGISTER:
            if self.contact is None:
                raise ValueError("2xx to REGISTER must include contact")
        if 200 <= self.status_code < 300 and self.cseq.method == SIPMethod.MESSAGE:
            if self.contact is not None:
                raise ValueError("2xx to MESSAGE must not include contact")
            if self.body is not None:
                raise ValueError("2xx to MESSAGE must not include body")
        return self

    @computed_field
    @property
    def status_class(self) -> StatusClass:
        return classify_status(self.status_code)


class SIPResponseDefinition(PacketDefinitionBase):
    status_code: int
    reason_phrase: str
    model_name: str
    status_class: StatusClass
    related_methods: tuple[SIPMethod, ...] = ()


class ResponseModelSpec(BaseModel):
    status_code: int
    reason_phrase: str
    model_name: str
    description: str
    typical_scenario: str
    reference_rfcs: tuple[str, ...]
    related_methods: tuple[SIPMethod, ...] = ()
    required_override_fields: tuple[str, ...] = ()
    conditional_required_fields: tuple[ConditionalFieldRule, ...] = ()


ALL_METHODS: tuple[SIPMethod, ...] = tuple(SIPMethod)
INVITE_ONLY = (SIPMethod.INVITE,)
INVITE_UPDATE = (SIPMethod.INVITE, SIPMethod.UPDATE)
EVENT_METHODS = (SIPMethod.SUBSCRIBE, SIPMethod.NOTIFY, SIPMethod.PUBLISH)
REGISTER_PUBLISH = (SIPMethod.REGISTER, SIPMethod.PUBLISH)
REGISTER_PUBLISH_SUBSCRIBE = (
    SIPMethod.REGISTER,
    SIPMethod.PUBLISH,
    SIPMethod.SUBSCRIBE,
)
REGISTER_ONLY = (SIPMethod.REGISTER,)
REFER_ONLY = (SIPMethod.REFER,)
INFO_ONLY = (SIPMethod.INFO,)
MESSAGE_SUBSCRIBE_REFER = (SIPMethod.MESSAGE, SIPMethod.SUBSCRIBE, SIPMethod.REFER)
GENERAL_REDIRECT = (SIPMethod.INVITE, SIPMethod.OPTIONS, SIPMethod.REGISTER)
AUTH_RELEVANT = tuple(
    method for method in SIPMethod if method not in {SIPMethod.ACK, SIPMethod.CANCEL}
)
UNWANTED_OUT_OF_DIALOG = (SIPMethod.INVITE, SIPMethod.MESSAGE, SIPMethod.SUBSCRIBE)

RELIABLE_PROVISIONAL_RULE = ConditionalFieldRule(
    field_name="rseq",
    condition="Include RSeq when the provisional response is sent reliably with 100rel.",
    reference_rfcs=("RFC3262",),
    note="RSeq is not mandatory for ordinary provisional responses, only for reliable ones.",
)

NON_100_TO_TAG_RULE = ConditionalFieldRule(
    field_name="to",
    condition="Except for 100 Trying, if the request lacked a To tag the response MUST add one.",
    reference_rfcs=("RFC3261",),
)

EARLY_DIALOG_CONTACT_RULE = ConditionalFieldRule(
    field_name="contact",
    condition="For non-100 provisional responses to INVITE that establish an early dialog, Contact is mandatory so the remote target is known.",
    reference_rfcs=("RFC3261",),
)

EARLY_DIALOG_RECORD_ROUTE_RULE = ConditionalFieldRule(
    field_name="record_route",
    condition="If the INVITE request contained Record-Route, copy it into the dialog-establishing provisional response.",
    reference_rfcs=("RFC3261",),
)

DIALOG_ESTABLISHING_RECORD_ROUTE_RULE = ConditionalFieldRule(
    field_name="record_route",
    condition="If the INVITE request contained Record-Route, copy it into the dialog-establishing 2xx response.",
    reference_rfcs=("RFC3261",),
)

EARLY_DIALOG_TERMINATED_REASON_RULE = ConditionalFieldRule(
    field_name="reason",
    condition="A 199 Early Dialog Terminated response MUST include a Reason header indicating which final outcome terminated the dialog.",
    reference_rfcs=("RFC6228",),
)

EARLY_DIALOG_TERMINATED_SUPPORT_RULE = ConditionalFieldRule(
    field_name="supported",
    condition="199 is only meaningful when the UAC indicated support for the '199' option-tag.",
    reference_rfcs=("RFC6228",),
)

OK_CONTACT_RULE = ConditionalFieldRule(
    field_name="contact",
    condition="2xx responses to INVITE require Contact so the remote target for the established dialog is known.",
    reference_rfcs=("RFC3261",),
)

SUBSCRIBE_SUCCESS_EXPIRES_RULE = ConditionalFieldRule(
    field_name="expires",
    condition="A 200-class response to SUBSCRIBE MUST include Expires to indicate the actual subscription duration granted by the notifier.",
    reference_rfcs=("RFC6665",),
)

MESSAGE_SUCCESS_NO_CONTACT_RULE = ConditionalFieldRule(
    field_name="contact",
    condition="A 2xx response to MESSAGE MUST NOT include Contact because MESSAGE does not establish a dialog.",
    reference_rfcs=("RFC3428",),
)

MESSAGE_SUCCESS_NO_BODY_RULE = ConditionalFieldRule(
    field_name="body",
    condition="A 2xx response to MESSAGE MUST NOT include a message body.",
    reference_rfcs=("RFC3428",),
)

INFO_FRAMEWORK_RESPONSE_RECV_INFO_RULE = ConditionalFieldRule(
    field_name="recv_info",
    condition="When the associated request used the INFO package framework and carried Recv-Info, reliable 18x/2xx responses include Recv-Info as well, even if empty.",
    reference_rfcs=("RFC6086",),
)

REGISTER_SUCCESS_CONTACT_RULE = ConditionalFieldRule(
    field_name="contact",
    condition="Successful REGISTER responses MUST return the current contact bindings known to the registrar.",
    reference_rfcs=("RFC3261",),
)

REGISTER_SUCCESS_PATH_RULE = ConditionalFieldRule(
    field_name="path",
    condition="When the Path extension is in use, a successful REGISTER response copies the Path header field values from the request.",
    reference_rfcs=("RFC3327",),
)

REGISTER_SUCCESS_SERVICE_ROUTE_RULE = ConditionalFieldRule(
    field_name="service_route",
    condition="A successful REGISTER response may include Service-Route values that the UA must use for future requests in the registered context.",
    reference_rfcs=("RFC3608",),
)

REDIRECT_CONTACT_RULE = ConditionalFieldRule(
    field_name="contact",
    condition="Typically carries one or more alternative targets for the redirection decision.",
    reference_rfcs=("RFC3261",),
)

ALTERNATIVE_SERVICE_BODY_RULE = ConditionalFieldRule(
    field_name="body",
    condition="Alternative services are described in the message body rather than by redirect Contact targets.",
    reference_rfcs=("RFC3261",),
)

BAD_EVENT_ALLOW_EVENTS_RULE = ConditionalFieldRule(
    field_name="allow_events",
    condition="Strongly recommended when advertising supported event packages after 489 Bad Event.",
    reference_rfcs=("RFC6665",),
)

SERVICE_UNAVAILABLE_RETRY_RULE = ConditionalFieldRule(
    field_name="retry_after",
    condition="Recommended when the server can indicate when the UE should retry.",
    reference_rfcs=("RFC3261",),
)

NO_NOTIFICATION_EXPIRES_RULE = ConditionalFieldRule(
    field_name="expires",
    condition="204 No Notification responses to SUBSCRIBE MUST include Expires to communicate the granted subscription duration.",
    reference_rfcs=("RFC5839", "RFC6665"),
)

CONSENT_PERMISSION_MISSING_RULE = ConditionalFieldRule(
    field_name="permission_missing",
    condition="SHOULD be included when the rejecting entity can identify which target URIs are missing consent.",
    reference_rfcs=("RFC5360",),
)

SECURITY_AGREEMENT_REQUIRE_RULE = ConditionalFieldRule(
    field_name="require",
    condition="Include the sec-agree option tag when the response instructs the UE to negotiate a security agreement before retrying.",
    reference_rfcs=("RFC3329",),
    note="The Require header should contain the 'sec-agree' option tag when applicable.",
)

SECURITY_AGREEMENT_CHALLENGE_RULE = ConditionalFieldRule(
    field_name="proxy_authenticate",
    condition="When the chosen security mechanism needs challenge material such as HTTP Digest, include the corresponding authentication challenge headers as well.",
    reference_rfcs=("RFC3329",),
)

REJECTED_CALL_INFO_RULE = ConditionalFieldRule(
    field_name="call_info",
    condition="Include a Call-Info URI when policy wants to provide a human- or machine-readable explanation for 608 Rejected.",
    reference_rfcs=("RFC8688",),
)

_RESPONSE_REQUIRED_FIELD_OVERRIDES: dict[str, tuple[object, object]] = {
    "alert_msg_error": (str, Field(..., min_length=1)),
    "allow": (tuple[SIPMethod, ...], Field(..., min_length=1)),
    "contact": (tuple[NameAddress, ...], Field(..., min_length=1)),
    "geolocation_error": (str, Field(..., min_length=1)),
    "min_expires": (int, Field(..., ge=0)),
    "min_se": (int, Field(..., ge=0)),
    "proxy_authenticate": (tuple[AuthChallenge, ...], Field(..., min_length=1)),
    "recv_info": (tuple[str, ...], Field(..., min_length=1)),
    "require": (tuple[str, ...], Field(..., min_length=1)),
    "security_server": (tuple[str, ...], Field(..., min_length=1)),
    "unsupported": (tuple[str, ...], Field(..., min_length=1)),
    "www_authenticate": (tuple[AuthChallenge, ...], Field(..., min_length=1)),
}


_RESPONSE_SPECS: tuple[ResponseModelSpec, ...] = (
    ResponseModelSpec(
        status_code=100,
        reason_phrase="Trying",
        model_name="TryingResponse",
        description="Provisional response indicating request processing has started.",
        typical_scenario="UE sent a request and the next hop has begun processing it.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=180,
        reason_phrase="Ringing",
        model_name="RingingResponse",
        description="Indicates the callee is alerting.",
        typical_scenario="UE receives 180 after sending INVITE for an outbound call.",
        reference_rfcs=("RFC3261",),
        related_methods=INVITE_ONLY,
        conditional_required_fields=(
            RELIABLE_PROVISIONAL_RULE,
            EARLY_DIALOG_CONTACT_RULE,
            EARLY_DIALOG_RECORD_ROUTE_RULE,
            INFO_FRAMEWORK_RESPONSE_RECV_INFO_RULE,
        ),
    ),
    ResponseModelSpec(
        status_code=181,
        reason_phrase="Call Is Being Forwarded",
        model_name="CallIsBeingForwardedResponse",
        description="Indicates the called party is being forwarded elsewhere.",
        typical_scenario="Outbound INVITE is being redirected during early dialog handling.",
        reference_rfcs=("RFC3261",),
        related_methods=INVITE_ONLY,
        conditional_required_fields=(
            RELIABLE_PROVISIONAL_RULE,
            EARLY_DIALOG_CONTACT_RULE,
            EARLY_DIALOG_RECORD_ROUTE_RULE,
            INFO_FRAMEWORK_RESPONSE_RECV_INFO_RULE,
        ),
    ),
    ResponseModelSpec(
        status_code=182,
        reason_phrase="Queued",
        model_name="QueuedResponse",
        description="Indicates the request has been placed in a queue.",
        typical_scenario="Outbound INVITE waits in a queue at the far end.",
        reference_rfcs=("RFC3261",),
        related_methods=INVITE_ONLY,
        conditional_required_fields=(
            RELIABLE_PROVISIONAL_RULE,
            EARLY_DIALOG_CONTACT_RULE,
            EARLY_DIALOG_RECORD_ROUTE_RULE,
            INFO_FRAMEWORK_RESPONSE_RECV_INFO_RULE,
        ),
    ),
    ResponseModelSpec(
        status_code=183,
        reason_phrase="Session Progress",
        model_name="SessionProgressResponse",
        description="Provides early session progress, often with early media information.",
        typical_scenario="Outbound INVITE receives early media/session setup details before final answer.",
        reference_rfcs=("RFC3261",),
        related_methods=INVITE_ONLY,
        conditional_required_fields=(
            RELIABLE_PROVISIONAL_RULE,
            EARLY_DIALOG_CONTACT_RULE,
            EARLY_DIALOG_RECORD_ROUTE_RULE,
            INFO_FRAMEWORK_RESPONSE_RECV_INFO_RULE,
        ),
    ),
    ResponseModelSpec(
        status_code=199,
        reason_phrase="Early Dialog Terminated",
        model_name="EarlyDialogTerminatedResponse",
        description="Signals that an established early dialog has terminated.",
        typical_scenario="One branch of a forked INVITE early dialog is ended before final answer.",
        reference_rfcs=("RFC6228",),
        related_methods=INVITE_ONLY,
        conditional_required_fields=(
            RELIABLE_PROVISIONAL_RULE,
            EARLY_DIALOG_TERMINATED_REASON_RULE,
            EARLY_DIALOG_TERMINATED_SUPPORT_RULE,
        ),
    ),
    ResponseModelSpec(
        status_code=200,
        reason_phrase="OK",
        model_name="OkResponse",
        description="Generic success response for SIP requests.",
        typical_scenario="UE request completed successfully.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
        conditional_required_fields=(
            OK_CONTACT_RULE,
            DIALOG_ESTABLISHING_RECORD_ROUTE_RULE,
            SUBSCRIBE_SUCCESS_EXPIRES_RULE,
            MESSAGE_SUCCESS_NO_CONTACT_RULE,
            MESSAGE_SUCCESS_NO_BODY_RULE,
            INFO_FRAMEWORK_RESPONSE_RECV_INFO_RULE,
            REGISTER_SUCCESS_CONTACT_RULE,
            REGISTER_SUCCESS_PATH_RULE,
            REGISTER_SUCCESS_SERVICE_ROUTE_RULE,
        ),
    ),
    ResponseModelSpec(
        status_code=202,
        reason_phrase="Accepted (Deprecated)",
        model_name="AcceptedDeprecatedResponse",
        description=(
            "Accepted but not yet fully completed; explicitly allowed for MESSAGE"
            " asynchronous gateway delivery (RFC 3428). Not mentioned by RFC 6665"
            " for SUBSCRIBE (200 OK is the expected response). Forbidden for REFER"
            " by RFC 7647 (MUST NOT send 202)."
        ),
        typical_scenario="Asynchronous MESSAGE processing via a store-and-forward gateway.",
        reference_rfcs=("RFC3261", "RFC3428", "RFC6665", "RFC7647"),
        related_methods=(SIPMethod.MESSAGE,),
    ),
    ResponseModelSpec(
        status_code=204,
        reason_phrase="No Notification",
        model_name="NoNotificationResponse",
        description="Successful SUBSCRIBE processing without sending a follow-up NOTIFY.",
        typical_scenario="In-dialog SUBSCRIBE refresh is accepted and the notifier suppresses an immediate NOTIFY.",
        reference_rfcs=("RFC5839",),
        related_methods=(SIPMethod.SUBSCRIBE,),
        conditional_required_fields=(NO_NOTIFICATION_EXPIRES_RULE,),
    ),
    ResponseModelSpec(
        status_code=300,
        reason_phrase="Multiple Choices",
        model_name="MultipleChoicesResponse",
        description="Indicates several possible targets are available.",
        typical_scenario="UE must choose between alternative redirect contacts.",
        reference_rfcs=("RFC3261",),
        related_methods=GENERAL_REDIRECT,
        required_override_fields=("contact",),
        conditional_required_fields=(REDIRECT_CONTACT_RULE,),
    ),
    ResponseModelSpec(
        status_code=301,
        reason_phrase="Moved Permanently",
        model_name="MovedPermanentlyResponse",
        description="Indicates the target has moved permanently.",
        typical_scenario="UE should update routing based on permanent redirection.",
        reference_rfcs=("RFC3261",),
        related_methods=GENERAL_REDIRECT,
        required_override_fields=("contact",),
        conditional_required_fields=(REDIRECT_CONTACT_RULE,),
    ),
    ResponseModelSpec(
        status_code=302,
        reason_phrase="Moved Temporarily",
        model_name="MovedTemporarilyResponse",
        description="Indicates the target has moved temporarily.",
        typical_scenario="UE retries the request using a temporary alternate target.",
        reference_rfcs=("RFC3261",),
        related_methods=GENERAL_REDIRECT,
        required_override_fields=("contact",),
        conditional_required_fields=(REDIRECT_CONTACT_RULE,),
    ),
    ResponseModelSpec(
        status_code=305,
        reason_phrase="Use Proxy",
        model_name="UseProxyResponse",
        description="Requires the client to use a specified proxy.",
        typical_scenario="UE must reattempt the request through a designated proxy.",
        reference_rfcs=("RFC3261",),
        related_methods=GENERAL_REDIRECT,
        required_override_fields=("contact",),
        conditional_required_fields=(REDIRECT_CONTACT_RULE,),
    ),
    ResponseModelSpec(
        status_code=380,
        reason_phrase="Alternative Service",
        model_name="AlternativeServiceResponse",
        description="Suggests an alternative service for the request.",
        typical_scenario="Outbound INVITE is redirected to a different service handling model.",
        reference_rfcs=("RFC3261",),
        related_methods=INVITE_ONLY,
        conditional_required_fields=(ALTERNATIVE_SERVICE_BODY_RULE,),
    ),
    ResponseModelSpec(
        status_code=400,
        reason_phrase="Bad Request",
        model_name="BadRequestResponse",
        description="The request could not be understood because of syntax or framing problems.",
        typical_scenario="Malformed or inconsistent request was rejected.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=401,
        reason_phrase="Unauthorized",
        model_name="UnauthorizedResponse",
        description="Origin server demands client authentication.",
        typical_scenario="UE must resend with Authorization credentials.",
        reference_rfcs=("RFC3261",),
        related_methods=AUTH_RELEVANT,
        required_override_fields=("www_authenticate",),
    ),
    ResponseModelSpec(
        status_code=402,
        reason_phrase="Payment Required",
        model_name="PaymentRequiredResponse",
        description="Reserved or rarely used payment-related rejection.",
        typical_scenario="Mostly theoretical SIP status code with little deployment use.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=403,
        reason_phrase="Forbidden",
        model_name="ForbiddenResponse",
        description="Policy or authorization rejected the request.",
        typical_scenario="Server understood the request but refuses to fulfill it.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=404,
        reason_phrase="Not Found",
        model_name="NotFoundResponse",
        description="Requested user or resource was not found.",
        typical_scenario="Outbound request targets an unknown user or resource.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=405,
        reason_phrase="Method Not Allowed",
        model_name="MethodNotAllowedResponse",
        description="Target does not allow the request method.",
        typical_scenario="UE used a method unsupported at the destination URI.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
        required_override_fields=("allow",),
    ),
    ResponseModelSpec(
        status_code=406,
        reason_phrase="Not Acceptable",
        model_name="NotAcceptableResponse",
        description="Request could not be fulfilled due to Accept-related constraints.",
        typical_scenario="Negotiated media or content preferences could not be satisfied.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=407,
        reason_phrase="Proxy Authentication Required",
        model_name="ProxyAuthenticationRequiredResponse",
        description="Proxy demands client authentication.",
        typical_scenario="UE must resend via proxy with Proxy-Authorization credentials.",
        reference_rfcs=("RFC3261",),
        related_methods=AUTH_RELEVANT,
        required_override_fields=("proxy_authenticate",),
    ),
    ResponseModelSpec(
        status_code=408,
        reason_phrase="Request Timeout",
        model_name="RequestTimeoutResponse",
        description="Request timed out before it could be completed.",
        typical_scenario="UE receives timeout for an outstanding SIP transaction.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=410,
        reason_phrase="Gone",
        model_name="GoneResponse",
        description="Target resource no longer exists.",
        typical_scenario="Requested user/resource was known but has permanently disappeared.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=412,
        reason_phrase="Conditional Request Failed",
        model_name="ConditionalRequestFailedResponse",
        description="Conditional publication or similar precondition failed.",
        typical_scenario="PUBLISH state version no longer matches current entity tag.",
        reference_rfcs=("RFC3903",),
        related_methods=(SIPMethod.PUBLISH,),
    ),
    ResponseModelSpec(
        status_code=413,
        reason_phrase="Request Entity Too Large",
        model_name="RequestEntityTooLargeResponse",
        description="Request body or headers are too large to process.",
        typical_scenario="UE sent a request payload that exceeds remote limits.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=414,
        reason_phrase="Request-URI Too Long",
        model_name="RequestUriTooLongResponse",
        description="Request-URI exceeded remote processing limits.",
        typical_scenario="Generated Request-URI is too long for the far end.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=415,
        reason_phrase="Unsupported Media Type",
        model_name="UnsupportedMediaTypeResponse",
        description="Message body media type is not supported.",
        typical_scenario="Remote endpoint rejects an SDP or payload content type.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=416,
        reason_phrase="Unsupported URI Scheme",
        model_name="UnsupportedUriSchemeResponse",
        description="URI scheme is unsupported by the receiver.",
        typical_scenario="Request targeted a URI scheme the remote side cannot process.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=417,
        reason_phrase="Unknown Resource-Priority",
        model_name="UnknownResourcePriorityResponse",
        description="Resource-Priority namespace or value is unknown.",
        typical_scenario="Resource-Priority extension is present but unsupported.",
        reference_rfcs=("RFC4412",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=420,
        reason_phrase="Bad Extension",
        model_name="BadExtensionResponse",
        description="Mandatory option tags are unsupported.",
        typical_scenario="UE required extensions that the far end does not support.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
        required_override_fields=("unsupported",),
    ),
    ResponseModelSpec(
        status_code=421,
        reason_phrase="Extension Required",
        model_name="ExtensionRequiredResponse",
        description="Remote endpoint requires an extension the UE did not use.",
        typical_scenario="UE must add the listed Require option tags and retry.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
        required_override_fields=("require",),
    ),
    ResponseModelSpec(
        status_code=422,
        reason_phrase="Session Interval Too Small",
        model_name="SessionIntervalTooSmallResponse",
        description="Session timer interval is smaller than acceptable.",
        typical_scenario="INVITE/UPDATE session timer negotiation failed due to too-small interval.",
        reference_rfcs=("RFC4028",),
        related_methods=INVITE_UPDATE,
        required_override_fields=("min_se",),
    ),
    ResponseModelSpec(
        status_code=423,
        reason_phrase="Interval Too Brief",
        model_name="IntervalTooBriefResponse",
        description="Expires interval is shorter than allowed.",
        typical_scenario="REGISTER or PUBLISH requested an expiry that is too short.",
        reference_rfcs=("RFC3261",),
        related_methods=REGISTER_PUBLISH_SUBSCRIBE,
        required_override_fields=("min_expires",),
    ),
    ResponseModelSpec(
        status_code=424,
        reason_phrase="Bad Location Information",
        model_name="BadLocationInformationResponse",
        description="Geolocation or location-format information is invalid.",
        typical_scenario="Request carrying geolocation information was rejected.",
        reference_rfcs=("RFC6442",),
        related_methods=ALL_METHODS,
        required_override_fields=("geolocation_error",),
    ),
    ResponseModelSpec(
        status_code=425,
        reason_phrase="Bad Alert Message",
        model_name="BadAlertMessageResponse",
        description="Alerting information extension was malformed or unacceptable.",
        typical_scenario="Alert-Info or alerting extension parameters were rejected.",
        reference_rfcs=("RFC8876",),
        related_methods=ALL_METHODS,
        required_override_fields=("alert_msg_error",),
    ),
    ResponseModelSpec(
        status_code=428,
        reason_phrase="Use Identity Header",
        model_name="UseIdentityHeaderResponse",
        description="Receiver insists on use of an Identity header.",
        typical_scenario="Identity assertion is required before request can proceed.",
        reference_rfcs=("RFC8224",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=429,
        reason_phrase="Provide Referrer Identity",
        model_name="ProvideReferrerIdentityResponse",
        description="REFER handling requires referrer identity information.",
        typical_scenario="REFER request lacks the identity information demanded by policy.",
        reference_rfcs=("RFC3892",),
        related_methods=REFER_ONLY,
    ),
    ResponseModelSpec(
        status_code=430,
        reason_phrase="Flow Failed",
        model_name="FlowFailedResponse",
        description="Previously established outbound flow failed.",
        typical_scenario="UE's SIP Outbound registration flow is no longer usable.",
        reference_rfcs=("RFC5626",),
        related_methods=REGISTER_ONLY,
    ),
    ResponseModelSpec(
        status_code=433,
        reason_phrase="Anonymity Disallowed",
        model_name="AnonymityDisallowedResponse",
        description="Policy forbids the requested anonymous identity behavior.",
        typical_scenario="Privacy or identity policy rejects anonymous signaling.",
        reference_rfcs=("RFC5079",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=436,
        reason_phrase="Bad Identity Info",
        model_name="BadIdentityInfoResponse",
        description="Identity information is invalid or unverifiable.",
        typical_scenario="Remote verifier cannot validate identity assertion metadata.",
        reference_rfcs=("RFC8224",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=437,
        reason_phrase="Unsupported Credential",
        model_name="UnsupportedCredentialResponse",
        description="Credential type is unsupported.",
        typical_scenario="Identity credentials are present but not supported by the verifier.",
        reference_rfcs=("RFC8224",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=438,
        reason_phrase="Invalid Identity Header",
        model_name="InvalidIdentityHeaderResponse",
        description="Identity header itself is syntactically or semantically invalid.",
        typical_scenario="Identity header value does not validate.",
        reference_rfcs=("RFC8224",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=439,
        reason_phrase="First Hop Lacks Outbound Support",
        model_name="FirstHopLacksOutboundSupportResponse",
        description="First-hop proxy does not support SIP Outbound.",
        typical_scenario="UE attempted an outbound-specific request through a non-outbound first hop.",
        reference_rfcs=("RFC5626",),
        related_methods=REGISTER_ONLY,
    ),
    ResponseModelSpec(
        status_code=440,
        reason_phrase="Max-Breadth Exceeded",
        model_name="MaxBreadthExceededResponse",
        description="Maximum recursion breadth was exceeded in REFER processing.",
        typical_scenario="REFER triggered recursive operations beyond configured breadth.",
        reference_rfcs=("RFC5393",),
        related_methods=REFER_ONLY,
    ),
    ResponseModelSpec(
        status_code=469,
        reason_phrase="Bad Info Package",
        model_name="BadInfoPackageResponse",
        description="INFO package is unsupported or malformed.",
        typical_scenario="INFO request used an unsupported Info Package token.",
        reference_rfcs=("RFC6086",),
        related_methods=INFO_ONLY,
        required_override_fields=("recv_info",),
    ),
    ResponseModelSpec(
        status_code=470,
        reason_phrase="Consent Needed",
        model_name="ConsentNeededResponse",
        description="Explicit user or policy consent is required before processing.",
        typical_scenario="Consent framework blocks request until recipient grants permission.",
        reference_rfcs=("RFC5360",),
        related_methods=ALL_METHODS,
        conditional_required_fields=(CONSENT_PERMISSION_MISSING_RULE,),
    ),
    ResponseModelSpec(
        status_code=480,
        reason_phrase="Temporarily Unavailable",
        model_name="TemporarilyUnavailableResponse",
        description="Target is temporarily unavailable.",
        typical_scenario="Called party or resource is not currently reachable.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=481,
        reason_phrase="Call/Transaction Does Not Exist",
        model_name="CallOrTransactionDoesNotExistResponse",
        description="Matching dialog, call leg, or transaction could not be found.",
        typical_scenario="In-dialog request references state that no longer exists remotely.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=482,
        reason_phrase="Loop Detected",
        model_name="LoopDetectedResponse",
        description="Routing loop was detected.",
        typical_scenario="Proxy routing causes the request to revisit a previous hop.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=483,
        reason_phrase="Too Many Hops",
        model_name="TooManyHopsResponse",
        description="Max-Forwards reached zero before successful routing.",
        typical_scenario="Request exceeded routing hop limit.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=484,
        reason_phrase="Address Incomplete",
        model_name="AddressIncompleteResponse",
        description="Address or dial string is incomplete.",
        typical_scenario="Request URI/user part lacks enough information to route.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=485,
        reason_phrase="Ambiguous",
        model_name="AmbiguousResponse",
        description="Target address resolves ambiguously to multiple resources.",
        typical_scenario="Far end cannot uniquely identify intended target.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=486,
        reason_phrase="Busy Here",
        model_name="BusyHereResponse",
        description=(
            "The callee's end system was contacted successfully but the callee is"
            " currently not willing or able to take additional calls at this end system"
            " (RFC 3261 §21.4.23). Semantically INVITE-specific: 'callee' and 'calls'"
            " terminology applies exclusively to session-establishment requests."
        ),
        typical_scenario="Remote user rejects INVITE because they are busy at this location.",
        reference_rfcs=("RFC3261",),
        related_methods=INVITE_ONLY,
    ),
    ResponseModelSpec(
        status_code=487,
        reason_phrase="Request Terminated",
        model_name="RequestTerminatedResponse",
        description="Request was terminated before completion.",
        typical_scenario="INVITE receives 487 after a CANCEL was processed.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=488,
        reason_phrase="Not Acceptable Here",
        model_name="NotAcceptableHereResponse",
        description="Proposed session description or conditions are unacceptable here.",
        typical_scenario="Local SDP or session offer cannot be accepted by the remote side.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=489,
        reason_phrase="Bad Event",
        model_name="BadEventResponse",
        description="Event package is unsupported or invalid.",
        typical_scenario="SUBSCRIBE or NOTIFY references an unknown event package.",
        reference_rfcs=("RFC6665",),
        related_methods=EVENT_METHODS,
        conditional_required_fields=(BAD_EVENT_ALLOW_EVENTS_RULE,),
    ),
    ResponseModelSpec(
        status_code=491,
        reason_phrase="Request Pending",
        model_name="RequestPendingResponse",
        description="Another conflicting request is already in progress.",
        typical_scenario="Concurrent re-INVITE or UPDATE collision occurs.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=493,
        reason_phrase="Undecipherable",
        model_name="UndecipherableResponse",
        description="Request could not be deciphered after security processing.",
        typical_scenario="Encrypted or integrity-protected SIP content cannot be interpreted.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=494,
        reason_phrase="Security Agreement Required",
        model_name="SecurityAgreementRequiredResponse",
        description="Security mechanism agreement is required before proceeding.",
        typical_scenario="IMS-style security negotiation must complete before REGISTER/INVITE proceeds.",
        reference_rfcs=("RFC3329",),
        related_methods=(SIPMethod.REGISTER, SIPMethod.INVITE),
        required_override_fields=("security_server", "require"),
        conditional_required_fields=(
            SECURITY_AGREEMENT_REQUIRE_RULE,
            SECURITY_AGREEMENT_CHALLENGE_RULE,
        ),
    ),
    ResponseModelSpec(
        status_code=500,
        reason_phrase="Server Internal Error",
        model_name="ServerInternalErrorResponse",
        description="Server hit an internal failure while processing the request.",
        typical_scenario="Remote SIP element encountered an unexpected processing error.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=501,
        reason_phrase="Not Implemented",
        model_name="NotImplementedResponse",
        description="Requested method or functionality is not implemented.",
        typical_scenario="Remote side does not implement the method or extension UE attempted to use.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=502,
        reason_phrase="Bad Gateway",
        model_name="BadGatewayResponse",
        description="Upstream or downstream gateway processing failed.",
        typical_scenario="Intermediary cannot complete the request because of another network element.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=503,
        reason_phrase="Service Unavailable",
        model_name="ServiceUnavailableResponse",
        description="Service is temporarily unavailable.",
        typical_scenario="Remote service is overloaded or intentionally unavailable for a period.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
        conditional_required_fields=(SERVICE_UNAVAILABLE_RETRY_RULE,),
    ),
    ResponseModelSpec(
        status_code=504,
        reason_phrase="Server Time-out",
        model_name="ServerTimeoutResponse",
        description="Server timed out waiting on another element.",
        typical_scenario="Downstream element failed to answer in time.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=505,
        reason_phrase="Version Not Supported",
        model_name="VersionNotSupportedResponse",
        description="SIP version in request is unsupported.",
        typical_scenario="Far end cannot process the request's SIP version.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=513,
        reason_phrase="Message Too Large",
        model_name="MessageTooLargeResponse",
        description="Entire SIP message is too large to process or forward.",
        typical_scenario="Headers and/or body exceeded transport or implementation limits.",
        reference_rfcs=("RFC3261",),
        related_methods=ALL_METHODS,
    ),
    ResponseModelSpec(
        status_code=555,
        reason_phrase="Push Notification Service Not Supported",
        model_name="PushNotificationServiceNotSupportedResponse",
        description="Push notification service extension is not supported.",
        typical_scenario="REGISTER request depends on a SIP push notification capability absent at the remote side.",
        reference_rfcs=("RFC8599",),
        related_methods=REGISTER_ONLY,
    ),
    ResponseModelSpec(
        status_code=580,
        reason_phrase="Precondition Failure",
        model_name="PreconditionFailureResponse",
        description="Requested session preconditions could not be met.",
        typical_scenario="INVITE or UPDATE preconditions fail during session setup.",
        reference_rfcs=("RFC3312",),
        related_methods=INVITE_UPDATE,
    ),
    ResponseModelSpec(
        status_code=600,
        reason_phrase="Busy Everywhere",
        model_name="BusyEverywhereResponse",
        description="All known contacts are busy.",
        typical_scenario="Forked INVITE failed because every reachable target is busy.",
        reference_rfcs=("RFC3261",),
        related_methods=INVITE_ONLY,
    ),
    ResponseModelSpec(
        status_code=603,
        reason_phrase="Decline",
        model_name="DeclineResponse",
        description="Request is explicitly declined.",
        typical_scenario="Remote user explicitly rejects the INVITE or similar contact attempt.",
        reference_rfcs=("RFC3261",),
        related_methods=INVITE_ONLY,
    ),
    ResponseModelSpec(
        status_code=604,
        reason_phrase="Does Not Exist Anywhere",
        model_name="DoesNotExistAnywhereResponse",
        description="Target does not exist at any location.",
        typical_scenario="Global lookup determines no valid destination exists.",
        reference_rfcs=("RFC3261",),
        related_methods=INVITE_ONLY,
    ),
    ResponseModelSpec(
        status_code=606,
        reason_phrase="Not Acceptable",
        model_name="GlobalNotAcceptableResponse",
        description="Session proposal is globally unacceptable.",
        typical_scenario="No reachable destination can accept the offered session characteristics.",
        reference_rfcs=("RFC3261",),
        related_methods=INVITE_ONLY,
    ),
    ResponseModelSpec(
        status_code=607,
        reason_phrase="Unwanted",
        model_name="UnwantedResponse",
        description="Request is classified as unwanted communication.",
        typical_scenario="Remote policy blocks unwanted INVITE, MESSAGE, or SUBSCRIBE attempts.",
        reference_rfcs=("RFC8197",),
        related_methods=UNWANTED_OUT_OF_DIALOG,
    ),
    ResponseModelSpec(
        status_code=608,
        reason_phrase="Rejected",
        model_name="RejectedResponse",
        description="Request is rejected for policy or feature-specific reasons.",
        typical_scenario="Feature-specific rejection of an INVITE, MESSAGE, or other out-of-dialog request.",
        reference_rfcs=("RFC8688",),
        related_methods=UNWANTED_OUT_OF_DIALOG,
        conditional_required_fields=(REJECTED_CALL_INFO_RULE,),
    ),
)


def _build_response_model(spec: ResponseModelSpec) -> type[SIPResponse]:
    overrides: dict[str, Any] = {
        "status_code": (
            int,
            Field(default=spec.status_code, ge=spec.status_code, le=spec.status_code),
        ),
        "reason_phrase": (str, Field(default=spec.reason_phrase, min_length=1)),
    }
    for field_name in spec.required_override_fields:
        overrides[field_name] = _RESPONSE_REQUIRED_FIELD_OVERRIDES[field_name]

    model_type = create_model(
        spec.model_name,
        __base__=SIPResponse,
        __module__=__name__,
        **overrides,
    )
    model_type.__doc__ = spec.description
    return model_type


RESPONSE_MODELS_BY_CODE: dict[int, type[SIPResponse]] = {
    spec.status_code: _build_response_model(spec) for spec in _RESPONSE_SPECS
}
for _spec in _RESPONSE_SPECS:
    globals()[_spec.model_name] = RESPONSE_MODELS_BY_CODE[_spec.status_code]


RESPONSE_DEFINITIONS: tuple[SIPResponseDefinition, ...] = tuple(
    SIPResponseDefinition(
        status_code=spec.status_code,
        reason_phrase=spec.reason_phrase,
        model_name=spec.model_name,
        status_class=classify_status(spec.status_code),
        direction=SIPDirection.INCOMING_TO_UE,
        ue_role=UERole.UAC,
        description=spec.description,
        typical_scenario=spec.typical_scenario,
        preconditions=("UE originated the corresponding request.",),
        reference_rfcs=spec.reference_rfcs,
        required_fields=model_field_partition(
            RESPONSE_MODELS_BY_CODE[spec.status_code]
        )[0],
        optional_fields=model_field_partition(
            RESPONSE_MODELS_BY_CODE[spec.status_code]
        )[1],
        field_descriptors=build_field_descriptors(
            RESPONSE_MODELS_BY_CODE[spec.status_code]
        ),
        conditional_required_fields=(
            spec.conditional_required_fields
            + (() if spec.status_code == 100 else (NON_100_TO_TAG_RULE,))
        ),
        related_methods=spec.related_methods,
    )
    for spec in _RESPONSE_SPECS
)


__all__ = [
    *[spec.model_name for spec in _RESPONSE_SPECS],
    "RESPONSE_DEFINITIONS",
    "RESPONSE_MODELS_BY_CODE",
    "ResponseModelSpec",
    "SIPResponse",
    "SIPResponseDefinition",
]
