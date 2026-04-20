import time
from copy import deepcopy
from uuid import uuid4
from typing import Any

from volte_mutation_fuzzer.generator.contracts import (
    DialogContext,
    GeneratorSettings,
    RequestSpec,
    ResponseSpec,
)
from volte_mutation_fuzzer.generator.optional_defaults import (
    get_request_optional_defaults,
    get_response_optional_defaults,
)
from volte_mutation_fuzzer.sip.body_factory import BodyContext, BodyFactory
from volte_mutation_fuzzer.sip.catalog import SIPCatalog, SIP_CATALOG
from volte_mutation_fuzzer.sip.common import (
    AuthChallenge,
    CSeqHeader,
    EventHeader,
    NameAddress,
    RAckHeader,
    RetryAfterHeader,
    SIPMethod,
    SIPURI,
    StatusClass,
    SubscriptionStateHeader,
    URIReference,
    ViaHeader,
)
from volte_mutation_fuzzer.sip.requests import REQUEST_MODELS_BY_METHOD, SIPRequest
from volte_mutation_fuzzer.sip.response_policy import get_response_policy
from volte_mutation_fuzzer.sip.responses import RESPONSE_MODELS_BY_CODE, SIPResponse

_DIALOG_PRECONDITIONS = frozenset(
    {
        "Confirmed dialog exists.",
        "Existing dialog exists.",
        "Early or confirmed dialog exists.",
    }
)

_INVITE_TRANSACTION_PRECONDITIONS = frozenset(
    {
        "Matching INVITE transaction exists.",
        "Matching INVITE server transaction is still proceeding.",
    }
)

_ADVISORY_PRECONDITIONS = frozenset(
    {
        "Active subscription or implicit REFER subscription exists.",
        "Reliable provisional response was sent.",
        "UE acts as a publication target/service.",
        "UE acts like a registrar or registration service.",
        "UE supports the targeted event package.",
    }
)

_RESPONSE_PRECONDITIONS = frozenset({"UE originated the corresponding request."})


class SIPGenerator:
    """Orchestrates request/response model generation from generator contracts."""

    def __init__(
        self,
        settings: GeneratorSettings,
        *,
        catalog: SIPCatalog | None = None,
    ) -> None:
        self.settings = settings
        self.catalog = SIP_CATALOG if catalog is None else catalog
        self._body_factory = BodyFactory()

    def generate_request(
        self,
        spec: RequestSpec,
        context: DialogContext | None = None,
    ) -> SIPRequest:
        model = self._resolve_request_model(spec)
        definition = self.catalog.get_request(spec.method)

        self._validate_preconditions(
            context=context,
            preconditions=definition.preconditions,
        )

        payload = self._build_request_defaults(spec, context)
        if spec.has_overrides:
            payload = self._apply_overrides(payload, spec.overrides)
        self._populate_body_header_defaults(payload)

        # Pydantic BaseModel 내부 메서드이며, payload 검증과 최종 모델 인스턴스 생성을 함께 수행한다.
        return model.model_validate(payload)

    def generate_response(
        self,
        spec: ResponseSpec,
        context: DialogContext,
    ) -> SIPResponse:
        model = self._resolve_response_model(spec)
        definition = self.catalog.get_response(spec.status_code)

        self._validate_preconditions(
            context=context,
            preconditions=definition.preconditions,
        )

        payload = self._build_response_defaults(spec, context)
        if spec.has_overrides:
            payload = self._apply_overrides(payload, spec.overrides)
        self._populate_body_header_defaults(payload)
        policy = get_response_policy(spec.related_method, spec.status_code)
        body = payload.get("body")
        if policy.body_forbidden and body is not None:
            raise ValueError(
                "response policy forbids a body for "
                f"{spec.related_method.value} {spec.status_code}"
            )
        if policy.body_required and (body is None or body == ""):
            raise ValueError(
                "response policy requires a body for "
                f"{spec.related_method.value} {spec.status_code}"
            )

        # Pydantic BaseModel 내부 메서드이며, payload 검증과 최종 모델 인스턴스 생성을 함께 수행한다.
        return model.model_validate(payload)

    def _resolve_request_model(self, spec: RequestSpec) -> type[SIPRequest]:
        try:
            definition = self.catalog.get_request(spec.method)
        except StopIteration as exc:
            raise ValueError(
                f"request method {spec.method} is not present in the SIP catalog"
            ) from exc

        try:
            model = REQUEST_MODELS_BY_METHOD[spec.method]
        except KeyError as exc:
            raise ValueError(
                f"request method {spec.method} does not have a registered SIP model"
            ) from exc

        if model.__name__ != definition.model_name:
            raise ValueError(
                f"request model mismatch for {spec.method}: "
                f"catalog expects {definition.model_name}, "
                f"mapping provides {model.__name__}"
            )

        return model

    def _resolve_response_model(self, spec: ResponseSpec) -> type[SIPResponse]:
        try:
            definition = self.catalog.get_response(spec.status_code)
        except StopIteration as exc:
            raise ValueError(
                f"response status {spec.status_code} is not present in the SIP catalog"
            ) from exc

        try:
            model = RESPONSE_MODELS_BY_CODE[spec.status_code]
        except KeyError as exc:
            raise ValueError(
                f"response status {spec.status_code} does not have a registered SIP model"
            ) from exc

        if model.__name__ != definition.model_name:
            raise ValueError(
                f"response model mismatch for {spec.status_code}: "
                f"catalog expects {definition.model_name}, "
                f"mapping provides {model.__name__}"
            )

        if (
            definition.related_methods
            and spec.related_method not in definition.related_methods
        ):
            allowed_methods = ", ".join(
                method.value for method in definition.related_methods
            )
            raise ValueError(
                f"response status {spec.status_code} does not support related method "
                f"{spec.related_method}; expected one of: {allowed_methods}"
            )

        return model

    def _build_request_defaults(
        self,
        spec: RequestSpec,
        context: DialogContext | None = None,
    ) -> dict[str, Any]:
        model = self._resolve_request_model(spec)
        request_uri = self._build_request_uri(context)

        defaults: dict[str, Any] = {
            "method": spec.method,
            "request_uri": request_uri,
            "sip_version": "SIP/2.0",
            "via": [self._build_via()],
            "max_forwards": 70,
            "from_": self._build_from(context),
            "to": self._build_to(context),
            "call_id": self._build_call_id(context),
            "cseq": self._build_cseq(spec.method, context),
            "user_agent": self.settings.user_agent,
            "content_length": 0,
        }

        if context is not None and context.route_set:
            defaults["route"] = list(context.route_set)

        if spec.method in {
            SIPMethod.BYE,
            SIPMethod.INFO,
            SIPMethod.INVITE,
            SIPMethod.NOTIFY,
            SIPMethod.OPTIONS,
            SIPMethod.PRACK,
            SIPMethod.REFER,
            SIPMethod.SUBSCRIBE,
            SIPMethod.UPDATE,
        }:
            defaults["contact"] = [self._build_contact()]

        if spec.method == SIPMethod.NOTIFY:
            defaults["event"] = self._build_event_header()
            defaults["subscription_state"] = SubscriptionStateHeader(
                state="active",
                expires=3600,
            )

        if spec.method == SIPMethod.PRACK:
            defaults["rack"] = RAckHeader(
                response_num=1,
                cseq_num=max(context.local_cseq, 1) if context is not None else 1,
                method=SIPMethod.INVITE,
            )

        if spec.method == SIPMethod.PUBLISH:
            defaults["event"] = self._build_event_header()

        if spec.method == SIPMethod.REFER:
            defaults["refer_to"] = NameAddress(
                display_name=self.settings.target_ue_name,
                uri=request_uri,
            )

        if spec.method == SIPMethod.SUBSCRIBE:
            defaults["event"] = self._build_event_header()

        if (
            "contact" in model.model_fields
            and model.model_fields["contact"].is_required()
        ):
            defaults.setdefault("contact", [self._build_contact()])

        is_real_ue = self.settings.mode == "real-ue-direct"

        if is_real_ue:
            # 3GPP IMS defaults — replaces softphone optional headers and SDP
            self._apply_3gpp_defaults(defaults, spec)
        else:
            # Softphone-only optional headers
            optional = get_request_optional_defaults(spec.method)
            for key, value in optional.items():
                defaults.setdefault(key, value)

            if spec.method == SIPMethod.INVITE:
                defaults.setdefault(
                    "p_asserted_identity", (self._build_from_name_address(),)
                )
            if spec.method == SIPMethod.REFER:
                defaults.setdefault("referred_by", self._build_from_name_address())

            # Softphone body (body_factory)
            if "body" not in (spec.overrides or {}):
                event_pkg = spec.event_package or self._infer_event_package(defaults)
                info_pkg = spec.info_package or self._infer_info_package(defaults)
                body_ctx = BodyContext(
                    method=spec.method,
                    body_kind=spec.body_kind,
                    event_package=event_pkg,
                    info_package=info_pkg,
                    sms_over_ip=spec.sms_over_ip,
                )
                body_model = self._body_factory.create(body_ctx)
                if body_model is not None:
                    defaults["body"] = body_model.render()
                    defaults["content_type"] = body_model.content_type
                    defaults["content_length"] = len(defaults["body"].encode("utf-8"))

        self._populate_body_header_defaults(defaults)

        return defaults

    def _infer_event_package(self, defaults: dict[str, Any]) -> str | None:
        event = defaults.get("event")
        if isinstance(event, EventHeader):
            return event.package
        return None

    def _infer_info_package(self, defaults: dict[str, Any]) -> str | None:
        info_package = defaults.get("info_package")
        if not isinstance(info_package, str):
            return None
        stripped = info_package.strip()
        return stripped or None

    def _build_response_defaults(
        self,
        spec: ResponseSpec,
        context: DialogContext,
    ) -> dict[str, Any]:
        model = self._resolve_response_model(spec)
        definition = self.catalog.get_response(spec.status_code)

        defaults: dict[str, Any] = {
            "status_code": spec.status_code,
            "reason_phrase": definition.reason_phrase,
            "sip_version": "SIP/2.0",
            "via": [self._build_via()],
            "from_": self._build_to(context),
            "to": self._build_from(context),
            "call_id": self._build_call_id(context),
            "cseq": self._build_cseq(
                spec.related_method,
                context,
                local_origin=True,
            ),
            "server": self.settings.user_agent,
            "content_length": 0,
            "timestamp": round(time.time(), 3),
        }

        if context.route_set:
            defaults["record_route"] = list(context.route_set)

        if (
            definition.status_class == StatusClass.SUCCESS
            and spec.related_method == SIPMethod.SUBSCRIBE
        ):
            defaults["expires"] = 3600

        if (
            (
                definition.status_class == StatusClass.INFORMATIONAL
                and spec.related_method == SIPMethod.INVITE
                and spec.status_code not in {100, 199}
            )
            or (
                definition.status_class == StatusClass.SUCCESS
                and spec.related_method == SIPMethod.INVITE
            )
            or (
                definition.status_class == StatusClass.SUCCESS
                and spec.related_method == SIPMethod.REGISTER
            )
            or definition.status_class == StatusClass.REDIRECTION
        ):
            defaults["contact"] = [self._build_contact()]

        if spec.status_code == 489:
            defaults["allow_events"] = ("presence",)

        if spec.status_code == 494:
            defaults["require"] = ("sec-agree",)

        if spec.status_code == 503:
            defaults["retry_after"] = RetryAfterHeader(seconds=120)

        policy = get_response_policy(spec.related_method, spec.status_code)
        for header_name in policy.required_headers:
            if header_name not in defaults:
                defaults[header_name] = self._build_required_response_field(header_name)
        for header_name in policy.forbidden_headers:
            defaults.pop(header_name, None)

        optional = get_response_optional_defaults(spec.related_method, spec.status_code)
        for key, value in optional.items():
            defaults.setdefault(key, value)

        if spec.related_method == SIPMethod.REGISTER and 200 <= spec.status_code < 300:
            defaults.setdefault("service_route", (self._build_from_name_address().uri,))
            defaults.setdefault("sip_etag", uuid4().hex)

        for header_name in policy.forbidden_headers:
            defaults.pop(header_name, None)

        if "body" not in (spec.overrides or {}):
            if policy.body_forbidden:
                defaults.pop("body", None)
                defaults.pop("content_type", None)
                defaults["content_length"] = 0
            else:
                body_ctx = BodyContext(
                    method=spec.related_method,
                    status_code=spec.status_code,
                    event_package=spec.event_package,
                )
                body_model = self._body_factory.create(body_ctx)
                if body_model is not None:
                    defaults["body"] = body_model.render()
                    defaults["content_type"] = body_model.content_type
                    defaults["content_length"] = len(defaults["body"].encode("utf-8"))

        for field_name, field in model.model_fields.items():
            if field_name in defaults or not field.is_required():
                continue
            defaults[field_name] = self._build_required_response_field(field_name)

        self._populate_body_header_defaults(defaults)

        return defaults

    def _populate_body_header_defaults(self, defaults: dict[str, Any]) -> None:
        """Set content_disposition and content_language when body is present."""
        body = defaults.get("body")
        if not body:
            return
        if defaults.get("content_length", 0) == 0:
            defaults["content_length"] = len(body.encode("utf-8"))
        content_type = str(defaults.get("content_type") or "")
        defaults.setdefault(
            "content_disposition",
            "session" if "sdp" in content_type else "render",
        )
        defaults.setdefault("content_language", ("en",))

    def _build_required_response_field(self, field_name: str) -> Any:
        if field_name == "allow":
            return tuple(SIPMethod)

        if field_name in {"proxy_authenticate", "www_authenticate"}:
            return (
                AuthChallenge(
                    realm=self.settings.from_host,
                    nonce=uuid4().hex,
                ),
            )

        if field_name == "unsupported":
            return ("100rel",)

        if field_name == "require":
            return ("100rel",)

        if field_name == "min_se":
            return 1800

        if field_name == "min_expires":
            return 300

        if field_name == "geolocation_error":
            return "location-invalid"

        if field_name == "alert_msg_error":
            return "unsupported-alert"

        if field_name == "recv_info":
            return ("g.3gpp.iari-ref",)

        if field_name == "security_server":
            return ("ipsec-3gpp;q=0.1",)

        if field_name == "expires":
            return 3600

        if field_name == "contact":
            return [self._build_contact()]

        raise ValueError(f"unsupported required response field: {field_name}")

    def _apply_overrides(
        self,
        defaults: dict[str, Any],
        overrides: dict[str, Any],
    ) -> dict[str, Any]:
        merged = deepcopy(defaults)

        for field_name, value in overrides.items():
            merged[self._normalize_override_field_name(field_name)] = deepcopy(value)

        return merged

    def _normalize_override_field_name(self, field_name: str) -> str:
        normalized_field_name = field_name.replace("-", "_").lower()
        if normalized_field_name == "from":
            return "from_"
        return normalized_field_name

    def _validate_preconditions(
        self,
        *,
        context: DialogContext | None,
        preconditions: tuple[str, ...],
    ) -> None:
        for precondition in preconditions:
            if precondition in _DIALOG_PRECONDITIONS:
                if context is None or not context.has_dialog:
                    raise ValueError(
                        f"{precondition} request generation requires an existing "
                        "dialog context with call-id/local-tag/remote-tag."
                    )
                continue

            if precondition in _INVITE_TRANSACTION_PRECONDITIONS:
                has_invite_transaction = (
                    context is not None
                    and context.call_id is not None
                    and context.remote_tag is not None
                    and context.request_uri is not None
                )
                if not has_invite_transaction:
                    raise ValueError(
                        f"{precondition} request generation requires INVITE "
                        "transaction context with call-id/from-tag/request-uri."
                    )
                continue

            if precondition in _ADVISORY_PRECONDITIONS:
                continue

            if precondition in _RESPONSE_PRECONDITIONS:
                has_originating_request_context = (
                    context is not None
                    and context.call_id is not None
                    and context.local_tag is not None
                    and context.local_cseq > 0
                )
                if not has_originating_request_context:
                    raise ValueError(
                        f"{precondition} response generation requires request "
                        "context with call-id/from-tag/local-cseq."
                    )
                continue

            raise ValueError(f"unsupported request precondition: {precondition}")

    def _build_via(self) -> ViaHeader:
        return ViaHeader(
            transport=self.settings.transport,
            host=self.settings.via_host,
            port=self.settings.via_port,
            branch=f"z9hG4bK-{uuid4().hex}",
            rport=True,
        )

    def _build_from(self, context: DialogContext | None) -> NameAddress:
        remote_tag = context.remote_tag if context is not None else None
        if remote_tag is None:
            remote_tag = self._new_tag()
            if context is not None:
                context.remote_tag = remote_tag

        return NameAddress(
            display_name=self.settings.from_display_name,
            uri=SIPURI(
                scheme="sip",
                user=self.settings.from_user,
                host=self.settings.from_host,
                port=self.settings.from_port,
            ),
            parameters={"tag": remote_tag},
        )

    def _build_to(self, context: DialogContext | None) -> NameAddress:
        parameters: dict[str, str | None] = {}
        if context is not None and context.local_tag is not None:
            parameters["tag"] = context.local_tag

        return NameAddress(
            display_name=self.settings.to_display_name,
            uri=SIPURI(
                scheme="sip",
                user=self.settings.to_user,
                host=self.settings.to_host,
                port=self.settings.to_port,
            ),
            parameters=parameters,
        )

    def _build_contact(self) -> NameAddress:
        has_contact_override = any(
            value is not None
            for value in (
                self.settings.contact_display_name,
                self.settings.contact_user,
                self.settings.contact_host,
                self.settings.contact_port,
            )
        )

        return NameAddress(
            display_name=(
                self.settings.contact_display_name
                if has_contact_override
                else self.settings.from_display_name
            ),
            uri=SIPURI(
                scheme="sip",
                user=self.settings.contact_user or self.settings.from_user,
                host=self.settings.contact_host or self.settings.from_host,
                port=(
                    self.settings.contact_port
                    if has_contact_override
                    else self.settings.from_port
                ),
            ),
        )

    def _build_call_id(self, context: DialogContext | None) -> str:
        if context is not None and context.call_id is not None:
            return context.call_id

        call_id = f"{uuid4().hex}@{self.settings.from_host}"
        if context is not None:
            context.call_id = call_id
        return call_id

    def _build_cseq(
        self,
        method: SIPMethod,
        context: DialogContext | None,
        *,
        local_origin: bool = False,
    ) -> CSeqHeader:
        if local_origin:
            sequence = (
                1 if context is None or context.local_cseq == 0 else context.local_cseq
            )
            return CSeqHeader(sequence=sequence, method=method)

        sequence = 1 if context is None else context.next_remote_cseq()
        return CSeqHeader(sequence=sequence, method=method)

    def _build_request_uri(
        self,
        context: DialogContext | None,
    ) -> URIReference:
        if context is not None and context.request_uri is not None:
            return context.request_uri

        request_uri = SIPURI(
            scheme="sip",
            user=self.settings.request_uri_user,
            host=self.settings.request_uri_host,
            port=self.settings.request_uri_port,
        )
        if context is not None:
            context.request_uri = request_uri
        return request_uri

    def _build_event_header(self) -> EventHeader:
        return EventHeader(package="presence")

    def _new_tag(self) -> str:
        return uuid4().hex[:16]

    def _build_from_name_address(self) -> NameAddress:
        """Build a tag-less NameAddress from the from_* settings."""
        return NameAddress(
            display_name=self.settings.from_display_name,
            uri=SIPURI(
                user=self.settings.from_user,
                host=self.settings.from_host,
                port=self.settings.from_port,
            ),
        )

    # ------------------------------------------------------------------
    # 3GPP IMS defaults (real-ue-direct mode)
    # ------------------------------------------------------------------

    def _apply_3gpp_defaults(
        self, defaults: dict[str, Any], spec: RequestSpec
    ) -> None:
        """Inject 3GPP IMS-standard headers sourced from .env settings.

        These headers make the packet acceptable to real VoLTE UEs that
        validate 3GPP-compliant message format.  All values come from
        ``GeneratorSettings`` which reads ``VMF_*`` environment variables.
        """
        s = self.settings
        domain = s.ims_domain

        # --- Common 3GPP headers (all methods) ---
        defaults["max_forwards"] = 66  # IMS core reduces from 70

        defaults.setdefault("p_asserted_identity", (
            NameAddress(
                uri=SIPURI(
                    user=s.from_user,
                    host=domain,
                ),
            ),
        ))

        defaults.setdefault("p_visited_network_id", domain)

        defaults.setdefault("p_access_network_info",
            f"3GPP-E-UTRAN-FDD;utran-cell-id-3gpp={s.cell_id}"
        )

        # --- INVITE-specific 3GPP headers ---
        if spec.method == SIPMethod.INVITE:
            self._apply_3gpp_invite_defaults(defaults)

        # --- MESSAGE-specific ---
        if spec.method == SIPMethod.MESSAGE:
            defaults.setdefault("p_preferred_service",
                "urn:urn-7:3gpp-service.ims.icsi.mmtel")

    def _apply_3gpp_invite_defaults(self, defaults: dict[str, Any]) -> None:
        """INVITE-specific 3GPP IMS headers and SDP."""
        s = self.settings
        pcscf_ip = s.via_host  # P-CSCF IP = Via host

        # Record-Route (P-CSCF + S-CSCF x2)
        from_tag = ""
        from_na = defaults.get("from_")
        if isinstance(from_na, NameAddress) and from_na.parameters:
            from_tag = from_na.parameters.get("tag", "")

        defaults.setdefault("record_route", [
            NameAddress(uri=SIPURI(
                user="mo", host=pcscf_ip, port=s.pcscf_mt_port,
                parameters={"lr": "on", "ftag": from_tag, "rm": "8", "did": "643.7a11"},
            )),
            NameAddress(uri=SIPURI(
                user="mo", host=s.scscf_ip, port=s.scscf_port,
                parameters={"transport": "tcp", "r2": "on", "lr": "on",
                             "ftag": from_tag, "did": "643.3382"},
            )),
            NameAddress(uri=SIPURI(
                user="mo", host=s.scscf_ip, port=s.scscf_port,
                parameters={"r2": "on", "lr": "on",
                             "ftag": from_tag, "did": "643.3382"},
            )),
        ])

        # Contact with 3GPP feature tags
        contact_uri = SIPURI(
            user=s.from_user,
            host=s.contact_host or s.from_host,
            port=s.contact_port or s.from_port,
        )
        defaults["contact"] = [NameAddress(
            uri=contact_uri,
            parameters={
                "+sip.instance": f'"<urn:gsma:imei:{s.mo_imei}>"',
                "+g.3gpp.icsi-ref": '"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"',
                "audio": None,
                "video": None,
                "+g.3gpp.mid-call": None,
                "+g.3gpp.srvcc-alerting": None,
                "+g.3gpp.ps2cs-srvcc-orig-pre-alerting": None,
            },
        )]

        # Accept-Contact
        defaults.setdefault("accept_contact",
            '*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"')

        # P-* headers
        defaults.setdefault("p_preferred_service",
            "urn:urn-7:3gpp-service.ims.icsi.mmtel")
        defaults.setdefault("p_early_media", "supported")
        defaults.setdefault("p_charging_vector",
            f"icid-value={uuid4().hex[:32].upper()};icid-generated-at={pcscf_ip}")

        # Supported / Allow / Accept
        defaults.setdefault("supported",
            ("100rel", "histinfo", "join", "norefersub",
             "precondition", "replaces", "timer", "sec-agree"))
        defaults.setdefault("allow", tuple(SIPMethod))
        defaults.setdefault("accept",
            ("application/sdp", "application/3gpp-ims+xml"))

        # Session timer
        defaults.setdefault("session_expires", 1800)
        defaults.setdefault("min_se", 90)

        # SDP body with AMR-WB/AMR codecs and QoS preconditions
        if "body" not in defaults:
            sdp = self._build_volte_sdp()
            defaults["body"] = sdp
            defaults["content_type"] = "application/sdp"
            defaults["content_length"] = len(sdp.encode("utf-8"))

    def _build_volte_sdp(self) -> str:
        """Build a 3GPP-compliant VoLTE SDP with AMR-WB/AMR and QoS preconditions."""
        s = self.settings
        ip = s.sdp_owner_ip
        port = s.sdp_audio_port
        rtcp = port + 1
        return (
            "v=0\r\n"
            f"o=rue 3251 3251 IN IP4 {ip}\r\n"
            "s=-\r\n"
            "b=AS:41\r\n"
            "b=RR:1537\r\n"
            "b=RS:512\r\n"
            "t=0 0\r\n"
            f"m=audio {port} RTP/AVP 107 106 105 104 101 102\r\n"
            f"c=IN IP4 {ip}\r\n"
            "b=AS:41\r\n"
            "b=RR:1537\r\n"
            "b=RS:512\r\n"
            "a=rtpmap:107 AMR-WB/16000\r\n"
            "a=fmtp:107 mode-change-capability=2;max-red=0\r\n"
            "a=rtpmap:106 AMR-WB/16000\r\n"
            "a=fmtp:106 octet-align=1;mode-change-capability=2;max-red=0\r\n"
            "a=rtpmap:105 AMR/8000\r\n"
            "a=fmtp:105 mode-change-capability=2;max-red=0\r\n"
            "a=rtpmap:104 AMR/8000\r\n"
            "a=fmtp:104 octet-align=1;mode-change-capability=2;max-red=0\r\n"
            "a=rtpmap:101 telephone-event/16000\r\n"
            "a=fmtp:101 0-15\r\n"
            "a=rtpmap:102 telephone-event/8000\r\n"
            "a=fmtp:102 0-15\r\n"
            "a=curr:qos local none\r\n"
            "a=curr:qos remote none\r\n"
            "a=des:qos mandatory local sendrecv\r\n"
            "a=des:qos optional remote sendrecv\r\n"
            "a=sendrecv\r\n"
            f"a=rtcp:{rtcp}\r\n"
            "a=ptime:20\r\n"
            "a=maxptime:240\r\n"
        )
