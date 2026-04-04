from copy import deepcopy
from uuid import uuid4
from typing import Any

from volte_mutation_fuzzer.generator.contracts import (
    DialogContext,
    GeneratorSettings,
    RequestSpec,
    ResponseSpec,
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
            SIPMethod.INVITE,
            SIPMethod.NOTIFY,
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

        if "body" not in (spec.overrides or {}):
            event_pkg = spec.event_package or self._infer_event_package(defaults)
            body_ctx = BodyContext(
                method=spec.method,
                event_package=event_pkg,
                info_package=spec.info_package,
                sms_over_ip=spec.sms_over_ip,
            )
            body_model = self._body_factory.create(body_ctx)
            if body_model is not None:
                defaults["body"] = body_model.render()
                defaults["content_type"] = body_model.content_type
                defaults["content_length"] = len(defaults["body"].encode("utf-8"))

        return defaults

    def _infer_event_package(self, defaults: dict[str, Any]) -> str | None:
        event = defaults.get("event")
        if isinstance(event, EventHeader):
            return event.package
        return None

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

        if "body" not in (spec.overrides or {}):
            if policy.body_forbidden:
                defaults.pop("body", None)
                defaults.pop("content_type", None)
                defaults["content_length"] = 0
            else:
                body_ctx = BodyContext(
                    method=spec.related_method,
                    status_code=spec.status_code,
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

        return defaults

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
