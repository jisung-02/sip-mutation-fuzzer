from __future__ import annotations

from dataclasses import dataclass

from volte_mutation_fuzzer.sip.bodies import (
    ConferenceInfoBody,
    DialogInfoBody,
    DtmfRelayBody,
    ImsServiceBody,
    MessageSummaryBody,
    PIdfBody,
    PlainTextBody,
    ReginfoBody,
    SDPBody,
    SIPBody,
    SipfragBody,
    SmsBody,
)
from volte_mutation_fuzzer.sip.common import SIPMethod

DEFAULT_INFO_PACKAGE = "dtmf"


@dataclass(frozen=True)
class BodyContext:
    method: SIPMethod
    status_code: int | None = None
    body_kind: str | None = None
    event_package: str | None = None
    info_package: str | None = None
    sms_over_ip: bool = False


class BodyFactory:
    _BODY_KIND_MAP: dict[str, type[SIPBody]] = {
        "conference": ConferenceInfoBody,
        "conference_info": ConferenceInfoBody,
        "conference-info": ConferenceInfoBody,
        "dialog": DialogInfoBody,
        "dialog_info": DialogInfoBody,
        "dialog-info": DialogInfoBody,
        "dtmf": DtmfRelayBody,
        "ims_service": ImsServiceBody,
        "ims-service": ImsServiceBody,
        "message_summary": MessageSummaryBody,
        "message-summary": MessageSummaryBody,
        "pidf": PIdfBody,
        "plain_text": PlainTextBody,
        "plain-text": PlainTextBody,
        "reginfo": ReginfoBody,
        "sdp": SDPBody,
        "sdp_offer": SDPBody,
        "sdp-offer": SDPBody,
        "sipfrag": SipfragBody,
        "sms": SmsBody,
    }
    _EVENT_BODY_MAP: dict[str, type[SIPBody]] = {
        "conference": ConferenceInfoBody,
        "dialog": DialogInfoBody,
        "message-summary": MessageSummaryBody,
        "presence": PIdfBody,
        "refer": SipfragBody,
        "reg": ReginfoBody,
    }
    _INFO_BODY_MAP: dict[str, type[SIPBody]] = {
        DEFAULT_INFO_PACKAGE: DtmfRelayBody,
    }
    _SDP_METHODS = frozenset({SIPMethod.INVITE, SIPMethod.PRACK, SIPMethod.UPDATE})

    def select(self, ctx: BodyContext) -> type[SIPBody] | None:
        normalized_body_kind = self._normalize(ctx.body_kind)
        explicit_body = self._BODY_KIND_MAP.get(normalized_body_kind)
        if explicit_body is not None:
            return explicit_body
        if normalized_body_kind:
            raise ValueError(f"unsupported body_kind: {ctx.body_kind}")
        if ctx.status_code is None:
            return self._select_request_body(ctx)
        return self._select_response_body(ctx)

    def create(self, ctx: BodyContext) -> SIPBody | None:
        body_model = self.select(ctx)
        if body_model is None:
            return None
        return body_model.default_instance()

    def _select_request_body(self, ctx: BodyContext) -> type[SIPBody] | None:
        if ctx.method == SIPMethod.NOTIFY:
            return self._EVENT_BODY_MAP.get(self._normalize(ctx.event_package))
        if ctx.method == SIPMethod.INFO:
            return self._INFO_BODY_MAP.get(self._normalize(ctx.info_package))
        if ctx.method == SIPMethod.MESSAGE:
            if ctx.sms_over_ip:
                return SmsBody
            return PlainTextBody
        if ctx.method == SIPMethod.PUBLISH:
            return PIdfBody
        if ctx.method in self._SDP_METHODS:
            return SDPBody
        return None

    def _select_response_body(self, ctx: BodyContext) -> type[SIPBody] | None:
        status_code = ctx.status_code
        if status_code is None:
            return None
        if ctx.method == SIPMethod.NOTIFY and ctx.event_package:
            body_cls = self._EVENT_BODY_MAP.get(self._normalize(ctx.event_package))
            if body_cls is not None and 200 <= status_code < 300:
                return body_cls
        if ctx.method == SIPMethod.INVITE and status_code == 380:
            return ImsServiceBody
        if ctx.method in self._SDP_METHODS and (
            status_code in {180, 183} or 200 <= status_code < 300
        ):
            return SDPBody
        if ctx.method == SIPMethod.OPTIONS and status_code == 200:
            return SDPBody
        if ctx.method == SIPMethod.MESSAGE:
            return None
        return None

    @staticmethod
    def _normalize(value: str | None) -> str:
        if value is None:
            return ""
        return value.strip().lower()
