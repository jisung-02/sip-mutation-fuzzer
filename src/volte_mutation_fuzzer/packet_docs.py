from pathlib import Path

from volte_mutation_fuzzer.sip import SIPMethod
from volte_mutation_fuzzer.sip.catalog import SIP_CATALOG
from volte_mutation_fuzzer.sip.common import wire_field_name

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_DOCS_DIR = ROOT / "docs" / "프로토콜"
REQUEST_DOC_PATH = PROTOCOL_DOCS_DIR / "요청-패킷-예시.md"
RESPONSE_DOC_PATH = PROTOCOL_DOCS_DIR / "응답-패킷-예시.md"

REQUEST_FIELD_ORDER = [
    "via",
    "max_forwards",
    "from",
    "to",
    "call_id",
    "cseq",
    "contact",
    "route",
    "record_route",
    "supported",
    "require",
    "proxy_require",
    "allow",
    "allow_events",
    "accept",
    "accept_encoding",
    "accept_language",
    "alert_info",
    "call_info",
    "event",
    "subscription_state",
    "expires",
    "info_package",
    "recv_info",
    "session_expires",
    "min_se",
    "sip_if_match",
    "refer_to",
    "referred_by",
    "refer_sub",
    "target_dialog",
    "path",
    "privacy",
    "p_asserted_identity",
    "reason",
    "subject",
    "organization",
    "priority",
    "user_agent",
    "content_type",
    "content_disposition",
    "content_encoding",
    "content_language",
    "content_length",
]

RESPONSE_FIELD_ORDER = [
    "via",
    "from",
    "to",
    "call_id",
    "cseq",
    "contact",
    "record_route",
    "allow",
    "allow_events",
    "supported",
    "require",
    "unsupported",
    "accept",
    "accept_encoding",
    "accept_language",
    "call_info",
    "warning",
    "retry_after",
    "proxy_authenticate",
    "www_authenticate",
    "authentication_info",
    "expires",
    "session_expires",
    "min_expires",
    "min_se",
    "recv_info",
    "rseq",
    "sip_etag",
    "security_server",
    "service_route",
    "error_info",
    "geolocation_error",
    "alert_msg_error",
    "permission_missing",
    "timestamp",
    "server",
    "reason",
    "content_type",
    "content_disposition",
    "content_encoding",
    "content_language",
    "content_length",
]

REQUEST_EXAMPLE_FIELDS: dict[SIPMethod, list[str]] = {
    SIPMethod.ACK: ["route"],
    SIPMethod.BYE: ["reason", "user_agent"],
    SIPMethod.CANCEL: ["reason", "user_agent"],
    SIPMethod.INFO: ["info_package", "content_type", "body"],
    SIPMethod.INVITE: [
        "contact",
        "supported",
        "allow",
        "recv_info",
        "session_expires",
        "min_se",
        "content_type",
        "body",
    ],
    SIPMethod.MESSAGE: ["content_type", "content_language", "body"],
    SIPMethod.NOTIFY: [
        "contact",
        "event",
        "subscription_state",
        "content_type",
        "body",
    ],
    SIPMethod.OPTIONS: ["accept", "allow", "supported"],
    SIPMethod.PRACK: ["rack", "recv_info"],
    SIPMethod.PUBLISH: ["event", "expires", "sip_if_match", "content_type", "body"],
    SIPMethod.REFER: [
        "contact",
        "refer_to",
        "referred_by",
        "refer_sub",
        "target_dialog",
    ],
    SIPMethod.REGISTER: ["contact", "expires", "path", "recv_info", "user_agent"],
    SIPMethod.SUBSCRIBE: ["contact", "event", "expires", "accept", "supported"],
    SIPMethod.UPDATE: [
        "contact",
        "recv_info",
        "session_expires",
        "min_se",
        "content_type",
        "body",
    ],
}

RESPONSE_EXTRA_FIELDS: dict[int, list[str]] = {
    180: ["require", "rseq"],
    181: ["require", "rseq", "contact"],
    182: ["require", "rseq"],
    183: ["require", "rseq", "content_type", "body"],
    199: ["require", "rseq"],
    200: ["contact", "content_type", "body"],
    202: [],
    204: ["expires"],
    300: ["contact"],
    301: ["contact"],
    302: ["contact"],
    305: ["contact"],
    380: ["content_type", "body"],
    401: ["www_authenticate"],
    405: ["allow"],
    407: ["proxy_authenticate"],
    420: ["unsupported"],
    421: ["require"],
    422: ["min_se"],
    423: ["min_expires"],
    424: ["geolocation_error"],
    425: ["alert_msg_error"],
    469: ["recv_info"],
    470: ["permission_missing"],
    494: ["require", "security_server"],
    503: ["retry_after"],
    608: ["call_info"],
}

METHOD_REQUEST_URIS: dict[SIPMethod, str] = {
    SIPMethod.REGISTER: "sip:registrar.ue.example.com",
    SIPMethod.OPTIONS: "sip:ue.example.com",
    SIPMethod.MESSAGE: "sip:ue@example.com",
    SIPMethod.PUBLISH: "sip:presence.ue.example.com",
    SIPMethod.SUBSCRIBE: "sip:presence.ue.example.com",
}

METHOD_BODY: dict[SIPMethod, tuple[str, str]] = {
    SIPMethod.INFO: (
        "application/dtmf-relay",
        "Signal=5\r\nDuration=160\r\n",
    ),
    SIPMethod.INVITE: (
        "application/sdp",
        "v=0\r\n"
        "o=- 0 0 IN IP4 caller.example.com\r\n"
        "s=-\r\n"
        "c=IN IP4 192.0.2.10\r\n"
        "t=0 0\r\n"
        "m=audio 49170 RTP/AVP 0\r\n",
    ),
    SIPMethod.MESSAGE: ("text/plain", "Hello from SIP MESSAGE\r\n"),
    SIPMethod.NOTIFY: (
        "application/pidf+xml",
        '<?xml version="1.0"?>\r\n<presence entity="sip:callee@ue.example.com"/>\r\n',
    ),
    SIPMethod.PUBLISH: (
        "application/pidf+xml",
        '<?xml version="1.0"?>\r\n<presence entity="sip:caller@example.com"/>\r\n',
    ),
    SIPMethod.UPDATE: (
        "application/sdp",
        "v=0\r\n"
        "o=- 1 1 IN IP4 caller.example.com\r\n"
        "s=-\r\n"
        "c=IN IP4 192.0.2.10\r\n"
        "t=0 0\r\n"
        "m=audio 49172 RTP/AVP 0\r\n",
    ),
}

RESPONSE_BODY: dict[int, tuple[str, str]] = {
    183: (
        "application/sdp",
        "v=0\r\n"
        "o=- 0 0 IN IP4 ims.example.com\r\n"
        "s=-\r\n"
        "c=IN IP4 198.51.100.20\r\n"
        "t=0 0\r\n"
        "m=audio 50000 RTP/AVP 0\r\n",
    ),
    200: (
        "application/sdp",
        "v=0\r\n"
        "o=- 0 0 IN IP4 ims.example.com\r\n"
        "s=-\r\n"
        "c=IN IP4 198.51.100.20\r\n"
        "t=0 0\r\n"
        "m=audio 50002 RTP/AVP 0\r\n",
    ),
    380: (
        "text/plain",
        "Alternative service available via sip:service@example.com\r\n",
    ),
}

COMMON_RFC_REFERENCES = [
    ("RFC 3261", "https://www.rfc-editor.org/rfc/rfc3261"),
    ("RFC 3262", "https://www.rfc-editor.org/rfc/rfc3262"),
    ("RFC 3311", "https://www.rfc-editor.org/rfc/rfc3311"),
    ("RFC 3329", "https://www.rfc-editor.org/rfc/rfc3329"),
    ("RFC 3428", "https://www.rfc-editor.org/rfc/rfc3428"),
    ("RFC 3515", "https://www.rfc-editor.org/rfc/rfc3515"),
    ("RFC 3903", "https://www.rfc-editor.org/rfc/rfc3903"),
    ("RFC 5360", "https://www.rfc-editor.org/rfc/rfc5360"),
    ("RFC 5839", "https://www.rfc-editor.org/rfc/rfc5839"),
    ("RFC 6086", "https://www.rfc-editor.org/rfc/rfc6086"),
    ("RFC 6442", "https://www.rfc-editor.org/rfc/rfc6442"),
    ("RFC 6665", "https://www.rfc-editor.org/rfc/rfc6665"),
    ("RFC 7647", "https://www.rfc-editor.org/rfc/rfc7647"),
    ("RFC 8197", "https://www.rfc-editor.org/rfc/rfc8197"),
    ("RFC 8599", "https://www.rfc-editor.org/rfc/rfc8599"),
    ("RFC 8688", "https://www.rfc-editor.org/rfc/rfc8688"),
    ("RFC 8876", "https://www.rfc-editor.org/rfc/rfc8876"),
]


def markdown_code(text: str) -> str:
    return f"```text\n{text.rstrip()}\n```"


def render_reference_section() -> str:
    lines = ["## 참고 RFC", ""]
    for title, url in COMMON_RFC_REFERENCES:
        lines.append(f"- [{title}]({url})")
    lines.append("")
    return "\n".join(lines)


def sample_request_uri(method: SIPMethod) -> str:
    return METHOD_REQUEST_URIS.get(method, "sip:callee@ue.example.com")


def sample_response_method(definition) -> SIPMethod:
    if definition.status_code == 200:
        return SIPMethod.INVITE
    preferred_order = (
        SIPMethod.INVITE,
        SIPMethod.REGISTER,
        SIPMethod.OPTIONS,
        SIPMethod.MESSAGE,
        SIPMethod.SUBSCRIBE,
        SIPMethod.BYE,
        SIPMethod.CANCEL,
        SIPMethod.INFO,
        SIPMethod.NOTIFY,
        SIPMethod.PRACK,
        SIPMethod.PUBLISH,
        SIPMethod.REFER,
        SIPMethod.UPDATE,
    )
    for preferred in preferred_order:
        if preferred in definition.related_methods:
            return preferred
    for method in definition.related_methods:
        if method != SIPMethod.ACK:
            return SIPMethod(method)
    return SIPMethod.OPTIONS


def request_body_for(method: SIPMethod) -> tuple[str | None, str | None]:
    return METHOD_BODY.get(method, (None, None))


def response_body_for(status_code: int) -> tuple[str | None, str | None]:
    return RESPONSE_BODY.get(status_code, (None, None))


def request_context(definition) -> dict[str, object]:
    method = SIPMethod(definition.method)
    content_type, body = request_body_for(method)
    return {
        "kind": "request",
        "method": method,
        "slug": method.value.lower(),
        "request_uri": sample_request_uri(method),
        "content_type": content_type,
        "body": body,
    }


def response_context(definition) -> dict[str, object]:
    method = sample_response_method(definition)
    content_type, body = response_body_for(definition.status_code)
    return {
        "kind": "response",
        "method": method,
        "slug": f"{definition.status_code}-{method.value.lower()}",
        "status_code": definition.status_code,
        "reason_phrase": definition.reason_phrase,
        "content_type": content_type,
        "body": body,
    }


def header_line(field_name: str, context: dict[str, object]) -> str:
    method = SIPMethod(context["method"])
    slug = str(context["slug"])
    body = context.get("body")
    content_type = context.get("content_type")
    status_code = context.get("status_code")

    if field_name == "via":
        return f"Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bK-{slug}"
    if field_name == "max_forwards":
        return "Max-Forwards: 70"
    if field_name == "from":
        if context["kind"] == "request":
            return 'From: "Caller" <sip:caller@example.com>;tag=from-tag'
        return 'From: "UE" <sip:ue@example.com>;tag=ue-tag'
    if field_name == "to":
        if context["kind"] == "request":
            return "To: <sip:callee@ue.example.com>"
        return 'To: "Network" <sip:network@ims.example.com>;tag=net-tag'
    if field_name == "call_id":
        return f"Call-ID: {slug}@example.com"
    if field_name == "cseq":
        return f"CSeq: 1 {method.value}"
    if field_name == "contact":
        if context["kind"] == "request":
            return "Contact: <sip:caller@caller.example.com>"
        return "Contact: <sip:network@ims.example.com>"
    if field_name == "route":
        return "Route: <sip:edge.example.com;lr>"
    if field_name == "record_route":
        return "Record-Route: <sip:proxy.example.com;lr>"
    if field_name == "supported":
        if status_code == 494:
            return "Supported: sec-agree"
        return "Supported: 100rel, timer"
    if field_name == "require":
        if status_code == 494:
            return "Require: sec-agree"
        if status_code in {180, 181, 182, 183, 199}:
            return "Require: 100rel"
        return "Require: timer"
    if field_name == "proxy_require":
        return "Proxy-Require: sec-agree"
    if field_name == "allow":
        return "Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, INFO, MESSAGE, NOTIFY, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE"
    if field_name == "allow_events":
        return "Allow-Events: presence, dialog, refer"
    if field_name == "accept":
        if method == SIPMethod.SUBSCRIBE:
            return "Accept: application/pidf+xml"
        return "Accept: application/sdp"
    if field_name == "accept_encoding":
        return "Accept-Encoding: gzip"
    if field_name == "accept_language":
        return "Accept-Language: ko, en"
    if field_name == "alert_info":
        return "Alert-Info: <urn:service:alerting>"
    if field_name == "call_info":
        return "Call-Info: <https://example.com/call-info>;purpose=info"
    if field_name == "event":
        if method == SIPMethod.PUBLISH:
            return "Event: presence"
        if method == SIPMethod.SUBSCRIBE:
            return "Event: presence"
        if method == SIPMethod.NOTIFY:
            return "Event: presence"
        return "Event: refer"
    if field_name == "subscription_state":
        return "Subscription-State: active;expires=300"
    if field_name == "expires":
        if method == SIPMethod.SUBSCRIBE:
            return "Expires: 300"
        if method == SIPMethod.REGISTER:
            return "Expires: 3600"
        if status_code == 204:
            return "Expires: 300"
        return "Expires: 600"
    if field_name == "info_package":
        return "Info-Package: dtmf"
    if field_name == "recv_info":
        return "Recv-Info: dtmf"
    if field_name == "session_expires":
        return "Session-Expires: 600;refresher=uac"
    if field_name == "min_se":
        return "Min-SE: 90"
    if field_name == "sip_if_match":
        return "SIP-If-Match: etag-1"
    if field_name == "refer_to":
        return "Refer-To: <sip:transfer-target@example.com>"
    if field_name == "referred_by":
        return "Referred-By: <sip:referrer@example.com>"
    if field_name == "refer_sub":
        return "Refer-Sub: false"
    if field_name == "target_dialog":
        return "Target-Dialog: dialog-1234@example.com;local-tag=ltag;remote-tag=rtag"
    if field_name == "path":
        return "Path: <sip:path.example.com;lr>"
    if field_name == "privacy":
        return "Privacy: id"
    if field_name == "p_asserted_identity":
        return "P-Asserted-Identity: <sip:caller@example.com>"
    if field_name == "reason":
        return 'Reason: SIP ;cause=200 ;text="Normal call clearing"'
    if field_name == "subject":
        return "Subject: SIP MESSAGE test"
    if field_name == "organization":
        return "Organization: Example Carrier"
    if field_name == "priority":
        return "Priority: normal"
    if field_name == "user_agent":
        return "User-Agent: VolteMutationFuzzer/0.1"
    if field_name == "warning":
        return 'Warning: 399 proxy.example.com "Informational warning"'
    if field_name == "retry_after":
        return "Retry-After: 120"
    if field_name == "proxy_authenticate":
        return 'Proxy-Authenticate: Digest realm="example.com", nonce="nonce-1"'
    if field_name == "www_authenticate":
        return 'WWW-Authenticate: Digest realm="example.com", nonce="nonce-1"'
    if field_name == "authentication_info":
        return 'Authentication-Info: nextnonce="nonce-2"'
    if field_name == "min_expires":
        return "Min-Expires: 600"
    if field_name == "rseq":
        return "RSeq: 1"
    if field_name == "sip_etag":
        return "SIP-ETag: etag-1"
    if field_name == "security_server":
        return "Security-Server: ipsec-3gpp;alg=hmac-md5-96;prot=esp;mod=trans"
    if field_name == "service_route":
        return "Service-Route: <sip:pcscf.example.com;lr>"
    if field_name == "unsupported":
        return "Unsupported: foo-ext"
    if field_name == "error_info":
        return "Error-Info: <https://example.com/error-info>"
    if field_name == "geolocation_error":
        return "Geolocation-Error: 100 locationValueError"
    if field_name == "alert_msg_error":
        return "AlertMsg-Error: 300 unsupported-alerting"
    if field_name == "permission_missing":
        return "Permission-Missing: <sip:callee@example.com>"
    if field_name == "timestamp":
        return "Timestamp: 1710000000.0"
    if field_name == "server":
        return "Server: IMS-Core/1.0"
    if field_name == "content_type":
        return f"Content-Type: {content_type or 'application/octet-stream'}"
    if field_name == "content_disposition":
        return "Content-Disposition: session"
    if field_name == "content_encoding":
        return "Content-Encoding: gzip"
    if field_name == "content_language":
        return "Content-Language: ko"
    if field_name == "content_length":
        body_text = body if isinstance(body, str) else ""
        return f"Content-Length: {len(body_text.encode('utf-8'))}"
    return f"{wire_field_name(field_name)}: <value>"


def build_packet_text(
    start_line: str, fields: list[str], context: dict[str, object]
) -> str:
    lines = [start_line]
    field_set = set(fields)
    body = context.get("body") if "body" in field_set else None

    if body and "content_type" not in field_set:
        field_set.add("content_type")
    field_set.add("content_length")

    ordered_fields = [
        name
        for name in (
            REQUEST_FIELD_ORDER
            if context["kind"] == "request"
            else RESPONSE_FIELD_ORDER
        )
        if name in field_set and name != "body"
    ]

    for field_name in ordered_fields:
        lines.append(header_line(field_name, context))

    lines.append("")
    if body:
        lines.append(str(body).rstrip("\r\n"))
    return "\n".join(lines)


def request_packet_example(definition) -> str:
    method = SIPMethod(definition.method)
    context = request_context(definition)
    shown_fields = list(
        dict.fromkeys(
            definition.required_fields + tuple(REQUEST_EXAMPLE_FIELDS.get(method, []))
        )
    )
    return build_packet_text(
        f"{method.value} {context['request_uri']} SIP/2.0", shown_fields, context
    )


def response_packet_example(definition) -> str:
    context = response_context(definition)
    shown_fields = list(
        dict.fromkeys(
            definition.required_fields
            + tuple(RESPONSE_EXTRA_FIELDS.get(definition.status_code, []))
        )
    )
    start_line = f"SIP/2.0 {definition.status_code} {definition.reason_phrase}"
    return build_packet_text(start_line, shown_fields, context)


def render_field_names(field_names: tuple[str, ...] | list[str]) -> str:
    if not field_names:
        return "- 없음\n"
    return "\n".join(f"- `{wire_field_name(name)}`" for name in field_names) + "\n"


def render_request_docs() -> str:
    lines = [
        "# SIP 요청 패킷 예시",
        "",
        "> 이 문서는 `scripts/generate_packet_docs.py` 로 생성된다.",
        "> 이 문서는 각 SIP 요청을 **실제 SIP 텍스트 패킷 형태**로 이해하기 위한 설명 문서이다.",
        "> 예시 패킷은 대표 예시이며, 모든 선택 헤더를 다 포함하지는 않는다.",
        "",
        "## 공통 요청 골격",
        "",
        markdown_code(
            "INVITE sip:callee@ue.example.com SIP/2.0\n"
            "Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bK-generic\n"
            "Max-Forwards: 70\n"
            'From: "Caller" <sip:caller@example.com>;tag=from-tag\n'
            "To: <sip:callee@ue.example.com>\n"
            "Call-ID: generic-request@example.com\n"
            "CSeq: 1 INVITE\n"
            "Content-Length: 0\n"
        ),
        "",
        "공통 필수 헤더:",
        render_field_names(("via", "max_forwards", "from", "to", "call_id", "cseq")),
    ]

    for definition in SIP_CATALOG.request_definitions:
        lines.extend(
            [
                f"## {definition.method}",
                "",
                f"- 설명: {definition.description}",
                f"- 대표 상황: {definition.typical_scenario}",
                f"- RFC: {', '.join(definition.reference_rfcs)}",
                "",
                "### 대표 SIP 패킷 예시",
                "",
                markdown_code(request_packet_example(definition)),
                "",
                "### 필수 헤더",
                render_field_names(definition.required_fields),
                "### 대표 선택/조건부 헤더",
                render_field_names(
                    tuple(
                        name
                        for name in REQUEST_EXAMPLE_FIELDS.get(
                            SIPMethod(definition.method), []
                        )
                        if name not in definition.required_fields and name != "body"
                    )
                ),
            ]
        )
        if definition.forbidden_fields:
            lines.extend(
                ["### 금지 헤더", render_field_names(definition.forbidden_fields)]
            )
        if definition.conditional_required_fields:
            lines.append("### 조건부 규칙")
            for rule in definition.conditional_required_fields:
                lines.append(
                    f"- `{wire_field_name(rule.field_name)}`: {rule.condition}"
                    + (f" — {rule.note}" if rule.note else "")
                )
            lines.append("")

    lines.append(render_reference_section())
    return "\n".join(lines).rstrip() + "\n"


def render_response_docs() -> str:
    lines = [
        "# SIP 응답 패킷 예시",
        "",
        "> 이 문서는 `scripts/generate_packet_docs.py` 로 생성된다.",
        "> 이 문서는 각 SIP 응답을 **실제 SIP 텍스트 패킷 형태**로 이해하기 위한 설명 문서이다.",
        "> 예시 패킷은 대표 예시이며, 응답 코드별 핵심 헤더만 우선 보여준다.",
        "",
        "## 공통 응답 골격",
        "",
        markdown_code(
            "SIP/2.0 200 OK\n"
            "Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bK-generic\n"
            'From: "UE" <sip:ue@example.com>;tag=ue-tag\n'
            'To: "Network" <sip:network@ims.example.com>;tag=net-tag\n'
            "Call-ID: generic-response@example.com\n"
            "CSeq: 1 INVITE\n"
            "Content-Length: 0\n"
        ),
        "",
        "공통 필수 헤더:",
        render_field_names(("via", "from", "to", "call_id", "cseq")),
    ]

    for definition in SIP_CATALOG.response_definitions:
        lines.extend(
            [
                f"## {definition.status_code} {definition.reason_phrase}",
                "",
                f"- 설명: {definition.description}",
                f"- 대표 상황: {definition.typical_scenario}",
                f"- 관련 메서드: {', '.join(definition.related_methods) if definition.related_methods else 'generic'}",
                f"- RFC: {', '.join(definition.reference_rfcs)}",
                "",
                "### 대표 SIP 패킷 예시",
                "",
                markdown_code(response_packet_example(definition)),
                "",
                "### 필수 헤더",
                render_field_names(definition.required_fields),
                "### 대표 선택/조건부 헤더",
                render_field_names(
                    tuple(
                        name
                        for name in RESPONSE_EXTRA_FIELDS.get(
                            definition.status_code, []
                        )
                        if name not in definition.required_fields and name != "body"
                    )
                ),
            ]
        )
        if definition.conditional_required_fields:
            lines.append("### 조건부 규칙")
            for rule in definition.conditional_required_fields:
                lines.append(
                    f"- `{wire_field_name(rule.field_name)}`: {rule.condition}"
                    + (f" — {rule.note}" if rule.note else "")
                )
            lines.append("")

    lines.append(render_reference_section())
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    PROTOCOL_DOCS_DIR.mkdir(parents=True, exist_ok=True)
    REQUEST_DOC_PATH.write_text(render_request_docs(), encoding="utf-8")
    RESPONSE_DOC_PATH.write_text(render_response_docs(), encoding="utf-8")
    print(
        "Generated protocol packet docs:",
        REQUEST_DOC_PATH.relative_to(ROOT),
        RESPONSE_DOC_PATH.relative_to(ROOT),
    )


if __name__ == "__main__":
    main()
