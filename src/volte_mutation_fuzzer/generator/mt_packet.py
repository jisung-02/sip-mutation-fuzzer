"""3GPP standard MT packet builder for all SIP methods.

Generates 3GPP-compliant SIP packets that real UEs (e.g. Samsung A31) accept.
Common 3GPP headers are shared across all methods; only the body differs per method.

Usage::

    wire_text = build_mt_packet(
        method="MESSAGE",
        msisdn="222222",
        impi="001010000123511",
        ue_ip="10.20.20.2",
        port_pc=9800,
        port_ps=9801,
        seed=0,
        body="Hello from fuzzer",
    )
"""

from __future__ import annotations

import os
import random
from typing import Final

from volte_mutation_fuzzer.sip.bodies import (
    DtmfRelayBody,
    PIdfBody,
    PIdfTuple,
    SDPBody,
    SDPConnection,
    SDPMediaDescription,
    SDPOrigin,
    SipfragBody,
    SmsBody,
)
from volte_mutation_fuzzer.sip.body_factory import DEFAULT_INFO_PACKAGE

_CRLF: Final[str] = "\r\n"

# INVITE-specific SDP template (AMR-WB with preconditions)
_INVITE_SDP_TEMPLATE: Final[str] = (
    "v=0\r\n"
    "o=rue {seed} {seed} IN IP4 {sdp_owner_ip}\r\n"
    "s=-\r\n"
    "b=AS:41\r\n"
    "b=RR:1537\r\n"
    "b=RS:512\r\n"
    "t=0 0\r\n"
    "m=audio {sdp_audio_port} RTP/AVP 107 106 105 104 101 102\r\n"
    "c=IN IP4 {sdp_owner_ip}\r\n"
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
    "a=rtcp:{sdp_rtcp_port}\r\n"
    "a=ptime:20\r\n"
    "a=maxptime:240\r\n"
)

_SMS_TEXT_ALPHABET: Final[str] = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789 ."
)
_SMS_DEFAULT_SMSC: Final[str] = "821000000000"
_SMS_DEFAULT_SCTS_HEX: Final[str] = "62403151423300"


def _encode_tbcd(digits: str) -> str:
    """Encode decimal digits as TBCD (nibble-swapped, F-padded to even length)."""
    padded = digits + ("F" if len(digits) % 2 else "")
    return "".join(padded[i + 1] + padded[i] for i in range(0, len(padded), 2))


def _build_default_sms_body(seed: int, from_msisdn: str) -> str:
    """Build deterministic RP-DATA + SMS-DELIVER TPDU as uppercase hex.

    Follows 3GPP TS 24.011 (RP-DATA, network → MS) wrapping TS 23.040
    SMS-DELIVER with 8-bit DCS so the payload stays ASCII-only on the wire.
    """
    rng = random.Random(seed ^ 0x534D53)
    token_length = rng.randint(16, 40)
    text = f"VMF seed={seed} " + "".join(
        rng.choice(_SMS_TEXT_ALPHABET) for _ in range(token_length)
    )
    ud_bytes = text.encode("ascii")

    tp_oa = f"{len(from_msisdn):02X}91{_encode_tbcd(from_msisdn)}"
    tpdu_hex = (
        "04"                   # first octet: MTI=DELIVER, MMS=1
        + tp_oa                # TP-Originating-Address
        + "00"                 # TP-PID
        + "04"                 # TP-DCS: 8-bit data
        + _SMS_DEFAULT_SCTS_HEX
        + f"{len(ud_bytes):02X}"
        + ud_bytes.hex()
    )
    tpdu_len = len(bytes.fromhex(tpdu_hex))

    rp_oa_body = f"91{_encode_tbcd(_SMS_DEFAULT_SMSC)}"
    rp_oa_len = len(bytes.fromhex(rp_oa_body))

    rp_data = (
        "00"                                  # RP-MTI = RP-DATA (n→ms)
        + f"{seed & 0xFF:02X}"                # RP-Message-Reference
        + f"{rp_oa_len:02X}{rp_oa_body}"      # RP-Originator-Address (SMSC)
        + "00"                                # RP-Destination-Address (empty)
        + f"{tpdu_len:02X}{tpdu_hex}"         # RP-User-Data (TPDU)
    )
    return rp_data.upper()


def _normalize_optional_token(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _build_pidf_body(
    *,
    impi: str,
    ims_domain: str,
    ue_ip: str,
    port_pc: int,
    seed: int,
) -> str:
    pidf = PIdfBody.default_instance(
        entity=f"sip:{impi}@{ims_domain}",
        tuples=(
            PIdfTuple(
                id=f"vmf-{seed:08x}",
                contact_uri=f"sip:{impi}@{ue_ip}:{port_pc}",
            ),
        ),
    )
    return pidf.render()


def _build_update_sdp_body(
    *,
    seed: int,
    sdp_owner_ip: str,
    sdp_audio_port: int,
) -> str:
    sdp = SDPBody.default_instance(
        origin=SDPOrigin(
            username="rue",
            sess_id=seed,
            sess_version=seed,
            address=sdp_owner_ip,
        ),
        connection=SDPConnection(address=sdp_owner_ip),
        media_descriptions=(
            SDPMediaDescription(
                port=sdp_audio_port,
                formats=(107, 106, 105, 104, 101, 102),
                attributes=(
                    "rtpmap:107 AMR-WB/16000",
                    "fmtp:107 mode-change-capability=2;max-red=0",
                    "rtpmap:106 AMR-WB/16000",
                    "fmtp:106 octet-align=1;mode-change-capability=2;max-red=0",
                    "rtpmap:105 AMR/8000",
                    "fmtp:105 mode-change-capability=2;max-red=0",
                    "rtpmap:104 AMR/8000",
                    "fmtp:104 octet-align=1;mode-change-capability=2;max-red=0",
                    "rtpmap:101 telephone-event/16000",
                    "fmtp:101 0-15",
                    "rtpmap:102 telephone-event/8000",
                    "fmtp:102 0-15",
                    "sendrecv",
                ),
            ),
        ),
    )
    return sdp.render()


def _build_body(
    method: str,
    *,
    seed: int,
    body: str | None,
    sdp_owner_ip: str,
    sdp_audio_port: int,
    impi: str,
    ims_domain: str,
    ue_ip: str,
    port_pc: int,
    from_msisdn: str,
    event_package: str | None,
    info_package: str | None,
) -> tuple[str, str]:
    """Return (content_type, body_text) for the given method."""
    method = method.upper()

    if body is not None:
        # User-specified body
        return "text/plain", body

    if method == "INVITE":
        sdp = _INVITE_SDP_TEMPLATE.format(
            seed=seed,
            sdp_owner_ip=sdp_owner_ip,
            sdp_audio_port=sdp_audio_port,
            sdp_rtcp_port=sdp_audio_port + 1,
        )
        return "application/sdp", sdp

    if method == "MESSAGE":
        sms = SmsBody(payload=_build_default_sms_body(seed, from_msisdn))
        return sms.content_type, sms.render()

    if method == "INFO" and info_package == "dtmf":
        body_model = DtmfRelayBody.default_instance(signal=str(seed % 10))
        return body_model.content_type, body_model.render()

    if method == "PUBLISH":
        return "application/pidf+xml", _build_pidf_body(
            impi=impi,
            ims_domain=ims_domain,
            ue_ip=ue_ip,
            port_pc=port_pc,
            seed=seed,
        )

    if method == "NOTIFY":
        if event_package == "refer":
            body_model = SipfragBody.default_instance()
            return body_model.content_type, body_model.render()
        if event_package == "presence":
            return "application/pidf+xml", _build_pidf_body(
                impi=impi,
                ims_domain=ims_domain,
                ue_ip=ue_ip,
                port_pc=port_pc,
                seed=seed,
            )

    if method == "UPDATE":
        return "application/sdp", _build_update_sdp_body(
            seed=seed,
            sdp_owner_ip=sdp_owner_ip,
            sdp_audio_port=sdp_audio_port,
        )

    # OPTIONS, BYE, CANCEL, etc. — no body
    return "", ""


def build_mt_packet(
    *,
    method: str,
    impi: str,
    msisdn: str,
    ue_ip: str,
    port_pc: int,
    port_ps: int,
    seed: int = 0,
    local_port: int = 15100,
    body: str | None = None,
    from_msisdn: str | None = None,
    event_package: str | None = None,
    info_package: str | None = None,
    env: dict[str, str] | None = None,
) -> str:
    """Build a 3GPP-compliant MT SIP packet for any method.

    Returns a CRLF-terminated wire-text string ready to send.
    """
    source = env if env is not None else dict(os.environ)
    method = method.upper()

    # Network environment
    ims_domain = source.get("VMF_IMS_DOMAIN", "ims.mnc001.mcc001.3gppnetwork.org")
    pcscf_ip = source.get("VMF_REAL_UE_PCSCF_IP", "172.22.0.21")
    scscf_ip = source.get("VMF_SCSCF_IP", "172.22.0.20")
    scscf_port = source.get("VMF_SCSCF_PORT", "6060")
    pcscf_mt_port = source.get("VMF_PCSCF_MT_PORT", "6101")
    cell_id = source.get("VMF_CELL_ID", "0010100010019B01")
    mo_imei = source.get("VMF_MO_IMEI", "86838903-875492-0")
    sdp_owner_ip = source.get("VMF_SDP_OWNER_IP", "172.22.0.16")
    sdp_audio_port = int(source.get("VMF_SDP_AUDIO_PORT", "49196"))

    # MO identity
    effective_from = from_msisdn or source.get("VMF_FROM_MSISDN", "222222")
    mo_contact_host = source.get("VMF_MO_CONTACT_HOST", "10.20.20.9")
    mo_contact_port_pc = source.get("VMF_MO_CONTACT_PORT_PC", "31800")
    mo_contact_port_ps = source.get("VMF_MO_CONTACT_PORT_PS", "31100")
    resolved_event_package = _normalize_optional_token(event_package)
    resolved_info_package = _normalize_optional_token(info_package)
    if method in ("SUBSCRIBE", "PUBLISH", "NOTIFY") and resolved_event_package is None:
        resolved_event_package = "presence"
    if method == "INFO" and resolved_info_package is None:
        resolved_info_package = DEFAULT_INFO_PACKAGE

    # Per-call deterministic identifiers
    rng = random.Random(seed)
    from_tag = f"vmf{rng.getrandbits(32):08x}"
    call_id = f"{rng.getrandbits(64):016x}@{mo_contact_host}"
    branch = f"z9hG4bKvmf{rng.getrandbits(32):08x}"
    icid = f"{rng.getrandbits(128):032X}"

    # Body
    content_type, body_text = _build_body(
        method,
        seed=seed,
        body=body,
        sdp_owner_ip=sdp_owner_ip,
        sdp_audio_port=sdp_audio_port,
        impi=impi,
        ims_domain=ims_domain,
        ue_ip=ue_ip,
        port_pc=port_pc,
        from_msisdn=effective_from,
        event_package=resolved_event_package,
        info_package=resolved_info_package,
    )
    body_bytes = body_text.encode("utf-8") if body_text else b""
    content_length = len(body_bytes)

    # --- Build headers ---
    lines: list[str] = []

    # Request line
    lines.append(
        f"{method} sip:{impi}@{ue_ip}:{port_pc}"
        f";alias={ue_ip}~{port_ps}~1 SIP/2.0"
    )

    # Via
    lines.append(f"Via: SIP/2.0/UDP {pcscf_ip}:{local_port};branch={branch}")

    # Max-Forwards
    lines.append("Max-Forwards: 66")

    # Record-Route (INVITE/SUBSCRIBE need dialog routing)
    if method in ("INVITE", "SUBSCRIBE", "REFER", "NOTIFY", "UPDATE"):
        lines.append(
            f"Record-Route: <sip:mo@{pcscf_ip}:{pcscf_mt_port}"
            f";lr=on;ftag={from_tag};rm=8;did=643.7a11>"
        )
        lines.append(
            f"Record-Route: <sip:mo@{scscf_ip}:{scscf_port}"
            f";transport=tcp;r2=on;lr=on;ftag={from_tag};did=643.3382>"
        )
        lines.append(
            f"Record-Route: <sip:mo@{scscf_ip}:{scscf_port}"
            f";r2=on;lr=on;ftag={from_tag};did=643.3382>"
        )

    # From / To
    lines.append(f"From: <sip:{effective_from}@{ims_domain}>;tag={from_tag}")
    lines.append(f'To: "{msisdn}"<tel:{msisdn};phone-context={ims_domain}>')

    # Call-ID / CSeq
    lines.append(f"Call-ID: {call_id}")
    lines.append(f"CSeq: 1 {method}")

    # Contact
    lines.append(
        f"Contact: <sip:{effective_from}@{mo_contact_host}:{mo_contact_port_pc}"
        f";alias={mo_contact_host}~{mo_contact_port_ps}~1>"
        f';+sip.instance="<urn:gsma:imei:{mo_imei}>"'
        f';+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"'
    )

    # 3GPP headers
    lines.append(f"P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp={cell_id}")
    lines.append("P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel")
    lines.append(f"P-Asserted-Identity: <sip:{effective_from}@{ims_domain}>")
    lines.append(f"P-Charging-Vector: icid-value={icid};icid-generated-at={pcscf_ip}")
    lines.append(f"P-Visited-Network-ID: {ims_domain}")

    # Method-specific headers
    if method == "INVITE":
        lines.append("P-Early-Media: supported")
        lines.append("Supported: 100rel,histinfo,join,norefersub,precondition,replaces,timer,sec-agree")
        lines.append("Allow: INVITE,ACK,OPTIONS,BYE,CANCEL,UPDATE,INFO,PRACK,NOTIFY,MESSAGE,REFER")
        lines.append("Accept: application/sdp,application/3gpp-ims+xml")
        lines.append("Session-Expires: 1800")
        lines.append("Min-SE: 90")
    elif method == "OPTIONS":
        lines.append("Accept: application/sdp")
    elif method == "SUBSCRIBE":
        if resolved_event_package is not None:
            lines.append(f"Event: {resolved_event_package}")
        lines.append("Expires: 3600")
    elif method == "INFO":
        if resolved_info_package is not None:
            lines.append(f"Info-Package: {resolved_info_package}")
    elif method == "PUBLISH":
        if resolved_event_package is not None:
            lines.append(f"Event: {resolved_event_package}")
        lines.append("Expires: 3600")
    elif method == "NOTIFY":
        if resolved_event_package is not None:
            lines.append(f"Event: {resolved_event_package}")
        lines.append("Subscription-State: active;expires=3600")
    elif method == "UPDATE":
        lines.append("Session-Expires: 1800")
        lines.append("Min-SE: 90")

    lines.append("User-Agent: IM-client/OMA1.0 HW-Rto/V1.0")

    # Content headers
    if content_type:
        lines.append(f"Content-Type: {content_type}")
    lines.append(f"Content-Length: {content_length}")

    # Assemble
    header_part = _CRLF.join(lines)
    if body_text:
        return header_part + _CRLF + _CRLF + body_text
    return header_part + _CRLF + _CRLF
