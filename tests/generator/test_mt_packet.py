from volte_mutation_fuzzer.generator.mt_packet import build_mt_packet
from volte_mutation_fuzzer.sip.body_factory import DEFAULT_INFO_PACKAGE


def _split_packet(packet: str) -> tuple[str, str]:
    header_part, separator, body_part = packet.partition("\r\n\r\n")
    assert separator == "\r\n\r\n"
    return header_part, body_part


def test_build_mt_packet_message_body_is_seeded_and_deterministic() -> None:
    packet_a = build_mt_packet(
        method="MESSAGE",
        impi="001010000123511",
        msisdn="111111",
        ue_ip="10.20.20.8",
        port_pc=31800,
        port_ps=31100,
        seed=7,
        env={},
    )
    packet_b = build_mt_packet(
        method="MESSAGE",
        impi="001010000123511",
        msisdn="111111",
        ue_ip="10.20.20.8",
        port_pc=31800,
        port_ps=31100,
        seed=7,
        env={},
    )
    packet_c = build_mt_packet(
        method="MESSAGE",
        impi="001010000123511",
        msisdn="111111",
        ue_ip="10.20.20.8",
        port_pc=31800,
        port_ps=31100,
        seed=8,
        env={},
    )

    assert packet_a == packet_b
    assert packet_a != packet_c

    headers, body = _split_packet(packet_a)
    assert "Content-Type: application/vnd.3gpp.sms" in headers
    assert body
    assert all(ch in "0123456789ABCDEF" for ch in body)
    decoded = bytes.fromhex(body)
    assert b"VMF seed=7" in decoded
    assert f"Content-Length: {len(body.encode('utf-8'))}" in headers


def test_build_mt_packet_message_respects_explicit_body_override() -> None:
    packet = build_mt_packet(
        method="MESSAGE",
        impi="001010000123511",
        msisdn="111111",
        ue_ip="10.20.20.8",
        port_pc=31800,
        port_ps=31100,
        seed=99,
        body="custom body from test",
        env={},
    )

    headers, body = _split_packet(packet)
    assert "Content-Type: text/plain" in headers
    assert body == "custom body from test"
    assert "seed=99" not in body
    assert f"Content-Length: {len(body.encode('utf-8'))}" in headers


def test_build_mt_packet_subscribe_has_presence_headers_and_empty_body() -> None:
    packet = build_mt_packet(
        method="SUBSCRIBE",
        impi="001010000123511",
        msisdn="111111",
        ue_ip="10.20.20.8",
        port_pc=31800,
        port_ps=31100,
        seed=3,
        env={},
    )

    headers, body = _split_packet(packet)
    assert "SUBSCRIBE sip:" in headers
    assert "Event: presence" in headers
    assert "Expires: 3600" in headers
    assert "Record-Route:" in headers
    assert "Content-Length: 0" in headers
    assert body == ""


def test_build_mt_packet_options_has_no_default_body() -> None:
    packet = build_mt_packet(
        method="OPTIONS",
        impi="001010000123511",
        msisdn="111111",
        ue_ip="10.20.20.8",
        port_pc=31800,
        port_ps=31100,
        seed=5,
        env={},
    )

    headers, body = _split_packet(packet)
    assert "OPTIONS sip:" in headers
    assert "Accept: application/sdp" in headers
    assert "Content-Length: 0" in headers
    assert body == ""


def test_build_mt_packet_info_has_default_dtmf_body_and_header() -> None:
    packet = build_mt_packet(
        method="INFO",
        impi="001010000123511",
        msisdn="111111",
        ue_ip="10.20.20.8",
        port_pc=31800,
        port_ps=31100,
        seed=4,
        env={},
    )

    headers, body = _split_packet(packet)
    assert "INFO sip:" in headers
    assert f"Info-Package: {DEFAULT_INFO_PACKAGE}" in headers
    assert "Content-Type: application/dtmf-relay" in headers
    assert "Signal=4" in body
    assert "Duration=160" in body


def test_build_mt_packet_publish_has_presence_event_and_pidf_body() -> None:
    packet = build_mt_packet(
        method="PUBLISH",
        impi="001010000123511",
        msisdn="111111",
        ue_ip="10.20.20.8",
        port_pc=31800,
        port_ps=31100,
        seed=11,
        env={},
    )

    headers, body = _split_packet(packet)
    assert "PUBLISH sip:" in headers
    assert "Event: presence" in headers
    assert "Expires: 3600" in headers
    assert "Content-Type: application/pidf+xml" in headers
    assert '<presence xmlns="urn:ietf:params:xml:ns:pidf"' in body
    assert 'entity="sip:001010000123511@ims.mnc001.mcc001.3gppnetwork.org"' in body


def test_build_mt_packet_notify_defaults_to_presence_with_subscription_state() -> None:
    packet = build_mt_packet(
        method="NOTIFY",
        impi="001010000123511",
        msisdn="111111",
        ue_ip="10.20.20.8",
        port_pc=31800,
        port_ps=31100,
        seed=12,
        env={},
    )

    headers, body = _split_packet(packet)
    assert "NOTIFY sip:" in headers
    assert "Event: presence" in headers
    assert "Subscription-State: active;expires=3600" in headers
    assert "Content-Type: application/pidf+xml" in headers
    assert "<presence " in body


def test_build_mt_packet_notify_supports_refer_event_sipfrag_body() -> None:
    packet = build_mt_packet(
        method="NOTIFY",
        impi="001010000123511",
        msisdn="111111",
        ue_ip="10.20.20.8",
        port_pc=31800,
        port_ps=31100,
        seed=13,
        event_package="refer",
        env={},
    )

    headers, body = _split_packet(packet)
    assert "Event: refer" in headers
    assert "Content-Type: message/sipfrag;version=2.0" in headers
    assert body == "SIP/2.0 200 OK"


def test_build_mt_packet_update_has_sdp_body_and_session_timer_headers() -> None:
    packet = build_mt_packet(
        method="UPDATE",
        impi="001010000123511",
        msisdn="111111",
        ue_ip="10.20.20.8",
        port_pc=31800,
        port_ps=31100,
        seed=21,
        env={},
    )

    headers, body = _split_packet(packet)
    assert "UPDATE sip:" in headers
    assert "Session-Expires: 1800" in headers
    assert "Min-SE: 90" in headers
    assert "Content-Type: application/sdp" in headers
    assert "o=rue 21 21 IN IP4" in body
    assert "m=audio" in body
