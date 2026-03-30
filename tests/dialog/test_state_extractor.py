from volte_mutation_fuzzer.dialog.state_extractor import extract_dialog_state
from volte_mutation_fuzzer.generator.contracts import DialogContext
from volte_mutation_fuzzer.sender.contracts import SocketObservation


def _make_observation(headers: dict[str, str]) -> SocketObservation:
    return SocketObservation(
        status_code=200,
        reason_phrase="OK",
        headers={k.casefold(): v for k, v in headers.items()},
        body="",
        raw_text="",
        raw_size=0,
        classification="success",
    )


class TestExtractToTag:
    def test_extracts_to_tag(self) -> None:
        obs = _make_observation({"To": "<sip:ue@example.com>;tag=abc123"})
        ctx = DialogContext(call_id="c1", remote_tag="uac-tag")
        result = extract_dialog_state(obs, ctx)
        assert result.local_tag == "abc123"

    def test_to_tag_with_display_name(self) -> None:
        obs = _make_observation({"To": '"UE" <sip:ue@example.com>;tag=xyz789'})
        ctx = DialogContext(call_id="c1", remote_tag="uac-tag")
        extract_dialog_state(obs, ctx)
        assert ctx.local_tag == "xyz789"

    def test_missing_to_tag_leaves_none(self) -> None:
        obs = _make_observation({"To": "<sip:ue@example.com>"})
        ctx = DialogContext(call_id="c1", remote_tag="uac-tag")
        extract_dialog_state(obs, ctx)
        assert ctx.local_tag is None

    def test_no_to_header_leaves_none(self) -> None:
        obs = _make_observation({})
        ctx = DialogContext(call_id="c1", remote_tag="uac-tag")
        extract_dialog_state(obs, ctx)
        assert ctx.local_tag is None


class TestExtractContactUri:
    def test_extracts_contact_uri(self) -> None:
        obs = _make_observation({"Contact": "<sip:ue@10.0.0.1:5060>"})
        ctx = DialogContext(call_id="c1", remote_tag="t")
        extract_dialog_state(obs, ctx)
        assert ctx.request_uri is not None
        assert ctx.request_uri.host == "10.0.0.1"

    def test_contact_port_extracted(self) -> None:
        obs = _make_observation({"Contact": "<sip:ue@10.0.0.1:5070>"})
        ctx = DialogContext(call_id="c1", remote_tag="t")
        extract_dialog_state(obs, ctx)
        from volte_mutation_fuzzer.sip.common import SIPURI

        assert isinstance(ctx.request_uri, SIPURI)
        assert ctx.request_uri.port == 5070

    def test_missing_contact_leaves_none(self) -> None:
        obs = _make_observation({"To": "<sip:ue@example.com>;tag=t1"})
        ctx = DialogContext(call_id="c1", remote_tag="t")
        extract_dialog_state(obs, ctx)
        assert ctx.request_uri is None

    def test_star_contact_leaves_none(self) -> None:
        obs = _make_observation({"Contact": "*"})
        ctx = DialogContext(call_id="c1", remote_tag="t")
        extract_dialog_state(obs, ctx)
        assert ctx.request_uri is None


class TestExtractRecordRoute:
    def test_single_record_route(self) -> None:
        obs = _make_observation({"Record-Route": "<sip:proxy1@example.com;lr>"})
        ctx = DialogContext(call_id="c1", remote_tag="t")
        extract_dialog_state(obs, ctx)
        assert len(ctx.route_set) == 1

    def test_multiple_record_routes_reversed(self) -> None:
        # Record-Route is ordered from first proxy to last (UAC→UAS direction)
        # Route set must be reversed for UAC use (RFC 3261 §12.1.2)
        obs = _make_observation(
            {"Record-Route": "<sip:p1@example.com;lr>,<sip:p2@example.com;lr>"}
        )
        ctx = DialogContext(call_id="c1", remote_tag="t")
        extract_dialog_state(obs, ctx)
        from volte_mutation_fuzzer.sip.common import SIPURI

        assert len(ctx.route_set) == 2
        assert isinstance(ctx.route_set[0], SIPURI)
        # p2 should be first after reversal
        assert (
            ctx.route_set[0].host == "p2@example.com" or ctx.route_set[0].user == "p2"
        )

    def test_no_record_route_leaves_empty(self) -> None:
        obs = _make_observation({"To": "<sip:ue@example.com>;tag=t1"})
        ctx = DialogContext(call_id="c1", remote_tag="t")
        extract_dialog_state(obs, ctx)
        assert ctx.route_set == ()


class TestExtractDialogStateReturnsContext:
    def test_returns_same_context_object(self) -> None:
        obs = _make_observation({"To": "<sip:ue@example.com>;tag=abc"})
        ctx = DialogContext(call_id="c1", remote_tag="t")
        returned = extract_dialog_state(obs, ctx)
        assert returned is ctx
