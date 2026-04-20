from volte_mutation_fuzzer.dialog.state_extractor import (
    extract_dialog_state,
    extract_dialog_state_from_responses,
)
from volte_mutation_fuzzer.generator.contracts import DialogContext
from volte_mutation_fuzzer.sender.contracts import SocketObservation
from volte_mutation_fuzzer.sip.common import SIPURI

IMS_DOMAIN = "ims.mnc001.mcc001.3gppnetwork.org"
UE_URI = f"sip:111111@{IMS_DOMAIN}"
ROUTE_1 = f"sip:pcscf1.{IMS_DOMAIN};lr"
ROUTE_2 = f"sip:pcscf2.{IMS_DOMAIN};lr"


def _make_observation(
    headers: dict[str, str],
    *,
    status_code: int = 200,
    reason_phrase: str = "OK",
    classification: str = "success",
) -> SocketObservation:
    return SocketObservation(
        status_code=status_code,
        reason_phrase=reason_phrase,
        headers={k.casefold(): v for k, v in headers.items()},
        body="",
        raw_text="",
        raw_size=0,
        classification=classification,
    )


class TestExtractToTag:
    def test_extracts_to_tag(self) -> None:
        obs = _make_observation({"To": f"<{UE_URI}>;tag=abc123"})
        ctx = DialogContext(call_id="c1", remote_tag="uac-tag")
        result = extract_dialog_state(obs, ctx)
        assert result.local_tag == "abc123"

    def test_to_tag_with_display_name(self) -> None:
        obs = _make_observation({"To": f'"UE" <{UE_URI}>;tag=xyz789'})
        ctx = DialogContext(call_id="c1", remote_tag="uac-tag")
        extract_dialog_state(obs, ctx)
        assert ctx.local_tag == "xyz789"

    def test_missing_to_tag_leaves_none(self) -> None:
        obs = _make_observation({"To": f"<{UE_URI}>"})
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
        assert isinstance(ctx.request_uri, SIPURI)
        assert ctx.request_uri.host == "10.0.0.1"

    def test_contact_port_extracted(self) -> None:
        obs = _make_observation({"Contact": "<sip:ue@10.0.0.1:5070>"})
        ctx = DialogContext(call_id="c1", remote_tag="t")
        extract_dialog_state(obs, ctx)
        assert isinstance(ctx.request_uri, SIPURI)
        assert ctx.request_uri.port == 5070

    def test_missing_contact_leaves_none(self) -> None:
        obs = _make_observation({"To": f"<{UE_URI}>;tag=t1"})
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
        obs = _make_observation({"Record-Route": f"<{ROUTE_1}>"})
        ctx = DialogContext(call_id="c1", remote_tag="t")
        extract_dialog_state(obs, ctx)
        assert len(ctx.route_set) == 1

    def test_multiple_record_routes_reversed(self) -> None:
        # Record-Route is ordered from first proxy to last (UAC→UAS direction)
        # Route set must be reversed for UAC use (RFC 3261 §12.1.2)
        obs = _make_observation(
            {"Record-Route": f"<{ROUTE_1}>,<{ROUTE_2}>"}
        )
        ctx = DialogContext(call_id="c1", remote_tag="t")
        extract_dialog_state(obs, ctx)
        assert len(ctx.route_set) == 2
        assert isinstance(ctx.route_set[0], SIPURI)
        assert ctx.route_set[0].host == f"pcscf2.{IMS_DOMAIN}"

    def test_no_record_route_leaves_empty(self) -> None:
        obs = _make_observation({"To": f"<{UE_URI}>;tag=t1"})
        ctx = DialogContext(call_id="c1", remote_tag="t")
        extract_dialog_state(obs, ctx)
        assert ctx.route_set == ()


class TestExtractDialogStateReturnsContext:
    def test_returns_same_context_object(self) -> None:
        obs = _make_observation({"To": f"<{UE_URI}>;tag=abc"})
        ctx = DialogContext(call_id="c1", remote_tag="t")
        returned = extract_dialog_state(obs, ctx)
        assert returned is ctx


class TestExtractEarlyDialogFromProvisionalInviteResponse:
    def test_extracts_183_dialog_state(self) -> None:
        obs = _make_observation(
            {
                "To": f"<{UE_URI}>;tag=early-tag-183",
                "Contact": "<sip:ue@10.0.0.9:5088;transport=udp>",
                "Record-Route": f"<{ROUTE_1}>,<{ROUTE_2}>",
            },
            status_code=183,
            reason_phrase="Session Progress",
            classification="provisional",
        )
        ctx = DialogContext(call_id="c1", remote_tag="uac-tag")

        extract_dialog_state(obs, ctx)

        assert ctx.local_tag == "early-tag-183"
        assert isinstance(ctx.request_uri, SIPURI)
        assert ctx.request_uri.host == "10.0.0.9"
        assert ctx.request_uri.port == 5088
        assert ctx.request_uri.parameters == {"transport": "udp"}
        assert len(ctx.route_set) == 2
        assert isinstance(ctx.route_set[0], SIPURI)
        assert ctx.route_set[0].host == f"pcscf2.{IMS_DOMAIN}"
        assert ctx.route_set[0].parameters == {"lr": None}

    def test_preserves_richer_183_state_when_later_180_is_poorer(self) -> None:
        responses = (
            _make_observation(
                {},
                status_code=100,
                reason_phrase="Trying",
                classification="provisional",
            ),
            _make_observation(
                {
                    "To": f"<{UE_URI}>;tag=early-tag-183",
                    "Contact": "<sip:ue@10.0.0.9:5088;transport=udp>",
                    "Record-Route": f"<{ROUTE_1}>,<{ROUTE_2}>",
                },
                status_code=183,
                reason_phrase="Session Progress",
                classification="provisional",
            ),
            _make_observation(
                {"To": f"<{UE_URI}>;tag=early-tag-183"},
                status_code=180,
                reason_phrase="Ringing",
                classification="provisional",
            ),
        )
        ctx = DialogContext(call_id="c1", remote_tag="uac-tag")

        extract_dialog_state_from_responses(responses, ctx)

        assert ctx.local_tag == "early-tag-183"
        assert isinstance(ctx.request_uri, SIPURI)
        assert ctx.request_uri.host == "10.0.0.9"
        assert ctx.request_uri.port == 5088
        assert ctx.request_uri.parameters == {"transport": "udp"}
        assert len(ctx.route_set) == 2
        assert isinstance(ctx.route_set[0], SIPURI)
        assert ctx.route_set[0].host == f"pcscf2.{IMS_DOMAIN}"
        assert ctx.route_set[0].parameters == {"lr": None}

    def test_extracts_reliable_provisional_rseq_and_invite_cseq(self) -> None:
        responses = (
            _make_observation(
                {
                    "To": f"<{UE_URI}>;tag=rel-183",
                    "Contact": "<sip:ue@10.0.0.9:5088;transport=udp>",
                    "Record-Route": f"<{ROUTE_1}>,<{ROUTE_2}>",
                    "Require": "100rel",
                    "RSeq": "73",
                    "CSeq": "41 INVITE",
                },
                status_code=183,
                reason_phrase="Session Progress",
                classification="provisional",
            ),
        )
        ctx = DialogContext(call_id="c1", remote_tag="uac-tag")

        extract_dialog_state_from_responses(responses, ctx)

        assert ctx.reliable_invite_rseq == 73
        assert ctx.reliable_invite_cseq == 41
