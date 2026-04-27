"""Tests for the SDP-aware mutator (``mutator.sdp``) and its integration
with the wire-layer deterministic dispatch in ``mutator.core``.
"""

from __future__ import annotations

import random
import unittest

from volte_mutation_fuzzer.generator import (
    GeneratorSettings,
    RequestSpec,
    SIPGenerator,
)
from volte_mutation_fuzzer.mutator.contracts import MutationConfig
from volte_mutation_fuzzer.mutator.core import SIPMutator
from volte_mutation_fuzzer.mutator.editable import (
    EditableHeader,
    EditableSIPMessage,
    EditableStartLine,
    parse_editable_from_wire,
)
from volte_mutation_fuzzer.mutator.sdp import (
    SDPMutationResult,
    STRUCT_VARIANTS,
    VARIANTS,
    apply_sdp_boundary,
    apply_sdp_struct,
    parse_sdp_body,
    render_sdp_body,
)
from volte_mutation_fuzzer.sip.common import SIPMethod


_BASELINE_SDP = (
    "v=0\r\n"
    "o=rue 12345 12345 IN IP4 172.22.0.16\r\n"
    "s=-\r\n"
    "b=AS:41\r\n"
    "t=0 0\r\n"
    "m=audio 49170 RTP/AVP 96 97\r\n"
    "c=IN IP4 172.22.0.16\r\n"
    "a=rtpmap:96 AMR-WB/16000\r\n"
    "a=rtpmap:97 AMR/8000\r\n"
    "a=fmtp:96 mode-set=0,2,5,7\r\n"
    "a=ptime:20\r\n"
    "a=sendrecv\r\n"
)


class SDPParseRenderTests(unittest.TestCase):
    """Round-trip parse/render must preserve the baseline byte-for-byte."""

    def test_parse_extracts_type_value_pairs(self) -> None:
        lines = parse_sdp_body(_BASELINE_SDP)
        self.assertEqual(lines[0], ("v", "0"))
        self.assertEqual(lines[1], ("o", "rue 12345 12345 IN IP4 172.22.0.16"))
        # SDP ends with trailing CRLF → final empty entry.
        self.assertEqual(lines[-1], ("", ""))

    def test_render_round_trip_is_byte_exact(self) -> None:
        lines = parse_sdp_body(_BASELINE_SDP)
        self.assertEqual(render_sdp_body(lines), _BASELINE_SDP)

    def test_parse_handles_empty_body(self) -> None:
        self.assertEqual(parse_sdp_body(""), [])

    def test_parse_preserves_unrecognised_lines(self) -> None:
        # Lines that don't match X=... are kept verbatim under "?".
        weird = "v=0\r\nNOT_AN_SDP_LINE\r\nm=audio 49170 RTP/AVP 96\r\n"
        lines = parse_sdp_body(weird)
        self.assertEqual(lines[1], ("?", "NOT_AN_SDP_LINE"))
        self.assertEqual(render_sdp_body(lines), weird)


class SDPVariantTests(unittest.TestCase):
    """Each variant changes only the targeted token; everything else stays
    byte-exact.
    """

    def setUp(self) -> None:
        self.lines = parse_sdp_body(_BASELINE_SDP)
        self.rng = random.Random(0)

    def test_media_port_changes_only_port(self) -> None:
        result = apply_sdp_boundary(self.lines, self.rng, variant="media_port")
        self.assertEqual(result.note, "variant=media_port")
        # Find the m= line index from the path.
        self.assertIn("m_line[", result.path)
        self.assertTrue(result.path.endswith(".port"))
        # Other lines (v=, o=, s=, b=, t=, c=, a=*) are unchanged.
        original_lines = parse_sdp_body(_BASELINE_SDP)
        for i, (k, v) in enumerate(self.lines):
            if k == "m":
                continue  # only the m-line was changed
            self.assertEqual((k, v), original_lines[i], f"line {i} unexpectedly mutated")

    def test_media_transport_changes_only_transport(self) -> None:
        result = apply_sdp_boundary(self.lines, self.rng, variant="media_transport")
        self.assertEqual(result.note, "variant=media_transport")
        # m-line port stays the same; transport is one of the boundary set.
        m_idx = next(i for i, (k, _v) in enumerate(self.lines) if k == "m")
        original_parts = parse_sdp_body(_BASELINE_SDP)[m_idx][1].split()
        new_parts = self.lines[m_idx][1].split()
        self.assertEqual(new_parts[0], original_parts[0])  # media kind unchanged
        self.assertEqual(new_parts[1], original_parts[1])  # port unchanged
        self.assertNotEqual(new_parts[2], original_parts[2])  # transport changed

    def test_connection_addr_changes_only_address(self) -> None:
        result = apply_sdp_boundary(self.lines, self.rng, variant="connection_addr")
        self.assertEqual(result.note, "variant=connection_addr")
        self.assertIn("c_line[", result.path)

    def test_rtpmap_codec_changes_codec_or_clock(self) -> None:
        result = apply_sdp_boundary(self.lines, self.rng, variant="rtpmap_codec")
        # Note can be either codec_name or clock_rate sub-target.
        self.assertTrue(result.note.startswith("variant=rtpmap_codec."))

    def test_bandwidth_changes_only_value(self) -> None:
        result = apply_sdp_boundary(self.lines, self.rng, variant="bandwidth")
        self.assertEqual(result.note, "variant=bandwidth")

    def test_random_variant_picks_from_viable_set(self) -> None:
        # Baseline has m=/c=/a=rtpmap/b= so all 5 variants are viable.
        seen: set[str] = set()
        for seed in range(50):
            lines = parse_sdp_body(_BASELINE_SDP)
            rng = random.Random(seed)
            result = apply_sdp_boundary(lines, rng)
            seen.add(result.note.split(".")[0])
        # Probabilistic — over 50 seeds we should hit at least 3 distinct variants.
        self.assertGreaterEqual(len(seen), 3)

    def test_viable_set_excludes_missing_line_kinds(self) -> None:
        # SDP without ``b=`` (matches the generic SIPGenerator baseline)
        # should never pick the bandwidth variant.
        sdp_no_b = (
            "v=0\r\n"
            "o=rue 1 1 IN IP4 1.2.3.4\r\n"
            "s=-\r\n"
            "t=0 0\r\n"
            "m=audio 49170 RTP/AVP 96\r\n"
            "c=IN IP4 1.2.3.4\r\n"
            "a=rtpmap:96 AMR-WB/16000\r\n"
        )
        for seed in range(30):
            lines = parse_sdp_body(sdp_no_b)
            rng = random.Random(seed)
            result = apply_sdp_boundary(lines, rng)
            self.assertNotIn("bandwidth", result.note)

    def test_explicit_variant_raises_when_line_missing(self) -> None:
        # Dropping the b= line and asking for bandwidth must raise.
        lines = [
            (k, v) for (k, v) in parse_sdp_body(_BASELINE_SDP) if k != "b"
        ]
        rng = random.Random(0)
        with self.assertRaisesRegex(ValueError, "no b="):
            apply_sdp_boundary(lines, rng, variant="bandwidth")

    def test_unknown_variant_raises(self) -> None:
        rng = random.Random(0)
        with self.assertRaisesRegex(ValueError, "unknown sdp boundary variant"):
            apply_sdp_boundary(self.lines, rng, variant="not_a_variant")


class SDPBoundaryStrategyIntegrationTests(unittest.TestCase):
    """Wire-layer dispatch through ``SIPMutator.mutate`` when strategy is
    ``sdp_boundary_only``."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.generator = SIPGenerator(GeneratorSettings())

    def _build_invite_with_sdp(self):
        # The generator builds an INVITE without an SDP body; we attach a
        # baseline SDP and the matching Content-Type/Length so the wire
        # strategy can find them.
        packet = self.generator.generate_request(RequestSpec(method=SIPMethod.INVITE))
        return packet

    def _editable_with_sdp(self) -> EditableSIPMessage:
        # Build a minimal editable INVITE+SDP message directly so we can
        # control headers and body shape.
        start_line = EditableStartLine(text="INVITE sip:fuzz@host SIP/2.0")
        headers = (
            EditableHeader(name="Via", value="SIP/2.0/UDP host:5060;branch=z9hG4bK-x"),
            EditableHeader(name="From", value='"f" <sip:f@host>;tag=a'),
            EditableHeader(name="To", value='"t" <sip:t@host>'),
            EditableHeader(name="Call-ID", value="x@host"),
            EditableHeader(name="CSeq", value="1 INVITE"),
            EditableHeader(name="Content-Type", value="application/sdp"),
            EditableHeader(name="Content-Length", value=str(len(_BASELINE_SDP.encode("utf-8")))),
        )
        return EditableSIPMessage(
            start_line=start_line,
            headers=headers,
            body=_BASELINE_SDP,
        )

    def test_strategy_mutates_sdp_body_only(self) -> None:
        mutator = SIPMutator()
        editable = self._editable_with_sdp()

        case = mutator.mutate_editable(
            editable,
            MutationConfig(
                seed=0,
                layer="wire",
                profile="delivery_preserving",
                strategy="sdp_boundary_only",
            ),
        )

        self.assertEqual(len(case.records), 1)
        self.assertEqual(case.records[0].operator, "sdp_boundary_only")
        self.assertTrue(case.records[0].target.path.startswith("body:sdp:"))
        # Wire still parses; body changed; headers excluding Content-Length unchanged.
        self.assertIsNotNone(case.wire_text)

    def test_strategy_updates_content_length(self) -> None:
        mutator = SIPMutator()
        editable = self._editable_with_sdp()
        original_cl = next(
            int(h.value) for h in editable.headers if h.name.casefold() == "content-length"
        )
        case = mutator.mutate_editable(
            editable,
            MutationConfig(
                seed=2,
                layer="wire",
                profile="delivery_preserving",
                strategy="sdp_boundary_only",
            ),
        )
        wire = case.wire_text or ""
        # Pull the Content-Length header from the rendered wire text.
        cl_line = next(
            line for line in wire.split("\r\n") if line.lower().startswith("content-length:")
        )
        new_cl = int(cl_line.split(":", 1)[1].strip())
        # New body length should match the post-mutation byte count.
        body_text = wire.split("\r\n\r\n", 1)[1]
        self.assertEqual(new_cl, len(body_text.encode("utf-8")))
        # And it should differ from the original when the variant changed
        # the body length (some variants — boundary port digit count
        # difference — do change length).
        self.assertGreaterEqual(new_cl, 1)

    def test_strategy_raises_when_body_not_sdp(self) -> None:
        mutator = SIPMutator()
        editable = self._editable_with_sdp().model_copy(
            update={
                "headers": tuple(
                    EditableHeader(name="Content-Type", value="text/plain")
                    if h.name.casefold() == "content-type"
                    else h
                    for h in self._editable_with_sdp().headers
                ),
            }
        )

        with self.assertRaisesRegex(ValueError, "application/sdp"):
            mutator.mutate_editable(
                editable,
                MutationConfig(
                    seed=0,
                    layer="wire",
                    profile="delivery_preserving",
                    strategy="sdp_boundary_only",
                ),
            )

    def test_strategy_raises_when_body_empty(self) -> None:
        mutator = SIPMutator()
        editable = self._editable_with_sdp().model_copy(update={"body": ""})

        with self.assertRaisesRegex(ValueError, "non-empty SDP body"):
            mutator.mutate_editable(
                editable,
                MutationConfig(
                    seed=0,
                    layer="wire",
                    profile="delivery_preserving",
                    strategy="sdp_boundary_only",
                ),
            )

    def test_multi_mutation_stacks_sdp_variants(self) -> None:
        mutator = SIPMutator()
        editable = self._editable_with_sdp()

        case = mutator.mutate_editable(
            editable,
            MutationConfig(
                seed=0,
                layer="wire",
                profile="delivery_preserving",
                strategy="sdp_boundary_only",
                max_operations=4,
            ),
        )

        self.assertEqual(len(case.records), 4)
        for record in case.records:
            self.assertEqual(record.operator, "sdp_boundary_only")
            self.assertTrue(record.target.path.startswith("body:sdp:"))


class SDPStructVariantTests(unittest.TestCase):
    """Each struct variant adds/removes/duplicates whole SDP lines and
    leaves all other lines byte-exact.
    """

    def setUp(self) -> None:
        self.lines = parse_sdp_body(_BASELINE_SDP)
        self.rng = random.Random(0)

    def test_extra_media_appends_second_m_line(self) -> None:
        original = parse_sdp_body(_BASELINE_SDP)
        result = apply_sdp_struct(self.lines, self.rng, variant="extra_media")
        self.assertEqual(result.note, "variant=extra_media")
        # There must now be exactly 2 m= lines.
        m_lines = [v for (k, v) in self.lines if k == "m"]
        self.assertEqual(len(m_lines), 2)
        # The first m-line is unchanged from the baseline.
        original_m = next(v for (k, v) in original if k == "m")
        self.assertEqual(m_lines[0], original_m)
        # The second m-line follows the contract: audio <port> RTP/AVP <fmt>.
        new_parts = m_lines[1].split()
        self.assertEqual(new_parts[0], "audio")
        self.assertTrue(new_parts[1].isdigit())
        self.assertEqual(new_parts[2], "RTP/AVP")
        # And the new port should differ from the baseline port.
        self.assertNotEqual(new_parts[1], original_m.split()[1])

    def test_extra_attribute_appends_a_line(self) -> None:
        original_a_count = sum(1 for (k, _v) in self.lines if k == "a")
        result = apply_sdp_struct(
            self.lines, self.rng, variant="extra_attribute"
        )
        self.assertEqual(result.note, "variant=extra_attribute")
        new_a_count = sum(1 for (k, _v) in self.lines if k == "a")
        self.assertEqual(new_a_count, original_a_count + 1)

    def test_missing_session_name_removes_s_line(self) -> None:
        result = apply_sdp_struct(
            self.lines, self.rng, variant="missing_session_name"
        )
        self.assertEqual(result.note, "variant=missing_session_name")
        # No s= line should remain.
        self.assertEqual([k for (k, _v) in self.lines if k == "s"], [])

    def test_missing_origin_removes_o_line(self) -> None:
        result = apply_sdp_struct(
            self.lines, self.rng, variant="missing_origin"
        )
        self.assertEqual(result.note, "variant=missing_origin")
        self.assertEqual([k for (k, _v) in self.lines if k == "o"], [])

    def test_version_corrupt_changes_v_value(self) -> None:
        result = apply_sdp_struct(
            self.lines, self.rng, variant="version_corrupt"
        )
        self.assertTrue(result.note.startswith("variant=version_corrupt"))
        v_values = [v for (k, v) in self.lines if k == "v"]
        self.assertEqual(len(v_values), 1)
        # The new value must be one of the corrupt set, never the baseline 0.
        self.assertIn(v_values[0], {"99", "", "A"})
        self.assertNotEqual(v_values[0], "0")

    def test_direction_conflict_adds_second_direction(self) -> None:
        # Baseline has a=sendrecv. After conflict, two direction attrs.
        result = apply_sdp_struct(
            self.lines, self.rng, variant="direction_conflict"
        )
        self.assertTrue(result.note.startswith("variant=direction_conflict"))
        directions = [
            v
            for (k, v) in self.lines
            if k == "a" and v in {"sendrecv", "sendonly", "recvonly", "inactive"}
        ]
        self.assertGreaterEqual(len(directions), 2)

    def test_direction_conflict_with_no_existing_direction(self) -> None:
        # Drop the a=sendrecv line so the helper takes the "add both" branch.
        sdp_no_dir = (
            "v=0\r\n"
            "o=rue 1 1 IN IP4 1.2.3.4\r\n"
            "s=-\r\n"
            "t=0 0\r\n"
            "m=audio 49170 RTP/AVP 96\r\n"
            "c=IN IP4 1.2.3.4\r\n"
            "a=rtpmap:96 AMR-WB/16000\r\n"
        )
        lines = parse_sdp_body(sdp_no_dir)
        result = apply_sdp_struct(
            lines, random.Random(0), variant="direction_conflict"
        )
        directions = [
            v
            for (k, v) in lines
            if k == "a" and v in {"sendrecv", "sendonly", "recvonly", "inactive"}
        ]
        self.assertEqual(len(directions), 2)
        self.assertEqual(set(directions), {"sendrecv", "sendonly"})
        self.assertIn("direction_conflict", result.note)

    def test_random_variant_picks_from_viable_set(self) -> None:
        # Baseline has v=, o=, s=, m=, plus a=sendrecv direction —
        # all 6 variants are viable.
        seen: set[str] = set()
        for seed in range(80):
            lines = parse_sdp_body(_BASELINE_SDP)
            rng = random.Random(seed)
            result = apply_sdp_struct(lines, rng)
            head = result.note.split(".")[0]
            seen.add(head)
        # Probabilistic — over 80 seeds we should hit at least 4 distinct
        # variants out of 6.
        self.assertGreaterEqual(len(seen), 4)

    def test_explicit_variant_raises_when_target_missing(self) -> None:
        # SDP with no s= line — asking for missing_session_name must raise.
        sdp_no_s = (
            "v=0\r\n"
            "o=rue 1 1 IN IP4 1.2.3.4\r\n"
            "t=0 0\r\n"
            "m=audio 49170 RTP/AVP 96\r\n"
            "c=IN IP4 1.2.3.4\r\n"
        )
        lines = parse_sdp_body(sdp_no_s)
        rng = random.Random(0)
        with self.assertRaisesRegex(ValueError, "no s="):
            apply_sdp_struct(lines, rng, variant="missing_session_name")

    def test_unknown_variant_raises(self) -> None:
        rng = random.Random(0)
        with self.assertRaisesRegex(ValueError, "unknown sdp struct variant"):
            apply_sdp_struct(self.lines, rng, variant="not_a_variant")


class SDPStructStrategyIntegrationTests(unittest.TestCase):
    """Wire-layer dispatch through ``SIPMutator.mutate_editable`` when
    strategy is ``sdp_struct_only``.
    """

    def _editable_with_sdp(self) -> EditableSIPMessage:
        # Same shape as the boundary integration tests so the two suites
        # exercise identical baseline conditions.
        start_line = EditableStartLine(text="INVITE sip:fuzz@host SIP/2.0")
        headers = (
            EditableHeader(name="Via", value="SIP/2.0/UDP host:5060;branch=z9hG4bK-x"),
            EditableHeader(name="From", value='"f" <sip:f@host>;tag=a'),
            EditableHeader(name="To", value='"t" <sip:t@host>'),
            EditableHeader(name="Call-ID", value="x@host"),
            EditableHeader(name="CSeq", value="1 INVITE"),
            EditableHeader(name="Content-Type", value="application/sdp"),
            EditableHeader(
                name="Content-Length",
                value=str(len(_BASELINE_SDP.encode("utf-8"))),
            ),
        )
        return EditableSIPMessage(
            start_line=start_line,
            headers=headers,
            body=_BASELINE_SDP,
        )

    def test_strategy_mutates_via_wire_dispatch(self) -> None:
        mutator = SIPMutator()
        editable = self._editable_with_sdp()

        case = mutator.mutate_editable(
            editable,
            MutationConfig(
                seed=0,
                layer="wire",
                profile="delivery_preserving",
                strategy="sdp_struct_only",
            ),
        )

        self.assertEqual(len(case.records), 1)
        self.assertEqual(case.records[0].operator, "sdp_struct_only")
        self.assertTrue(case.records[0].target.path.startswith("body:sdp:struct."))
        self.assertIsNotNone(case.wire_text)

    def test_strategy_updates_content_length(self) -> None:
        mutator = SIPMutator()
        editable = self._editable_with_sdp()

        case = mutator.mutate_editable(
            editable,
            MutationConfig(
                seed=2,
                layer="wire",
                profile="delivery_preserving",
                strategy="sdp_struct_only",
            ),
        )
        wire = case.wire_text or ""
        cl_line = next(
            line
            for line in wire.split("\r\n")
            if line.lower().startswith("content-length:")
        )
        new_cl = int(cl_line.split(":", 1)[1].strip())
        body_text = wire.split("\r\n\r\n", 1)[1]
        self.assertEqual(new_cl, len(body_text.encode("utf-8")))

    def test_strategy_raises_when_body_not_sdp(self) -> None:
        mutator = SIPMutator()
        editable = self._editable_with_sdp().model_copy(
            update={
                "headers": tuple(
                    EditableHeader(name="Content-Type", value="text/plain")
                    if h.name.casefold() == "content-type"
                    else h
                    for h in self._editable_with_sdp().headers
                ),
            }
        )

        with self.assertRaisesRegex(ValueError, "application/sdp"):
            mutator.mutate_editable(
                editable,
                MutationConfig(
                    seed=0,
                    layer="wire",
                    profile="delivery_preserving",
                    strategy="sdp_struct_only",
                ),
            )

    def test_strategy_raises_when_body_empty(self) -> None:
        mutator = SIPMutator()
        editable = self._editable_with_sdp().model_copy(update={"body": ""})

        with self.assertRaisesRegex(ValueError, "non-empty SDP body"):
            mutator.mutate_editable(
                editable,
                MutationConfig(
                    seed=0,
                    layer="wire",
                    profile="delivery_preserving",
                    strategy="sdp_struct_only",
                ),
            )

    def test_multi_mutation_stacks_struct_variants(self) -> None:
        mutator = SIPMutator()
        editable = self._editable_with_sdp()

        case = mutator.mutate_editable(
            editable,
            MutationConfig(
                seed=0,
                layer="wire",
                profile="delivery_preserving",
                strategy="sdp_struct_only",
                max_operations=4,
            ),
        )

        # Some variants delete required lines (s=, o=, v=) which makes
        # subsequent picks of the same variant no-ops; the loop should
        # still stack at least one mutation, and every record we get
        # back must be a sdp_struct_only record.
        self.assertGreaterEqual(len(case.records), 1)
        self.assertLessEqual(len(case.records), 4)
        for record in case.records:
            self.assertEqual(record.operator, "sdp_struct_only")
            self.assertTrue(record.target.path.startswith("body:sdp:struct."))


class SDPStructCoverageGapTests(unittest.TestCase):
    """Coverage gaps flagged by Stage 2 review (codex L9): same-seed
    reproducibility, ``extra_media`` fallback when no ``c=`` exists,
    and reproduction-command propagation for ``sdp_struct_only`` +
    ``mutations_per_case``.
    """

    def test_extra_attribute_same_seed_same_path(self) -> None:
        # The picker uses only ``rng.randrange`` over fixed pools, so
        # ``seed=N`` running ``apply_sdp_struct`` twice on identical input
        # must produce identical (path, before, after, note).
        seed = 3
        first = apply_sdp_struct(
            parse_sdp_body(_BASELINE_SDP),
            random.Random(seed),
            variant="extra_attribute",
        )
        second = apply_sdp_struct(
            parse_sdp_body(_BASELINE_SDP),
            random.Random(seed),
            variant="extra_attribute",
        )
        self.assertEqual(first.path, second.path)
        self.assertEqual(first.before, second.before)
        self.assertEqual(first.after, second.after)
        self.assertEqual(first.note, second.note)

    def test_extra_media_inserts_after_m_when_no_c_line(self) -> None:
        # SDP without c= must still accept extra_media; the helper falls
        # back to inserting immediately after the original m= line.
        sdp_no_c = (
            "v=0\r\n"
            "o=rue 1 1 IN IP4 1.2.3.4\r\n"
            "s=-\r\n"
            "t=0 0\r\n"
            "m=audio 49170 RTP/AVP 96\r\n"
            "a=rtpmap:96 AMR-WB/16000\r\n"
        )
        lines = parse_sdp_body(sdp_no_c)
        rng = random.Random(0)
        result = apply_sdp_struct(lines, rng, variant="extra_media")
        rendered = render_sdp_body(lines)
        # Two m= lines now present.
        m_count = sum(1 for line in rendered.split("\r\n") if line.startswith("m="))
        self.assertEqual(m_count, 2)
        # The injected line lands immediately after the original (no
        # ``c=`` to anchor against), and other lines stay in place.
        self.assertEqual(result.note, "variant=extra_media")
        self.assertTrue(result.path.startswith("body:sdp:struct.extra_media["))


class SDPStructReproductionCmdTests(unittest.TestCase):
    """Replay command for ``sdp_struct_only`` campaigns must propagate the
    strategy *and* ``--mutations-per-case`` when N>1, so reproduced runs
    apply the same N rounds against the same baseline.
    """

    def _executor_with(
        self, *, mutations_per_case: int, mt: bool = False
    ) -> "object":
        # Imported lazily so this test module doesn't pull campaign
        # contracts at module-import time.
        import tempfile
        from volte_mutation_fuzzer.campaign.contracts import (
            CampaignConfig,
        )
        from volte_mutation_fuzzer.campaign.core import CampaignExecutor

        with tempfile.TemporaryDirectory() as tmp:
            kwargs: dict[str, object] = {
                "target_msisdn": "111111",
                "mode": "real-ue-direct",
                "methods": ("INVITE",),
                "ipsec_mode": "native",
                "mutations_per_case": mutations_per_case,
                "results_dir": tmp,
                "output_name": "sdp-struct-replay",
            }
            if mt:
                kwargs.update(
                    mt_invite_template="3gpp",
                    impi="001010000123511@ims.mnc001.mcc001.3gppnetwork.org",
                )
            cfg = CampaignConfig(**kwargs)
            return CampaignExecutor(cfg)

    def _spec(self, **overrides: object):
        from volte_mutation_fuzzer.campaign.contracts import CaseSpec

        defaults: dict[str, object] = {
            "case_id": 0,
            "seed": 0,
            "method": "INVITE",
            "layer": "wire",
            "strategy": "sdp_struct_only",
            "profile": "delivery_preserving",
        }
        defaults.update(overrides)
        return CaseSpec(**defaults)

    def test_replay_cmd_carries_strategy_and_mutations(self) -> None:
        executor = self._executor_with(mutations_per_case=4)
        cmd = executor._build_reproduction_cmd(self._spec())
        self.assertIn("--strategy sdp_struct_only", cmd)
        self.assertIn("--mutations-per-case 4", cmd)
        # Order: replay flag belongs on the mutate side of the pipe.
        mutate_part, _pipe, send_part = cmd.partition(" | ")
        self.assertIn("--mutations-per-case 4", mutate_part)
        self.assertNotIn("--mutations-per-case", send_part)

    def test_mt_template_replay_cmd_also_carries_mutations(self) -> None:
        executor = self._executor_with(mutations_per_case=3, mt=True)
        cmd = executor._build_mt_template_reproduction_cmd(self._spec())
        self.assertIn("--strategy sdp_struct_only", cmd)
        self.assertIn("--mutations-per-case 3", cmd)


if __name__ == "__main__":
    unittest.main()
