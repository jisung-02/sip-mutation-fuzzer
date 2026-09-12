import unittest

from volte_mutation_fuzzer.mutator.contracts import MutationConfig
from volte_mutation_fuzzer.mutator.core import SIPMutator
from volte_mutation_fuzzer.mutator.editable import parse_editable_from_wire
from volte_mutation_fuzzer.mutator.profile_catalog import profile_supports_strategy

WIRE = (
    "OPTIONS sip:111111@10.20.20.8 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.20.20.3:5060;branch=z9hG4bK-dos\r\n"
    "Call-ID: dos-test@10.20.20.3\r\n"
    "CSeq: 1 OPTIONS\r\n"
    "From: <sip:222222@ims.test>;tag=fromtag\r\n"
    "To: <sip:111111@ims.test>\r\n"
    "Accept: application/sdp\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)

WIRE_WITH_BODY = (
    "MESSAGE sip:111111@10.20.20.8 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.20.20.3:5060;branch=z9hG4bK-dos2\r\n"
    "Call-ID: dos-body@10.20.20.3\r\n"
    "CSeq: 1 MESSAGE\r\n"
    "From: <sip:222222@ims.test>;tag=fromtag\r\n"
    "To: <sip:111111@ims.test>\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 3\r\n"
    "\r\n"
    "abc"
)

# Only routing-critical headers — no floodable target.
PROTECTED_ONLY_WIRE = (
    "OPTIONS sip:111111@10.20.20.8 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 10.20.20.3:5060;branch=z9hG4bK-dos3\r\n"
    "Call-ID: protected-only@10.20.20.3\r\n"
    "CSeq: 1 OPTIONS\r\n"
    "\r\n"
)


class DelimiterFloodTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mutator = SIPMutator()
        self.message = parse_editable_from_wire(WIRE)

    def _mutate(self, seed: int, message=None):
        return self.mutator.mutate_editable(
            message if message is not None else self.message,
            MutationConfig(seed=seed, strategy="delimiter_flood", layer="wire"),
        )

    def test_flood_appends_repeated_delimiter_run(self) -> None:
        case = self._mutate(seed=7)
        wire_text = case.wire_text
        assert wire_text is not None
        record = case.records[0]
        self.assertEqual(record.operator, "delimiter_flood")
        after = record.after
        assert isinstance(after, dict)
        self.assertIn(after["variant"], {"semi", "param", "comma"})
        self.assertGreaterEqual(len(wire_text), len(WIRE) + int(after["chars"]) - 2)
        unit = {"semi": ";", "param": ";a=a", "comma": ","}[after["variant"]]
        self.assertIn(unit * 32, wire_text)

    def test_routing_headers_survive_untouched(self) -> None:
        case = self._mutate(seed=3)
        wire_text = case.wire_text
        assert wire_text is not None
        lines = wire_text.split("\r\n")
        self.assertIn("Via: SIP/2.0/UDP 10.20.20.3:5060;branch=z9hG4bK-dos", lines)
        self.assertIn("Call-ID: dos-test@10.20.20.3", lines)
        self.assertIn("CSeq: 1 OPTIONS", lines)
        self.assertIn("OPTIONS sip:111111@10.20.20.8 SIP/2.0", lines)

    def test_record_stays_compact(self) -> None:
        case = self._mutate(seed=1)
        after = case.records[0].after
        assert isinstance(after, dict)
        self.assertLessEqual(len(after["prefix"]), 32)
        # The full flood never enters the record — only its summary.
        self.assertNotIn(str(after["chars"]) * 8, str(after))

    def test_same_seed_is_deterministic(self) -> None:
        first = self._mutate(seed=11)
        second = self._mutate(seed=11)
        self.assertEqual(first.wire_text, second.wire_text)
        self.assertEqual(first.records, second.records)

    def test_variants_and_sizes_vary_across_seeds(self) -> None:
        variants = {
            self._mutate(seed=seed).records[0].after["variant"] for seed in range(40)
        }
        self.assertGreaterEqual(len(variants), 2)

    def test_protected_only_message_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-protected header"):
            self._mutate(seed=1, message=parse_editable_from_wire(PROTECTED_ONLY_WIRE))


class ContentLengthMismatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mutator = SIPMutator()

    def _mutate(self, wire: str, seed: int):
        return self.mutator.mutate_editable(
            parse_editable_from_wire(wire),
            MutationConfig(seed=seed, strategy="content_length_mismatch", layer="wire"),
        )

    def test_lie_replaces_existing_content_length(self) -> None:
        case = self._mutate(WIRE, seed=7)
        wire_text = case.wire_text
        assert wire_text is not None
        self.assertNotIn("Content-Length: 0\r\n", wire_text)
        record = case.records[0]
        self.assertEqual(record.operator, "content_length_mismatch")
        declared = int(record.after)
        self.assertIn(declared, {1, 999, 999_999_999, 2_147_483_647})
        self.assertEqual(case.records[0].note, f"declared {declared} vs actual 0")

    def test_body_message_can_lie_to_zero_and_edges(self) -> None:
        seen_declarations = set()
        for seed in range(40):
            record = self._mutate(WIRE_WITH_BODY, seed=seed).records[0]
            seen_declarations.add(int(record.after))
        self.assertIn(0, seen_declarations)  # 0-with-body truncation lie
        self.assertIn(4, seen_declarations)  # body+1 off-by-one lie
        self.assertIn(3999, seen_declarations)  # ~1000x preallocation lie
        self.assertIn(2_147_483_647, seen_declarations)

    def test_missing_content_length_header_is_appended(self) -> None:
        wire_no_cl = WIRE.replace("Content-Length: 0\r\n", "")
        case = self._mutate(wire_no_cl, seed=2)
        wire_text = case.wire_text
        assert wire_text is not None
        self.assertIn("Content-Length:", wire_text)
        self.assertEqual(len(case.records), 1)

    def test_exactly_one_content_length_header_after_lie(self) -> None:
        case = self._mutate(WIRE, seed=5)
        wire_text = case.wire_text
        assert wire_text is not None
        self.assertEqual(wire_text.count("Content-Length:"), 1)

    def test_once_only_on_reapplication(self) -> None:
        first = self.mutator.mutate_editable(
            parse_editable_from_wire(WIRE),
            MutationConfig(seed=1, strategy="content_length_mismatch", layer="wire"),
        )
        self.assertEqual(len(first.records), 1)
        # Applying to the already-lied message must raise (once-only), so
        # multi-round loops degrade to the single application.
        lied = parse_editable_from_wire(first.wire_text or "")
        with self.assertRaisesRegex(ValueError, "already applied"):
            self.mutator.mutate_editable(
                lied,
                MutationConfig(
                    seed=2, strategy="content_length_mismatch", layer="wire"
                ),
            )

    def test_body_bytes_are_preserved(self) -> None:
        case = self._mutate(WIRE_WITH_BODY, seed=9)
        wire_text = case.wire_text
        assert wire_text is not None
        self.assertTrue(wire_text.endswith("\r\n\r\nabc"))


class CatalogRegistrationTests(unittest.TestCase):
    def test_legacy_and_parser_breaker_allow_both(self) -> None:
        for strategy in ("delimiter_flood", "content_length_mismatch"):
            self.assertTrue(profile_supports_strategy("legacy", "wire", strategy))
            self.assertTrue(
                profile_supports_strategy("parser_breaker", "wire", strategy)
            )

    def test_other_wire_profiles_do_not_inherit(self) -> None:
        for profile in (
            "delivery_preserving",
            "ims_specific",
            "pixel_ims",
            "iphone_ims",
        ):
            for strategy in ("delimiter_flood", "content_length_mismatch"):
                self.assertFalse(
                    profile_supports_strategy(profile, "wire", strategy),
                    f"{profile}/{strategy}",
                )

    def test_delivery_preserving_request_is_rejected(self) -> None:
        mutator = SIPMutator()
        with self.assertRaises(ValueError):
            mutator.mutate_editable(
                parse_editable_from_wire(WIRE),
                MutationConfig(
                    seed=1,
                    profile="delivery_preserving",
                    strategy="delimiter_flood",
                    layer="wire",
                ),
            )


if __name__ == "__main__":
    unittest.main()
