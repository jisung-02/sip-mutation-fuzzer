import random
import unittest

from volte_mutation_fuzzer.generator import GeneratorSettings, RequestSpec, SIPGenerator
from volte_mutation_fuzzer.mutator.contracts import MutationConfig, MutationTarget
from volte_mutation_fuzzer.mutator.core import (
    _INTERESTING_BYTE_VALUES,
    _SIP_DICT_TOKENS,
    SIPMutator,
)
from volte_mutation_fuzzer.mutator.editable import EditablePacketBytes
from volte_mutation_fuzzer.sip.common import SIPMethod

SAMPLE = (
    b"OPTIONS sip:111111@10.20.20.8 SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP 10.20.20.3:5060;branch=z9hG4bK-op\r\n"
    b"From: <sip:222222@ims.test>;tag=fromtag\r\n"
    b"To: <sip:111111@ims.test>\r\n"
    b"Call-ID: byte-op-test@10.20.20.3\r\n"
    b"CSeq: 1 OPTIONS\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)

SECONDARY = (
    b"MESSAGE sip:111111@10.20.20.8 SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP 10.20.20.4:5060;branch=z9hG4bK-msg\r\n"
    b"From: <sip:333333@ims.test>;tag=othertag\r\n"
    b"To: <sip:111111@ims.test>\r\n"
    b"Call-ID: splice-test@10.20.20.4\r\n"
    b"CSeq: 9 MESSAGE\r\n"
    b"Content-Length: 3\r\n"
    b"\r\n"
    b"abc"
)


class ByteOperatorUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mutator = SIPMutator()
        self.editable = EditablePacketBytes(data=SAMPLE)

    def _apply(self, operator: str, path: str, seed: int = 1):
        target = MutationTarget(layer="byte", path=path)
        return self.mutator._apply_byte_operator(
            self.editable, target, operator, random.Random(seed)
        )

    def test_set_byte_replaces_with_interesting_value(self) -> None:
        mutated, record = self._apply("set_byte", "byte[12]")
        self.assertIn(mutated.data[12], _INTERESTING_BYTE_VALUES)
        self.assertEqual(record.before, SAMPLE[12])
        self.assertIn(record.after, _INTERESTING_BYTE_VALUES)
        # Only the targeted byte changed
        self.assertEqual(
            mutated.data[:12] + mutated.data[13:], SAMPLE[:12] + SAMPLE[13:]
        )

    def test_arith_byte_is_small_signed_delta(self) -> None:
        mutated, record = self._apply("arith_byte", "byte[20]", seed=3)
        before, after = SAMPLE[20], mutated.data[20]
        delta = (after - before) % 256
        # delta in [1,35] or its two's-complement equivalent in [-35,-1]
        self.assertTrue(1 <= delta <= 35 or 221 <= delta <= 255)
        self.assertNotEqual(before, after)

    def test_fill_range_fills_block_with_repeated_interesting_value(self) -> None:
        mutated, record = self._apply("fill_range", "range[5:11]", seed=2)
        filled = mutated.data[5:11]
        self.assertEqual(len(filled), 6)
        self.assertEqual(len(set(filled)), 1)
        self.assertIn(filled[0], _INTERESTING_BYTE_VALUES)
        self.assertEqual(record.before, SAMPLE[5:11])

    def test_insert_dict_token_inserts_known_token_at_crlf_boundary(self) -> None:
        mutated, record = self._apply("insert_dict_token", "delimiter:CRLF", seed=4)
        self.assertEqual(len(mutated.data), len(SAMPLE) + len(record.after))
        self.assertIn(record.after, _SIP_DICT_TOKENS)
        self.assertIn(record.after, mutated.data)
        # note records the offset for replay debugging
        self.assertTrue(record.note and record.note.startswith("at offset "))

    def test_block_duplicate_duplicates_whole_line(self) -> None:
        mutated, record = self._apply("block_duplicate", "line[2]", seed=5)
        line = b"From: <sip:222222@ims.test>;tag=fromtag\r\n"
        self.assertEqual(mutated.data.count(line), 2)
        self.assertEqual(record.after, line)

    def test_block_move_preserves_line_multiset(self) -> None:
        mutated, record = self._apply("block_move", "line[2]", seed=6)
        self.assertEqual(len(mutated.data), len(SAMPLE))
        original_lines = sorted(line for line in SAMPLE.split(b"\r\n") if line)
        mutated_lines = sorted(line for line in mutated.data.split(b"\r\n") if line)
        self.assertEqual(mutated_lines, original_lines)
        # The moved line is no longer at its original position
        self.assertNotEqual(mutated.data, SAMPLE)
        self.assertTrue(record.note and record.note.startswith("moved to offset "))

    def test_insert_bytes_position_varies_across_seeds(self) -> None:
        offsets = set()
        for seed in range(20):
            _, record = self._apply("insert_bytes", "segment:start_line", seed=seed)
            note_offset = int(record.note.removeprefix("at offset "))
            offsets.add(note_offset)
        self.assertGreater(len(offsets), 1)

    def test_collect_byte_targets_includes_line_targets(self) -> None:
        targets = self.mutator._collect_byte_targets(self.editable)
        paths = {target.path for target in targets}
        self.assertIn("line[0]", paths)
        self.assertIn("line[6]", paths)  # last header line
        self.assertNotIn("line[7]", paths)  # empty span between CRLFs is skipped

    def test_targeted_line_mutation_through_mutate_field(self) -> None:
        generator = SIPGenerator(GeneratorSettings())
        packet = generator.generate_request(RequestSpec(method=SIPMethod.OPTIONS))
        target = MutationTarget(
            layer="byte",
            path="line[2]",
            operator_hint="block_duplicate",
        )
        config = MutationConfig(seed=11, layer="byte")
        case = self.mutator.mutate_field(packet, target, config)
        assert case.packet_bytes is not None
        self.assertTrue(
            any(record.operator == "block_duplicate" for record in case.records)
        )


class DefaultStrategyPoolTests(unittest.TestCase):
    def test_default_strategy_pool_reaches_new_operators(self) -> None:
        """New operators must be reachable from the plain ``default`` strategy.

        Runs many seeded single-buffer mutations and asserts every new
        operator appears at least once — guards against accidental removal
        from the resolver pools.
        """
        mutator = SIPMutator()
        seen: set[str] = set()
        for seed in range(400):
            case = mutator.mutate_packet_bytes(
                SAMPLE,
                MutationConfig(seed=seed, strategy="default", max_operations=6),
            )
            seen.update(record.operator for record in case.records)
        for operator in (
            "set_byte",
            "arith_byte",
            "fill_range",
            "insert_dict_token",
            "block_duplicate",
            "block_move",
        ):
            self.assertIn(operator, seen)

    def test_safe_strategy_never_touches_protected_lines(self) -> None:
        mutator = SIPMutator()
        case = mutator.mutate_packet_bytes(
            SAMPLE,
            MutationConfig(seed=9, strategy="safe", max_operations=12),
        )
        out = case.packet_bytes
        assert out is not None
        # start line, Via, Call-ID, CSeq lines must survive byte-identical
        for protected in (
            b"OPTIONS sip:111111@10.20.20.8 SIP/2.0",
            b"Via: SIP/2.0/UDP 10.20.20.3:5060;branch=z9hG4bK-op",
            b"Call-ID: byte-op-test@10.20.20.3",
            b"CSeq: 1 OPTIONS",
        ):
            self.assertIn(protected, out.split(b"\r\n"))

    def test_splice_strategy_rejected_on_single_buffer_paths(self) -> None:
        mutator = SIPMutator()
        with self.assertRaisesRegex(ValueError, "two seed buffers"):
            mutator.mutate_packet_bytes(
                SAMPLE,
                MutationConfig(seed=1, strategy="splice", layer="byte"),
            )


class SplicePacketBytesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mutator = SIPMutator()

    def test_same_seed_is_deterministic(self) -> None:
        first = self.mutator.splice_packet_bytes(SAMPLE, SECONDARY, seed=42)
        second = self.mutator.splice_packet_bytes(SAMPLE, SECONDARY, seed=42)
        self.assertEqual(first.packet_bytes, second.packet_bytes)
        self.assertEqual(first.records, second.records)
        self.assertEqual(first.strategy, "splice")
        self.assertEqual(first.final_layer, "byte")
        self.assertEqual(first.seed, 42)

    def test_output_is_boundary_aligned_composition(self) -> None:
        spliced = self.mutator.splice_packet_bytes(SAMPLE, SECONDARY, seed=42)
        data = spliced.packet_bytes
        assert data is not None
        note = spliced.records[0].note
        assert note is not None
        # note encodes "primary[0:X] + secondary[Y:Z]"
        parts = note.replace("primary[0:", "").split("] + secondary[")
        cut_a = int(parts[0])
        cut_b = int(parts[1].split(":")[0])
        self.assertEqual(data, SAMPLE[:cut_a] + SECONDARY[cut_b:])
        # cuts land on CRLF boundaries (or buffer ends)
        self.assertIn(cut_a, {0, len(SAMPLE)} | {
            offset + 2
            for offset in range(len(SAMPLE))
            if SAMPLE[offset : offset + 2] == b"\r\n"
        })

    def test_different_seeds_produce_different_cuts(self) -> None:
        outputs = {
            self.mutator.splice_packet_bytes(SAMPLE, SECONDARY, seed=seed).packet_bytes
            for seed in range(24)
        }
        self.assertGreater(len(outputs), 1)

    def test_empty_buffer_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-empty primary"):
            self.mutator.splice_packet_bytes(b"", SECONDARY, seed=1)
        with self.assertRaisesRegex(ValueError, "non-empty secondary"):
            self.mutator.splice_packet_bytes(SAMPLE, b"", seed=1)

    def test_record_carries_crossover_metadata(self) -> None:
        spliced = self.mutator.splice_packet_bytes(SAMPLE, SECONDARY, seed=5)
        record = spliced.records[0]
        self.assertEqual(record.operator, "splice")
        self.assertEqual(record.layer, "byte")
        self.assertEqual(record.before, len(SAMPLE))
        self.assertEqual(record.after, len(spliced.packet_bytes))


if __name__ == "__main__":
    unittest.main()
