import unittest

from volte_mutation_fuzzer.generator import GeneratorSettings, RequestSpec, SIPGenerator
from volte_mutation_fuzzer.mutator.contracts import MutationConfig, MutationTarget
from volte_mutation_fuzzer.mutator.core import SIPMutator
from volte_mutation_fuzzer.mutator.editable import EditablePacketBytes
from volte_mutation_fuzzer.sip.common import SIPMethod


class SIPMutatorByteMutationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.generator = SIPGenerator(GeneratorSettings())

    def build_request(self):
        return self.generator.generate_request(RequestSpec(method=SIPMethod.OPTIONS))

    def build_original_bytes(
        self,
        mutator: SIPMutator,
        packet,
    ) -> bytes:
        return EditablePacketBytes.from_message(
            mutator._to_editable_message(packet)
        ).data

    def test_flip_byte_is_reproducible_for_same_seed(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()
        target = MutationTarget(
            layer="byte",
            path="byte[0]",
            operator_hint="flip_byte",
        )
        config = MutationConfig(seed=41, layer="byte")

        first_case = mutator.mutate_field(packet, target, config)
        second_case = mutator.mutate_field(packet, target, config)

        self.assertEqual(first_case.packet_bytes, second_case.packet_bytes)
        self.assertEqual(
            tuple(record.model_dump(mode="python") for record in first_case.records),
            tuple(record.model_dump(mode="python") for record in second_case.records),
        )
        assert first_case.packet_bytes is not None
        original_bytes = self.build_original_bytes(mutator, packet)
        self.assertNotEqual(first_case.packet_bytes[0], original_bytes[0])

    def test_targeted_insert_bytes_grows_payload_length(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()
        original_bytes = self.build_original_bytes(mutator, packet)

        case = mutator.mutate_field(
            packet,
            MutationTarget(
                layer="byte",
                path="segment:start_line",
                operator_hint="insert_bytes",
            ),
            MutationConfig(seed=8, layer="byte"),
        )

        assert case.packet_bytes is not None
        self.assertEqual(case.records[0].target.path, "segment:start_line")
        self.assertEqual(case.records[0].operator, "insert_bytes")
        self.assertEqual(len(case.packet_bytes), len(original_bytes) + 2)

    def test_targeted_delete_range_reduces_payload_length(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()
        original_bytes = self.build_original_bytes(mutator, packet)

        case = mutator.mutate_field(
            packet,
            MutationTarget(
                layer="byte",
                path="range[0:2]",
                operator_hint="delete_range",
            ),
            MutationConfig(seed=7, layer="byte"),
        )

        assert case.packet_bytes is not None
        self.assertEqual(case.records[0].target.path, "range[0:2]")
        self.assertEqual(case.records[0].operator, "delete_range")
        self.assertEqual(len(case.packet_bytes), len(original_bytes) - 2)

    def test_targeted_truncate_bytes_shortens_payload(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()
        original_bytes = self.build_original_bytes(mutator, packet)

        case = mutator.mutate_field(
            packet,
            MutationTarget(
                layer="byte",
                path="segment:start_line",
                operator_hint="truncate_bytes",
            ),
            MutationConfig(seed=13, layer="byte"),
        )

        assert case.packet_bytes is not None
        self.assertEqual(case.records[0].target.path, "segment:start_line")
        self.assertEqual(case.records[0].operator, "truncate_bytes")
        self.assertLess(len(case.packet_bytes), len(original_bytes))

    def test_targeted_damage_crlf_breaks_line_delimiter(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()
        original_bytes = self.build_original_bytes(mutator, packet)

        case = mutator.mutate_field(
            packet,
            MutationTarget(
                layer="byte",
                path="delimiter:CRLF",
                operator_hint="damage_crlf",
            ),
            MutationConfig(seed=19, layer="byte"),
        )

        assert case.packet_bytes is not None
        self.assertEqual(case.records[0].target.path, "delimiter:CRLF")
        self.assertEqual(case.records[0].operator, "damage_crlf")
        self.assertLess(case.packet_bytes.count(b"\r\n"), original_bytes.count(b"\r\n"))

    def test_byte_results_may_be_non_utf8(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()

        case = mutator.mutate_field(
            packet,
            MutationTarget(
                layer="byte",
                path="segment:start_line",
                operator_hint="insert_bytes",
            ),
            MutationConfig(seed=23, layer="byte"),
        )

        assert case.packet_bytes is not None
        self.assertIn(0xFF, case.packet_bytes)
        with self.assertRaises(UnicodeDecodeError):
            case.packet_bytes.decode("utf-8")

    def test_mutate_returns_byte_case(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()

        case = mutator.mutate(
            packet,
            MutationConfig(seed=17, layer="byte", strategy="default"),
        )

        self.assertEqual(case.final_layer, "byte")
        self.assertIsNotNone(case.packet_bytes)
        self.assertIsNone(case.mutated_packet)
        self.assertIsNone(case.wire_text)
        self.assertGreaterEqual(len(case.records), 1)

    def test_tail_chop_1_removes_only_last_byte(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()
        original_bytes = self.build_original_bytes(mutator, packet)

        case = mutator.mutate(
            packet,
            MutationConfig(seed=201, layer="byte", strategy="tail_chop_1"),
        )

        assert case.packet_bytes is not None
        self.assertEqual(case.final_layer, "byte")
        self.assertEqual(case.packet_bytes, original_bytes[:-1])
        self.assertEqual(len(case.records), 1)
        self.assertEqual(case.records[0].target.path, "segment:tail")
        self.assertEqual(case.records[0].operator, "tail_chop_1")
        self.assertEqual(case.records[0].before, original_bytes[-1:])
        self.assertEqual(case.records[0].after, b"")

    def test_tail_garbage_appends_replay_like_suffix(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()
        original_bytes = self.build_original_bytes(mutator, packet)

        case = mutator.mutate(
            packet,
            MutationConfig(seed=202, layer="byte", strategy="tail_garbage"),
        )

        assert case.packet_bytes is not None
        suffix = case.packet_bytes[len(original_bytes) :]
        self.assertEqual(case.final_layer, "byte")
        self.assertTrue(case.packet_bytes.startswith(original_bytes))
        self.assertGreater(len(suffix), 0)
        self.assertLessEqual(len(suffix), 8)
        self.assertEqual(len(case.records), 1)
        self.assertEqual(case.records[0].target.path, "segment:tail")
        self.assertEqual(case.records[0].operator, "tail_garbage")
        self.assertEqual(case.records[0].before, b"")
        self.assertEqual(case.records[0].after, suffix)

    def test_deterministic_tail_byte_strategies_are_reproducible_by_seed(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()

        configs = (
            MutationConfig(seed=211, layer="byte", strategy="tail_chop_1"),
            MutationConfig(seed=212, layer="byte", strategy="tail_garbage"),
        )

        for config in configs:
            with self.subTest(strategy=config.strategy):
                first_case = mutator.mutate(packet, config)
                second_case = mutator.mutate(packet, config)

                self.assertEqual(first_case.packet_bytes, second_case.packet_bytes)
                self.assertEqual(
                    tuple(
                        record.model_dump(mode="python")
                        for record in first_case.records
                    ),
                    tuple(
                        record.model_dump(mode="python")
                        for record in second_case.records
                    ),
                )


if __name__ == "__main__":
    unittest.main()
