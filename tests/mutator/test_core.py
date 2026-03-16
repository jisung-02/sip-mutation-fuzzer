from __future__ import annotations

import unittest

from volte_mutation_fuzzer.generator import (
    DialogContext,
    GeneratorSettings,
    RequestSpec,
    ResponseSpec,
    SIPGenerator,
)
from volte_mutation_fuzzer.mutator.contracts import (
    MutationConfig,
    MutationRecord,
    MutationTarget,
)
from volte_mutation_fuzzer.mutator.core import SIPMutator
from volte_mutation_fuzzer.sip.catalog import SIPCatalog, SIP_CATALOG
from volte_mutation_fuzzer.sip.common import SIPMethod, SIPURI
from volte_mutation_fuzzer.sip.requests import SIPRequestDefinition
from volte_mutation_fuzzer.sip.responses import SIPResponseDefinition


class SIPMutatorTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.generator = SIPGenerator(GeneratorSettings())

    def build_request(self):
        return self.generator.generate_request(RequestSpec(method=SIPMethod.OPTIONS))

    def build_response(self):
        context = DialogContext(
            call_id="call-1",
            local_tag="ue-tag",
            local_cseq=7,
        )
        return self.generator.generate_response(
            ResponseSpec(status_code=200, related_method=SIPMethod.INVITE),
            context,
        )

    def build_context(self) -> DialogContext:
        return DialogContext(
            call_id="call-ctx-1",
            local_tag="local-tag",
            remote_tag="remote-tag",
            local_cseq=3,
            remote_cseq=4,
            request_uri=SIPURI(scheme="sip", user="ue", host="device.example.net"),
            is_registered=True,
        )

    def path_value(self, packet, path: str):
        current = packet
        for segment in path.split("."):
            if isinstance(current, dict):
                current = current[segment]
            else:
                current = getattr(current, segment)
        return current


class SIPMutatorInitTests(SIPMutatorTestCase):
    def test_init_uses_default_catalog(self) -> None:
        mutator = SIPMutator()

        self.assertIs(mutator.catalog, SIP_CATALOG)

    def test_init_accepts_custom_catalog(self) -> None:
        custom_catalog = SIPCatalog(
            request_definitions=SIP_CATALOG.request_definitions,
            response_definitions=SIP_CATALOG.response_definitions,
        )

        mutator = SIPMutator(catalog=custom_catalog)

        self.assertIs(mutator.catalog, custom_catalog)


class SIPMutatorDefinitionResolutionTests(SIPMutatorTestCase):
    def test_resolve_packet_definition_returns_request_definition(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()

        definition = mutator._resolve_packet_definition(packet)
        assert isinstance(definition, SIPRequestDefinition)

        self.assertEqual(definition.method, SIPMethod.OPTIONS)
        self.assertEqual(definition.model_name, packet.__class__.__name__)

    def test_resolve_packet_definition_returns_response_definition(self) -> None:
        mutator = SIPMutator()
        packet = self.build_response()

        definition = mutator._resolve_packet_definition(packet)
        assert isinstance(definition, SIPResponseDefinition)

        self.assertEqual(definition.status_code, 200)
        self.assertEqual(definition.model_name, packet.__class__.__name__)


class SIPMutatorReproducibilityHelperTests(SIPMutatorTestCase):
    def test_rng_from_seed_returns_reproducible_sequence(self) -> None:
        mutator = SIPMutator()

        first_rng = mutator._rng_from_seed(19)
        second_rng = mutator._rng_from_seed(19)

        self.assertEqual(
            [first_rng.randrange(1000) for _ in range(4)],
            [second_rng.randrange(1000) for _ in range(4)],
        )

    def test_record_mutation_creates_normalized_model_record(self) -> None:
        mutator = SIPMutator()
        target = MutationTarget(layer="model", path="call_id")

        record = mutator._record_mutation(
            target=target,
            operator="replace_text",
            before="call-1",
            after="call-2",
            note=" generated in helper ",
        )

        self.assertIsInstance(record, MutationRecord)
        self.assertEqual(record.layer, "model")
        self.assertEqual(record.target.path, "call_id")
        self.assertEqual(record.operator, "replace_text")
        self.assertEqual(record.before, "call-1")
        self.assertEqual(record.after, "call-2")
        self.assertEqual(record.note, "generated in helper")

    def test_snapshot_context_returns_none_for_missing_context(self) -> None:
        mutator = SIPMutator()

        self.assertIsNone(mutator._snapshot_context(None))

    def test_snapshot_context_returns_copy_without_mutating_source(self) -> None:
        mutator = SIPMutator()
        context = self.build_context()

        snapshot = mutator._snapshot_context(context)

        self.assertIsInstance(snapshot, dict)
        assert snapshot is not None
        self.assertEqual(snapshot["call_id"], "call-ctx-1")
        self.assertEqual(snapshot["local_cseq"], 3)
        self.assertEqual(snapshot["request_uri"]["host"], "device.example.net")

        snapshot["local_cseq"] = 99
        snapshot["request_uri"]["host"] = "mutated.example.net"

        self.assertEqual(context.local_cseq, 3)
        request_uri = context.request_uri
        assert isinstance(request_uri, SIPURI)
        self.assertEqual(request_uri.host, "device.example.net")


class SIPMutatorModelMutationTests(SIPMutatorTestCase):
    def test_mutate_request_returns_model_case(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()

        case = mutator.mutate(
            packet,
            MutationConfig(seed=11, layer="auto", max_operations=2),
        )

        mutated_packet = case.mutated_packet
        assert mutated_packet is not None

        self.assertEqual(case.final_layer, "model")
        self.assertEqual(len(case.records), 2)
        self.assertEqual(len({record.target.path for record in case.records}), 2)
        self.assertEqual(case.original_packet.call_id, packet.call_id)

        for record in case.records:
            self.assertEqual(self.path_value(packet, record.target.path), record.before)
            self.assertEqual(
                self.path_value(mutated_packet, record.target.path),
                record.after,
            )
            self.assertNotEqual(record.before, record.after)

    def test_mutate_response_supports_state_breaker_strategy(self) -> None:
        mutator = SIPMutator()
        packet = self.build_response()

        case = mutator.mutate(
            packet,
            MutationConfig(seed=7, layer="model", strategy="state_breaker"),
        )

        mutated_packet = case.mutated_packet
        assert mutated_packet is not None
        record = case.records[0]

        self.assertEqual(case.final_layer, "model")
        self.assertEqual(len(case.records), 1)
        self.assertIn(
            record.target.path,
            {
                "call_id",
                "cseq.sequence",
                "from_.parameters.tag",
                "to.parameters.tag",
                "request_uri.host",
            },
        )
        self.assertEqual(self.path_value(packet, record.target.path), record.before)
        self.assertEqual(self.path_value(mutated_packet, record.target.path), record.after)

    def test_mutate_field_normalizes_alias_and_only_changes_requested_field(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()

        case = mutator.mutate_field(
            packet,
            MutationTarget(layer="model", path="Call-ID"),
            MutationConfig(seed=5, layer="model"),
        )

        mutated_packet = case.mutated_packet
        assert mutated_packet is not None
        record = case.records[0]

        self.assertEqual(record.target.path, "call_id")
        self.assertNotEqual(mutated_packet.call_id, packet.call_id)
        self.assertEqual(mutated_packet.cseq.sequence, packet.cseq.sequence)
        self.assertEqual(
            self.path_value(mutated_packet, "request_uri.host"),
            self.path_value(packet, "request_uri.host"),
        )

    def test_same_seed_produces_same_model_mutation(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()
        config = MutationConfig(seed=23, layer="model", max_operations=2)

        first_case = mutator.mutate(packet, config)
        second_case = mutator.mutate(packet, config)

        first_mutated_packet = first_case.mutated_packet
        second_mutated_packet = second_case.mutated_packet
        assert first_mutated_packet is not None
        assert second_mutated_packet is not None

        self.assertEqual(
            first_mutated_packet.model_dump(mode="python"),
            second_mutated_packet.model_dump(mode="python"),
        )
        self.assertEqual(
            tuple(record.model_dump(mode="python") for record in first_case.records),
            tuple(record.model_dump(mode="python") for record in second_case.records),
        )

    def test_mutate_does_not_mutate_original_context(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()
        context = self.build_context()

        mutator.mutate(
            packet,
            MutationConfig(seed=13, layer="model"),
            context=context,
        )

        self.assertEqual(context.call_id, "call-ctx-1")
        self.assertEqual(context.local_tag, "local-tag")
        self.assertEqual(context.remote_tag, "remote-tag")
        self.assertEqual(context.local_cseq, 3)
        request_uri = context.request_uri
        assert isinstance(request_uri, SIPURI)
        self.assertEqual(request_uri.host, "device.example.net")


class SIPMutatorModelMutationFailureTests(SIPMutatorTestCase):
    def test_mutate_rejects_wire_layer_until_later_phase(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()

        with self.assertRaisesRegex(ValueError, "layer='model' or 'auto'"):
            mutator.mutate(packet, MutationConfig(layer="wire"))

    def test_mutate_rejects_unsupported_strategy(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()

        with self.assertRaisesRegex(ValueError, "unsupported mutation strategy"):
            mutator.mutate(packet, MutationConfig(strategy="header_chaos"))

    def test_mutate_field_rejects_reason_phrase_for_request_packets(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()

        with self.assertRaisesRegex(ValueError, "model target is not available"):
            mutator.mutate_field(
                packet,
                MutationTarget(layer="model", path="reason_phrase"),
                MutationConfig(layer="model"),
            )

    def test_mutate_field_rejects_missing_to_tag_on_request_packets(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()

        with self.assertRaisesRegex(ValueError, "model target is not available"):
            mutator.mutate_field(
                packet,
                MutationTarget(layer="model", path="To.tag"),
                MutationConfig(layer="model"),
            )

    def test_mutate_field_rejects_unsupported_target_path(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()

        with self.assertRaisesRegex(ValueError, "unsupported model target path"):
            mutator.mutate_field(
                packet,
                MutationTarget(layer="model", path="via.host"),
                MutationConfig(layer="model"),
            )


if __name__ == "__main__":
    unittest.main()
