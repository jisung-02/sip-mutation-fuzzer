from __future__ import annotations

import random
from typing import Any, TypeAlias

from volte_mutation_fuzzer.generator import DialogContext
from volte_mutation_fuzzer.mutator.contracts import (
    MutatedCase,
    MutationConfig,
    MutationRecord,
    MutationTarget,
    PacketModel,
)
from volte_mutation_fuzzer.sip.catalog import SIPCatalog, SIP_CATALOG
from volte_mutation_fuzzer.sip.requests import SIPRequest, SIPRequestDefinition
from volte_mutation_fuzzer.sip.responses import SIPResponse, SIPResponseDefinition

PacketDefinition: TypeAlias = SIPRequestDefinition | SIPResponseDefinition

_SUPPORTED_MODEL_TARGETS: tuple[str, ...] = (
    "call_id",
    "cseq.sequence",
    "max_forwards",
    "request_uri.host",
    "from_.parameters.tag",
    "to.parameters.tag",
    "reason_phrase",
)

_STATE_BREAKER_TARGETS: tuple[str, ...] = (
    "call_id",
    "cseq.sequence",
    "from_.parameters.tag",
    "to.parameters.tag",
    "request_uri.host",
)

_MODEL_TARGET_ALIASES = {
    "call-id": "call_id",
    "call_id": "call_id",
    "callid": "call_id",
    "cseq": "cseq.sequence",
    "cseq.sequence": "cseq.sequence",
    "max-forwards": "max_forwards",
    "max_forwards": "max_forwards",
    "request-uri.host": "request_uri.host",
    "request_uri.host": "request_uri.host",
    "from.tag": "from_.parameters.tag",
    "from_.tag": "from_.parameters.tag",
    "from_.parameters.tag": "from_.parameters.tag",
    "to.tag": "to.parameters.tag",
    "to.parameters.tag": "to.parameters.tag",
    "reason-phrase": "reason_phrase",
    "reason_phrase": "reason_phrase",
}

_MODEL_TARGET_OPERATORS = {
    "call_id": "replace_text",
    "cseq.sequence": "replace_integer",
    "max_forwards": "replace_integer",
    "request_uri.host": "replace_host",
    "from_.parameters.tag": "replace_text",
    "to.parameters.tag": "replace_text",
    "reason_phrase": "replace_text",
}

_MISSING = object()


class SIPMutator:
    """Public mutator service boundary for request/response mutation workflows."""

    def __init__(self, catalog: SIPCatalog | None = None) -> None:
        self.catalog = SIP_CATALOG if catalog is None else catalog

    def mutate(
        self,
        packet: PacketModel,
        config: MutationConfig,
        context: DialogContext | None = None,
    ) -> MutatedCase:
        definition = self._resolve_packet_definition(packet)
        return self._mutate_packet(
            packet=packet,
            definition=definition,
            config=config,
            context=context,
            target=None,
        )

    def mutate_field(
        self,
        packet: PacketModel,
        target: MutationTarget,
        config: MutationConfig,
        context: DialogContext | None = None,
    ) -> MutatedCase:
        definition = self._resolve_packet_definition(packet)
        return self._mutate_packet(
            packet=packet,
            definition=definition,
            config=config,
            context=context,
            target=target,
        )

    def _resolve_packet_definition(self, packet: PacketModel) -> PacketDefinition:
        if isinstance(packet, SIPRequest):
            return self.catalog.get_request(packet.method)
        if isinstance(packet, SIPResponse):
            return self.catalog.get_response(packet.status_code)
        raise TypeError("packet must be a SIPRequest or SIPResponse")

    def _collect_model_targets(
        self,
        packet: PacketModel,
        definition: PacketDefinition,
    ) -> tuple[MutationTarget, ...]:
        available_roots = {descriptor.python_name for descriptor in definition.field_descriptors}
        targets: list[MutationTarget] = []

        for path in _SUPPORTED_MODEL_TARGETS:
            root_name = path.split(".", 1)[0]
            if root_name not in available_roots:
                continue
            value = self._get_path_value(packet, path)
            if value is _MISSING or value is None:
                continue
            targets.append(MutationTarget(layer="model", path=path))

        return tuple(targets)

    def _normalize_target_name(self, target: MutationTarget) -> str:
        if target.layer != "model":
            raise ValueError("model mutation only supports model-layer targets")

        raw_name = target.path.strip()
        if raw_name in _SUPPORTED_MODEL_TARGETS:
            return raw_name

        canonical_name = _MODEL_TARGET_ALIASES.get(raw_name.lower())
        if canonical_name is None:
            raise ValueError(f"unsupported model target path: {target.path}")
        return canonical_name

    def _apply_model_operator(
        self,
        packet: PacketModel,
        target: MutationTarget,
        operator: str,
        rng: random.Random,
    ) -> tuple[PacketModel, MutationRecord]:
        canonical_path = target.path
        before_value = self._get_path_value(packet, canonical_path)
        if before_value is _MISSING or before_value is None:
            raise ValueError(f"model target is not available on packet: {canonical_path}")

        after_value = self._build_model_value(
            target_path=canonical_path,
            current_value=before_value,
            rng=rng,
        )

        payload = self._build_packet_payload(packet)
        self._set_path_value(payload, canonical_path, after_value)
        mutated_packet = packet.__class__.model_validate(payload)
        record = MutationRecord(
            layer="model",
            target=target,
            operator=operator,
            before=before_value,
            after=after_value,
        )
        return mutated_packet, record

    def _mutate_model(
        self,
        packet: PacketModel,
        definition: PacketDefinition,
        config: MutationConfig,
        context: DialogContext | None,
        target: MutationTarget | None = None,
    ) -> MutatedCase:
        _ = context
        available_targets = self._collect_model_targets(packet, definition)
        rng = random.Random(config.seed)

        if target is not None:
            selected_target = self._build_canonical_model_target(target)
            if not any(candidate.path == selected_target.path for candidate in available_targets):
                raise ValueError(
                    f"model target is not available for packet: {selected_target.path}"
                )
            operator = self._resolve_model_operator(selected_target)
            mutated_packet, record = self._apply_model_operator(
                packet,
                selected_target,
                operator,
                rng,
            )
            return MutatedCase(
                original_packet=packet,
                mutated_packet=mutated_packet,
                records=(record,),
                seed=config.seed,
                strategy=config.strategy,
                final_layer="model",
            )

        candidate_targets = self._targets_for_strategy(available_targets, config.strategy)
        if not candidate_targets:
            raise ValueError("no model mutation targets available for packet")

        remaining_targets = list(candidate_targets)
        operation_count = min(config.max_operations, len(remaining_targets))
        current_packet = packet
        records: list[MutationRecord] = []

        for _index in range(operation_count):
            selected_index = rng.randrange(len(remaining_targets))
            selected_target = remaining_targets.pop(selected_index)
            operator = self._resolve_model_operator(selected_target)
            current_packet, record = self._apply_model_operator(
                current_packet,
                selected_target,
                operator,
                rng,
            )
            records.append(record)

        return MutatedCase(
            original_packet=packet,
            mutated_packet=current_packet,
            records=tuple(records),
            seed=config.seed,
            strategy=config.strategy,
            final_layer="model",
        )

    def _mutate_packet(
        self,
        *,
        packet: PacketModel,
        definition: PacketDefinition,
        config: MutationConfig,
        context: DialogContext | None,
        target: MutationTarget | None,
    ) -> MutatedCase:
        self._validate_supported_strategy(config.strategy)

        if config.layer in {"wire", "byte"}:
            raise ValueError("model mutation phase only supports layer='model' or 'auto'")

        return self._mutate_model(
            packet=packet,
            definition=definition,
            config=config,
            context=context,
            target=target,
        )

    def _build_canonical_model_target(self, target: MutationTarget) -> MutationTarget:
        canonical_path = self._normalize_target_name(target)
        alias = target.alias
        if alias is None and target.path != canonical_path:
            alias = target.path
        return MutationTarget(
            layer="model",
            path=canonical_path,
            alias=alias,
            operator_hint=target.operator_hint,
        )

    def _resolve_model_operator(self, target: MutationTarget) -> str:
        operator = _MODEL_TARGET_OPERATORS[target.path]
        if target.operator_hint is not None and target.operator_hint != operator:
            raise ValueError(
                f"operator_hint '{target.operator_hint}' is not supported for {target.path}"
            )
        return operator

    def _targets_for_strategy(
        self,
        available_targets: tuple[MutationTarget, ...],
        strategy: str,
    ) -> tuple[MutationTarget, ...]:
        if strategy == "default":
            return available_targets
        if strategy == "state_breaker":
            available_by_path = {target.path: target for target in available_targets}
            prioritized_targets = [
                available_by_path[path]
                for path in _STATE_BREAKER_TARGETS
                if path in available_by_path
            ]
            return tuple(prioritized_targets)
        raise ValueError(f"unsupported mutation strategy: {strategy}")

    def _validate_supported_strategy(self, strategy: str) -> None:
        if strategy not in {"default", "state_breaker"}:
            raise ValueError(f"unsupported mutation strategy: {strategy}")

    def _build_model_value(
        self,
        *,
        target_path: str,
        current_value: Any,
        rng: random.Random,
    ) -> Any:
        if target_path in {
            "call_id",
            "from_.parameters.tag",
            "to.parameters.tag",
            "reason_phrase",
        }:
            return f"mut-{rng.getrandbits(32):08x}"
        if target_path == "request_uri.host":
            return f"mut-{rng.getrandbits(32):08x}.invalid"
        if target_path == "cseq.sequence":
            return self._mutate_bounded_integer(
                current_value=int(current_value),
                modulus=2**31,
                rng=rng,
            )
        if target_path == "max_forwards":
            return self._mutate_bounded_integer(
                current_value=int(current_value),
                modulus=256,
                rng=rng,
            )
        raise ValueError(f"unsupported model target path: {target_path}")

    def _mutate_bounded_integer(
        self,
        *,
        current_value: int,
        modulus: int,
        rng: random.Random,
    ) -> int:
        return (current_value + rng.randrange(1, modulus)) % modulus

    def _build_packet_payload(self, packet: PacketModel) -> dict[str, Any]:
        payload = packet.model_dump(mode="python", by_alias=False)
        for key in tuple(payload):
            if key not in packet.__class__.model_fields:
                payload.pop(key)
        return payload

    def _get_path_value(self, payload: Any, path: str) -> Any:
        current = payload
        for segment in path.split("."):
            if isinstance(current, dict):
                if segment not in current:
                    return _MISSING
                current = current[segment]
                continue
            if not hasattr(current, segment):
                return _MISSING
            current = getattr(current, segment)
        return current

    def _set_path_value(self, payload: dict[str, Any], path: str, value: Any) -> None:
        segments = path.split(".")
        current: Any = payload
        for segment in segments[:-1]:
            current = current[segment]
        current[segments[-1]] = value


__all__ = ["PacketDefinition", "SIPMutator"]
