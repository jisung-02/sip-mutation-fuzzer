from __future__ import annotations

import random
import re
from typing import Any, TypeAlias

from volte_mutation_fuzzer.generator import DialogContext
from volte_mutation_fuzzer.mutator.contracts import (
    MutatedCase,
    MutationConfig,
    MutationRecord,
    MutationTarget,
    PacketModel,
)
from volte_mutation_fuzzer.mutator.editable import (
    EditableHeader,
    EditableSIPMessage,
    EditableStartLine,
)
from volte_mutation_fuzzer.sip.catalog import SIPCatalog, SIP_CATALOG
from volte_mutation_fuzzer.sip.common import (
    AbsoluteURI,
    AuthChallenge,
    CSeqHeader,
    EventHeader,
    NameAddress,
    RAckHeader,
    RetryAfterHeader,
    SIPFieldLocation,
    SIPURI,
    SubscriptionStateHeader,
    ViaHeader,
)
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

_WIRE_TARGET_ALIASES = {
    "start-line": "start_line",
    "start_line": "start_line",
    "body": "body",
    "content-length": "content_length",
    "content_length": "content_length",
}

_HEADER_INDEX_PATTERN = re.compile(r"^header\[(\d+)\]$")
_CONTENT_LENGTH_HEADER = "Content-Length"

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
        available_roots = {
            descriptor.python_name for descriptor in definition.field_descriptors
        }
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
        if target.layer == "model":
            raw_name = target.path.strip()
            if raw_name in _SUPPORTED_MODEL_TARGETS:
                return raw_name

            canonical_name = _MODEL_TARGET_ALIASES.get(raw_name.lower())
            if canonical_name is None:
                raise ValueError(f"unsupported model target path: {target.path}")
            return canonical_name

        if target.layer == "wire":
            raw_name = target.path.strip()
            if header_match := _HEADER_INDEX_PATTERN.fullmatch(raw_name):
                return f"header[{int(header_match.group(1))}]"

            if raw_name.lower().startswith("header:"):
                header_name = raw_name.split(":", 1)[1].strip()
                if not header_name:
                    raise ValueError(f"unsupported wire target path: {target.path}")
                return f"header:{header_name}"

            canonical_name = _WIRE_TARGET_ALIASES.get(raw_name.lower())
            if canonical_name is None:
                raise ValueError(f"unsupported wire target path: {target.path}")
            return canonical_name

        raise ValueError(f"unsupported target layer: {target.layer}")

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
            raise ValueError(
                f"model target is not available on packet: {canonical_path}"
            )

        after_value = self._build_model_value(
            target_path=canonical_path,
            current_value=before_value,
            rng=rng,
        )

        payload = self._build_packet_payload(packet)
        self._set_path_value(payload, canonical_path, after_value)
        mutated_packet = packet.__class__.model_validate(payload)
        record = self._record_mutation(
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
        self._snapshot_context(context)
        available_targets = self._collect_model_targets(packet, definition)
        rng = self._rng_from_seed(config.seed)

        if target is not None:
            selected_target = self._build_canonical_model_target(target)
            if not any(
                candidate.path == selected_target.path for candidate in available_targets
            ):
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

        candidate_targets = self._targets_for_strategy(
            available_targets,
            config.strategy,
        )
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
        effective_layer = config.layer if target is None else target.layer
        if effective_layer == "auto":
            effective_layer = "model"

        if effective_layer == "byte":
            raise ValueError("byte mutation is not implemented yet")

        self._validate_supported_strategy(config.strategy, effective_layer)

        if effective_layer == "model":
            model_target = target if target is None or target.layer == "model" else None
            return self._mutate_model(
                packet=packet,
                definition=definition,
                config=config,
                context=context,
                target=model_target,
            )

        if effective_layer == "wire":
            editable_message = self._to_editable_message(packet)
            wire_target = target if target is None or target.layer == "wire" else None
            return self._mutate_wire(
                packet=packet,
                definition=definition,
                editable_message=editable_message,
                config=config,
                context=context,
                target=wire_target,
            )

        raise ValueError(f"unsupported mutation layer: {effective_layer}")

    def _rng_from_seed(self, seed: int | None) -> random.Random:
        return random.Random(seed)

    def _record_mutation(
        self,
        *,
        target: MutationTarget,
        operator: str,
        before: Any,
        after: Any,
        note: str | None = None,
    ) -> MutationRecord:
        return MutationRecord(
            layer=target.layer,
            target=target,
            operator=operator,
            before=before,
            after=after,
            note=note,
        )

    def _snapshot_context(
        self,
        context: DialogContext | None,
    ) -> dict[str, Any] | None:
        if context is None:
            return None
        return context.model_dump(mode="python")

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

    def _validate_supported_strategy(self, strategy: str, layer: str) -> None:
        if layer == "model":
            if strategy not in {"default", "state_breaker"}:
                raise ValueError(f"unsupported mutation strategy: {strategy}")
            return
        if layer == "wire":
            if strategy != "default":
                raise ValueError(
                    f"unsupported wire mutation strategy: {strategy}"
                )
            return
        raise ValueError(f"unsupported mutation layer: {layer}")

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

    def _to_editable_message(self, packet: PacketModel) -> EditableSIPMessage:
        definition = self._resolve_packet_definition(packet)
        headers: list[EditableHeader] = []

        for descriptor in definition.field_descriptors:
            if descriptor.location != SIPFieldLocation.HEADER:
                continue

            value = getattr(packet, descriptor.python_name)
            if value is None:
                continue

            if descriptor.repeatable:
                values = tuple(value)
            else:
                values = (value,)

            for item in values:
                headers.append(
                    EditableHeader(
                        name=descriptor.wire_name,
                        value=self._serialize_wire_value(
                            descriptor.python_name,
                            item,
                        ),
                    )
                )

        declared_content_length = int(packet.content_length)
        body = packet.body or ""
        return EditableSIPMessage(
            start_line=EditableStartLine(text=self._serialize_start_line(packet)),
            headers=tuple(headers),
            body=body,
            declared_content_length=declared_content_length,
        )

    def _collect_wire_targets(
        self,
        editable_message: EditableSIPMessage,
        definition: PacketDefinition,
    ) -> tuple[MutationTarget, ...]:
        del definition
        targets: list[MutationTarget] = [
            MutationTarget(layer="wire", path="start_line"),
            MutationTarget(layer="wire", path="body"),
            MutationTarget(layer="wire", path="content_length"),
        ]
        seen_header_names: set[str] = set()

        for index, header in enumerate(editable_message.headers):
            header_key = self._header_name_key(header.name)
            if header_key not in seen_header_names:
                targets.append(
                    MutationTarget(
                        layer="wire",
                        path=f"header:{header.name}",
                    )
                )
                seen_header_names.add(header_key)

            targets.append(MutationTarget(layer="wire", path=f"header[{index}]"))

        return tuple(targets)

    def _apply_wire_operator(
        self,
        editable_message: EditableSIPMessage,
        target: MutationTarget,
        operator: str,
        rng: random.Random,
    ) -> tuple[EditableSIPMessage, MutationRecord]:
        if target.path == "start_line":
            before = editable_message.start_line.text
            after = f"{before} MUT-{rng.getrandbits(16):04x}"
            mutated_message = editable_message.model_copy(
                update={"start_line": EditableStartLine(text=after)}
            )
            record = self._record_mutation(
                target=target,
                operator=operator,
                before=before,
                after=after,
            )
            return mutated_message, record

        if target.path in {"body", "content_length"}:
            actual_length = len(editable_message.body.encode("utf-8"))
            mutated_length = actual_length + rng.randrange(1, 10)
            content_length_indices = self._find_header_indices(
                editable_message,
                _CONTENT_LENGTH_HEADER,
            )
            if content_length_indices:
                before = tuple(
                    editable_message.headers[index].value
                    for index in content_length_indices
                )
                updated_headers = list(editable_message.headers)
                for index in content_length_indices:
                    header = updated_headers[index]
                    updated_headers[index] = EditableHeader(
                        name=header.name,
                        value=str(mutated_length),
                    )
                mutated_message = editable_message.model_copy(
                    update={
                        "headers": tuple(updated_headers),
                        "declared_content_length": mutated_length,
                    }
                )
                after: Any = tuple(
                    updated_headers[index].value for index in content_length_indices
                )
            else:
                before = editable_message.declared_content_length
                mutated_message = editable_message.model_copy(
                    update={"declared_content_length": mutated_length}
                )
                after = mutated_length

            record = self._record_mutation(
                target=target,
                operator=operator,
                before=before,
                after=after,
            )
            return mutated_message, record

        if operator == "remove_header":
            return self._remove_wire_header(editable_message, target)
        if operator == "duplicate_header":
            return self._duplicate_wire_header(editable_message, target, rng)
        if operator == "shuffle_header":
            return self._shuffle_wire_header(editable_message, target, rng)

        raise ValueError(f"unsupported wire operator: {operator}")

    def _mutate_wire(
        self,
        *,
        packet: PacketModel,
        definition: PacketDefinition,
        editable_message: EditableSIPMessage,
        config: MutationConfig,
        context: DialogContext | None,
        target: MutationTarget | None,
    ) -> MutatedCase:
        del definition
        self._snapshot_context(context)
        rng = self._rng_from_seed(config.seed)
        current_message = editable_message
        records: list[MutationRecord] = []

        if target is not None:
            selected_target = self._build_canonical_wire_target(target, current_message)
            operator = self._resolve_wire_operator(selected_target, current_message, rng)
            current_message, record = self._apply_wire_operator(
                current_message,
                selected_target,
                operator,
                rng,
            )
            records.append(record)
        else:
            used_paths: set[str] = set()
            for _ in range(config.max_operations):
                available_targets = tuple(
                    candidate
                    for candidate in self._collect_wire_targets(current_message, self._resolve_packet_definition(packet))
                    if candidate.path not in used_paths
                )
                if not available_targets:
                    break

                selected_target = available_targets[rng.randrange(len(available_targets))]
                operator = self._resolve_wire_operator(
                    selected_target,
                    current_message,
                    rng,
                )
                current_message, record = self._apply_wire_operator(
                    current_message,
                    selected_target,
                    operator,
                    rng,
                )
                used_paths.add(selected_target.path)
                records.append(record)

        return MutatedCase(
            original_packet=packet,
            wire_text=self._finalize_wire_message(current_message),
            records=tuple(records),
            seed=config.seed,
            strategy=config.strategy,
            final_layer="wire",
        )

    def _finalize_wire_message(self, editable_message: EditableSIPMessage) -> str:
        return editable_message.render()

    def _build_canonical_wire_target(
        self,
        target: MutationTarget,
        editable_message: EditableSIPMessage,
    ) -> MutationTarget:
        canonical_path = self._normalize_target_name(target)
        alias = target.alias
        if alias is None and target.path != canonical_path:
            alias = target.path

        if canonical_path.startswith("header:"):
            requested_name = canonical_path.split(":", 1)[1]
            actual_name = self._find_header_name(editable_message, requested_name)
            if actual_name is None:
                raise ValueError(
                    f"wire target is not available for packet: {canonical_path}"
                )
            canonical_path = f"header:{actual_name}"
        elif header_match := _HEADER_INDEX_PATTERN.fullmatch(canonical_path):
            header_index = int(header_match.group(1))
            if header_index >= len(editable_message.headers):
                raise ValueError(
                    f"wire target is not available for packet: {canonical_path}"
                )

        return MutationTarget(
            layer="wire",
            path=canonical_path,
            alias=alias,
            operator_hint=target.operator_hint,
        )

    def _resolve_wire_operator(
        self,
        target: MutationTarget,
        editable_message: EditableSIPMessage,
        rng: random.Random,
    ) -> str:
        if target.path == "start_line":
            operators = ("mutate_start_line",)
        elif target.path in {"body", "content_length"}:
            operators = ("mismatch_content_length",)
        else:
            operators = ["remove_header", "duplicate_header"]
            if len(editable_message.headers) > 1:
                operators.append("shuffle_header")
            operators = tuple(operators)

        if target.operator_hint is not None:
            if target.operator_hint not in operators:
                raise ValueError(
                    f"operator_hint '{target.operator_hint}' is not supported for {target.path}"
                )
            return target.operator_hint
        return operators[rng.randrange(len(operators))]

    def _remove_wire_header(
        self,
        editable_message: EditableSIPMessage,
        target: MutationTarget,
    ) -> tuple[EditableSIPMessage, MutationRecord]:
        if target.path.startswith("header:"):
            header_name = target.path.split(":", 1)[1]
            indices = self._find_header_indices(editable_message, header_name)
        else:
            header_index = self._parse_header_index(target.path)
            indices = [header_index]

        before_headers = tuple(
            self._header_snapshot(editable_message.headers[index]) for index in indices
        )
        filtered_headers = tuple(
            header
            for index, header in enumerate(editable_message.headers)
            if index not in set(indices)
        )
        mutated_message = editable_message.model_copy(update={"headers": filtered_headers})
        record = self._record_mutation(
            target=target,
            operator="remove_header",
            before=before_headers,
            after=(),
        )
        return mutated_message, record

    def _duplicate_wire_header(
        self,
        editable_message: EditableSIPMessage,
        target: MutationTarget,
        rng: random.Random,
    ) -> tuple[EditableSIPMessage, MutationRecord]:
        index = self._select_header_index(editable_message, target, rng)
        headers = list(editable_message.headers)
        selected_header = headers[index]
        headers.insert(index + 1, selected_header.model_copy())
        mutated_message = editable_message.model_copy(update={"headers": tuple(headers)})
        record = self._record_mutation(
            target=target,
            operator="duplicate_header",
            before=self._header_snapshot(selected_header),
            after=(
                self._header_snapshot(headers[index]),
                self._header_snapshot(headers[index + 1]),
            ),
        )
        return mutated_message, record

    def _shuffle_wire_header(
        self,
        editable_message: EditableSIPMessage,
        target: MutationTarget,
        rng: random.Random,
    ) -> tuple[EditableSIPMessage, MutationRecord]:
        if len(editable_message.headers) < 2:
            raise ValueError("shuffle_header requires at least two headers")

        original_index = self._select_header_index(editable_message, target, rng)
        headers = list(editable_message.headers)
        selected_header = headers.pop(original_index)
        destination_choices = [
            index for index in range(len(headers) + 1) if index != original_index
        ]
        destination_index = destination_choices[rng.randrange(len(destination_choices))]
        headers.insert(destination_index, selected_header)
        mutated_message = editable_message.model_copy(update={"headers": tuple(headers)})
        record = self._record_mutation(
            target=target,
            operator="shuffle_header",
            before={"index": original_index, "header": self._header_snapshot(selected_header)},
            after={"index": destination_index, "header": self._header_snapshot(selected_header)},
        )
        return mutated_message, record

    def _serialize_start_line(self, packet: PacketModel) -> str:
        if isinstance(packet, SIPRequest):
            return (
                f"{packet.method} "
                f"{self._serialize_uri_reference(packet.request_uri)} "
                f"{packet.sip_version}"
            )
        return f"{packet.sip_version} {packet.status_code} {packet.reason_phrase}"

    def _serialize_wire_value(self, python_name: str, value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, int | float):
            return str(value)
        if isinstance(value, SIPURI | AbsoluteURI):
            return self._serialize_uri_reference(value)
        if isinstance(value, NameAddress):
            return self._serialize_name_address(value)
        if isinstance(value, ViaHeader):
            return self._serialize_via_header(value)
        if isinstance(value, CSeqHeader):
            return f"{value.sequence} {value.method}"
        if isinstance(value, EventHeader):
            return self._serialize_parameterized_value(value.package, value.parameters)
        if isinstance(value, SubscriptionStateHeader):
            parameters = dict(value.parameters)
            if value.expires is not None:
                parameters["expires"] = str(value.expires)
            if value.reason is not None:
                parameters["reason"] = value.reason
            if value.retry_after is not None:
                parameters["retry-after"] = str(value.retry_after)
            return self._serialize_parameterized_value(value.state, parameters)
        if isinstance(value, RAckHeader):
            return f"{value.response_num} {value.cseq_num} {value.method}"
        if isinstance(value, RetryAfterHeader):
            rendered = str(value.seconds)
            if value.comment is not None:
                rendered = f"{rendered} ({value.comment})"
            parameters = dict(value.parameters)
            if value.duration is not None:
                parameters["duration"] = str(value.duration)
            return rendered + self._serialize_parameters(parameters)
        if isinstance(value, AuthChallenge):
            parameters: list[str] = [
                f'realm="{value.realm}"',
                f'nonce="{value.nonce}"',
            ]
            if value.algorithm is not None:
                parameters.append(f"algorithm={value.algorithm}")
            if value.opaque is not None:
                parameters.append(f'opaque="{value.opaque}"')
            if value.qop is not None:
                parameters.append(f'qop="{",".join(value.qop)}"')
            if value.stale is not None:
                parameters.append(f"stale={'true' if value.stale else 'false'}")
            for key, item in value.parameters.items():
                parameters.append(f"{key}={item}")
            return f"{value.scheme} " + ", ".join(parameters)
        if isinstance(value, dict):
            return self._serialize_dict_value(python_name, value)
        return str(value)

    def _serialize_uri_reference(self, value: SIPURI | AbsoluteURI) -> str:
        if isinstance(value, AbsoluteURI):
            return value.uri

        if value.scheme == "tel":
            rendered = f"tel:{value.user}"
        else:
            authority = ""
            if value.user is not None:
                authority = value.user
                if value.password is not None:
                    authority = f"{authority}:{value.password}"
                authority = f"{authority}@"
            rendered = f"{value.scheme}:{authority}{value.host}"
            if value.port is not None:
                rendered = f"{rendered}:{value.port}"

        rendered += self._serialize_parameters(value.parameters)
        if value.headers:
            rendered += "?" + "&".join(
                f"{key}={item}" for key, item in value.headers.items()
            )
        return rendered

    def _serialize_name_address(self, value: NameAddress) -> str:
        rendered = f"<{self._serialize_uri_reference(value.uri)}>"
        if value.display_name is not None:
            rendered = f'"{value.display_name}" {rendered}'
        return rendered + self._serialize_parameters(value.parameters)

    def _serialize_via_header(self, value: ViaHeader) -> str:
        rendered = f"SIP/2.0/{value.transport} {value.host}"
        if value.port is not None:
            rendered = f"{rendered}:{value.port}"

        parameters: dict[str, str | None] = {"branch": value.branch}
        if value.received is not None:
            parameters["received"] = value.received
        if value.rport is True:
            parameters["rport"] = None
        elif value.rport is not None:
            parameters["rport"] = str(value.rport)
        if value.maddr is not None:
            parameters["maddr"] = value.maddr
        if value.ttl is not None:
            parameters["ttl"] = str(value.ttl)
        parameters.update(value.parameters)
        return rendered + self._serialize_parameters(parameters)

    def _serialize_parameterized_value(
        self,
        base: str,
        parameters: dict[str, str | None],
    ) -> str:
        return base + self._serialize_parameters(parameters)

    def _serialize_parameters(self, parameters: dict[str, str | None]) -> str:
        if not parameters:
            return ""
        return "".join(
            f";{key}" if item is None else f";{key}={item}"
            for key, item in parameters.items()
        )

    def _serialize_dict_value(self, python_name: str, value: dict[str, Any]) -> str:
        if python_name == "authentication_info":
            return ", ".join(f"{key}={item}" for key, item in value.items())
        return ", ".join(
            f"{key}={item}" if item is not None else key for key, item in value.items()
        )

    def _header_name_key(self, value: str) -> str:
        return value.strip().casefold()

    def _find_header_name(
        self,
        editable_message: EditableSIPMessage,
        requested_name: str,
    ) -> str | None:
        requested_key = self._header_name_key(requested_name)
        for header in editable_message.headers:
            if self._header_name_key(header.name) == requested_key:
                return header.name
        return None

    def _find_header_indices(
        self,
        editable_message: EditableSIPMessage,
        requested_name: str,
    ) -> list[int]:
        requested_key = self._header_name_key(requested_name)
        return [
            index
            for index, header in enumerate(editable_message.headers)
            if self._header_name_key(header.name) == requested_key
        ]

    def _parse_header_index(self, path: str) -> int:
        header_match = _HEADER_INDEX_PATTERN.fullmatch(path)
        if header_match is None:
            raise ValueError(f"unsupported wire target path: {path}")
        return int(header_match.group(1))

    def _select_header_index(
        self,
        editable_message: EditableSIPMessage,
        target: MutationTarget,
        rng: random.Random,
    ) -> int:
        if target.path.startswith("header:"):
            indices = self._find_header_indices(
                editable_message,
                target.path.split(":", 1)[1],
            )
            return indices[rng.randrange(len(indices))]
        return self._parse_header_index(target.path)

    def _header_snapshot(self, header: EditableHeader) -> tuple[str, str]:
        return (header.name, header.value)


__all__ = ["PacketDefinition", "SIPMutator"]
