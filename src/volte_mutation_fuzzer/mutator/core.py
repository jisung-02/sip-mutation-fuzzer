import random
import re
from types import UnionType
from typing import Any, TypeAlias, Union, get_args, get_origin

from pydantic import ValidationError

from volte_mutation_fuzzer.generator import DialogContext
from volte_mutation_fuzzer.mutator.contracts import (
    MutatedCase,
    MutatedWireCase,
    MutationConfig,
    MutationRecord,
    MutationTarget,
    PacketModel,
)
from volte_mutation_fuzzer.mutator.editable import (
    EditableHeader,
    EditablePacketBytes,
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
    SIPMethod,
    SIPURI,
    SubscriptionStateHeader,
    URIReference,
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

_BYTE_TARGET_ALIASES = {
    "delimiter:crlf": "delimiter:CRLF",
    "segment:start-line": "segment:start_line",
    "segment:start_line": "segment:start_line",
}

_HEADER_INDEX_PATTERN = re.compile(r"^header\[(\d+)\]$")
_BYTE_INDEX_PATTERN = re.compile(r"^byte\[(\d+)\]$")
_BYTE_RANGE_PATTERN = re.compile(r"^range\[(\d+):(\d+)\]$")
_CONTENT_LENGTH_HEADER = "Content-Length"
_CRLF_DELIMITER = b"\r\n"

_MODEL_EXCLUDED_FIELDS: frozenset[str] = frozenset(
    {
        # Protocol constants
        "sip_version",
        "method",
        "status_code",
        # Body (handled separately)
        "content_length",
        "body",
        "extension_headers",
        "content_type",
        # Routing-critical: mutating these prevents packet delivery or response receipt
        "request_uri",      # Changed = packet won't reach UE
        "via",              # Changed = can't receive response (180 etc)
        "call_id",          # Changed = BYE/CANCEL dialog matching breaks
        "cseq",             # Changed = transaction matching breaks
    }
)

_MISSING = object()


def _is_union_annotation(annotation: Any) -> bool:
    return get_origin(annotation) in (Union, UnionType)


def _unwrap_optional(annotation: Any) -> Any:
    if not _is_union_annotation(annotation):
        return annotation

    args = tuple(arg for arg in get_args(annotation) if arg is not type(None))
    if len(args) == 1:
        return args[0]
    return annotation


def _annotation_union_members(annotation: Any) -> tuple[Any, ...]:
    annotation = _unwrap_optional(annotation)
    if not _is_union_annotation(annotation):
        return ()
    return tuple(arg for arg in get_args(annotation) if arg is not type(None))


def _is_uri_reference_annotation(annotation: Any) -> bool:
    annotation = _unwrap_optional(annotation)
    if annotation in {SIPURI, AbsoluteURI, URIReference}:
        return True

    union_args = _annotation_union_members(annotation)
    return SIPURI in union_args


def _is_name_address_or_uri_annotation(annotation: Any) -> bool:
    annotation = _unwrap_optional(annotation)
    if annotation is NameAddress or _is_uri_reference_annotation(annotation):
        return True

    union_args = _annotation_union_members(annotation)
    return bool(union_args) and all(
        arg is NameAddress or _is_uri_reference_annotation(arg) for arg in union_args
    )


def _classify_field(field_name: str, annotation: Any, value: Any) -> str:
    del field_name
    annotation = _unwrap_optional(annotation)
    origin = get_origin(annotation)
    args = get_args(annotation)

    if annotation is str:
        return "string"
    if annotation is bool or isinstance(value, bool):
        return "boolean"
    if annotation is int:
        return "integer"
    if annotation is float:
        return "float_"
    if annotation is NameAddress:
        return "name_address"
    if annotation is CSeqHeader:
        return "cseq"
    if annotation is EventHeader:
        return "event"
    if annotation is SubscriptionStateHeader:
        return "subscription_state"
    if annotation is RAckHeader:
        return "rack"
    if _is_uri_reference_annotation(annotation):
        return "uri_reference"

    if origin is list and args:
        item_annotation = _unwrap_optional(args[0])
        if item_annotation is NameAddress:
            return "name_address_list"
        if item_annotation is ViaHeader:
            return "via_list"
        if _is_name_address_or_uri_annotation(item_annotation):
            return "addr_or_uri_list"
        return "unsupported"

    if origin is tuple and len(args) == 2 and args[1] is Ellipsis:
        item_annotation = _unwrap_optional(args[0])
        if item_annotation in {str, SIPMethod}:
            return "str_tuple"
        if _is_name_address_or_uri_annotation(item_annotation):
            return "addr_or_uri_tuple"
        return "unsupported"

    if _is_union_annotation(annotation):
        if isinstance(value, NameAddress):
            return "name_address"
        if isinstance(value, (SIPURI, AbsoluteURI)):
            return "uri_reference"

    return "unsupported"


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

    def mutate_editable(
        self,
        message: EditableSIPMessage,
        config: MutationConfig,
    ) -> MutatedWireCase:
        """Mutate an already-parsed ``EditableSIPMessage`` without a backing PacketModel.

        Supports ``layer="wire"`` and ``layer="byte"`` only (model layer requires a
        PacketModel and is rejected).  Supports ``strategy="identity"`` for a
        zero-operation pass-through that returns the message unchanged.

        Use this entry point when fuzzing MT INVITE replay templates where the full
        3GPP header set is not modelled in the SIP catalog.
        """
        effective_layer = config.layer if config.layer != "auto" else "wire"
        if effective_layer == "model":
            raise ValueError(
                "mutate_editable does not support the model layer; use wire or byte"
            )
        self._validate_supported_strategy(config.strategy, effective_layer)

        if config.strategy == "identity":
            if effective_layer == "wire":
                return MutatedWireCase(
                    wire_text=self._finalize_wire_message(message),
                    records=(),
                    seed=config.seed,
                    strategy="identity",
                    final_layer="wire",
                )
            editable_bytes = self._to_packet_bytes(message)
            return MutatedWireCase(
                packet_bytes=self._finalize_packet_bytes(editable_bytes),
                records=(),
                seed=config.seed,
                strategy="identity",
                final_layer="byte",
            )

        if effective_layer == "wire":
            mutated_msg, records = self._apply_wire_operations(message, config)
            return MutatedWireCase(
                wire_text=self._finalize_wire_message(mutated_msg),
                records=tuple(records),
                seed=config.seed,
                strategy=config.strategy,
                final_layer="wire",
            )

        # byte layer
        editable_bytes = self._to_packet_bytes(message)
        mutated_bytes, records = self._apply_byte_operations(editable_bytes, config)
        return MutatedWireCase(
            packet_bytes=self._finalize_packet_bytes(mutated_bytes),
            records=tuple(records),
            seed=config.seed,
            strategy=config.strategy,
            final_layer="byte",
        )

    def _apply_wire_operations(
        self,
        message: EditableSIPMessage,
        config: MutationConfig,
    ) -> tuple[EditableSIPMessage, list[MutationRecord]]:
        """Core wire mutation loop; no packet/definition dependency."""
        rng = self._rng_from_seed(config.seed)
        current_message = message
        records: list[MutationRecord] = []
        used_paths: set[str] = set()
        for _ in range(config.max_operations):
            available_targets = tuple(
                candidate
                for candidate in self._collect_wire_targets(current_message)
                if candidate.path not in used_paths
            )
            if not available_targets:
                break
            selected_target = available_targets[rng.randrange(len(available_targets))]
            operator = self._resolve_wire_operator(selected_target, current_message, rng)
            current_message, record = self._apply_wire_operator(
                current_message, selected_target, operator, rng
            )
            used_paths.add(selected_target.path)
            records.append(record)
        return current_message, records

    def _apply_byte_operations(
        self,
        editable_bytes: EditablePacketBytes,
        config: MutationConfig,
    ) -> tuple[EditablePacketBytes, list[MutationRecord]]:
        """Core byte mutation loop; no packet/context dependency."""
        rng = self._rng_from_seed(config.seed)
        current_bytes = editable_bytes
        records: list[MutationRecord] = []
        used_paths: set[str] = set()
        for _ in range(config.max_operations):
            available_targets = tuple(
                candidate
                for candidate in self._collect_byte_targets(current_bytes)
                if candidate.path not in used_paths
            )
            if not available_targets:
                break
            selected_target = available_targets[rng.randrange(len(available_targets))]
            operator = self._resolve_byte_operator(selected_target, rng)
            current_bytes, record = self._apply_byte_operator(
                current_bytes, selected_target, operator, rng
            )
            used_paths.add(selected_target.path)
            records.append(record)
        return current_bytes, records

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
        del definition
        targets: list[MutationTarget] = []

        for field_name, field_info in packet.__class__.model_fields.items():
            if field_name in _MODEL_EXCLUDED_FIELDS:
                continue
            value = getattr(packet, field_name)
            if value is None:
                continue
            category = _classify_field(field_name, field_info.annotation, value)
            if category == "unsupported":
                continue
            targets.append(MutationTarget(layer="model", path=field_name))

        legacy_sub_paths = {
            "cseq": "cseq.sequence",
            "request_uri": "request_uri.host",
            "from_": "from_.parameters.tag",
            "to": "to.parameters.tag",
        }
        for root_name, sub_path in legacy_sub_paths.items():
            if not any(target.path == root_name for target in targets):
                continue
            value = self._get_path_value(packet, sub_path)
            if value is _MISSING or value is None:
                continue
            targets.append(MutationTarget(layer="model", path=sub_path))

        return tuple(targets)

    def _normalize_target_name(self, target: MutationTarget) -> str:
        if target.layer == "model":
            raw_name = target.path.strip()
            if raw_name in _SUPPORTED_MODEL_TARGETS:
                return raw_name

            canonical_name = _MODEL_TARGET_ALIASES.get(raw_name.lower())
            if canonical_name is not None:
                return canonical_name

            normalized = raw_name.lower().replace("-", "_")
            if "." in normalized:
                raise ValueError(f"unsupported model target path: {target.path}")
            return normalized

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

        if target.layer == "byte":
            raw_name = target.path.strip()
            if byte_match := _BYTE_INDEX_PATTERN.fullmatch(raw_name):
                return f"byte[{int(byte_match.group(1))}]"

            if range_match := _BYTE_RANGE_PATTERN.fullmatch(raw_name):
                start = int(range_match.group(1))
                end = int(range_match.group(2))
                return f"range[{start}:{end}]"

            canonical_name = _BYTE_TARGET_ALIASES.get(raw_name.lower())
            if canonical_name is None:
                raise ValueError(f"unsupported byte target path: {target.path}")
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
        category = self._resolve_field_category(packet, canonical_path)
        before_value = self._get_path_value(packet, canonical_path)
        if before_value is _MISSING or before_value is None:
            raise ValueError(
                f"model target is not available on packet: {canonical_path}"
            )

        payload = self._build_packet_payload(packet)
        payload_value = self._get_path_value(payload, canonical_path)

        after_value = self._build_model_value(
            target_path=canonical_path,
            current_value=payload_value,
            category=category,
            rng=rng,
        )

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
                candidate.path == selected_target.path
                for candidate in available_targets
            ):
                raise ValueError(
                    f"model target is not available for packet: {selected_target.path}"
                )
            operator = self._resolve_model_operator(selected_target, packet)
            try:
                mutated_packet, record = self._apply_model_operator(
                    packet,
                    selected_target,
                    operator,
                    rng,
                )
            except (ValidationError, ValueError) as exc:
                raise ValueError(
                    f"model target could not be mutated: {selected_target.path}"
                ) from exc
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
        current_packet = packet
        records: list[MutationRecord] = []

        while remaining_targets and len(records) < config.max_operations:
            selected_index = rng.randrange(len(remaining_targets))
            selected_target = remaining_targets.pop(selected_index)
            operator = self._resolve_model_operator(selected_target, current_packet)
            try:
                current_packet, record = self._apply_model_operator(
                    current_packet,
                    selected_target,
                    operator,
                    rng,
                )
            except (ValidationError, ValueError):
                continue
            records.append(record)

        if not records:
            raise ValueError("no model mutation targets available for packet")

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

        if effective_layer == "byte":
            editable_message = self._to_editable_message(packet)
            editable_bytes = self._to_packet_bytes(editable_message)
            byte_target = target if target is None or target.layer == "byte" else None
            return self._mutate_bytes(
                packet=packet,
                editable_bytes=editable_bytes,
                config=config,
                context=context,
                target=byte_target,
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

    def _resolve_model_operator(
        self,
        target: MutationTarget,
        packet: PacketModel | None = None,
    ) -> str:
        if target.path in _MODEL_TARGET_OPERATORS:
            operator = _MODEL_TARGET_OPERATORS[target.path]
        else:
            if packet is None:
                raise ValueError(
                    f"packet required to resolve operator for: {target.path}"
                )
            category = self._resolve_field_category(packet, target.path)
            category_operators = {
                "string": "replace_text",
                "integer": "replace_integer",
                "float_": "replace_float",
                "boolean": "flip_boolean",
                "str_tuple": "mutate_str_tuple",
                "name_address": "corrupt_name_address",
                "name_address_list": "corrupt_name_address_list",
                "via_list": "corrupt_via",
                "cseq": "replace_integer",
                "event": "corrupt_event",
                "subscription_state": "corrupt_subscription_state",
                "rack": "corrupt_rack",
                "uri_reference": "replace_host",
                "addr_or_uri_list": "corrupt_addr_or_uri_list",
                "addr_or_uri_tuple": "corrupt_addr_or_uri_tuple",
            }
            operator = category_operators.get(category)
            if operator is None:
                raise ValueError(f"no operator for category: {category}")

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
            if strategy not in {"default", "identity"}:
                raise ValueError(f"unsupported wire mutation strategy: {strategy}")
            return
        if layer == "byte":
            if strategy not in {"default", "identity"}:
                raise ValueError(f"unsupported byte mutation strategy: {strategy}")
            return
        raise ValueError(f"unsupported mutation layer: {layer}")

    def _build_model_value(
        self,
        *,
        target_path: str,
        current_value: Any,
        category: str,
        rng: random.Random,
    ) -> Any:
        token = f"mut-{rng.getrandbits(32):08x}"
        host = f"{token}.invalid"

        if target_path in {"from_.parameters.tag", "to.parameters.tag"}:
            return token
        if target_path == "cseq.sequence":
            return self._mutate_bounded_integer(
                current_value=int(current_value),
                modulus=2**31,
                rng=rng,
            )
        if target_path == "request_uri.host":
            return host
        if target_path == "max_forwards":
            return self._mutate_bounded_integer(
                current_value=int(current_value),
                modulus=256,
                rng=rng,
            )

        if category == "string":
            return token
        if category == "integer":
            return self._mutate_bounded_integer(
                current_value=int(current_value),
                modulus=2**31,
                rng=rng,
            )
        if category == "float_":
            return round(float(current_value) + rng.uniform(-100.0, 100.0), 3)
        if category == "boolean":
            return not current_value
        if category == "str_tuple":
            items = list(current_value)
            if not items:
                return (token,)
            operation_choices = ["add", "replace"]
            if len(items) > 1:
                operation_choices.insert(0, "remove")
            operation = operation_choices[rng.randrange(len(operation_choices))]
            if operation == "remove":
                items.pop(rng.randrange(len(items)))
            elif operation == "add":
                items.insert(rng.randrange(len(items) + 1), token)
            else:
                items[rng.randrange(len(items))] = token
            return tuple(items)
        if category == "name_address":
            mutated_value = dict(current_value)
            uri = dict(mutated_value["uri"])
            if "host" in uri:
                uri["host"] = host
            elif "uri" in uri:
                uri["uri"] = f"https://{host}"
            mutated_value["uri"] = uri
            return mutated_value
        if category == "name_address_list":
            mutated_value = [dict(item) for item in current_value]
            first = dict(mutated_value[0])
            uri = dict(first["uri"])
            if "host" in uri:
                uri["host"] = host
            elif "uri" in uri:
                uri["uri"] = f"https://{host}"
            first["uri"] = uri
            mutated_value[0] = first
            return mutated_value
        if category == "via_list":
            mutated_value = [dict(item) for item in current_value]
            first = dict(mutated_value[0])
            first["host"] = host
            first["branch"] = f"z9hG4bK-{token}"
            mutated_value[0] = first
            return mutated_value
        if category == "cseq":
            mutated_value = dict(current_value)
            mutated_value["sequence"] = self._mutate_bounded_integer(
                current_value=int(mutated_value["sequence"]),
                modulus=2**31,
                rng=rng,
            )
            return mutated_value
        if category == "event":
            mutated_value = dict(current_value)
            mutated_value["package"] = token
            return mutated_value
        if category == "subscription_state":
            mutated_value = dict(current_value)
            mutated_value["state"] = token
            return mutated_value
        if category == "rack":
            mutated_value = dict(current_value)
            mutated_value["response_num"] = self._mutate_bounded_integer(
                current_value=int(mutated_value["response_num"]),
                modulus=2**31,
                rng=rng,
            )
            return mutated_value
        if category == "uri_reference":
            mutated_value = dict(current_value)
            if "host" in mutated_value:
                mutated_value["host"] = host
            elif "uri" in mutated_value:
                mutated_value["uri"] = f"https://{host}"
            return mutated_value
        if category in {"addr_or_uri_list", "addr_or_uri_tuple"}:
            items = [dict(item) for item in current_value]
            first = dict(items[0])
            if "uri" in first and isinstance(first["uri"], dict):
                uri = dict(first["uri"])
                if "host" in uri:
                    uri["host"] = host
                elif "uri" in uri:
                    uri["uri"] = f"https://{host}"
                first["uri"] = uri
            elif "host" in first:
                first["host"] = host
            elif "uri" in first:
                first["uri"] = f"https://{host}"
            items[0] = first
            if category == "addr_or_uri_tuple":
                return tuple(items)
            return items
        raise ValueError(f"unsupported model target path: {target_path}")

    def _resolve_field_category(self, packet: PacketModel, path: str) -> str:
        legacy_path_categories = {
            "cseq.sequence": "integer",
            "request_uri.host": "string",
            "from_.parameters.tag": "string",
            "to.parameters.tag": "string",
        }
        if path in legacy_path_categories:
            return legacy_path_categories[path]

        root_name = path.split(".", 1)[0]
        field_info = packet.__class__.model_fields.get(root_name)
        if field_info is None:
            raise ValueError(f"unknown model field: {root_name}")
        value = getattr(packet, root_name)
        return _classify_field(root_name, field_info.annotation, value)

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
        definition: PacketDefinition | None = None,
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
        if operator == "mutate_header_value":
            return self._mutate_wire_header_value(editable_message, target, rng)
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
            operator = self._resolve_wire_operator(
                selected_target, current_message, rng
            )
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
                    for candidate in self._collect_wire_targets(
                        current_message, self._resolve_packet_definition(packet)
                    )
                    if candidate.path not in used_paths
                )
                if not available_targets:
                    break

                selected_target = available_targets[
                    rng.randrange(len(available_targets))
                ]
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

    def _to_packet_bytes(
        self,
        editable_message: EditableSIPMessage,
    ) -> EditablePacketBytes:
        return EditablePacketBytes.from_message(editable_message)

    def _collect_byte_targets(
        self,
        editable_bytes: EditablePacketBytes,
    ) -> tuple[MutationTarget, ...]:
        data = editable_bytes.data
        if not data:
            return ()

        targets: list[MutationTarget] = [
            MutationTarget(layer="byte", path=f"byte[{index}]")
            for index in range(len(data))
        ]
        targets.extend(
            MutationTarget(layer="byte", path=f"range[{index}:{index + 1}]")
            for index in range(len(data))
        )

        if self._find_crlf_offsets(data):
            targets.append(MutationTarget(layer="byte", path="delimiter:CRLF"))

        targets.append(MutationTarget(layer="byte", path="segment:start_line"))
        return tuple(targets)

    def _apply_byte_operator(
        self,
        editable_bytes: EditablePacketBytes,
        target: MutationTarget,
        operator: str,
        rng: random.Random,
    ) -> tuple[EditablePacketBytes, MutationRecord]:
        data = editable_bytes.data

        if operator == "flip_byte":
            index = self._parse_byte_index(target.path)
            before = data[index]
            mask = 1 << rng.randrange(8)
            after = before ^ mask
            mutated_bytes = editable_bytes.overwrite(index, bytes([after]))
            record = self._record_mutation(
                target=target,
                operator=operator,
                before=before,
                after=after,
            )
            return mutated_bytes, record

        if operator == "insert_bytes":
            start, end = self._start_line_range(data)
            del start
            insert_at = end
            inserted = bytes([0xFF, rng.randrange(256)])
            mutated_bytes = editable_bytes.insert(insert_at, inserted)
            record = self._record_mutation(
                target=target,
                operator=operator,
                before=b"",
                after=inserted,
            )
            return mutated_bytes, record

        if operator == "delete_range":
            start, end = self._parse_byte_range(target.path)
            before = data[start:end]
            mutated_bytes = editable_bytes.delete(start, end)
            record = self._record_mutation(
                target=target,
                operator=operator,
                before=before,
                after=b"",
            )
            return mutated_bytes, record

        if operator == "truncate_bytes":
            _start, end = self._start_line_range(data)
            truncation_length = rng.randrange(end + 1)
            before = data
            mutated_bytes = editable_bytes.truncate(truncation_length)
            record = self._record_mutation(
                target=target,
                operator=operator,
                before=before[:end],
                after=mutated_bytes.data,
            )
            return mutated_bytes, record

        if operator == "damage_crlf":
            offsets = self._find_crlf_offsets(data)
            offset = offsets[rng.randrange(len(offsets))]
            before = data[offset : offset + len(_CRLF_DELIMITER)]
            mutated_bytes = editable_bytes.delete(offset, offset + 1)
            after = mutated_bytes.data[offset : offset + 1]
            record = self._record_mutation(
                target=target,
                operator=operator,
                before=before,
                after=after,
            )
            return mutated_bytes, record

        raise ValueError(f"unsupported byte operator: {operator}")

    def _mutate_bytes(
        self,
        *,
        packet: PacketModel,
        editable_bytes: EditablePacketBytes,
        config: MutationConfig,
        context: DialogContext | None,
        target: MutationTarget | None,
    ) -> MutatedCase:
        self._snapshot_context(context)
        rng = self._rng_from_seed(config.seed)
        current_bytes = editable_bytes
        records: list[MutationRecord] = []

        if target is not None:
            selected_target = self._build_canonical_byte_target(target, current_bytes)
            operator = self._resolve_byte_operator(selected_target, rng)
            current_bytes, record = self._apply_byte_operator(
                current_bytes,
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
                    for candidate in self._collect_byte_targets(current_bytes)
                    if candidate.path not in used_paths
                )
                if not available_targets:
                    break

                selected_target = available_targets[
                    rng.randrange(len(available_targets))
                ]
                operator = self._resolve_byte_operator(selected_target, rng)
                current_bytes, record = self._apply_byte_operator(
                    current_bytes,
                    selected_target,
                    operator,
                    rng,
                )
                used_paths.add(selected_target.path)
                records.append(record)

        return MutatedCase(
            original_packet=packet,
            packet_bytes=self._finalize_packet_bytes(current_bytes),
            records=tuple(records),
            seed=config.seed,
            strategy=config.strategy,
            final_layer="byte",
        )

    def _finalize_packet_bytes(self, editable_bytes: EditablePacketBytes) -> bytes:
        return editable_bytes.data

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

    def _build_canonical_byte_target(
        self,
        target: MutationTarget,
        editable_bytes: EditablePacketBytes,
    ) -> MutationTarget:
        canonical_path = self._normalize_target_name(target)
        alias = target.alias
        if alias is None and target.path != canonical_path:
            alias = target.path

        data = editable_bytes.data
        if canonical_path.startswith("byte["):
            index = self._parse_byte_index(canonical_path)
            if index >= len(data):
                raise ValueError(
                    f"byte target is not available for packet: {canonical_path}"
                )
        elif canonical_path.startswith("range["):
            start, end = self._parse_byte_range(canonical_path)
            if start >= len(data) or end > len(data):
                raise ValueError(
                    f"byte target is not available for packet: {canonical_path}"
                )
        elif canonical_path == "delimiter:CRLF":
            if not self._find_crlf_offsets(data):
                raise ValueError(
                    f"byte target is not available for packet: {canonical_path}"
                )
        elif canonical_path == "segment:start_line":
            if not data:
                raise ValueError(
                    f"byte target is not available for packet: {canonical_path}"
                )

        return MutationTarget(
            layer="byte",
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
            operators = ["remove_header", "duplicate_header", "mutate_header_value"]
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

    def _resolve_byte_operator(
        self,
        target: MutationTarget,
        rng: random.Random,
    ) -> str:
        if target.path.startswith("byte["):
            operators = ("flip_byte",)
        elif target.path.startswith("range["):
            operators = ("delete_range",)
        elif target.path == "delimiter:CRLF":
            operators = ("damage_crlf",)
        elif target.path == "segment:start_line":
            operators = ("truncate_bytes", "insert_bytes")
        else:
            raise ValueError(f"unsupported byte target path: {target.path}")

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
        mutated_message = editable_message.model_copy(
            update={"headers": filtered_headers}
        )
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
        mutated_message = editable_message.model_copy(
            update={"headers": tuple(headers)}
        )
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

    def _mutate_wire_header_value(
        self,
        editable_message: EditableSIPMessage,
        target: MutationTarget,
        rng: random.Random,
    ) -> tuple[EditableSIPMessage, MutationRecord]:
        index = self._select_header_index(editable_message, target, rng)
        headers = list(editable_message.headers)
        original_header = headers[index]
        strategy = rng.choice(
            (
                "empty",
                "overflow",
                "garbage",
                "wrong_format",
                "crlf_inject",
                "null_byte",
            )
        )

        if strategy == "empty":
            mutated_value = ""
        elif strategy == "overflow":
            mutated_value = "X" * rng.randint(1000, 5000)
        elif strategy == "garbage":
            mutated_value = rng.randbytes(rng.randint(10, 100)).hex()
        elif strategy == "wrong_format":
            mutated_value = str(rng.randint(0, 99999))
        elif strategy == "crlf_inject":
            mutated_value = f"injected\r\nEvil-Header: mut-{rng.getrandbits(32):08x}"
        else:
            mutated_value = f"before\x00after-{rng.getrandbits(16):04x}"

        headers[index] = EditableHeader(
            name=original_header.name,
            value=mutated_value,
        )
        mutated_message = editable_message.model_copy(
            update={"headers": tuple(headers)}
        )
        record = self._record_mutation(
            target=target,
            operator="mutate_header_value",
            before=(original_header.name, original_header.value),
            after=(original_header.name, mutated_value),
            note=f"sub_strategy={strategy}",
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
        mutated_message = editable_message.model_copy(
            update={"headers": tuple(headers)}
        )
        record = self._record_mutation(
            target=target,
            operator="shuffle_header",
            before={
                "index": original_index,
                "header": self._header_snapshot(selected_header),
            },
            after={
                "index": destination_index,
                "header": self._header_snapshot(selected_header),
            },
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

    def _parse_byte_index(self, path: str) -> int:
        byte_match = _BYTE_INDEX_PATTERN.fullmatch(path)
        if byte_match is None:
            raise ValueError(f"unsupported byte target path: {path}")
        return int(byte_match.group(1))

    def _parse_byte_range(self, path: str) -> tuple[int, int]:
        range_match = _BYTE_RANGE_PATTERN.fullmatch(path)
        if range_match is None:
            raise ValueError(f"unsupported byte target path: {path}")
        start = int(range_match.group(1))
        end = int(range_match.group(2))
        if end <= start:
            raise ValueError(f"unsupported byte target path: {path}")
        return start, end

    def _find_crlf_offsets(self, data: bytes) -> list[int]:
        offsets: list[int] = []
        start = 0
        while True:
            offset = data.find(_CRLF_DELIMITER, start)
            if offset < 0:
                break
            offsets.append(offset)
            start = offset + 1
        return offsets

    def _start_line_range(self, data: bytes) -> tuple[int, int]:
        first_crlf = data.find(_CRLF_DELIMITER)
        if first_crlf < 0:
            return (0, len(data))
        return (0, first_crlf)


__all__ = ["PacketDefinition", "SIPMutator", "MutatedWireCase"]
