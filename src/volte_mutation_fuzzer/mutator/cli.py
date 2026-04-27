import json
import sys
from typing import Annotated, Any

import typer
from pydantic import ValidationError

from volte_mutation_fuzzer.generator.contracts import (
    DialogContext,
    GeneratorSettings,
    RequestSpec,
    ResponseSpec,
)
from volte_mutation_fuzzer.generator.core import SIPGenerator
from volte_mutation_fuzzer.mutator.contracts import (
    MutatedCase,
    MutationConfig,
    MutationTarget,
    PacketModel,
)
from volte_mutation_fuzzer.mutator.core import SIPMutator
from volte_mutation_fuzzer.mutator.profile_catalog import (
    SUPPORTED_STRATEGIES_BY_LAYER,
    normalize_profile_name,
    profile_supports_strategy,
)
from volte_mutation_fuzzer.sip.common import SIPMethod
from volte_mutation_fuzzer.sip.requests import REQUEST_MODELS_BY_METHOD
from volte_mutation_fuzzer.sip.responses import SIPResponse

app = typer.Typer(
    add_completion=False,
    help="Mutate SIP packets using configurable strategies and layers.",
)

_AUTO_LAYER_ORDER = ("model", "wire", "byte")


def _parse_packet_json(raw_json: str) -> PacketModel:
    try:
        data: dict[str, Any] = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(
            f"Invalid value: {exc.msg}",
            param_hint="stdin",
        ) from exc

    if not isinstance(data, dict):
        raise typer.BadParameter(
            "Invalid value: must be a JSON object", param_hint="stdin"
        )

    try:
        if "method" in data:
            method = SIPMethod(data["method"])
            model_cls = REQUEST_MODELS_BY_METHOD[method]
            return model_cls.model_validate(data)
        else:
            return SIPResponse.model_validate(data)
    except (ValidationError, ValueError, KeyError) as exc:
        raise typer.BadParameter(f"Invalid value: {exc}", param_hint="stdin") from exc


def _parse_context(raw_value: str | None, *, required: bool) -> DialogContext | None:
    if raw_value is None:
        if required:
            raise typer.BadParameter(
                "must be provided as a JSON object", param_hint="--context"
            )
        return None

    try:
        data = json.loads(raw_value)
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(
            f"must be valid JSON: {exc.msg}", param_hint="--context"
        ) from exc

    if not isinstance(data, dict):
        raise typer.BadParameter("must be a JSON object", param_hint="--context")

    try:
        return DialogContext.model_validate(data)
    except ValidationError as exc:
        raise typer.BadParameter(str(exc), param_hint="--context") from exc


def _build_config(
    profile: str, strategy: str, layer: str, seed: int | None
) -> MutationConfig:
    return MutationConfig(
        profile=profile,
        strategy=strategy,
        layer=layer,
        seed=seed,
    )  # type: ignore[arg-type]


def _resolve_cli_layer(profile: str, strategy: str, layer: str) -> str:
    if layer != "auto":
        return layer

    normalized_profile = normalize_profile_name(profile)
    compatible_layers = tuple(
        candidate
        for candidate in _AUTO_LAYER_ORDER
        if profile_supports_strategy(normalized_profile, candidate, strategy)
    )
    if compatible_layers:
        return compatible_layers[0]

    globally_supported_layers = tuple(
        candidate
        for candidate in _AUTO_LAYER_ORDER
        if strategy in SUPPORTED_STRATEGIES_BY_LAYER.get(candidate, frozenset())
    )
    if not globally_supported_layers:
        raise ValueError(f"unsupported mutation strategy: {strategy}")

    raise ValueError(
        f"profile '{normalized_profile}' does not support strategy '{strategy}' "
        "on any layer"
    )


def _build_target(target: str | None, layer: str) -> MutationTarget | None:
    if target is None:
        return None
    return MutationTarget(layer=layer, path=target)  # type: ignore[arg-type]


def _execute_mutation(
    mutator: SIPMutator,
    packet: PacketModel,
    config: MutationConfig,
    mutation_target: MutationTarget | None,
    context: DialogContext | None = None,
) -> MutatedCase:
    if mutation_target is not None:
        return mutator.mutate_field(packet, mutation_target, config, context)
    return mutator.mutate(packet, config, context)


def _apply_profile(case: MutatedCase, profile: str) -> MutatedCase:
    if case.profile == profile:
        return case
    return case.model_copy(update={"profile": profile})


def _run_mutation_command(
    packet: PacketModel,
    *,
    profile: str,
    strategy: str,
    layer: str,
    seed: int | None,
    target: str | None,
    context: DialogContext | None = None,
) -> MutatedCase:
    try:
        resolved_layer = _resolve_cli_layer(profile, strategy, layer)
        config = _build_config(profile, strategy, resolved_layer, seed)
        mutation_target = _build_target(target, resolved_layer)
        mutator = SIPMutator()
        return _apply_profile(
            _execute_mutation(mutator, packet, config, mutation_target, context),
            config.profile,
        )
    except (ValidationError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc


def _render_result(case: MutatedCase) -> str:
    payload = case.model_dump(mode="json", by_alias=True, exclude_none=True)

    # The on-the-wire SIP text gets split into two outputs so neither path is
    # awkward to read:
    #   1. ``raw_wire_text`` stays inside the JSON payload, byte-exact with
    #      ``\r\n`` line separators, for byte-level inspection.
    #   2. The human-friendly LF-only form is rendered *above* the JSON as
    #      a separate block so SIP messages display with real line breaks
    #      instead of escaped ``\n`` runs inside a JSON string.
    formatted_wire: str | None = None
    if "wire_text" in payload:
        raw = payload.pop("wire_text")
        payload["raw_wire_text"] = raw
        formatted_wire = raw.replace("\r\n", "\n")

    # Records hold the structured before/after snapshots, but spotting *what*
    # changed inside a 50-line packet from those alone is tedious. Add a
    # ``mutation_diff`` block that renders each record as a unified-diff-ish
    # ``@ <target>`` / ``- before`` / ``+ after`` triple with control chars
    # made visible, so the diff is readable inline.
    records = payload.get("records") or []
    if records:
        diff_lines: list[str] = []
        for record in records:
            target = (record.get("target") or {}).get("path", "?")
            operator = record.get("operator", "?")
            note = record.get("note")
            header = f"@ {target}  operator={operator}"
            if note:
                header += f"  note={note}"
            diff_lines.append(header)
            diff_lines.append(f"  - {_format_record_side(record.get('before'))}")
            diff_lines.append(f"  + {_format_record_side(record.get('after'))}")
        payload["mutation_diff"] = diff_lines

    json_block = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if formatted_wire is None:
        return json_block
    return (
        "=== wire_text ===\n"
        f"{formatted_wire}\n"
        "=== mutation_result (json) ===\n"
        f"{json_block}"
    )


def _format_record_side(value: object) -> str:
    """Render a record's before/after side as a single readable line.

    Control characters (\t, \r, \n, \x00, ...) and high-bit bytes are made
    visible via ``repr``-style escapes; structured snapshots (header dicts,
    name/value tuples) are flattened to ``Name<separator>Value``.
    """
    if value is None:
        return "<none>"
    if isinstance(value, dict):
        # Header snapshot: {"name": ..., "separator": ..., "value": ...}
        if "name" in value and ("value" in value or "separator" in value):
            name = value.get("name", "")
            separator = value.get("separator", ": ")
            inner = value.get("value", "")
            return _escape_visible(f"{name}{separator}{inner}")
        return _escape_visible(repr(value))
    if isinstance(value, (list, tuple)):
        # mutate_header_value uses (name, value) tuples; duplicate_header
        # uses tuple of header snapshots; render either compactly.
        if len(value) == 2 and all(isinstance(part, str) for part in value):
            name, inner = value
            return _escape_visible(f"{name}: {inner}")
        return _escape_visible(repr(list(value)))
    if isinstance(value, str):
        return _escape_visible(value)
    return _escape_visible(repr(value))


def _escape_visible(text: str) -> str:
    """Make whitespace/control chars visible without breaking the line."""
    out: list[str] = []
    for ch in text:
        codepoint = ord(ch)
        if ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\x00":
            out.append("\\x00")
        elif codepoint < 0x20 or codepoint == 0x7F:
            out.append(f"\\x{codepoint:02x}")
        else:
            out.append(ch)
    return "".join(out)


_STRATEGY_HELP = (
    "Mutation strategy name. Examples: default, safe, header_targeted, "
    "final_crlf_loss, duplicate_content_length_conflict, tail_chop_1, "
    "tail_garbage, alias_port_desync."
)
_PROFILE_HELP = (
    "Mutation profile name. Examples: legacy, delivery_preserving, "
    "ims_specific, parser_breaker."
)


@app.command("packet")
def packet_command(
    profile: Annotated[
        str, typer.Option("--profile", help=_PROFILE_HELP)
    ] = "legacy",
    strategy: Annotated[
        str, typer.Option("--strategy", help=_STRATEGY_HELP)
    ] = "default",
    layer: Annotated[
        str,
        typer.Option(
            "--layer",
            help="Mutation layer: model, wire, byte, or auto (profile-aware).",
        ),
    ] = "auto",
    seed: Annotated[
        int | None, typer.Option("--seed", help="Random seed for reproducibility.")
    ] = None,
    target: Annotated[
        str | None, typer.Option("--target", help="Explicit mutation target path.")
    ] = None,
) -> None:
    """Mutate a SIP packet from JSON read on stdin."""
    raw = sys.stdin.read()
    packet = _parse_packet_json(raw)
    case = _run_mutation_command(
        packet,
        profile=profile,
        strategy=strategy,
        layer=layer,
        seed=seed,
        target=target,
    )
    typer.echo(_render_result(case))


@app.command("request")
def request_command(
    method: SIPMethod,
    profile: Annotated[
        str, typer.Option("--profile", help=_PROFILE_HELP)
    ] = "legacy",
    strategy: Annotated[
        str, typer.Option("--strategy", help=_STRATEGY_HELP)
    ] = "default",
    layer: Annotated[
        str,
        typer.Option(
            "--layer",
            help="Mutation layer: model, wire, byte, or auto (profile-aware).",
        ),
    ] = "auto",
    seed: Annotated[
        int | None, typer.Option("--seed", help="Random seed for reproducibility.")
    ] = None,
    target: Annotated[
        str | None, typer.Option("--target", help="Explicit mutation target path.")
    ] = None,
) -> None:
    """Generate a SIP request baseline and mutate it."""
    generator = SIPGenerator(GeneratorSettings.from_env(prefix=None))
    spec = RequestSpec(method=method)
    try:
        packet = generator.generate_request(spec, None)
    except (ValidationError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    case = _run_mutation_command(
        packet,
        profile=profile,
        strategy=strategy,
        layer=layer,
        seed=seed,
        target=target,
    )
    typer.echo(_render_result(case))


@app.command("response")
def response_command(
    status_code: int,
    related_method: SIPMethod,
    context: Annotated[
        str, typer.Option("--context", help="Required DialogContext JSON object.")
    ],
    profile: Annotated[
        str, typer.Option("--profile", help=_PROFILE_HELP)
    ] = "legacy",
    strategy: Annotated[
        str, typer.Option("--strategy", help=_STRATEGY_HELP)
    ] = "default",
    layer: Annotated[
        str,
        typer.Option(
            "--layer",
            help="Mutation layer: model, wire, byte, or auto (profile-aware).",
        ),
    ] = "auto",
    seed: Annotated[
        int | None, typer.Option("--seed", help="Random seed for reproducibility.")
    ] = None,
    target: Annotated[
        str | None, typer.Option("--target", help="Explicit mutation target path.")
    ] = None,
) -> None:
    """Generate a SIP response baseline and mutate it."""
    dialog_context = _parse_context(context, required=True)
    assert dialog_context is not None

    generator = SIPGenerator(GeneratorSettings.from_env(prefix=None))
    spec = ResponseSpec(status_code=status_code, related_method=related_method)
    try:
        packet = generator.generate_response(spec, dialog_context)
    except (ValidationError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    case = _run_mutation_command(
        packet,
        profile=profile,
        strategy=strategy,
        layer=layer,
        seed=seed,
        target=target,
        context=dialog_context,
    )
    typer.echo(_render_result(case))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
