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
    profile: str,
    strategy: str,
    layer: str,
    seed: int | None,
    max_operations: int = 1,
) -> MutationConfig:
    return MutationConfig(
        profile=profile,
        strategy=strategy,
        layer=layer,
        seed=seed,
        max_operations=max_operations,
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
    max_operations: int = 1,
    multi_mutation_option_name: str = "--mutations-per-case",
) -> MutatedCase:
    try:
        resolved_layer = _resolve_cli_layer(profile, strategy, layer)
        config = _build_config(profile, strategy, resolved_layer, seed, max_operations)
        mutation_target = _build_target(target, resolved_layer)
        mutator = SIPMutator()
        case = _apply_profile(
            _execute_mutation(mutator, packet, config, mutation_target, context),
            config.profile,
        )
        # ``--target`` pins mutation to a specific path and the explicit-target
        # branches in the mutator only apply a single op before returning.
        # Warn only after the mutation succeeds so invalid target/profile
        # combinations fail with their real error instead of a misleading
        # "ignored" banner.
        if mutation_target is not None and max_operations > 1:
            typer.secho(
                f"warning: {multi_mutation_option_name}={max_operations} ignored because "
                "--target is set; explicit-target mutations are single-shot. "
                "Drop --target to apply multiple rounds.",
                fg=typer.colors.YELLOW,
                err=True,
            )
        return case
    except (ValidationError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc


def _render_result(case: MutatedCase) -> str:
    # ``mode="python"`` keeps ``bytes`` as ``bytes`` instead of running
    # pydantic's UTF-8 decode for ``mode="json"``. Byte-layer mutations
    # legitimately produce non-UTF-8 buffers (e.g. flip_byte ``0x20`` →
    # ``0xe9``), so the JSON serializer's strict UTF-8 path was crashing
    # the entire output. We re-encode via latin-1 below — every byte maps
    # 1:1 to a code point, so the round-trip is lossless and the JSON
    # output stays human-readable.
    payload = case.model_dump(mode="python", by_alias=True, exclude_none=True)

    # The on-the-wire SIP text gets split into two outputs so neither path is
    # awkward to read:
    #   1. ``raw_wire_text`` stays inside the JSON payload, byte-exact with
    #      ``\r\n`` line separators, for byte-level inspection.
    #   2. The human-friendly LF-only form is rendered *above* the JSON as
    #      a separate block so SIP messages display with real line breaks
    #      instead of escaped ``\n`` runs inside a JSON string.
    # Wire-layer mutations populate ``wire_text`` (str); byte-layer mutations
    # populate ``packet_bytes`` (bytes) — normalise both to a latin-1 string
    # under the same ``raw_wire_text`` banner.
    formatted_wire: str | None = None
    for source_key in ("wire_text", "packet_bytes"):
        if source_key in payload:
            raw_value = payload.pop(source_key)
            raw_text = (
                raw_value.decode("latin-1")
                if isinstance(raw_value, (bytes, bytearray))
                else str(raw_value)
            )
            payload["raw_wire_text"] = raw_text
            formatted_wire = raw_text.replace("\r\n", "\n")
            break

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

    # Pin-point each record onto a specific line/column of the wire form.
    # ``mutation_diff`` shows *what* changed; this block shows *where* in
    # the rendered SIP message — line, column, the affected line itself,
    # plus a ``^`` pointer when we know the column. Spotting a single
    # byte flip in a 50-line packet without this is impractical.
    raw_wire = payload.get("raw_wire_text")
    change_context: list[str] = []
    if raw_wire and records:
        change_context = _format_change_context(records, raw_wire)

    json_block = json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        # Safety net: any stray ``bytes`` left over from ``mode="python"``
        # (e.g. nested in ``records[*].before/after`` Any fields) gets
        # latin-1-decoded so it never aborts the whole output.
        default=lambda obj: obj.decode("latin-1") if isinstance(obj, (bytes, bytearray)) else repr(obj),
    )
    if formatted_wire is None:
        return json_block

    parts = [
        "=== wire_text ===",
        formatted_wire.rstrip("\n"),
        "",
    ]
    if change_context:
        parts.append("=== change context ===")
        parts.extend(change_context)
        parts.append("")
    parts.append("=== mutation_result (json) ===")
    parts.append(json_block)
    return "\n".join(parts)


def _format_change_context(records: list, raw_wire: str) -> list[str]:
    """Render each record as ``@ target  line N, col M`` + the affected
    line + a column ``^`` pointer when applicable.

    ``raw_wire`` is the ``\r\n``-separated wire form. Byte indices into
    that buffer are translated to (line_index, col_index_in_line) so the
    pointer lands on the correct character.
    """
    out: list[str] = []
    formatted_lines = raw_wire.replace("\r\n", "\n").split("\n")

    for record in records:
        target = (record.get("target") or {}).get("path", "")
        operator = record.get("operator", "?")
        note = record.get("note")

        line_num = -1
        col = -1
        if target.startswith("byte["):
            try:
                idx = int(target[len("byte[") : -1])
            except ValueError:
                idx = -1
            if idx >= 0:
                line_num, col = _byte_index_to_line_col(raw_wire, idx)
        elif target.startswith("range["):
            try:
                start_str = target[len("range[") : -1].split(":")[0]
                idx = int(start_str)
            except (ValueError, IndexError):
                idx = -1
            if idx >= 0:
                line_num, col = _byte_index_to_line_col(raw_wire, idx)
        elif target.startswith("header["):
            try:
                hdr_idx = int(target[len("header[") : -1])
            except ValueError:
                hdr_idx = -1
            if hdr_idx >= 0:
                # header[N] = (N+1)th line — start_line is at index 0.
                line_num = hdr_idx + 1

        suffix = f"  operator={operator}"
        if note:
            suffix += f"  note={note}"
        if line_num < 0:
            out.append(f"@ {target or '?'}{suffix}  (location not resolvable)")
            continue

        coord = f"line {line_num + 1}"
        if col >= 0:
            coord += f", col {col}"
        out.append(f"@ {target}  {coord}{suffix}")

        if 0 <= line_num < len(formatted_lines):
            line_text = formatted_lines[line_num]
            out.append(f"  {_escape_visible(line_text)}")
            if col >= 0 and col <= len(line_text):
                out.append(f"  {' ' * col}^")
        else:
            out.append("  (line out of range)")

    return out


def _byte_index_to_line_col(raw_wire: str, byte_idx: int) -> tuple[int, int]:
    """Locate ``byte_idx`` (offset into the CRLF-encoded wire buffer) as a
    (line_index, col_index_in_line) pair.

    Uses the byte length of each line to walk the buffer so multi-byte
    UTF-8 doesn't off-by-one the result; SIP text is normally ASCII but
    fuzz mutations may inject non-ASCII bytes.
    """
    encoded = raw_wire.encode("utf-8")
    if not 0 <= byte_idx < len(encoded):
        return -1, -1
    pos = 0
    for line_num, line in enumerate(raw_wire.split("\r\n")):
        line_bytes = len(line.encode("utf-8"))
        # Each split chunk except the last is followed by a \r\n.
        terminator_bytes = 2 if line_num < raw_wire.count("\r\n") else 0
        end = pos + line_bytes + terminator_bytes
        if byte_idx < end:
            col = byte_idx - pos
            return line_num, col
        pos = end
    return -1, -1


def _format_record_side(value: object) -> str:
    """Render a record's before/after side as a single readable line.

    Control characters (\t, \r, \n, \x00, ...) and high-bit bytes are made
    visible via ``repr``-style escapes; structured snapshots (header dicts,
    name/value tuples) are flattened to ``Name<separator>Value``; raw byte
    values from byte-layer ops (e.g. ``flip_byte`` records ``before=32``,
    ``after=48``) are decorated with hex + printable-char so the diff is
    self-explanatory.
    """
    if value is None:
        return "<none>"
    if isinstance(value, bool):
        # bool is a subclass of int — handle before the int branch so True/False
        # don't render as 0x01/0x00.
        return repr(value)
    if isinstance(value, int):
        return _format_byte_value(value)
    if isinstance(value, (bytes, bytearray)):
        if len(value) == 0:
            return "b''"
        if len(value) == 1:
            return _format_byte_value(value[0])
        # Show hex + ASCII-ish rendition for short byte sequences.
        hex_part = " ".join(f"{b:02x}" for b in value)
        ascii_part = _escape_visible(value.decode("latin-1"))
        return f"{hex_part}  ({ascii_part})"
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
        # Raw byte sequences (e.g. delete_range records ``(0x42, 0x59)``):
        # render as space-separated hex.
        if value and all(isinstance(part, int) and 0 <= part <= 0xFF for part in value):
            return " ".join(_format_byte_value(part) for part in value)
        return _escape_visible(repr(list(value)))
    if isinstance(value, str):
        return _escape_visible(value)
    return _escape_visible(repr(value))


def _format_byte_value(byte: int) -> str:
    """Render a single byte (0-255) as ``0xNN (' x ')`` when printable else ``0xNN``."""
    if not 0 <= byte <= 0xFF:
        return repr(byte)
    if 0x20 <= byte <= 0x7E:
        return f"0x{byte:02x} ({chr(byte)!r})"
    return f"0x{byte:02x}"


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
    max_operations: Annotated[
        int,
        typer.Option(
            "--max-operations",
            help="Number of mutation rounds to apply per case (default 1). "
            "Each round operates on the result of the previous one, so multiple "
            "single-shot strategies (null_byte_only / boundary_only / byte_edit_only) "
            "stack their effects. Combine with deterministic strategies for "
            "compound fuzz pressure.",
        ),
    ] = 1,
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
        max_operations=max_operations,
        multi_mutation_option_name="--max-operations",
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
    max_operations: Annotated[
        int,
        typer.Option(
            "--mutations-per-case",
            help="Number of mutation rounds to apply per case (default 1).",
        ),
    ] = 1,
) -> None:
    """Generate a SIP request baseline and mutate it."""
    generator = SIPGenerator(GeneratorSettings.from_env(prefix=None))
    spec = RequestSpec(method=method)
    try:
        # Pass the same seed used for mutation through to baseline generation
        # so transaction-unique IDs (Call-ID / branch / tag / nonce / icid)
        # are reproducible too — without this, two runs with identical
        # ``--seed`` produce byte-different wires (the mutation is the same,
        # but the IDs are fresh ``uuid4`` every time).
        packet = generator.generate_request(spec, None, seed=seed)
    except (ValidationError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    case = _run_mutation_command(
        packet,
        profile=profile,
        strategy=strategy,
        layer=layer,
        seed=seed,
        target=target,
        max_operations=max_operations,
        multi_mutation_option_name="--mutations-per-case",
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
    max_operations: Annotated[
        int,
        typer.Option(
            "--mutations-per-case",
            help="Number of mutation rounds to apply per case (default 1).",
        ),
    ] = 1,
) -> None:
    """Generate a SIP response baseline and mutate it."""
    dialog_context = _parse_context(context, required=True)
    assert dialog_context is not None

    generator = SIPGenerator(GeneratorSettings.from_env(prefix=None))
    spec = ResponseSpec(status_code=status_code, related_method=related_method)
    try:
        # Same reasoning as ``request_command``: forward the seed so the
        # generated baseline is byte-exact reproducible.
        packet = generator.generate_response(spec, dialog_context, seed=seed)
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
        max_operations=max_operations,
        multi_mutation_option_name="--mutations-per-case",
    )
    typer.echo(_render_result(case))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
