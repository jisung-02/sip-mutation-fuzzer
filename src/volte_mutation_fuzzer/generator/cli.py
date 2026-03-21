from __future__ import annotations

import json
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
from volte_mutation_fuzzer.mutator.cli import app as mutator_app
from volte_mutation_fuzzer.sender.cli import app as sender_app
from volte_mutation_fuzzer.sip.common import SIPMethod
from volte_mutation_fuzzer.sip.requests import SIPRequest
from volte_mutation_fuzzer.sip.responses import SIPResponse

app = typer.Typer(
    add_completion=False,
    help="Generate baseline SIP request/response packets from the catalog.",
)
app.add_typer(mutator_app, name="mutate")
app.add_typer(sender_app, name="send")


def _parse_json_object(raw_value: str | None, *, option_name: str) -> dict[str, Any]:
    if raw_value is None:
        return {}

    try:
        value = json.loads(raw_value)
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(
            f"must be valid JSON: {exc.msg}",
            param_hint=option_name,
        ) from exc

    if not isinstance(value, dict):
        raise typer.BadParameter(
            "must be a JSON object",
            param_hint=option_name,
        )

    return value


def _parse_context(raw_value: str | None, *, required: bool) -> DialogContext | None:
    if raw_value is None:
        if required:
            raise typer.BadParameter(
                "must be provided as a JSON object", param_hint="--context"
            )
        return None

    payload = _parse_json_object(raw_value, option_name="--context")

    try:
        return DialogContext.model_validate(payload)
    except ValidationError as exc:
        raise typer.BadParameter(str(exc), param_hint="--context") from exc


def _build_generator(*, env_prefix: str | None) -> SIPGenerator:
    settings = GeneratorSettings.from_env(prefix=env_prefix)
    return SIPGenerator(settings)


def _render_packet(packet: SIPRequest | SIPResponse) -> str:
    payload = packet.model_dump(mode="json", by_alias=True, exclude_none=True)
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


@app.command("request")
def request_command(
    method: SIPMethod,
    scenario: Annotated[str | None, typer.Option("--scenario")] = None,
    body_kind: Annotated[str | None, typer.Option("--body-kind")] = None,
    override: Annotated[
        str | None,
        typer.Option("--override", help="Top-level override JSON object."),
    ] = None,
    context: Annotated[
        str | None,
        typer.Option("--context", help="Optional DialogContext JSON object."),
    ] = None,
    env_prefix: Annotated[
        str | None,
        typer.Option("--env-prefix", help="Override the generator env prefix."),
    ] = None,
) -> None:
    generator = _build_generator(env_prefix=env_prefix)
    spec = RequestSpec(
        method=method,
        scenario=scenario,
        body_kind=body_kind,
        overrides=_parse_json_object(override, option_name="--override"),
    )
    dialog_context = _parse_context(context, required=False)

    try:
        packet = generator.generate_request(spec, dialog_context)
    except (ValidationError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    typer.echo(_render_packet(packet))


@app.command("response")
def response_command(
    status_code: int,
    related_method: SIPMethod,
    context: Annotated[
        str,
        typer.Option("--context", help="Required DialogContext JSON object."),
    ],
    scenario: Annotated[str | None, typer.Option("--scenario")] = None,
    override: Annotated[
        str | None,
        typer.Option("--override", help="Top-level override JSON object."),
    ] = None,
    env_prefix: Annotated[
        str | None,
        typer.Option("--env-prefix", help="Override the generator env prefix."),
    ] = None,
) -> None:
    generator = _build_generator(env_prefix=env_prefix)
    spec = ResponseSpec(
        status_code=status_code,
        related_method=related_method,
        scenario=scenario,
        overrides=_parse_json_object(override, option_name="--override"),
    )
    dialog_context = _parse_context(context, required=True)
    assert dialog_context is not None

    try:
        packet = generator.generate_response(spec, dialog_context)
    except (ValidationError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    typer.echo(_render_packet(packet))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
