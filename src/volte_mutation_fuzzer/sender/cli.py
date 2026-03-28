import json
import sys
from typing import Annotated, Any, cast

import typer
from pydantic import ValidationError

from volte_mutation_fuzzer.generator.contracts import (
    DialogContext,
    GeneratorSettings,
    RequestSpec,
    ResponseSpec,
)
from volte_mutation_fuzzer.generator.core import SIPGenerator
from volte_mutation_fuzzer.sender.contracts import (
    SendArtifact,
    SendReceiveResult,
    TargetEndpoint,
    TargetMode,
    TransportProtocol,
)
from volte_mutation_fuzzer.sender.core import SIPSenderReactor
from volte_mutation_fuzzer.sip.common import SIPMethod
from volte_mutation_fuzzer.sip.render import PacketModel
from volte_mutation_fuzzer.sip.requests import REQUEST_MODELS_BY_METHOD
from volte_mutation_fuzzer.sip.responses import SIPResponse

app = typer.Typer(
    add_completion=False,
    help="Send generated or mutated SIP artifacts to softphone or real-ue-direct targets and collect socket responses.",
)


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
        raise typer.BadParameter("must be a JSON object", param_hint=option_name)
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


def _parse_packet_data(data: dict[str, Any]) -> PacketModel:
    try:
        if "method" in data:
            method = SIPMethod(data["method"])
            return REQUEST_MODELS_BY_METHOD[method].model_validate(data)
        return SIPResponse.model_validate(data)
    except (ValidationError, ValueError, KeyError) as exc:
        raise typer.BadParameter(
            f"Invalid packet payload: {exc}", param_hint="stdin"
        ) from exc


def _parse_stdin_artifact(raw: str) -> SendArtifact:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return SendArtifact.from_wire_text(raw)

    if not isinstance(payload, dict):
        raise typer.BadParameter(
            "stdin must contain a JSON object or raw SIP text", param_hint="stdin"
        )

    if "final_layer" in payload:
        final_layer = payload.get("final_layer")
        if final_layer == "model":
            packet_payload = payload.get("mutated_packet") or payload.get(
                "original_packet"
            )
            if not isinstance(packet_payload, dict):
                raise typer.BadParameter(
                    "model mutation output must include a packet object",
                    param_hint="stdin",
                )
            return SendArtifact.from_packet(_parse_packet_data(packet_payload))
        if final_layer == "wire":
            wire_text = payload.get("wire_text")
            if not isinstance(wire_text, str):
                raise typer.BadParameter(
                    "wire mutation output must include wire_text", param_hint="stdin"
                )
            return SendArtifact.from_wire_text(wire_text)
        if final_layer == "byte":
            packet_bytes = payload.get("packet_bytes")
            if isinstance(packet_bytes, str):
                return SendArtifact.from_packet_bytes(packet_bytes.encode("utf-8"))
            raise typer.BadParameter(
                "byte mutation output must include packet_bytes text",
                param_hint="stdin",
            )

    return SendArtifact.from_packet(_parse_packet_data(payload))


def _build_target(
    *,
    host: str | None,
    port: int | None,
    msisdn: str | None,
    transport: str,
    mode: str,
    timeout_seconds: float,
    label: str | None,
) -> TargetEndpoint:
    if mode == "real-ue-direct" and host is not None and msisdn is not None:
        raise typer.BadParameter(
            "real-ue-direct requires exactly one of host or msisdn"
        )
    try:
        return TargetEndpoint(
            host=host,
            port=port,
            msisdn=msisdn,
            transport=cast(TransportProtocol, transport),
            mode=cast(TargetMode, mode),
            timeout_seconds=timeout_seconds,
            label=label,
        )
    except ValidationError as exc:
        raise typer.BadParameter(str(exc)) from exc


def _render_result(result: SendReceiveResult) -> str:
    payload = result.model_dump(mode="json", exclude_none=True)
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


@app.command("packet")
def packet_command(
    target_host: Annotated[
        str | None,
        typer.Option(
            "--target-host",
            help="Explicit target IP/host. Required outside real-ue-direct MSISDN resolution.",
        ),
    ] = None,
    target_port: Annotated[
        int | None,
        typer.Option(
            "--target-port",
            help="Explicit target port override. Defaults to 5060 unless MSISDN resolution returns a contact port.",
        ),
    ] = None,
    target_msisdn: Annotated[
        str | None,
        typer.Option(
            "--target-msisdn",
            help="Resolve a real UE contact from an MSISDN when using --mode real-ue-direct.",
        ),
    ] = None,
    transport: Annotated[str, typer.Option("--transport")] = "UDP",
    mode: Annotated[str, typer.Option("--mode")] = "softphone",
    timeout: Annotated[float, typer.Option("--timeout")] = 2.0,
    label: Annotated[str | None, typer.Option("--label")] = None,
    collect_all_responses: Annotated[
        bool,
        typer.Option(
            "--collect-all-responses",
            help="Keep reading provisional responses until timeout or a final response arrives.",
        ),
    ] = False,
) -> None:
    """Send a packet JSON object, mutator output JSON, or raw SIP text read from stdin."""
    artifact = _parse_stdin_artifact(sys.stdin.read())
    target = _build_target(
        host=target_host,
        port=target_port,
        msisdn=target_msisdn,
        transport=transport,
        mode=mode,
        timeout_seconds=timeout,
        label=label,
    )
    result = SIPSenderReactor().send_artifact(
        artifact,
        target,
        collect_all_responses=collect_all_responses,
    )
    typer.echo(_render_result(result))


@app.command("request")
def request_command(
    method: SIPMethod,
    target_host: Annotated[
        str | None,
        typer.Option(
            "--target-host",
            help="Explicit target IP/host. Required outside real-ue-direct MSISDN resolution.",
        ),
    ] = None,
    target_port: Annotated[
        int | None,
        typer.Option(
            "--target-port",
            help="Explicit target port override. Defaults to 5060 unless MSISDN resolution returns a contact port.",
        ),
    ] = None,
    target_msisdn: Annotated[
        str | None,
        typer.Option(
            "--target-msisdn",
            help="Resolve a real UE contact from an MSISDN when using --mode real-ue-direct.",
        ),
    ] = None,
    transport: Annotated[str, typer.Option("--transport")] = "UDP",
    mode: Annotated[str, typer.Option("--mode")] = "softphone",
    timeout: Annotated[float, typer.Option("--timeout")] = 2.0,
    label: Annotated[str | None, typer.Option("--label")] = None,
    scenario: Annotated[str | None, typer.Option("--scenario")] = None,
    body_kind: Annotated[str | None, typer.Option("--body-kind")] = None,
    override: Annotated[str | None, typer.Option("--override")] = None,
    context: Annotated[str | None, typer.Option("--context")] = None,
    env_prefix: Annotated[str | None, typer.Option("--env-prefix")] = None,
    collect_all_responses: Annotated[
        bool, typer.Option("--collect-all-responses")
    ] = False,
) -> None:
    """Generate a baseline request and immediately send it."""
    generator = SIPGenerator(GeneratorSettings.from_env(prefix=env_prefix))
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

    target = _build_target(
        host=target_host,
        port=target_port,
        msisdn=target_msisdn,
        transport=transport,
        mode=mode,
        timeout_seconds=timeout,
        label=label,
    )
    result = SIPSenderReactor().send_packet(
        packet,
        target,
        collect_all_responses=collect_all_responses,
    )
    typer.echo(_render_result(result))


@app.command("response")
def response_command(
    status_code: int,
    related_method: SIPMethod,
    context: Annotated[str, typer.Option("--context")],
    target_host: Annotated[
        str | None,
        typer.Option(
            "--target-host",
            help="Explicit target IP/host. Required outside real-ue-direct MSISDN resolution.",
        ),
    ] = None,
    target_port: Annotated[
        int | None,
        typer.Option(
            "--target-port",
            help="Explicit target port override. Defaults to 5060 unless MSISDN resolution returns a contact port.",
        ),
    ] = None,
    target_msisdn: Annotated[
        str | None,
        typer.Option(
            "--target-msisdn",
            help="Resolve a real UE contact from an MSISDN when using --mode real-ue-direct.",
        ),
    ] = None,
    transport: Annotated[str, typer.Option("--transport")] = "UDP",
    mode: Annotated[str, typer.Option("--mode")] = "softphone",
    timeout: Annotated[float, typer.Option("--timeout")] = 2.0,
    label: Annotated[str | None, typer.Option("--label")] = None,
    scenario: Annotated[str | None, typer.Option("--scenario")] = None,
    override: Annotated[str | None, typer.Option("--override")] = None,
    env_prefix: Annotated[str | None, typer.Option("--env-prefix")] = None,
    collect_all_responses: Annotated[
        bool, typer.Option("--collect-all-responses")
    ] = False,
) -> None:
    """Generate a baseline response and immediately send it."""
    dialog_context = _parse_context(context, required=True)
    assert dialog_context is not None

    generator = SIPGenerator(GeneratorSettings.from_env(prefix=env_prefix))
    spec = ResponseSpec(
        status_code=status_code,
        related_method=related_method,
        scenario=scenario,
        overrides=_parse_json_object(override, option_name="--override"),
    )
    try:
        packet = generator.generate_response(spec, dialog_context)
    except (ValidationError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    target = _build_target(
        host=target_host,
        port=target_port,
        msisdn=target_msisdn,
        transport=transport,
        mode=mode,
        timeout_seconds=timeout,
        label=label,
    )
    result = SIPSenderReactor().send_packet(
        packet,
        target,
        collect_all_responses=collect_all_responses,
    )
    typer.echo(_render_result(result))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
