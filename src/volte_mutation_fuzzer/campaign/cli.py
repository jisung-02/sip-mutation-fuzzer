import json
import sys
from pathlib import Path
from typing import Annotated

import typer

from volte_mutation_fuzzer.campaign.contracts import CampaignConfig
from volte_mutation_fuzzer.campaign.core import CampaignExecutor, ResultStore

app = typer.Typer(
    add_completion=False,
    help="Run mutation fuzzing campaigns and analyze results.",
)


def _parse_methods(raw: str | None) -> tuple[str, ...] | None:
    if raw is None:
        return None
    return tuple(method.strip().upper() for method in raw.split(",") if method.strip())


def _parse_response_codes(raw: str | None) -> tuple[int, ...] | None:
    if raw is None:
        return None
    return tuple(int(code.strip()) for code in raw.split(",") if code.strip())


@app.command("run")
def run_command(
    target_host: Annotated[
        str | None, typer.Option("--target-host", help="Target SIP host (auto-resolved from --target-msisdn if not provided).")
    ] = None,
    target_port: Annotated[
        int, typer.Option("--target-port", help="Target SIP port.")
    ] = 5060,
    methods: Annotated[
        str | None,
        typer.Option("--methods", help="Comma-separated SIP methods to fuzz."),
    ] = None,
    response_codes: Annotated[
        str | None,
        typer.Option(
            "--response-codes",
            help="Comma-separated SIP response codes to fuzz.",
        ),
    ] = None,
    with_dialog: Annotated[
        bool | None,
        typer.Option(
            "--with-dialog/--no-with-dialog",
            help="Use synthetic dialog context for request generation when needed.",
        ),
    ] = None,
    strategy: Annotated[
        str | None,
        typer.Option(
            "--strategy",
            help="Mutation strategy (default/state_breaker). Comma-separated for multiple.",
        ),
    ] = None,
    layer: Annotated[
        str | None,
        typer.Option(
            "--layer",
            help="Mutation layer (model/wire/byte). Comma-separated for multiple.",
        ),
    ] = None,
    max_cases: Annotated[
        int, typer.Option("--max-cases", help="Maximum number of test cases.")
    ] = 1000,
    timeout: Annotated[
        float, typer.Option("--timeout", help="Socket timeout in seconds.")
    ] = 5.0,
    cooldown: Annotated[
        float, typer.Option("--cooldown", help="Cooldown seconds between cases.")
    ] = 0.2,
    seed_start: Annotated[
        int, typer.Option("--seed-start", help="Starting seed value.")
    ] = 0,
    output: Annotated[
        str, typer.Option("--output", help="Output JSONL file path.")
    ] = "results/campaign.jsonl",
    process_name: Annotated[
        str,
        typer.Option(
            "--process-name", help="Process name to check for crash detection."
        ),
    ] = "baresip",
    no_process_check: Annotated[
        bool, typer.Option("--no-process-check", help="Disable process liveness check.")
    ] = False,
    transport: Annotated[
        str, typer.Option("--transport", help="Transport protocol (UDP/TCP).")
    ] = "UDP",
    mode: Annotated[
        str,
        typer.Option("--mode", help="Target mode (softphone/real-ue-direct)."),
    ] = "softphone",
    log_path: Annotated[
        str | None,
        typer.Option(
            "--log-path",
            help="Path to target process log file for stack trace detection.",
        ),
    ] = None,
    adb: Annotated[
        bool, typer.Option("--adb/--no-adb", help="Enable ADB logcat monitoring.")
    ] = False,
    adb_serial: Annotated[
        str | None, typer.Option("--adb-serial", help="ADB device serial.")
    ] = None,
    adb_buffers: Annotated[
        str | None,
        typer.Option("--adb-buffers", help="Comma-separated logcat buffers."),
    ] = None,
    pcap: Annotated[
        bool,
        typer.Option(
            "--pcap/--no-pcap",
            help="Enable per-case pcap capture via sudo tcpdump.",
        ),
    ] = False,
    pcap_dir: Annotated[
        str,
        typer.Option("--pcap-dir", help="Directory to store .pcap files."),
    ] = "results/pcap",
    pcap_interface: Annotated[
        str,
        typer.Option("--pcap-interface", help="Network interface for tcpdump."),
    ] = "any",
    target_msisdn: Annotated[
        str | None,
        typer.Option("--target-msisdn", help="UE MSISDN for real-ue-direct MT INVITE template mode."),
    ] = None,
    impi: Annotated[
        str | None,
        typer.Option("--impi", help="UE IMPI for MT INVITE Request-URI."),
    ] = None,
    mt_invite_template: Annotated[
        str | None,
        typer.Option("--mt-invite-template", help="MT INVITE template name (e.g. 'a31') or file path."),
    ] = None,
    ipsec_mode: Annotated[
        str | None,
        typer.Option(
            "--ipsec-mode",
            help="IPsec bypass strategy: 'null' (host spoofing, requires null encryption) or 'bypass' (docker exec, xfrm policy bypass).",
        ),
    ] = None,
    preserve_via: Annotated[
        bool,
        typer.Option("--preserve-via/--no-preserve-via", help="Do not rewrite Via host/port."),
    ] = False,
    preserve_contact: Annotated[
        bool,
        typer.Option("--preserve-contact/--no-preserve-contact", help="Do not rewrite Contact host/port."),
    ] = False,
    mo_contact_host: Annotated[
        str,
        typer.Option("--mo-contact-host", help="MO UE IP for MT INVITE Contact header."),
    ] = "10.20.20.9",
    mo_contact_port_pc: Annotated[
        int,
        typer.Option("--mo-contact-port-pc", help="MO UE protected client port for Contact."),
    ] = 31800,
    mo_contact_port_ps: Annotated[
        int,
        typer.Option("--mo-contact-port-ps", help="MO UE protected server port for Contact."),
    ] = 31100,
    from_msisdn: Annotated[
        str,
        typer.Option("--from-msisdn", help="Originating MSISDN for From/Contact in MT INVITE."),
    ] = "222222",
    mt_local_port: Annotated[
        int,
        typer.Option(
            "--mt-local-port",
            help="Fixed local UDP/TCP port for MT INVITE sends. Must match Via sent-by so responses come back to the same socket and keep the high-port xfrm bypass.",
        ),
    ] = 15100,
    crash_analysis: Annotated[
        bool,
        typer.Option(
            "--crash-analysis/--no-crash-analysis",
            help="Enable real-time crash analysis and reporting.",
        ),
    ] = False,
    crash_analysis_output: Annotated[
        str,
        typer.Option("--crash-analysis-output", help="Output directory for crash analysis results."),
    ] = "crash_analysis",
    resume: Annotated[
        bool,
        typer.Option("--resume/--no-resume", help="Resume campaign from last checkpoint in output file."),
    ] = False,
) -> None:
    """Execute a fuzzing campaign against a SIP target."""
    strategies = (
        tuple(s.strip() for s in strategy.split(","))
        if strategy
        else ("default", "state_breaker")
    )
    layers = (
        tuple(lyr.strip() for lyr in layer.split(","))
        if layer
        else ("model", "wire", "byte")
    )

    payload: dict[str, object] = {
        "target_host": target_host,
        "target_port": target_port,
        "transport": transport,
        "mode": mode,
        "strategies": strategies,
        "layers": layers,
        "max_cases": max_cases,
        "timeout_seconds": timeout,
        "cooldown_seconds": cooldown,
        "seed_start": seed_start,
        "output_path": output,
        "process_name": process_name,
        "check_process": not no_process_check,
        "log_path": log_path,
        "adb_enabled": adb,
        "pcap_enabled": pcap,
        "pcap_dir": pcap_dir,
        "pcap_interface": pcap_interface,
        "preserve_via": preserve_via,
        "preserve_contact": preserve_contact,
        "mo_contact_host": mo_contact_host,
        "mo_contact_port_pc": mo_contact_port_pc,
        "mo_contact_port_ps": mo_contact_port_ps,
        "from_msisdn": from_msisdn,
        "mt_local_port": mt_local_port,
        "crash_analysis": crash_analysis,
        "crash_analysis_output": crash_analysis_output,
        "resume": resume,
    }
    if ipsec_mode is not None:
        payload["ipsec_mode"] = ipsec_mode
    if target_msisdn is not None:
        payload["target_msisdn"] = target_msisdn
    if impi is not None:
        payload["impi"] = impi
    if mt_invite_template is not None:
        payload["mt_invite_template"] = mt_invite_template

    if adb_serial is not None:
        payload["adb_serial"] = adb_serial
    if adb_buffers is not None:
        payload["adb_buffers"] = tuple(
            b.strip() for b in adb_buffers.split(",") if b.strip()
        )

    parsed_methods = _parse_methods(methods)
    if parsed_methods is not None:
        payload["methods"] = parsed_methods

    parsed_response_codes = _parse_response_codes(response_codes)
    if parsed_response_codes is not None:
        payload["response_codes"] = parsed_response_codes

    if with_dialog is not None:
        payload["with_dialog"] = with_dialog

    # Validate that either target_host or target_msisdn is provided for real-ue-direct mode
    if mode == "real-ue-direct":
        if target_host is None and target_msisdn is None:
            typer.echo(
                "Error: real-ue-direct mode requires either --target-host or --target-msisdn",
                err=True,
            )
            raise typer.Exit(code=1)

    try:
        config = CampaignConfig(**payload)
    except Exception as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(code=1)

    methods_label = ",".join(config.methods) if config.methods else "-"
    response_codes_label = (
        ",".join(str(code) for code in config.response_codes)
        if config.response_codes
        else "-"
    )
    crash_analysis_label = " crash_analysis=enabled" if config.crash_analysis else ""
    print(
        "[vmf campaign] starting: "
        f"methods={methods_label} "
        f"response_codes={response_codes_label} "
        f"with_dialog={config.with_dialog} "
        f"max_cases={max_cases} "
        f"target={target_host}:{target_port}"
        f"{crash_analysis_label}",
        file=sys.stderr,
    )

    executor = CampaignExecutor(config)
    result = executor.run()

    print(
        f"[vmf campaign] {result.status}: total={result.summary.total}"
        f" normal={result.summary.normal}"
        f" suspicious={result.summary.suspicious}"
        f" timeout={result.summary.timeout}"
        f" crash={result.summary.crash}"
        f" stack_failure={result.summary.stack_failure}",
        file=sys.stderr,
    )
    print(f"[vmf campaign] results saved to: {output}", file=sys.stderr)


@app.command("report")
def report_command(
    path: Annotated[str, typer.Argument(help="Path to campaign JSONL file.")],
    filter_verdict: Annotated[
        str | None,
        typer.Option(
            "--filter",
            help="Filter by verdict(s). Comma-separated (e.g. suspicious,crash).",
        ),
    ] = None,
) -> None:
    """Display campaign results summary."""
    store = ResultStore(Path(path))
    try:
        header, cases = store.read_all()
    except Exception as exc:
        typer.echo(f"Error reading {path}: {exc}", err=True)
        raise typer.Exit(code=1)

    verdicts_filter: set[str] | None = None
    if filter_verdict:
        verdicts_filter = {v.strip() for v in filter_verdict.split(",")}

    filtered = [
        c for c in cases if verdicts_filter is None or c.verdict in verdicts_filter
    ]

    report = {
        "campaign_id": header.campaign_id,
        "status": header.status,
        "started_at": header.started_at,
        "completed_at": header.completed_at,
        "config": header.config.model_dump(mode="json"),
        "summary": header.summary.model_dump(mode="json"),
        "cases": [
            {
                "case_id": c.case_id,
                "method": c.method,
                "layer": c.layer,
                "strategy": c.strategy,
                "seed": c.seed,
                "verdict": c.verdict,
                "reason": c.reason,
                "response_code": c.response_code,
                "elapsed_ms": c.elapsed_ms,
                "reproduction_cmd": c.reproduction_cmd,
            }
            for c in filtered
        ],
    }
    typer.echo(json.dumps(report, ensure_ascii=False, indent=2))


@app.command("replay")
def replay_command(
    path: Annotated[str, typer.Argument(help="Path to campaign JSONL file.")],
    case_id: Annotated[int, typer.Option("--case-id", help="Case ID to replay.")],
) -> None:
    """Replay a specific test case by its ID."""
    store = ResultStore(Path(path))
    try:
        header, _ = store.read_all()
        case = store.read_case(case_id)
    except Exception as exc:
        typer.echo(f"Error reading {path}: {exc}", err=True)
        raise typer.Exit(code=1)

    if case is None:
        typer.echo(f"Case ID {case_id} not found in {path}", err=True)
        raise typer.Exit(code=1)

    from volte_mutation_fuzzer.campaign.contracts import CaseSpec
    from volte_mutation_fuzzer.campaign.core import CampaignExecutor

    cfg = header.config
    executor = CampaignExecutor(cfg)
    spec = CaseSpec(
        case_id=case.case_id,
        seed=case.seed,
        method=case.method,
        layer=case.layer,
        strategy=case.strategy,
        response_code=case.fuzz_response_code,
        related_method=case.fuzz_related_method,
    )
    result = executor._execute_case(spec)
    typer.echo(json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2))
