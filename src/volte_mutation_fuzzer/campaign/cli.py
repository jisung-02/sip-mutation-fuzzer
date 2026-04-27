import json
import sys
from pathlib import Path
from typing import Annotated, Literal, cast, get_args

import typer
from pydantic import ValidationError

from volte_mutation_fuzzer.campaign.contracts import CampaignConfig
from volte_mutation_fuzzer.campaign.core import CampaignExecutor, ResultStore

IpsecMode = Literal["null", "bypass", "native", "ipsec"]
_IPSEC_MODES: tuple[str, ...] = get_args(IpsecMode)

app = typer.Typer(
    add_completion=False,
    help="Run mutation fuzzing campaigns and analyze results.",
)


def _parse_methods(raw: str | None) -> tuple[str, ...] | None:
    if raw is None:
        return None
    return tuple(method.strip().upper() for method in raw.split(",") if method.strip())


def _parse_csv(raw: str | None) -> tuple[str, ...] | None:
    if raw is None:
        return None
    return tuple(item.strip() for item in raw.split(",") if item.strip())


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
    profile: Annotated[
        str | None,
        typer.Option(
            "--profile",
            help="Mutation profile (legacy/delivery_preserving/ims_specific/parser_breaker). Comma-separated for multiple.",
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
    mutations_per_case: Annotated[
        int,
        typer.Option(
            "--mutations-per-case",
            help="Number of mutation rounds applied per case. >1 stacks "
            "deterministic strategies (null_byte_only / boundary_only / "
            "byte_edit_only) so a single packet carries N mutations.",
        ),
    ] = 1,
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
        str | None, typer.Option("--output", help="Campaign directory name under results/ (auto-generated if omitted).")
    ] = None,
    process_name: Annotated[
        str,
        typer.Option(
            "--process-name", help="Process name to check for crash detection."
        ),
    ] = "baresip",
    no_process_check: Annotated[
        bool | None, typer.Option("--no-process-check", help="Disable process liveness check. Auto-disabled for real-ue-direct mode.")
    ] = None,
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
        bool | None, typer.Option("--adb/--no-adb", help="Enable ADB logcat monitoring. Auto-enabled for real-ue-direct mode.")
    ] = None,
    adb_serial: Annotated[
        str | None, typer.Option("--adb-serial", help="ADB device serial.")
    ] = None,
    adb_buffers: Annotated[
        str | None,
        typer.Option("--adb-buffers", help="Comma-separated logcat buffers."),
    ] = None,
    ios: Annotated[
        bool,
        typer.Option(
            "--ios/--no-ios",
            help="Enable iPhone (libimobiledevice) log collection.",
        ),
    ] = False,
    ios_udid: Annotated[
        str | None,
        typer.Option("--ios-udid", help="Target iPhone UDID (auto if omitted)."),
    ] = None,
    ios_filter_processes: Annotated[
        str | None,
        typer.Option(
            "--ios-filter-processes",
            help="Comma-separated process names for idevicesyslog -p filter.",
        ),
    ] = None,
    ios_diagnostics: Annotated[
        bool,
        typer.Option(
            "--ios-diagnostics/--no-ios-diagnostics",
            help="Run idevicediagnostics per case (slower).",
        ),
    ] = False,
    pcap: Annotated[
        bool | None,
        typer.Option(
            "--pcap/--no-pcap",
            help="Enable per-case pcap capture via sudo tcpdump. Auto-enabled for real-ue-direct mode.",
        ),
    ] = None,
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
    mt: Annotated[
        bool,
        typer.Option("--mt/--no-mt", help="Use 3GPP standard MT-INVITE format for all packets."),
    ] = False,
    mt_invite_template: Annotated[
        str | None,
        typer.Option("--mt-invite-template", help="MT INVITE template name (e.g. '3gpp') or file path. --mt uses default template."),
    ] = None,
    ipsec_mode: Annotated[
        str | None,
        typer.Option(
            "--ipsec-mode",
            help="IPsec mode: 'null' (host spoofing, requires null encryption), 'bypass' (docker exec, xfrm policy bypass), or 'native' (alias 'ipsec').",
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
    resume: Annotated[
        bool,
        typer.Option("--resume/--no-resume", help="Resume campaign from last checkpoint in output file."),
    ] = False,
    circuit_breaker: Annotated[
        int,
        typer.Option("--circuit-breaker", help="Abort after N consecutive timeout/unknown verdicts. 0 to disable."),
    ] = 10,
) -> None:
    """Execute a fuzzing campaign against a SIP target."""
    strategies = _parse_csv(strategy) or ("default",)
    layers = _parse_csv(layer) or ("model", "wire", "byte")

    if ipsec_mode is not None and ipsec_mode not in _IPSEC_MODES:
        typer.echo(
            f"Error: --ipsec-mode must be one of {','.join(_IPSEC_MODES)}",
            err=True,
        )
        raise typer.Exit(code=1)
    ipsec_mode_value = cast(IpsecMode | None, ipsec_mode)

    _field_defaults = CampaignConfig.model_fields
    adb_buffers_value: tuple[str, ...] = (
        tuple(b.strip() for b in adb_buffers.split(",") if b.strip())
        if adb_buffers is not None
        else _field_defaults["adb_buffers"].default
    )
    ios_filter_processes_value: tuple[str, ...] = (
        tuple(p.strip() for p in ios_filter_processes.split(",") if p.strip())
        if ios_filter_processes is not None
        else _field_defaults["ios_filter_processes"].default
    )

    try:
        config = CampaignConfig(
            target_host=target_host,
            target_port=target_port,
            transport=transport,
            mode=mode,
            methods=_parse_methods(methods) or (),
            response_codes=_parse_response_codes(response_codes) or (),
            with_dialog=bool(with_dialog) if with_dialog is not None else False,
            profiles=profile,
            strategies=strategies,
            layers=layers,
            max_cases=max_cases,
            mutations_per_case=mutations_per_case,
            timeout_seconds=timeout,
            cooldown_seconds=cooldown,
            seed_start=seed_start,
            output_name=output,
            crash_analysis=crash_analysis,
            process_name=process_name,
            check_process=None if no_process_check is None else not no_process_check,
            log_path=log_path,
            adb_enabled=adb,
            adb_serial=adb_serial,
            ios_enabled=ios,
            ios_udid=ios_udid,
            ios_run_diagnostics=ios_diagnostics,
            pcap_enabled=pcap,
            pcap_interface=pcap_interface,
            target_msisdn=target_msisdn,
            impi=impi,
            mt=mt,
            mt_invite_template=mt_invite_template,
            ipsec_mode=ipsec_mode_value,
            preserve_via=preserve_via,
            preserve_contact=preserve_contact,
            mo_contact_host=mo_contact_host,
            mo_contact_port_pc=mo_contact_port_pc,
            mo_contact_port_ps=mo_contact_port_ps,
            from_msisdn=from_msisdn,
            mt_local_port=mt_local_port,
            resume=resume,
            circuit_breaker_threshold=circuit_breaker,
            adb_buffers=adb_buffers_value,
            ios_filter_processes=ios_filter_processes_value,
        )
        if strategy is None:
            default_strategies = (
                ("default", "state_breaker")
                if config.profiles == ("legacy",)
                else ("default",)
            )
            if config.strategies != default_strategies:
                config = config.model_copy(update={"strategies": default_strategies})
    except ValidationError as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(code=1)

    methods_label = ",".join(config.methods) if config.methods else "-"
    response_codes_label = (
        ",".join(str(code) for code in config.response_codes)
        if config.response_codes
        else "-"
    )
    crash_analysis_label = " crash_analysis=enabled" if config.crash_analysis else ""
    if config.target_host:
        target_label = f"{config.target_host}:{config.target_port}"
    elif config.target_msisdn:
        target_label = f"msisdn:{config.target_msisdn}"
    else:
        target_label = f"-:{config.target_port}"
    print(
        "[vmf campaign] starting: "
        f"methods={methods_label} "
        f"response_codes={response_codes_label} "
        f"with_dialog={config.with_dialog} "
        f"max_cases={max_cases} "
        f"target={target_label}"
        f"{crash_analysis_label}",
        file=sys.stderr,
    )

    executor = CampaignExecutor(config)
    print(f"[vmf campaign] output: {executor.campaign_dir}", file=sys.stderr)
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
    print(f"[vmf campaign] results saved to: {executor.campaign_dir}", file=sys.stderr)


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
    html: Annotated[
        bool,
        typer.Option("--html", help="Generate standalone HTML report."),
    ] = False,
) -> None:
    """Display campaign results summary."""
    if html:
        from volte_mutation_fuzzer.campaign.report import HtmlReportGenerator

        try:
            report_path = HtmlReportGenerator(Path(path)).generate()
            typer.echo(f"HTML report generated: {report_path}")
        except Exception as exc:
            typer.echo(f"Error generating HTML report: {exc}", err=True)
            raise typer.Exit(code=1)
        return

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
                "profile": c.profile,
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
    executor = CampaignExecutor(cfg, campaign_dir=Path(path).parent)
    spec = CaseSpec(
        case_id=case.case_id,
        seed=case.seed,
        profile=case.profile,
        method=case.method,
        layer=case.layer,
        strategy=case.strategy,
        response_code=case.fuzz_response_code,
        related_method=case.fuzz_related_method,
    )
    result = executor._execute_case(spec)
    typer.echo(json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2))
