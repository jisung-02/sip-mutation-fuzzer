import json
import sys
from pathlib import Path
from typing import Annotated, Literal, cast, get_args

import typer
from pydantic import ValidationError

from volte_mutation_fuzzer.campaign.contracts import CampaignConfig
from volte_mutation_fuzzer.campaign.core import CampaignExecutor, ResultStore

IpsecMode = Literal["null", "bypass", "native"]
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
    codes: list[int] = []
    for raw_code in raw.split(","):
        code = raw_code.strip()
        if not code:
            continue
        try:
            codes.append(int(code))
        except ValueError as exc:
            raise typer.BadParameter(
                f"response codes must be integers: {code!r}",
                param_hint="--response-codes",
            ) from exc
    return tuple(codes)


@app.command("run")
def run_command(
    target_host: Annotated[
        str | None,
        typer.Option(
            "--target-host",
            help="Target SIP host (auto-resolved from --target-msisdn if not provided).",
        ),
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
            help=(
                "Mutation profile. Profiles: legacy, delivery_preserving, "
                "ims_specific, parser_breaker, pixel_ims, iphone_ims. "
                "Comma-separated for multiple."
            ),
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
    oracle_log_grace: Annotated[
        float | None,
        typer.Option(
            "--oracle-log-grace",
            help=(
                "ADB/iOS log grace window per case (seconds). "
                "Default: 8 s for INVITE, 1 s for others. "
                "If set below 8, the campaign automatically collects logs for "
                "10 s after the last case to catch delayed async crashes."
            ),
        ),
    ] = None,
    wait_idle_timeout: Annotated[
        float,
        typer.Option(
            "--wait-idle-timeout",
            help=(
                "Max seconds to wait for UE call state to return to IDLE between "
                "INVITE cases (default 10 s). Set to 0 to skip idle waiting "
                "entirely — useful for high-rate campaigns or listener-leak testing."
            ),
        ),
    ] = 10.0,
    no_teardown: Annotated[
        bool,
        typer.Option(
            "--no-teardown",
            help=(
                "Do not send CANCEL to tear down each INVITE. Lets the UE "
                "actually alert/ring — use for baseline 'does it ring' checks. "
                "By default INVITEs are cancelled so the UE doesn't keep ringing."
            ),
        ),
    ] = False,
    seed_start: Annotated[
        int, typer.Option("--seed-start", help="Starting seed value.")
    ] = 0,
    output: Annotated[
        str | None,
        typer.Option(
            "--output",
            help="Campaign directory name under results/ (auto-generated if omitted).",
        ),
    ] = None,
    process_name: Annotated[
        str,
        typer.Option(
            "--process-name", help="Process name to check for crash detection."
        ),
    ] = "baresip",
    no_process_check: Annotated[
        bool | None,
        typer.Option(
            "--no-process-check",
            help="Disable process liveness check. Auto-disabled for real-ue-direct mode.",
        ),
    ] = None,
    transport: Annotated[
        str, typer.Option("--transport", help="Transport protocol (UDP/TCP).")
    ] = "UDP",
    mode: Annotated[
        str,
        typer.Option("--mode", help="Target mode (softphone/real-ue-direct)."),
    ] = "real-ue-direct",
    log_path: Annotated[
        str | None,
        typer.Option(
            "--log-path",
            help="Path to target process log file for stack trace detection.",
        ),
    ] = None,
    adb: Annotated[
        bool | None,
        typer.Option(
            "--adb/--no-adb",
            help="Enable ADB logcat monitoring. Auto-enabled for real-ue-direct mode.",
        ),
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
        typer.Option(
            "--ios-udid",
            help="Target iPhone UDID. Omit when exactly one iPhone is connected.",
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
        typer.Option(
            "--pcap-interface",
            help=(
                "Network interface for tcpdump. In real-ue-direct mode, the "
                "default 'any' value is normalized to br-volte."
            ),
        ),
    ] = "any",
    target_msisdn: Annotated[
        str | None,
        typer.Option(
            "--target-msisdn",
            help=(
                "UE MSISDN for real-ue-direct target resolution. "
                "Defaults to 111111 in real-ue-direct mode."
            ),
        ),
    ] = None,
    impi: Annotated[
        str | None,
        typer.Option("--impi", help="UE IMPI for MT INVITE Request-URI."),
    ] = None,
    mt: Annotated[
        bool,
        typer.Option(
            "--mt/--no-mt", help="Use 3GPP standard MT-INVITE format for all packets."
        ),
    ] = False,
    packet_file: Annotated[
        str | None,
        typer.Option(
            "--packet-file",
            help=(
                "Path to a file containing a complete SIP packet. Read as raw "
                "bytes (null-byte safe) and sent verbatim. Mutually exclusive "
                "with --mt. Real-ue-direct mode only."
            ),
        ),
    ] = None,
    corpus_dir: Annotated[
        str | None,
        typer.Option(
            "--corpus-dir",
            help=(
                "Path to a directory of seed packets (.sip/.bin/.bytes/.txt). "
                "Each case mutates one seed at the byte layer instead of "
                "generating a fresh packet — feed 'campaign promote' output "
                "here to re-fuzz previously interesting payloads. Mutually "
                "exclusive with --mt and --packet-file. Real-ue-direct only."
            ),
        ),
    ] = None,
    ipsec_mode: Annotated[
        str | None,
        typer.Option(
            "--ipsec-mode",
            help=(
                "IPsec mode: 'null' (plaintext path through the P-CSCF namespace), "
                "'bypass' (P-CSCF namespace with xfrm policy bypass), or "
                "'native'. Defaults to native in real-ue-direct mode."
            ),
        ),
    ] = None,
    preserve_via: Annotated[
        bool,
        typer.Option(
            "--preserve-via/--no-preserve-via", help="Do not rewrite Via host/port."
        ),
    ] = False,
    preserve_contact: Annotated[
        bool,
        typer.Option(
            "--preserve-contact/--no-preserve-contact",
            help="Do not rewrite Contact host/port.",
        ),
    ] = False,
    pixel_mode: Annotated[
        bool,
        typer.Option(
            "--pixel/--no-pixel",
            help="Pixel mode: rewrite Request-URI to use resolved UE Contact URI (UUID@IP:port) so Shannon IMS accepts the packet.",
        ),
    ] = False,
    mo_contact_host: Annotated[
        str,
        typer.Option(
            "--mo-contact-host", help="MO UE IP for MT INVITE Contact header."
        ),
    ] = "10.20.20.9",
    mo_contact_port_pc: Annotated[
        int,
        typer.Option(
            "--mo-contact-port-pc", help="MO UE protected client port for Contact."
        ),
    ] = 31800,
    mo_contact_port_ps: Annotated[
        int,
        typer.Option(
            "--mo-contact-port-ps", help="MO UE protected server port for Contact."
        ),
    ] = 31100,
    from_msisdn: Annotated[
        str,
        typer.Option(
            "--from-msisdn", help="Originating MSISDN for From/Contact in MT INVITE."
        ),
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
        typer.Option(
            "--resume/--no-resume",
            help="Resume campaign from last checkpoint in output file.",
        ),
    ] = False,
    circuit_breaker: Annotated[
        int,
        typer.Option(
            "--circuit-breaker",
            help="Abort after N consecutive timeout/unknown verdicts. 0 to disable.",
        ),
    ] = 10,
    feedback: Annotated[
        bool,
        typer.Option(
            "--feedback/--no-feedback",
            help=(
                "Runtime feedback: promote interesting-case payloads into "
                "<campaign>/corpus/ as they happen, and let corpus cases "
                "continue mutating the most recent promoted seed."
            ),
        ),
    ] = True,
) -> None:
    """Execute a fuzzing campaign against a SIP target."""
    strategies = _parse_csv(strategy) or (
        ("identity",) if packet_file is not None else ("default",)
    )
    layers = _parse_csv(layer) or (
        ("byte",)
        if packet_file is not None or corpus_dir is not None
        else ("model", "wire", "byte")
    )
    profiles = tuple(profile.split(",")) if profile is not None else ("legacy",)

    if ipsec_mode is not None and ipsec_mode not in _IPSEC_MODES:
        typer.echo(
            f"Error: --ipsec-mode must be one of {','.join(_IPSEC_MODES)}",
            err=True,
        )
        raise typer.Exit(code=1)
    target_msisdn_value = target_msisdn
    ipsec_mode_value = cast(IpsecMode | None, ipsec_mode)
    if mode == "real-ue-direct":
        target_msisdn_value = target_msisdn_value or "111111"
        ipsec_mode_value = ipsec_mode_value or "native"

    _field_defaults = CampaignConfig.model_fields
    adb_buffers_value: tuple[str, ...] = (
        tuple(b.strip() for b in adb_buffers.split(",") if b.strip())
        if adb_buffers is not None
        else _field_defaults["adb_buffers"].default
    )
    if ios and adb is None:
        adb = False

    try:
        config = CampaignConfig(
            target_host=target_host,
            target_port=target_port,
            transport=transport,
            mode=mode,
            methods=_parse_methods(methods) or (),
            response_codes=_parse_response_codes(response_codes) or (),
            with_dialog=bool(with_dialog) if with_dialog is not None else False,
            profiles=profiles,
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
            target_msisdn=target_msisdn_value,
            impi=impi,
            mt=mt,
            packet_file=packet_file,
            corpus_dir=corpus_dir,
            ipsec_mode=ipsec_mode_value,
            preserve_via=preserve_via,
            preserve_contact=preserve_contact,
            pixel_mode=pixel_mode,
            mo_contact_host=mo_contact_host,
            mo_contact_port_pc=mo_contact_port_pc,
            mo_contact_port_ps=mo_contact_port_ps,
            from_msisdn=from_msisdn,
            mt_local_port=mt_local_port,
            resume=resume,
            circuit_breaker_threshold=circuit_breaker,
            feedback_enabled=feedback,
            adb_buffers=adb_buffers_value,
            oracle_log_grace_seconds=oracle_log_grace,
            post_campaign_log_grace_seconds=(
                10.0 if oracle_log_grace is not None and oracle_log_grace < 8.0 else 0.0
            ),
            wait_idle_timeout_seconds=wait_idle_timeout,
            invite_teardown=not no_teardown,
        )
        if (
            strategy is None
            and config.packet_file is None
            and config.corpus_dir is None
        ):
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


@app.command("promote")
def promote_command(
    path: Annotated[str, typer.Argument(help="Path to campaign JSONL file.")],
    out: Annotated[
        str | None,
        typer.Option(
            "--out",
            help=(
                "Output corpus directory. Defaults to <campaign_dir>/corpus "
                "next to the JSONL file."
            ),
        ),
    ] = None,
) -> None:
    """Promote interesting-case payloads into a reusable corpus directory.

    Copies the exact sent bytes (sent.bin / sent.sip) of every
    crash/stack_failure/suspicious case into a seed directory that
    'fuzzer campaign run --corpus-dir' consumes, plus a manifest.json
    describing each promoted seed. This closes the loop: anomalies found by
    one campaign become mutation seeds for the next.
    """
    from volte_mutation_fuzzer.campaign.evidence import promote_corpus

    jsonl_path = Path(path)
    if not jsonl_path.is_file():
        typer.echo(f"Error: campaign JSONL not found: {path}", err=True)
        raise typer.Exit(code=1)

    try:
        count, out_path = promote_corpus(
            jsonl_path, Path(out) if out is not None else None
        )
    except Exception as exc:
        typer.echo(f"Error promoting corpus: {exc}", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Promoted {count} seed(s) into {out_path}")
    if count == 0:
        typer.echo(
            "No interesting cases with evidence payloads found — nothing to recycle.",
            err=True,
        )


@app.command("sequence")
def sequence_command(
    scenario: Annotated[
        str,
        typer.Option(
            "--scenario",
            help=(
                "Sequence scenario name. Available: cancel_retransmit, "
                "invite_double_bye, invite_early_bye, invite_retransmit."
            ),
        ),
    ],
    repeats: Annotated[
        int,
        typer.Option(
            "--repeats",
            min=1,
            max=10,
            help="Retransmission count override for repeated scenario steps.",
        ),
    ] = 2,
    target_host: Annotated[
        str | None,
        typer.Option("--target-host", help="Target SIP host (optional)."),
    ] = None,
    target_msisdn: Annotated[
        str | None,
        typer.Option("--target-msisdn", help="UE MSISDN (defaults to 111111)."),
    ] = None,
    ipsec_mode: Annotated[
        str | None,
        typer.Option(
            "--ipsec-mode", help="IPsec mode: null, bypass, or native (default)."
        ),
    ] = None,
    profile: Annotated[
        str | None,
        typer.Option("--profile", help="Mutation profile (default legacy)."),
    ] = None,
    layer: Annotated[
        str | None,
        typer.Option("--layer", help="Mutation layer (default wire)."),
    ] = None,
    strategy: Annotated[
        str | None,
        typer.Option("--strategy", help="Mutation strategy (default identity)."),
    ] = None,
    mutations_per_case: Annotated[
        int,
        typer.Option(
            "--mutations-per-case",
            min=1,
            max=100,
            help="Mutation rounds applied to each mutated scenario step.",
        ),
    ] = 1,
    max_cases: Annotated[
        int,
        typer.Option("--max-cases", min=0, help="Number of cases (0 = unlimited)."),
    ] = 10,
    seed_start: Annotated[
        int,
        typer.Option("--seed-start", min=0, help="First seed value."),
    ] = 0,
    timeout: Annotated[
        float,
        typer.Option("--timeout", min=0.1, max=60.0, help="Per-response timeout (s)."),
    ] = 5.0,
    cooldown: Annotated[
        float,
        typer.Option(
            "--cooldown", min=0.0, max=10.0, help="Cooldown between cases (s)."
        ),
    ] = 1.0,
    adb: Annotated[
        bool | None,
        typer.Option("--adb/--no-adb", help="Override ADB evidence collection."),
    ] = None,
    pcap: Annotated[
        bool | None,
        typer.Option("--pcap/--no-pcap", help="Override pcap capture."),
    ] = None,
    feedback: Annotated[
        bool,
        typer.Option(
            "--feedback/--no-feedback",
            help="Promote interesting payloads into <campaign>/corpus/ live.",
        ),
    ] = True,
) -> None:
    """Run a multi-message sequence scenario (state-attack mode).

    Unlike ``campaign run`` (one mutated packet per case), sequence mode
    chains several messages in one dialog — retransmitted INVITEs, teardown
    before provisional responses, double BYEs — mutating every step flagged
    by the scenario.
    """
    from volte_mutation_fuzzer.dialog.sequence_catalog import (
        SEQUENCE_SCENARIO_NAMES,
    )

    if ipsec_mode is not None and ipsec_mode not in _IPSEC_MODES:
        typer.echo(
            f"Error: --ipsec-mode must be one of {','.join(_IPSEC_MODES)}",
            err=True,
        )
        raise typer.Exit(code=1)
    if scenario.strip().lower() not in SEQUENCE_SCENARIO_NAMES:
        typer.echo(
            f"Error: unknown sequence scenario '{scenario}'. "
            f"Available: {', '.join(SEQUENCE_SCENARIO_NAMES)}",
            err=True,
        )
        raise typer.Exit(code=1)

    target_msisdn_value = target_msisdn or "111111"
    ipsec_mode_value = cast(IpsecMode | None, ipsec_mode) or "native"

    try:
        config = CampaignConfig(
            mode="real-ue-direct",
            target_host=target_host,
            target_msisdn=target_msisdn_value,
            ipsec_mode=ipsec_mode_value,
            methods=("INVITE",),
            profiles=tuple(profile.split(",")) if profile is not None else ("legacy",),
            strategies=_parse_csv(strategy) or ("identity",),
            layers=_parse_csv(layer) or ("wire",),
            max_cases=max_cases,
            mutations_per_case=mutations_per_case,
            timeout_seconds=timeout,
            cooldown_seconds=cooldown,
            seed_start=seed_start,
            adb_enabled=adb,
            pcap_enabled=pcap,
            sequence_scenario=scenario.strip().lower(),
            sequence_repeats=repeats,
            feedback_enabled=feedback,
        )
    except ValidationError as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(code=1)

    print(
        f"[vmf sequence] starting: scenario={config.sequence_scenario}"
        f" repeats={config.sequence_repeats}"
        f" strategy={','.join(config.strategies)}"
        f" max_cases={max_cases}"
        f" target=msisdn:{target_msisdn_value}",
        file=sys.stderr,
    )

    executor = CampaignExecutor(config)
    print(f"[vmf sequence] output: {executor.campaign_dir}", file=sys.stderr)
    result = executor.run()

    print(
        f"[vmf sequence] {result.status}: total={result.summary.total}"
        f" normal={result.summary.normal}"
        f" suspicious={result.summary.suspicious}"
        f" timeout={result.summary.timeout}"
        f" crash={result.summary.crash}"
        f" stack_failure={result.summary.stack_failure}",
        file=sys.stderr,
    )
