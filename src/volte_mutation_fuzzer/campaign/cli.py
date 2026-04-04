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


@app.command("run")
def run_command(
    target_host: Annotated[str, typer.Option("--target-host", help="Target SIP host.")],
    target_port: Annotated[
        int, typer.Option("--target-port", help="Target SIP port.")
    ] = 5060,
    scope: Annotated[
        str,
        typer.Option("--scope", help="Tier scope (tier1/tier2/tier3/tier4/tier5/all)."),
    ] = "tier1",
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
        typer.Option(
            "--mode", help="Target mode (softphone/real-ue-pcscf/real-ue-direct)."
        ),
    ] = "softphone",
    log_path: Annotated[
        str | None,
        typer.Option(
            "--log-path",
            help="Path to target process log file for stack trace detection.",
        ),
    ] = None,
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

    try:
        config = CampaignConfig(
            target_host=target_host,
            target_port=target_port,
            transport=transport,
            mode=mode,
            scope=scope,
            strategies=strategies,
            layers=layers,
            max_cases=max_cases,
            timeout_seconds=timeout,
            cooldown_seconds=cooldown,
            seed_start=seed_start,
            output_path=output,
            process_name=process_name,
            check_process=not no_process_check,
            log_path=log_path,
        )
    except Exception as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(code=1)

    print(
        f"[vmf campaign] starting: scope={scope} max_cases={max_cases} target={target_host}:{target_port}",
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
        f" stack_failure={result.summary.stack_failure}"
        f" setup_failed={result.summary.setup_failed}",
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

    from volte_mutation_fuzzer.campaign.core import CampaignExecutor
    from volte_mutation_fuzzer.campaign.contracts import CaseSpec

    cfg = header.config
    executor = CampaignExecutor(cfg)
    spec = CaseSpec(
        case_id=case.case_id,
        seed=case.seed,
        method=case.method,
        layer=case.layer,
        strategy=case.strategy,
        dialog_scenario=case.dialog_scenario,
        status_code=case.fuzz_status_code,
        related_method=case.fuzz_related_method,
    )
    result = executor._execute_case(spec)
    typer.echo(json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2))
