import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from typer.testing import CliRunner

from volte_mutation_fuzzer.campaign.contracts import (
    CampaignConfig,
    CampaignResult,
    CampaignSummary,
    CaseResult,
)
from volte_mutation_fuzzer.campaign.core import ResultStore
from volte_mutation_fuzzer.generator.cli import app
from tests.sender._server import UDPResponder


def _make_config(host: str = "127.0.0.1", port: int = 5060) -> CampaignConfig:
    return CampaignConfig(
        target_host=host,
        target_port=port,
        methods=("OPTIONS", "INVITE", "MESSAGE", "REGISTER"),
        layers=("model",),
        strategies=("default",),
        max_cases=4,
        timeout_seconds=1.0,
        cooldown_seconds=0.0,
        check_process=False,
    )


def _make_case_result(case_id: int = 0, verdict: str = "normal") -> CaseResult:
    return CaseResult(
        case_id=case_id,
        seed=case_id,
        method="OPTIONS",
        layer="model",
        strategy="default",
        verdict=verdict,
        reason="ok",
        elapsed_ms=50.0,
        reproduction_cmd="uv run fuzzer mutate request OPTIONS --strategy default --layer model --seed 0 | uv run fuzzer send packet --target-host 127.0.0.1 --target-port 5060",
        timestamp=time.time(),
    )


def _write_sample_jsonl(path: Path, cases: list[CaseResult]) -> None:
    config = _make_config()
    campaign = CampaignResult(
        campaign_id="testcampaign",
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T01:00:00Z",
        status="completed",
        config=config,
    )
    store = ResultStore(path)
    store.write_header(campaign)
    for case in cases:
        store.append(case)
    store.write_footer(campaign)


class CampaignRunCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_run_command_creates_output_file(self) -> None:
        responder = UDPResponder(
            responses=(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n",)
        )
        responder.start()
        self.addCleanup(responder.close)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Use tmpdir as results_dir, with output name "test_run"
            import os
            os.environ["_VMF_TEST_RESULTS_DIR"] = tmpdir
            result = self.runner.invoke(
                app,
                [
                    "campaign",
                    "run",
                    "--target-host",
                    responder.host,
                    "--target-port",
                    str(responder.port),
                    "--methods",
                    "OPTIONS,INVITE,MESSAGE,REGISTER",
                    "--layer",
                    "model",
                    "--strategy",
                    "default",
                    "--max-cases",
                    "2",
                    "--timeout",
                    "0.5",
                    "--cooldown",
                    "0",
                    "--no-process-check",
                    "--output",
                    "test_run",
                ],
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            # campaign.jsonl should exist under results/test_run/
            campaign_dir = Path("results") / "test_run"
            self.assertTrue((campaign_dir / "campaign.jsonl").exists())
            # cleanup
            import shutil
            shutil.rmtree("results/test_run", ignore_errors=True)

    def test_run_command_passes_crash_analysis_flags(self) -> None:
        captured: dict[str, CampaignConfig] = {}

        def _build_executor(config: CampaignConfig) -> Mock:
            captured["config"] = config
            executor = Mock()
            executor.run.return_value = CampaignResult(
                campaign_id="cli-crash-analysis",
                started_at="2026-01-01T00:00:00Z",
                completed_at="2026-01-01T00:00:01Z",
                status="completed",
                config=config,
                summary=CampaignSummary(total=1),
            )
            return executor

        with patch(
            "volte_mutation_fuzzer.campaign.cli.CampaignExecutor",
            side_effect=_build_executor,
        ):
            result = self.runner.invoke(
                app,
                [
                    "campaign",
                    "run",
                    "--target-host",
                    "127.0.0.1",
                    "--target-port",
                    "5060",
                    "--methods",
                    "OPTIONS",
                    "--layer",
                    "model",
                    "--strategy",
                    "default",
                    "--max-cases",
                    "1",
                    "--timeout",
                    "0.1",
                    "--cooldown",
                    "0",
                    "--no-process-check",
                    "--output",
                    "test_run",
                    "--crash-analysis",
                ],
            )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertTrue(captured["config"].crash_analysis)

    def test_run_command_msisdn_banner_omits_unresolved_port(self) -> None:
        def _build_executor(config: CampaignConfig) -> Mock:
            executor = Mock()
            executor.campaign_dir = Path("results") / "test_run"
            executor.run.return_value = CampaignResult(
                campaign_id="cli-msisdn-banner",
                started_at="2026-01-01T00:00:00Z",
                completed_at="2026-01-01T00:00:01Z",
                status="completed",
                config=config,
                summary=CampaignSummary(total=1),
            )
            return executor

        with patch(
            "volte_mutation_fuzzer.campaign.cli.CampaignExecutor",
            side_effect=_build_executor,
        ):
            result = self.runner.invoke(
                app,
                [
                    "campaign",
                    "run",
                    "--mode",
                    "real-ue-direct",
                    "--target-msisdn",
                    "111111",
                    "--methods",
                    "OPTIONS",
                    "--layer",
                    "model",
                    "--strategy",
                    "default",
                    "--max-cases",
                    "1",
                    "--timeout",
                    "0.1",
                    "--cooldown",
                    "0",
                    "--no-process-check",
                    "--output",
                    "test_run",
                ],
            )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("target=msisdn:111111", result.output)
        self.assertNotIn("target=msisdn:111111:5060", result.output)

    def test_run_command_real_ue_missing_target_uses_config_validation(self) -> None:
        result = self.runner.invoke(
            app,
            [
                "campaign",
                "run",
                "--mode",
                "real-ue-direct",
                "--max-cases",
                "1",
            ],
        )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Configuration error:", result.output)
        self.assertIn(
            "real-ue-direct mode requires either target_host or target_msisdn",
            result.output,
        )

    def test_run_command_invalid_host_exits_nonzero(self) -> None:
        result = self.runner.invoke(
            app,
            [
                "campaign",
                "run",
                "--target-host",
                "",
                "--max-cases",
                "1",
            ],
        )
        self.assertNotEqual(result.exit_code, 0)


class CampaignReportCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_report_shows_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            _write_sample_jsonl(path, [_make_case_result(0), _make_case_result(1)])

            result = self.runner.invoke(app, ["campaign", "report", str(path)])
            self.assertEqual(result.exit_code, 0, msg=result.output)

            payload = json.loads(result.stdout)
            self.assertEqual(payload["campaign_id"], "testcampaign")
            self.assertIn("summary", payload)
            self.assertIn("cases", payload)

    def test_report_filter_suspicious_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            cases = [
                _make_case_result(0, "normal"),
                _make_case_result(1, "suspicious"),
                _make_case_result(2, "normal"),
            ]
            _write_sample_jsonl(path, cases)

            result = self.runner.invoke(
                app,
                ["campaign", "report", str(path), "--filter", "suspicious"],
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            payload = json.loads(result.stdout)
            self.assertEqual(len(payload["cases"]), 1)
            self.assertEqual(payload["cases"][0]["verdict"], "suspicious")

    def test_report_missing_file_exits_nonzero(self) -> None:
        result = self.runner.invoke(
            app, ["campaign", "report", "/nonexistent/file.jsonl"]
        )
        self.assertNotEqual(result.exit_code, 0)


class CampaignReplayCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_replay_command_re_executes_case(self) -> None:
        responder = UDPResponder(
            responses=(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n",)
        )
        responder.start()
        self.addCleanup(responder.close)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            config = CampaignConfig(
                target_host=responder.host,
                target_port=responder.port,
                methods=("OPTIONS", "INVITE", "MESSAGE", "REGISTER"),
                layers=("model",),
                strategies=("default",),
                max_cases=1,
                timeout_seconds=0.5,
                cooldown_seconds=0.0,
                check_process=False,
            )
            campaign = CampaignResult(
                campaign_id="replaytest",
                started_at="2026-01-01T00:00:00Z",
                status="completed",
                config=config,
            )
            store = ResultStore(path)
            store.write_header(campaign)
            store.append(_make_case_result(0))
            store.write_footer(campaign)

            result = self.runner.invoke(
                app,
                ["campaign", "replay", str(path), "--case-id", "0"],
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            payload = json.loads(result.stdout)
            self.assertIn("verdict", payload)

    def test_replay_missing_case_id_exits_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            _write_sample_jsonl(path, [_make_case_result(0)])
            result = self.runner.invoke(
                app,
                ["campaign", "replay", str(path), "--case-id", "999"],
            )
            self.assertNotEqual(result.exit_code, 0)
