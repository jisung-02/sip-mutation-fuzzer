import json
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path

from volte_mutation_fuzzer.analysis.crash_analyzer import CampaignCrashAnalyzer
from volte_mutation_fuzzer.campaign.contracts import (
    CampaignConfig,
    CampaignResult,
    CaseResult,
    CaseSpec,
)
from volte_mutation_fuzzer.campaign.core import (
    CampaignExecutor,
    CaseGenerator,
    ResultStore,
    _SUPPORTED_STRATEGIES,
)
from volte_mutation_fuzzer.sip.catalog import SIP_CATALOG
from tests.sender._server import UDPResponder


# ---------------------------------------------------------------------------
# CaseGenerator tests
# ---------------------------------------------------------------------------


class CaseGeneratorTests(unittest.TestCase):
    def _config(self, **kwargs) -> CampaignConfig:
        defaults = dict(target_host="127.0.0.1")
        defaults.update(kwargs)
        return CampaignConfig(**defaults)

    def test_methods_generate_direct_combinations(self) -> None:
        cfg = self._config(methods=("OPTIONS", "INVITE"), max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        self.assertEqual(len(cases), 8)

    def test_max_cases_caps_output(self) -> None:
        cfg = self._config(methods=("OPTIONS", "INVITE"), max_cases=5)
        cases = list(CaseGenerator(cfg).generate())
        self.assertEqual(len(cases), 5)

    def test_seeds_increment_from_seed_start(self) -> None:
        cfg = self._config(methods=("OPTIONS", "INVITE"), max_cases=8, seed_start=100)
        cases = list(CaseGenerator(cfg).generate())
        for i, case in enumerate(cases):
            self.assertEqual(case.seed, 100 + i)

    def test_case_ids_are_sequential(self) -> None:
        cfg = self._config(methods=("OPTIONS", "INVITE"), max_cases=8)
        cases = list(CaseGenerator(cfg).generate())
        for i, case in enumerate(cases):
            self.assertEqual(case.case_id, i)

    def test_layer_filter_from_config(self) -> None:
        cfg = self._config(
            methods=("OPTIONS", "INVITE"), layers=("model",), max_cases=10000
        )
        cases = list(CaseGenerator(cfg).generate())
        for case in cases:
            self.assertEqual(case.layer, "model")

    def test_strategy_filter_from_config(self) -> None:
        cfg = self._config(
            methods=("OPTIONS", "INVITE"), strategies=("default",), max_cases=10000
        )
        cases = list(CaseGenerator(cfg).generate())
        for case in cases:
            self.assertEqual(case.strategy, "default")

    def test_methods_come_from_config(self) -> None:
        cfg = self._config(methods=("OPTIONS", "INVITE"), max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        methods_seen = {c.method for c in cases if c.response_code is None}
        self.assertEqual(methods_seen, {"OPTIONS", "INVITE"})

    def test_no_invalid_layer_strategy_combinations(self) -> None:
        cfg = self._config(methods=("OPTIONS", "INVITE"), max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        for case in cases:
            supported = _SUPPORTED_STRATEGIES.get(case.layer, frozenset())
            self.assertIn(
                case.strategy,
                supported,
                f"Invalid combo: layer={case.layer} strategy={case.strategy}",
            )

    def test_wire_layer_only_generates_default_strategy(self) -> None:
        cfg = self._config(
            methods=("OPTIONS", "INVITE"), layers=("wire",), max_cases=10000
        )
        cases = list(CaseGenerator(cfg).generate())
        for case in cases:
            self.assertEqual(case.strategy, "default")

    def test_response_codes_generate_related_method_cases(self) -> None:
        cfg = self._config(
            methods=(),
            response_codes=(200,),
            layers=("model",),
            strategies=("default",),
            max_cases=10000,
        )
        cases = list(CaseGenerator(cfg).generate())
        expected_related_methods = tuple(
            method.value for method in SIP_CATALOG.get_response(200).related_methods
        )
        self.assertEqual(len(cases), len(expected_related_methods))
        self.assertTrue(all(case.response_code == 200 for case in cases))
        self.assertEqual(
            {case.related_method for case in cases},
            set(expected_related_methods),
        )


# ---------------------------------------------------------------------------
# ResultStore tests
# ---------------------------------------------------------------------------


class ResultStoreTests(unittest.TestCase):
    def _make_config(self) -> CampaignConfig:
        return CampaignConfig(target_host="127.0.0.1")

    def _make_campaign(self, path: str) -> CampaignResult:
        return CampaignResult(
            campaign_id="test123",
            started_at="2026-01-01T00:00:00Z",
            config=self._make_config(),
            status="running",
        )

    def _make_case_result(self, case_id: int = 0) -> CaseResult:
        return CaseResult(
            case_id=case_id,
            seed=case_id,
            method="OPTIONS",
            layer="model",
            strategy="default",
            verdict="normal",
            reason="ok",
            elapsed_ms=50.0,
            reproduction_cmd="uv run fuzzer ...",
            timestamp=time.time(),
        )

    def test_write_header_and_read_all(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            store = ResultStore(path)
            campaign = self._make_campaign(str(path))
            store.write_header(campaign)

            header, cases = store.read_all()
            self.assertEqual(header.campaign_id, "test123")
            self.assertEqual(cases, [])

    def test_append_and_read_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            store = ResultStore(path)
            campaign = self._make_campaign(str(path))
            store.write_header(campaign)

            for i in range(3):
                store.append(self._make_case_result(i))

            _, cases = store.read_all()
            self.assertEqual(len(cases), 3)
            self.assertEqual([c.case_id for c in cases], [0, 1, 2])

    def test_write_footer_updates_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            store = ResultStore(path)
            campaign = self._make_campaign(str(path))
            store.write_header(campaign)
            store.append(self._make_case_result(0))
            completed = campaign.model_copy(
                update={"status": "completed", "completed_at": "2026-01-01T01:00:00Z"}
            )
            store.write_footer(completed)

            header, cases = store.read_all()
            self.assertEqual(header.status, "completed")
            self.assertEqual(len(cases), 1)

    def test_read_case_by_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            store = ResultStore(path)
            store.write_header(self._make_campaign(str(path)))
            for i in range(5):
                store.append(self._make_case_result(i))

            result = store.read_case(3)
            self.assertIsNotNone(result)
            self.assertEqual(result.case_id, 3)

    def test_read_case_not_found(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            store = ResultStore(path)
            store.write_header(self._make_campaign(str(path)))
            result = store.read_case(99)
            self.assertIsNone(result)

    def test_creates_parent_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "nested" / "dir" / "campaign.jsonl"
            store = ResultStore(path)
            store.write_header(self._make_campaign(str(path)))
            self.assertTrue(path.exists())

    def test_jsonl_format_each_line_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            store = ResultStore(path)
            store.write_header(self._make_campaign(str(path)))
            store.append(self._make_case_result(0))
            for line in path.read_text().splitlines():
                obj = json.loads(line)
                self.assertIn("type", obj)


# ---------------------------------------------------------------------------
# CampaignExecutor integration tests
# ---------------------------------------------------------------------------


class CampaignExecutorTests(unittest.TestCase):
    def _make_config(self, host: str, port: int, **kwargs) -> CampaignConfig:
        defaults = dict(
            target_host=host,
            target_port=port,
            methods=("OPTIONS", "INVITE", "MESSAGE", "REGISTER"),
            layers=("model",),
            strategies=("default",),
            max_cases=4,
            timeout_seconds=1.0,
            cooldown_seconds=0.0,
            check_process=False,
            adb_enabled=False,
            pcap_enabled=False,
        )
        defaults.update(kwargs)
        return CampaignConfig(**defaults)

    def test_run_small_campaign_produces_results(self) -> None:
        responder = UDPResponder(
            responses=(
                b"SIP/2.0 200 OK\r\n"
                b"Via: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bK-1\r\n"
                b"Content-Length: 0\r\n"
                b"\r\n",
            )
        )
        responder.start()
        self.addCleanup(responder.close)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = str(Path(tmpdir) / "campaign.jsonl")
            cfg = self._make_config(
                responder.host,
                responder.port,
                output_path=out_path,
            )
            executor = CampaignExecutor(cfg)
            result = executor.run()

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.summary.total, 4)
        self.assertIsNotNone(result.completed_at)

    def test_run_populates_normal_verdicts_on_200(self) -> None:
        responder = UDPResponder(
            responses=(
                b"SIP/2.0 200 OK\r\n"
                b"Via: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bK-1\r\n"
                b"Content-Length: 0\r\n"
                b"\r\n",
            )
        )
        responder.start()
        self.addCleanup(responder.close)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = str(Path(tmpdir) / "campaign.jsonl")
            cfg = self._make_config(
                responder.host,
                responder.port,
                output_path=out_path,
            )
            executor = CampaignExecutor(cfg)
            result = executor.run()

        self.assertGreater(result.summary.normal, 0)

    def test_run_returns_timeout_verdict_for_silent_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = str(Path(tmpdir) / "campaign.jsonl")
            cfg = self._make_config(
                "127.0.0.1",
                19999,
                methods=("OPTIONS", "INVITE"),
                max_cases=2,
                output_path=out_path,
                timeout_seconds=0.2,
            )
            executor = CampaignExecutor(cfg)
            result = executor.run()

        self.assertEqual(result.summary.total, 2)
        self.assertEqual(result.summary.timeout, 2)

    def test_run_writes_jsonl_with_correct_case_count(self) -> None:
        responder = UDPResponder(
            responses=(
                b"SIP/2.0 200 OK\r\n"
                b"Via: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bK-1\r\n"
                b"Content-Length: 0\r\n"
                b"\r\n",
            )
        )
        responder.start()
        self.addCleanup(responder.close)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = str(Path(tmpdir) / "campaign.jsonl")
            cfg = self._make_config(
                responder.host,
                responder.port,
                methods=("OPTIONS", "INVITE", "MESSAGE"),
                max_cases=3,
                output_path=out_path,
            )
            executor = CampaignExecutor(cfg)
            executor.run()

            store = ResultStore(Path(out_path))
            _, cases = store.read_all()

        self.assertEqual(len(cases), 3)

    def test_reproduction_cmd_contains_method_and_seed(self) -> None:
        responder = UDPResponder(
            responses=(
                b"SIP/2.0 200 OK\r\n"
                b"Via: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bK-1\r\n"
                b"Content-Length: 0\r\n"
                b"\r\n",
            )
        )
        responder.start()
        self.addCleanup(responder.close)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = str(Path(tmpdir) / "campaign.jsonl")
            cfg = self._make_config(
                responder.host,
                responder.port,
                methods=("OPTIONS",),
                output_path=out_path,
                max_cases=1,
            )
            executor = CampaignExecutor(cfg)
            executor.run()

            store = ResultStore(Path(out_path))
            _, cases = store.read_all()

        cmd = cases[0].reproduction_cmd
        self.assertIn("fuzzer mutate request", cmd)
        self.assertIn("--seed", cmd)
        self.assertIn(responder.host, cmd)

    def test_reproduction_cmd_includes_ipsec_mode_for_real_ue_direct(self) -> None:
        cfg = self._make_config(
            "10.20.20.8",
            5060,
            mode="real-ue-direct",
            methods=("OPTIONS",),
            ipsec_mode="null",
        )
        executor = CampaignExecutor(cfg)
        cmd = executor._build_reproduction_cmd(
            CaseSpec(
                case_id=0,
                seed=7,
                method="OPTIONS",
                layer="model",
                strategy="default",
            )
        )

        self.assertIn("--mode real-ue-direct", cmd)
        self.assertIn("--ipsec-mode null", cmd)

    def test_mt_template_reproduction_cmd_includes_ipsec_mode(self) -> None:
        cfg = self._make_config(
            "10.20.20.8",
            5060,
            mode="real-ue-direct",
            methods=("INVITE",),
            target_msisdn="111111",
            impi="001010000123511",
            mt_invite_template="a31",
            ipsec_mode="bypass",
            mt_local_port=15100,
        )
        executor = CampaignExecutor(cfg)
        spec = CaseSpec(
            case_id=0,
            seed=0,
            method="INVITE",
            layer="wire",
            strategy="default",
        )
        cmd = executor._build_mt_template_reproduction_cmd(spec)

        self.assertIn("--ipsec-mode bypass", cmd)
        self.assertIn("--mt-local-port 15100", cmd)

    def test_unknown_verdict_prints_error_to_stderr(self) -> None:
        import io
        from unittest.mock import patch as mock_patch

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = str(Path(tmpdir) / "campaign.jsonl")
            cfg = self._make_config(
                "127.0.0.1",
                19998,
                methods=("OPTIONS",),
                max_cases=1,
                output_path=out_path,
                timeout_seconds=0.1,
                layers=("model",),
                strategies=("default",),
            )
            executor = CampaignExecutor(cfg)
            with mock_patch.object(
                executor._generator,
                "generate_request",
                side_effect=RuntimeError("test error"),
            ):
                stderr_buf = io.StringIO()
                with mock_patch("sys.stderr", stderr_buf):
                    executor.run()
                output = stderr_buf.getvalue()

        self.assertIn("ERROR", output)
        self.assertIn("test error", output)

    def test_run_invokes_realtime_crash_analysis_and_final_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = str(Path(tmpdir) / "campaign.jsonl")
            cfg = self._make_config(
                "127.0.0.1",
                5060,
                methods=("OPTIONS",),
                max_cases=1,
                output_path=out_path,
                crash_analysis=True,
                crash_analysis_output=str(Path(tmpdir) / "crash-analysis"),
            )
            analyzer = CampaignCrashAnalyzer(
                output_dir=cfg.crash_analysis_output,
                enabled=True,
                source_name=cfg.output_path,
            )
            fake_case = CaseResult(
                case_id=0,
                seed=0,
                method="OPTIONS",
                layer="model",
                strategy="default",
                verdict="normal",
                reason="ok",
                elapsed_ms=10.0,
                reproduction_cmd="uv run fuzzer ...",
                timestamp=1.0,
            )

            with unittest.mock.patch.object(
                analyzer,
                "analyze_case_immediately",
                wraps=analyzer.analyze_case_immediately,
            ) as analyze_mock, unittest.mock.patch.object(
                analyzer,
                "generate_final_report",
                wraps=analyzer.generate_final_report,
            ) as report_mock:
                executor = CampaignExecutor(cfg)
                executor._crash_analyzer = analyzer
                executor._execute_case = unittest.mock.Mock(return_value=fake_case)
                executor.run()

            self.assertEqual(analyze_mock.call_count, 1)
            report_mock.assert_called_once()
            self.assertTrue(Path(cfg.crash_analysis_output).exists())


class UpdateSummaryTests(unittest.TestCase):
    """Tests for CampaignExecutor._update_summary."""

    def test_infra_failure_increments_counter(self) -> None:
        from volte_mutation_fuzzer.campaign.contracts import CampaignSummary

        summary = CampaignSummary()
        CampaignExecutor._update_summary(summary, "infra_failure")
        self.assertEqual(summary.infra_failure, 1)
        self.assertEqual(summary.total, 1)
        self.assertEqual(summary.timeout, 0)

    def test_timeout_does_not_increment_infra(self) -> None:
        from volte_mutation_fuzzer.campaign.contracts import CampaignSummary

        summary = CampaignSummary()
        CampaignExecutor._update_summary(summary, "timeout")
        self.assertEqual(summary.timeout, 1)
        self.assertEqual(summary.infra_failure, 0)


class SACircuitBreakerTests(unittest.TestCase):
    """Tests for SA-triggered circuit breaker in the campaign run loop."""

    def _make_timeout_case(self, case_id: int) -> CaseResult:
        return CaseResult(
            case_id=case_id,
            seed=case_id,
            method="INVITE",
            layer="wire",
            strategy="identity",
            verdict="timeout",
            reason="no response received within timeout",
            elapsed_ms=5000.0,
            reproduction_cmd="uv run fuzzer ...",
            timestamp=time.time(),
        )

    def test_sa_expiry_reclassifies_to_infra_failure(self) -> None:
        """When SA is dead, consecutive timeouts should trigger infra_failure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = str(Path(tmpdir) / "campaign.jsonl")
            cfg = CampaignConfig(
                target_host="10.20.20.8",
                target_msisdn="111111",
                impi="001010000123511",
                mode="real-ue-direct",
                ipsec_mode="null",
                mt_invite_template="a31",
                methods=("INVITE",),
                layers=("wire", "byte"),
                strategies=("identity", "default"),
                max_cases=10,
                timeout_seconds=0.2,
                cooldown_seconds=0.0,
                check_process=False,
                adb_enabled=False,
                pcap_enabled=False,
                circuit_breaker_threshold=6,
                output_path=out_path,
            )
            executor = CampaignExecutor(cfg)

            # Mock _execute_case to always return timeout
            call_count = [0]
            def fake_execute(spec):
                call_count[0] += 1
                return self._make_timeout_case(spec.case_id)

            executor._execute_case = fake_execute

            # Mock SA check to return dead
            from volte_mutation_fuzzer.sender.real_ue import IPsecSAStatus

            with unittest.mock.patch(
                "volte_mutation_fuzzer.campaign.core.check_ipsec_sa_alive",
                return_value=IPsecSAStatus(alive=False, sa_count=0, detail="no UE SAs found"),
            ):
                result = executor.run()

            # Should abort due to SA expiry
            self.assertEqual(result.status, "aborted")
            # At least one case should be reclassified as infra_failure
            self.assertGreater(result.summary.infra_failure, 0)
