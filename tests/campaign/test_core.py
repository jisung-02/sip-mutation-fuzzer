import json
import tempfile
import time
import unittest
from pathlib import Path


from volte_mutation_fuzzer.campaign.contracts import (
    CampaignConfig,
    CampaignResult,
    CampaignSummary,
    CaseResult,
)
from volte_mutation_fuzzer.campaign.core import (
    CampaignExecutor,
    CaseGenerator,
    ResultStore,
    TIER_DEFINITIONS,
    _SUPPORTED_STRATEGIES,
)
from tests.sender._server import UDPResponder


# ---------------------------------------------------------------------------
# CaseGenerator tests
# ---------------------------------------------------------------------------


class CaseGeneratorTests(unittest.TestCase):
    def _config(self, **kwargs) -> CampaignConfig:
        defaults = dict(target_host="127.0.0.1")
        defaults.update(kwargs)
        return CampaignConfig(**defaults)

    def test_tier1_generates_correct_combinations(self) -> None:
        # tier1: 4 methods × (model×2 + wire×1 + byte×1) = 16 valid combos
        cfg = self._config(scope="tier1", max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        self.assertEqual(len(cases), 16)

    def test_tier1_combination_count(self) -> None:
        # wire/state_breaker and byte/state_breaker are filtered out
        cfg = self._config(scope="tier1", max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        self.assertEqual(len(cases), 16)

    def test_max_cases_caps_output(self) -> None:
        cfg = self._config(scope="tier1", max_cases=5)
        cases = list(CaseGenerator(cfg).generate())
        self.assertEqual(len(cases), 5)

    def test_seeds_increment_from_seed_start(self) -> None:
        cfg = self._config(scope="tier1", max_cases=10, seed_start=100)
        cases = list(CaseGenerator(cfg).generate())
        for i, case in enumerate(cases):
            self.assertEqual(case.seed, 100 + i)

    def test_case_ids_are_sequential(self) -> None:
        cfg = self._config(scope="tier1", max_cases=10)
        cases = list(CaseGenerator(cfg).generate())
        for i, case in enumerate(cases):
            self.assertEqual(case.case_id, i)

    def test_layer_filter_from_config(self) -> None:
        cfg = self._config(scope="tier1", layers=("model",), max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        for case in cases:
            self.assertEqual(case.layer, "model")

    def test_strategy_filter_from_config(self) -> None:
        cfg = self._config(scope="tier1", strategies=("default",), max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        for case in cases:
            self.assertEqual(case.strategy, "default")

    def test_methods_come_from_tier(self) -> None:
        cfg = self._config(scope="tier1", max_cases=10000)
        tier = TIER_DEFINITIONS["tier1"]
        cases = list(CaseGenerator(cfg).generate())
        methods_seen = {c.method for c in cases}
        self.assertEqual(methods_seen, set(tier.methods))

    def test_no_invalid_layer_strategy_combinations(self) -> None:
        cfg = self._config(scope="tier1", max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        for case in cases:
            supported = _SUPPORTED_STRATEGIES.get(case.layer, frozenset())
            self.assertIn(
                case.strategy,
                supported,
                f"Invalid combo: layer={case.layer} strategy={case.strategy}",
            )

    def test_wire_layer_only_generates_default_strategy(self) -> None:
        cfg = self._config(scope="tier1", layers=("wire",), max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        for case in cases:
            self.assertEqual(case.strategy, "default")

    def test_all_scope_includes_all_tiers(self) -> None:
        cfg = self._config(scope="all", max_cases=100000)
        cases = list(CaseGenerator(cfg).generate())
        all_methods = {m for t in TIER_DEFINITIONS.values() for m in t.methods}
        methods_seen = {c.method for c in cases}
        self.assertTrue(methods_seen.issubset(all_methods))


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
            scope="tier1",
            layers=("model",),
            strategies=("default",),
            max_cases=4,
            timeout_seconds=1.0,
            cooldown_seconds=0.0,
            check_process=False,
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

    def test_unknown_verdict_prints_error_to_stderr(self) -> None:
        import io
        from unittest.mock import patch as mock_patch

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = str(Path(tmpdir) / "campaign.jsonl")
            cfg = self._make_config(
                "127.0.0.1",
                19998,
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

        self.assertIn("[ERROR]", output)
        self.assertIn("test error", output)


# ---------------------------------------------------------------------------
# Tier5 / dialog fuzzing tests
# ---------------------------------------------------------------------------


class Tier5CaseGeneratorTests(unittest.TestCase):
    def _config(self, **kwargs) -> CampaignConfig:
        defaults = dict(target_host="127.0.0.1")
        defaults.update(kwargs)
        return CampaignConfig(**defaults)

    def test_tier5_generates_dialog_scenarios(self) -> None:
        cfg = self._config(
            scope="tier5",
            layers=("model",),
            strategies=("default",),
            max_cases=10000,
        )
        cases = list(CaseGenerator(cfg).generate())
        # All tier5 cases should have a dialog_scenario set
        for case in cases:
            self.assertIsNotNone(
                case.dialog_scenario,
                f"Expected dialog_scenario for method {case.method}",
            )

    def test_tier5_methods_are_dialog_methods(self) -> None:
        cfg = self._config(scope="tier5", max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        expected_methods = {"CANCEL", "ACK", "BYE", "UPDATE", "REFER", "INFO", "PRACK"}
        methods_seen = {c.method for c in cases}
        self.assertEqual(methods_seen, expected_methods)

    def test_tier5_scenario_types_are_valid(self) -> None:
        from volte_mutation_fuzzer.dialog.contracts import DialogScenarioType

        valid_types = {t.value for t in DialogScenarioType}
        cfg = self._config(
            scope="tier5",
            layers=("model",),
            strategies=("default",),
            max_cases=10000,
        )
        cases = list(CaseGenerator(cfg).generate())
        for case in cases:
            if case.dialog_scenario is not None:
                self.assertIn(case.dialog_scenario, valid_types)

    def test_tier1_cases_have_no_dialog_scenario(self) -> None:
        cfg = self._config(scope="tier1", max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        for case in cases:
            self.assertIsNone(case.dialog_scenario)


class Tier2And3CaseGeneratorTests(unittest.TestCase):
    def _config(self, **kwargs) -> CampaignConfig:
        defaults = dict(target_host="127.0.0.1")
        defaults.update(kwargs)
        return CampaignConfig(**defaults)

    def test_tier2_methods(self) -> None:
        cfg = self._config(scope="tier2", max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        methods_seen = {c.method for c in cases}
        self.assertEqual(methods_seen, {"SUBSCRIBE", "NOTIFY", "PUBLISH", "PRACK"})

    def test_tier2_no_dialog_scenario(self) -> None:
        cfg = self._config(scope="tier2", max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        for case in cases:
            self.assertIsNone(case.dialog_scenario)

    def test_tier3_methods(self) -> None:
        cfg = self._config(scope="tier3", max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        methods_seen = {c.method for c in cases}
        self.assertEqual(methods_seen, {"CANCEL", "ACK"})

    def test_tier3_no_dialog_scenario(self) -> None:
        cfg = self._config(scope="tier3", max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        for case in cases:
            self.assertIsNone(case.dialog_scenario)

    def test_scope_all_generates_both_stateless_and_stateful_cancel_ack(self) -> None:
        # tier3 produces stateless CANCEL/ACK (dialog_scenario=None)
        # tier5 produces stateful CANCEL/ACK (dialog_scenario set)
        # Both must survive deduplication when scope=all
        cfg = self._config(scope="all", max_cases=100000)
        cases = list(CaseGenerator(cfg).generate())
        cancel_scenarios = {c.dialog_scenario for c in cases if c.method == "CANCEL"}
        ack_scenarios = {c.dialog_scenario for c in cases if c.method == "ACK"}
        self.assertIn(None, cancel_scenarios, "stateless CANCEL missing")
        self.assertTrue(
            any(s is not None for s in cancel_scenarios),
            "stateful CANCEL missing",
        )
        self.assertIn(None, ack_scenarios, "stateless ACK missing")
        self.assertTrue(
            any(s is not None for s in ack_scenarios),
            "stateful ACK missing",
        )


class DialogCaseExecutionTests(unittest.TestCase):
    """Test that dialog cases (spec.dialog_scenario set) use _execute_dialog_case."""

    def _make_config(self, host: str, port: int, **kwargs) -> CampaignConfig:
        defaults = dict(
            target_host=host,
            target_port=port,
            scope="tier5",
            layers=("model",),
            strategies=("default",),
            max_cases=2,
            timeout_seconds=0.3,
            cooldown_seconds=0.0,
            check_process=False,
        )
        defaults.update(kwargs)
        return CampaignConfig(**defaults)

    def test_dialog_case_setup_failed_on_silent_target(self) -> None:
        """A silent target causes setup_failed verdicts for dialog cases."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = str(Path(tmpdir) / "campaign.jsonl")
            cfg = self._make_config("127.0.0.1", 19997, output_path=out_path)
            executor = CampaignExecutor(cfg)
            result = executor.run()

        # All cases should be setup_failed (target doesn't respond to INVITE)
        self.assertGreater(result.summary.setup_failed, 0)
        self.assertEqual(
            result.summary.total, result.summary.setup_failed + result.summary.unknown
        )

    def test_dialog_case_verdict_in_summary(self) -> None:
        """Summary properly counts setup_failed."""
        summary = CampaignSummary()
        from volte_mutation_fuzzer.campaign.core import CampaignExecutor as CE

        CE._update_summary(summary, "setup_failed")
        self.assertEqual(summary.setup_failed, 1)
        self.assertEqual(summary.total, 1)


# ---------------------------------------------------------------------------
# Response-plane tier tests (tier6-tier11)
# ---------------------------------------------------------------------------


class ResponseTierCaseGeneratorTests(unittest.TestCase):
    def _config(self, **kwargs) -> CampaignConfig:
        defaults = dict(target_host="127.0.0.1")
        defaults.update(kwargs)
        return CampaignConfig(**defaults)

    def test_tier6_generates_response_cases(self) -> None:
        cfg = self._config(scope="tier6", max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        codes = {c.status_code for c in cases}
        self.assertEqual(codes, {100, 180, 183})

    def test_tier7_generates_response_cases(self) -> None:
        cfg = self._config(scope="tier7", max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        codes = {c.status_code for c in cases}
        self.assertEqual(codes, {200, 202})

    def test_tier8_generates_response_cases(self) -> None:
        cfg = self._config(scope="tier8", max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        codes = {c.status_code for c in cases}
        self.assertEqual(codes, {301, 302, 408, 480, 503})

    def test_tier9_generates_response_cases(self) -> None:
        cfg = self._config(scope="tier9", max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        codes = {c.status_code for c in cases}
        self.assertEqual(codes, {401, 407, 494})

    def test_tier10_generates_response_cases(self) -> None:
        cfg = self._config(scope="tier10", max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        codes = {c.status_code for c in cases}
        self.assertEqual(codes, {403, 404, 486, 500})

    def test_tier11_generates_response_cases(self) -> None:
        cfg = self._config(scope="tier11", max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        codes = {c.status_code for c in cases}
        self.assertEqual(codes, {600, 603, 604, 606})

    def test_response_cases_have_status_code_set(self) -> None:
        for tier in ("tier6", "tier7", "tier8", "tier9", "tier10", "tier11"):
            cfg = self._config(scope=tier, max_cases=10000)
            cases = list(CaseGenerator(cfg).generate())
            for case in cases:
                self.assertIsNotNone(
                    case.status_code, f"{tier} case missing status_code"
                )
                self.assertIsNotNone(
                    case.related_method, f"{tier} case missing related_method"
                )

    def test_response_cases_have_no_dialog_scenario(self) -> None:
        cfg = self._config(scope="tier7", max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        for case in cases:
            self.assertIsNone(case.dialog_scenario)

    def test_response_cases_are_unique(self) -> None:
        cfg = self._config(scope="all", max_cases=100000)
        cases = list(CaseGenerator(cfg).generate())
        resp_cases = [c for c in cases if c.status_code is not None]
        keys = [
            (c.status_code, c.related_method, c.layer, c.strategy) for c in resp_cases
        ]
        self.assertEqual(len(keys), len(set(keys)), "Duplicate response cases found")

    def test_scope_all_includes_both_request_and_response_cases(self) -> None:
        cfg = self._config(scope="all", max_cases=100000)
        cases = list(CaseGenerator(cfg).generate())
        req_cases = [c for c in cases if c.status_code is None]
        resp_cases = [c for c in cases if c.status_code is not None]
        self.assertGreater(len(req_cases), 0, "No request-plane cases in scope=all")
        self.assertGreater(len(resp_cases), 0, "No response-plane cases in scope=all")

    def test_response_case_execution_produces_result(self) -> None:
        """Response cases against a live UDP server produce a CaseResult."""
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
            cfg = CampaignConfig(
                target_host=responder.host,
                target_port=responder.port,
                scope="tier7",
                layers=("model",),
                strategies=("default",),
                max_cases=2,
                timeout_seconds=2.0,
                cooldown_seconds=0.0,
                check_process=False,
                output_path=out_path,
            )
            executor = CampaignExecutor(cfg)
            campaign = executor.run()

            self.assertEqual(campaign.summary.total, 2)
            store = ResultStore(Path(out_path))
            _, results = store.read_all()
            for r in results:
                self.assertIsNotNone(r.fuzz_status_code)
                self.assertIsNotNone(r.fuzz_related_method)

    def test_response_reproduction_cmd_contains_mutate_response(self) -> None:
        from volte_mutation_fuzzer.campaign.contracts import CaseSpec

        spec = CaseSpec(
            case_id=0,
            seed=42,
            method="INVITE",
            layer="model",
            strategy="default",
            status_code=200,
            related_method="INVITE",
        )
        cfg = CampaignConfig(
            target_host="127.0.0.1",
            target_port=5060,
            check_process=False,
        )
        executor = CampaignExecutor(cfg)
        cmd = executor._build_reproduction_cmd(spec)
        self.assertIn("mutate response", cmd)
        self.assertIn("200", cmd)
        self.assertIn("INVITE", cmd)

    def test_all_methods_code_generates_all_related_methods(self) -> None:
        """200 OK (ALL_METHODS)는 14개 related_method를 모두 생성해야 한다."""
        cfg = CampaignConfig(target_host="127.0.0.1", scope="tier7", max_cases=500)
        cases = list(CaseGenerator(cfg).generate())
        code_200_methods = {c.related_method for c in cases if c.status_code == 200}
        self.assertEqual(len(code_200_methods), 14)

    def test_auth_relevant_code_generates_12_methods(self) -> None:
        """401 Unauthorized (AUTH_RELEVANT)는 ACK, CANCEL 제외 12개 메서드를 생성해야 한다."""
        cfg = CampaignConfig(target_host="127.0.0.1", scope="tier9", max_cases=500)
        cases = list(CaseGenerator(cfg).generate())
        code_401_methods = {c.related_method for c in cases if c.status_code == 401}
        self.assertEqual(len(code_401_methods), 12)
        self.assertNotIn("ACK", code_401_methods)
        self.assertNotIn("CANCEL", code_401_methods)

    def test_invite_only_code_generates_single_method(self) -> None:
        """600 Busy Everywhere (INVITE_ONLY)는 INVITE 하나만 생성해야 한다."""
        cfg = CampaignConfig(target_host="127.0.0.1", scope="tier11", max_cases=500)
        cases = list(CaseGenerator(cfg).generate())
        code_600_methods = {c.related_method for c in cases if c.status_code == 600}
        self.assertEqual(code_600_methods, {"INVITE"})

    def test_general_redirect_generates_3_methods(self) -> None:
        """301 Moved Permanently (GENERAL_REDIRECT)는 INVITE, OPTIONS, REGISTER 3개를 생성해야 한다."""
        cfg = CampaignConfig(target_host="127.0.0.1", scope="tier8", max_cases=500)
        cases = list(CaseGenerator(cfg).generate())
        code_301_methods = {c.related_method for c in cases if c.status_code == 301}
        self.assertEqual(code_301_methods, {"INVITE", "OPTIONS", "REGISTER"})

    def test_202_accepted_generates_message_only(self) -> None:
        """202 Accepted는 MESSAGE 하나만 허용된다."""
        cfg = CampaignConfig(target_host="127.0.0.1", scope="tier7", max_cases=500)
        cases = list(CaseGenerator(cfg).generate())
        code_202_methods = {c.related_method for c in cases if c.status_code == 202}
        self.assertEqual(code_202_methods, {"MESSAGE"})

    def test_494_generates_register_and_invite(self) -> None:
        """494 Security Agreement Required는 REGISTER, INVITE 2개를 생성해야 한다."""
        cfg = CampaignConfig(target_host="127.0.0.1", scope="tier9", max_cases=500)
        cases = list(CaseGenerator(cfg).generate())
        code_494_methods = {c.related_method for c in cases if c.status_code == 494}
        self.assertEqual(code_494_methods, {"REGISTER", "INVITE"})

    def test_total_response_cases_increased(self) -> None:
        """scope=all 시 응답 케이스가 200개 이상이어야 한다 (이전 ~46개에서 ~360개로 증가)."""
        cfg = CampaignConfig(target_host="127.0.0.1", scope="all", max_cases=2000)
        cases = list(CaseGenerator(cfg).generate())
        resp_cases = [c for c in cases if c.status_code is not None]
        self.assertGreaterEqual(len(resp_cases), 200)
