import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

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
        tier = TIER_DEFINITIONS["tier1"]
        cfg = self._config(scope="tier1", max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        combo_count = len(tier.methods) * len(tier.layers) * len(tier.strategies)
        self.assertEqual(len(cases), min(combo_count, 10000))

    def test_tier1_combination_count(self) -> None:
        tier = TIER_DEFINITIONS["tier1"]
        cfg = self._config(scope="tier1", max_cases=10000)
        cases = list(CaseGenerator(cfg).generate())
        expected = len(tier.methods) * len(tier.layers) * len(tier.strategies)
        self.assertEqual(len(cases), expected)

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
            completed = campaign.model_copy(update={"status": "completed", "completed_at": "2026-01-01T01:00:00Z"})
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
                responder.host, responder.port,
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
                responder.host, responder.port,
                output_path=out_path,
            )
            executor = CampaignExecutor(cfg)
            result = executor.run()

        self.assertGreater(result.summary.normal, 0)

    def test_run_returns_timeout_verdict_for_silent_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = str(Path(tmpdir) / "campaign.jsonl")
            cfg = self._make_config(
                "127.0.0.1", 19999,
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
                responder.host, responder.port,
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
                responder.host, responder.port,
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

