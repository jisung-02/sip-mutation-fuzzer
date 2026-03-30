import unittest

from pydantic import ValidationError

from volte_mutation_fuzzer.campaign.contracts import (
    CampaignConfig,
    CampaignResult,
    CampaignSummary,
    CaseResult,
    CaseSpec,
)


class CampaignConfigTests(unittest.TestCase):
    def test_defaults(self) -> None:
        cfg = CampaignConfig(target_host="127.0.0.1")
        self.assertEqual(cfg.target_port, 5060)
        self.assertEqual(cfg.scope, "tier1")
        self.assertEqual(cfg.max_cases, 1000)
        self.assertEqual(cfg.timeout_seconds, 5.0)
        self.assertEqual(cfg.cooldown_seconds, 0.2)
        self.assertEqual(cfg.seed_start, 0)
        self.assertEqual(cfg.process_name, "baresip")
        self.assertTrue(cfg.check_process)

    def test_target_host_required(self) -> None:
        with self.assertRaises(ValidationError):
            CampaignConfig(target_host="")

    def test_port_bounds(self) -> None:
        with self.assertRaises(ValidationError):
            CampaignConfig(target_host="127.0.0.1", target_port=0)
        with self.assertRaises(ValidationError):
            CampaignConfig(target_host="127.0.0.1", target_port=65536)

    def test_max_cases_must_be_positive(self) -> None:
        with self.assertRaises(ValidationError):
            CampaignConfig(target_host="127.0.0.1", max_cases=0)

    def test_scope_valid_values(self) -> None:
        for scope in ("tier1", "tier2", "tier3", "tier4", "tier5", "all"):
            cfg = CampaignConfig(target_host="127.0.0.1", scope=scope)
            self.assertEqual(cfg.scope, scope)

    def test_scope_invalid(self) -> None:
        with self.assertRaises(ValidationError):
            CampaignConfig(target_host="127.0.0.1", scope="tier6")

    def test_extra_fields_forbidden(self) -> None:
        with self.assertRaises(ValidationError):
            CampaignConfig(target_host="127.0.0.1", unknown="x")


class CaseSpecTests(unittest.TestCase):
    def test_valid(self) -> None:
        spec = CaseSpec(
            case_id=0, seed=42, method="OPTIONS", layer="model", strategy="default"
        )
        self.assertEqual(spec.case_id, 0)
        self.assertEqual(spec.seed, 42)

    def test_negative_case_id_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            CaseSpec(
                case_id=-1, seed=0, method="OPTIONS", layer="model", strategy="default"
            )


class CaseResultTests(unittest.TestCase):
    def _make(self, **kwargs) -> CaseResult:
        defaults = dict(
            case_id=0,
            seed=0,
            method="OPTIONS",
            layer="model",
            strategy="default",
            verdict="normal",
            reason="ok",
            elapsed_ms=50.0,
            reproduction_cmd="uv run fuzzer ...",
            timestamp=1.0,
        )
        defaults.update(kwargs)
        return CaseResult(**defaults)

    def test_normal_case(self) -> None:
        r = self._make(response_code=200)
        self.assertEqual(r.verdict, "normal")
        self.assertEqual(r.response_code, 200)
        self.assertIsNone(r.raw_response)

    def test_crash_case_with_raw_response(self) -> None:
        r = self._make(verdict="crash", raw_response="SIP/2.0 500 Error\r\n\r\n")
        self.assertEqual(r.verdict, "crash")
        self.assertIsNotNone(r.raw_response)

    def test_mutation_ops_default_empty(self) -> None:
        r = self._make()
        self.assertEqual(r.mutation_ops, ())


class CampaignSummaryTests(unittest.TestCase):
    def test_defaults_all_zero(self) -> None:
        s = CampaignSummary()
        self.assertEqual(s.total, 0)
        self.assertEqual(s.normal, 0)
        self.assertEqual(s.crash, 0)

    def test_mutation(self) -> None:
        s = CampaignSummary()
        s.total += 3
        s.normal += 2
        s.crash += 1
        self.assertEqual(s.total, 3)


class CampaignResultTests(unittest.TestCase):
    def _make_config(self) -> CampaignConfig:
        return CampaignConfig(target_host="127.0.0.1")

    def test_defaults(self) -> None:
        r = CampaignResult(
            campaign_id="abc123",
            started_at="2026-01-01T00:00:00Z",
            config=self._make_config(),
        )
        self.assertEqual(r.status, "running")
        self.assertIsNone(r.completed_at)
        self.assertEqual(r.summary.total, 0)

    def test_invalid_status(self) -> None:
        with self.assertRaises(ValidationError):
            CampaignResult(
                campaign_id="abc",
                started_at="2026-01-01T00:00:00Z",
                config=self._make_config(),
                status="invalid",
            )
