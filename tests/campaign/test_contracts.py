import unittest

from pydantic import ValidationError

from volte_mutation_fuzzer.campaign.contracts import (
    ALL_SIP_METHODS,
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
        self.assertEqual(cfg.methods, ALL_SIP_METHODS)
        self.assertEqual(cfg.response_codes, ())
        self.assertFalse(cfg.with_dialog)
        self.assertEqual(cfg.max_cases, 1000)
        self.assertEqual(cfg.timeout_seconds, 5.0)
        self.assertEqual(cfg.cooldown_seconds, 0.2)
        self.assertEqual(cfg.seed_start, 0)
        self.assertFalse(cfg.crash_analysis)
        self.assertEqual(cfg.results_dir, "results")
        self.assertIsNone(cfg.output_name)
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

    def test_max_cases_rejects_negative(self) -> None:
        with self.assertRaises(ValidationError):
            CampaignConfig(target_host="127.0.0.1", max_cases=-1)

    def test_max_cases_zero_is_unlimited(self) -> None:
        cfg = CampaignConfig(target_host="127.0.0.1", max_cases=0)
        self.assertEqual(cfg.max_cases, 0)

    def test_extra_fields_forbidden(self) -> None:
        with self.assertRaises(ValidationError):
            CampaignConfig.model_validate({"target_host": "127.0.0.1", "unknown": "x"})

    def test_mt_template_defaults_ipsec_mode_for_real_ue_direct(self) -> None:
        cfg = CampaignConfig(
            target_host="10.20.20.8",
            mode="real-ue-direct",
            target_msisdn="111111",
            impi="001010000123511",
            mt_invite_template="a31",
        )

        self.assertEqual(cfg.ipsec_mode, "null")

    def test_mt_template_accepts_explicit_ipsec_mode(self) -> None:
        cfg = CampaignConfig(
            target_host="10.20.20.8",
            mode="real-ue-direct",
            target_msisdn="111111",
            impi="001010000123511",
            mt_invite_template="a31",
            ipsec_mode="bypass",
        )

        self.assertEqual(cfg.ipsec_mode, "bypass")

    def test_mt_template_accepts_native_ipsec_mode(self) -> None:
        cfg = CampaignConfig(
            target_host="10.20.20.8",
            mode="real-ue-direct",
            target_msisdn="111111",
            impi="001010000123511",
            mt_invite_template="a31",
            ipsec_mode="native",
        )

        self.assertEqual(cfg.ipsec_mode, "native")
        self.assertEqual(cfg.bind_container, "pcscf")
        self.assertFalse(cfg.preserve_via)
        self.assertFalse(cfg.preserve_contact)

    def test_ipsec_alias_normalizes_to_native(self) -> None:
        cfg = CampaignConfig(
            target_host="10.20.20.8",
            mode="real-ue-direct",
            target_msisdn="111111",
            impi="001010000123511",
            mt_invite_template="a31",
            ipsec_mode="ipsec",
        )

        self.assertEqual(cfg.ipsec_mode, "native")

    def test_native_ipsec_rejects_tcp_in_real_ue_direct(self) -> None:
        with self.assertRaises(ValidationError):
            CampaignConfig(
                target_host="10.20.20.8",
                mode="real-ue-direct",
                transport="TCP",
                target_msisdn="111111",
                impi="001010000123511",
                mt_invite_template="a31",
                ipsec_mode="native",
            )

    def test_native_ipsec_requires_target_msisdn_in_real_ue_direct(self) -> None:
        with self.assertRaises(ValidationError) as ctx:
            CampaignConfig(
                target_host="10.20.20.8",
                mode="real-ue-direct",
                ipsec_mode="native",
            )

        self.assertIn("target_msisdn", str(ctx.exception))


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
        return CaseResult.model_validate(defaults)

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

    def test_details_default_empty(self) -> None:
        r = self._make()
        self.assertEqual(r.details, {})


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

    def test_infra_failure_counter(self) -> None:
        s = CampaignSummary()
        self.assertEqual(s.infra_failure, 0)
        s.infra_failure += 1
        self.assertEqual(s.infra_failure, 1)


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
            CampaignResult.model_validate(
                {
                    "campaign_id": "abc",
                    "started_at": "2026-01-01T00:00:00Z",
                    "config": self._make_config().model_dump(mode="json"),
                    "status": "invalid",
                }
            )


class AdbCampaignConfigTests(unittest.TestCase):
    def test_adb_defaults(self) -> None:
        cfg = CampaignConfig(target_host="127.0.0.1")
        self.assertFalse(cfg.adb_enabled)
        self.assertIsNone(cfg.adb_serial)
        self.assertEqual(cfg.adb_buffers, ("main", "system", "radio", "crash"))

    def test_adb_custom_buffers(self) -> None:
        cfg = CampaignConfig(
            target_host="127.0.0.1", adb_enabled=True, adb_buffers=("radio", "crash")
        )
        self.assertTrue(cfg.adb_enabled)
        self.assertEqual(cfg.adb_buffers, ("radio", "crash"))

    def test_adb_extra_forbid(self) -> None:
        with self.assertRaises(Exception):
            CampaignConfig.model_validate(
                {"target_host": "127.0.0.1", "unknown_adb_field": True}
            )


class IosCampaignConfigTests(unittest.TestCase):
    def test_ios_defaults(self) -> None:
        cfg = CampaignConfig(target_host="127.0.0.1")
        self.assertFalse(cfg.ios_enabled)
        self.assertIsNone(cfg.ios_udid)
        self.assertIn("CommCenter", cfg.ios_filter_processes)
        self.assertFalse(cfg.ios_run_diagnostics)

    def test_ios_enabled_with_udid(self) -> None:
        cfg = CampaignConfig(
            target_host="127.0.0.1",
            ios_enabled=True,
            ios_udid="ABC-123",
            ios_filter_processes=("CommCenter",),
            ios_run_diagnostics=True,
        )
        self.assertTrue(cfg.ios_enabled)
        self.assertEqual(cfg.ios_udid, "ABC-123")
        self.assertEqual(cfg.ios_filter_processes, ("CommCenter",))
        self.assertTrue(cfg.ios_run_diagnostics)

    def test_ios_not_auto_enabled_in_real_ue_direct(self) -> None:
        cfg = CampaignConfig(
            target_host="127.0.0.1",
            mode="real-ue-direct",
        )
        self.assertFalse(cfg.ios_enabled)
