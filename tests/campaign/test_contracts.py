import tempfile
import unittest
from pathlib import Path

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
        self.assertEqual(cfg.profiles, ("legacy",))
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
        self.assertTrue(cfg.invite_teardown)

    def test_invite_teardown_can_be_disabled(self) -> None:
        cfg = CampaignConfig(target_host="127.0.0.1", invite_teardown=False)
        self.assertFalse(cfg.invite_teardown)

    def test_profiles_normalize_and_dedupe(self) -> None:
        cfg = CampaignConfig(
            target_host="127.0.0.1",
            profiles=(" parser_breaker ", "legacy", "parser_breaker"),
        )

        self.assertEqual(cfg.profiles, ("parser_breaker", "legacy"))

    def test_profiles_reject_blank_and_unknown_values(self) -> None:
        with self.assertRaises(ValidationError) as ctx:
            CampaignConfig(
                target_host="127.0.0.1",
                profiles=("   ",),
            )
        self.assertIn("profile must not be blank", str(ctx.exception))

        with self.assertRaises(ValidationError) as ctx:
            CampaignConfig(
                target_host="127.0.0.1",
                profiles=("unknown",),
            )
        self.assertIn("unsupported mutation profile", str(ctx.exception))

    def test_oracle_log_grace_seconds_for_method_uses_real_ue_defaults(self) -> None:
        cfg = CampaignConfig(target_host="10.20.20.8", mode="real-ue-direct")

        self.assertEqual(cfg.oracle_log_grace_seconds_for_method("INVITE"), 8.0)
        self.assertEqual(cfg.oracle_log_grace_seconds_for_method("OPTIONS"), 1.0)
        self.assertEqual(cfg.oracle_log_grace_seconds_for_method("BYE"), 2.0)

    def test_oracle_log_grace_seconds_for_method_returns_zero_outside_real_ue_direct(
        self,
    ) -> None:
        cfg = CampaignConfig(target_host="127.0.0.1")

        self.assertEqual(cfg.oracle_log_grace_seconds_for_method("INVITE"), 0.0)

    def test_oracle_log_grace_seconds_for_method_preserves_explicit_override(
        self,
    ) -> None:
        cfg = CampaignConfig(
            target_host="10.20.20.8",
            mode="real-ue-direct",
            oracle_log_grace_seconds=6.5,
        )

        self.assertEqual(cfg.oracle_log_grace_seconds_for_method("INVITE"), 6.5)
        self.assertEqual(cfg.oracle_log_grace_seconds_for_method("OPTIONS"), 6.5)

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

    def test_mt_invite_template_field_is_not_supported(self) -> None:
        with self.assertRaises(ValidationError):
            CampaignConfig.model_validate(
                {
                    "mode": "real-ue-direct",
                    "target_msisdn": "111111",
                    "mt_invite_template": "3gpp",
                }
            )

    def test_mt_template_defaults_ipsec_mode_for_real_ue_direct(self) -> None:
        cfg = CampaignConfig(
            target_host="10.20.20.8",
            mode="real-ue-direct",
            target_msisdn="111111",
            impi="001010000123511",
            mt=True,
        )

        self.assertEqual(cfg.ipsec_mode, "null")

    def test_mt_template_accepts_explicit_ipsec_mode(self) -> None:
        cfg = CampaignConfig(
            target_host="10.20.20.8",
            mode="real-ue-direct",
            target_msisdn="111111",
            impi="001010000123511",
            mt=True,
            ipsec_mode="bypass",
        )

        self.assertEqual(cfg.ipsec_mode, "bypass")

    def test_mt_template_accepts_native_ipsec_mode(self) -> None:
        cfg = CampaignConfig(
            target_host="10.20.20.8",
            mode="real-ue-direct",
            target_msisdn="111111",
            impi="001010000123511",
            mt=True,
            ipsec_mode="native",
        )

        self.assertEqual(cfg.ipsec_mode, "native")
        self.assertEqual(cfg.bind_container, "pcscf")
        self.assertFalse(cfg.preserve_via)
        self.assertFalse(cfg.preserve_contact)

    def test_ipsec_alias_is_not_supported(self) -> None:
        with self.assertRaises(ValidationError):
            CampaignConfig.model_validate(
                {
                    "target_host": "10.20.20.8",
                    "mode": "real-ue-direct",
                    "target_msisdn": "111111",
                    "impi": "001010000123511",
                    "mt": True,
                    "ipsec_mode": "ipsec",
                }
            )

    def test_native_ipsec_accepts_tcp_in_real_ue_direct(self) -> None:
        cfg = CampaignConfig(
            target_host="10.20.20.8",
            mode="real-ue-direct",
            transport="TCP",
            target_msisdn="111111",
            impi="001010000123511",
            mt=True,
            ipsec_mode="native",
        )

        self.assertEqual(cfg.ipsec_mode, "native")
        self.assertEqual(cfg.transport, "TCP")

    def test_native_ipsec_rejects_unsupported_transport_in_real_ue_direct(self) -> None:
        with self.assertRaises(ValidationError):
            CampaignConfig(
                target_host="10.20.20.8",
                mode="real-ue-direct",
                transport="SCTP",
                target_msisdn="111111",
                impi="001010000123511",
                mt=True,
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


class PacketFileConfigTests(unittest.TestCase):
    """``--packet-file`` option validators on CampaignConfig."""

    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(suffix=".sip", delete=False)
        # Include a NUL byte so we cover the binary-safe path.
        self._tmp.write(b"OPTIONS sip:user@host SIP/2.0\r\n\x00\r\n")
        self._tmp.close()
        self._path = self._tmp.name
        self.addCleanup(lambda: Path(self._path).unlink(missing_ok=True))

    def test_packet_file_accepted_with_real_ue_direct_and_msisdn(self) -> None:
        cfg = CampaignConfig(
            mode="real-ue-direct",
            target_msisdn="111111",
            packet_file=self._path,
            methods=("OPTIONS",),
            layers=("byte",),
        )

        self.assertEqual(cfg.packet_file, self._path)
        self.assertEqual(cfg.ipsec_mode, "null")  # default for packet_file mode

    def test_packet_file_defaults_to_file_method_byte_layer_and_identity_strategy(
        self,
    ) -> None:
        cfg = CampaignConfig(
            mode="real-ue-direct",
            target_msisdn="111111",
            packet_file=self._path,
        )

        self.assertEqual(cfg.methods, ("OPTIONS",))
        self.assertEqual(cfg.layers, ("byte",))
        self.assertEqual(cfg.strategies, ("identity",))

    def test_packet_file_rejects_softphone_mode(self) -> None:
        with self.assertRaises(ValidationError) as ctx:
            CampaignConfig(
                target_host="127.0.0.1",
                packet_file=self._path,
                layers=("byte",),
            )
        self.assertIn("packet_file requires mode='real-ue-direct'", str(ctx.exception))

    def test_packet_file_requires_target_msisdn(self) -> None:
        with self.assertRaises(ValidationError) as ctx:
            CampaignConfig(
                target_host="10.20.20.8",
                mode="real-ue-direct",
                packet_file=self._path,
                layers=("byte",),
            )
        self.assertIn("target_msisdn", str(ctx.exception))

    def test_packet_file_mutually_exclusive_with_mt_flag(self) -> None:
        with self.assertRaises(ValidationError) as ctx:
            CampaignConfig(
                mode="real-ue-direct",
                target_msisdn="111111",
                impi="001010000123511",
                mt=True,
                packet_file=self._path,
                layers=("byte",),
            )
        self.assertIn("mutually exclusive", str(ctx.exception))

    def test_packet_file_rejects_wire_layer(self) -> None:
        with self.assertRaises(ValidationError) as ctx:
            CampaignConfig(
                mode="real-ue-direct",
                target_msisdn="111111",
                packet_file=self._path,
                layers=("wire",),
            )
        self.assertIn("packet_file supports layers", str(ctx.exception))

    def test_packet_file_rejects_multiple_methods(self) -> None:
        with self.assertRaises(ValidationError) as ctx:
            CampaignConfig(
                mode="real-ue-direct",
                target_msisdn="111111",
                packet_file=self._path,
                methods=("OPTIONS", "INVITE"),
                layers=("byte",),
            )
        self.assertIn("packet_file supports exactly one method", str(ctx.exception))

    def test_packet_file_rejects_method_mismatch(self) -> None:
        with self.assertRaises(ValidationError) as ctx:
            CampaignConfig(
                mode="real-ue-direct",
                target_msisdn="111111",
                packet_file=self._path,
                methods=("INVITE",),
                layers=("byte",),
            )
        self.assertIn(
            "packet_file method must match file start-line", str(ctx.exception)
        )

    def test_packet_file_rejects_response_codes(self) -> None:
        with self.assertRaises(ValidationError) as ctx:
            CampaignConfig(
                mode="real-ue-direct",
                target_msisdn="111111",
                packet_file=self._path,
                methods=("OPTIONS",),
                response_codes=(486,),
                layers=("byte",),
            )
        self.assertIn("packet_file does not support response_codes", str(ctx.exception))

    def test_packet_file_rejects_non_identity_strategy(self) -> None:
        with self.assertRaises(ValidationError) as ctx:
            CampaignConfig(
                mode="real-ue-direct",
                target_msisdn="111111",
                packet_file=self._path,
                methods=("OPTIONS",),
                layers=("byte",),
                strategies=("default",),
            )
        self.assertIn("packet_file supports only identity strategy", str(ctx.exception))

    def test_packet_file_rejects_missing_request_line(self) -> None:
        empty = tempfile.NamedTemporaryFile(suffix=".sip", delete=False)
        empty.close()
        self.addCleanup(lambda: Path(empty.name).unlink(missing_ok=True))

        with self.assertRaises(ValidationError) as ctx:
            CampaignConfig(
                mode="real-ue-direct",
                target_msisdn="111111",
                packet_file=empty.name,
                layers=("byte",),
                strategies=("identity",),
            )
        self.assertIn("packet_file start-line", str(ctx.exception))

    def test_packet_file_rejects_missing_path(self) -> None:
        with self.assertRaises(ValidationError) as ctx:
            CampaignConfig(
                mode="real-ue-direct",
                target_msisdn="111111",
                packet_file="/nonexistent/path/that/does/not/exist.sip",
                layers=("byte",),
            )
        self.assertIn("packet_file not found", str(ctx.exception))


class CaseSpecTests(unittest.TestCase):
    def test_valid(self) -> None:
        spec = CaseSpec(
            case_id=0, seed=42, method="OPTIONS", layer="model", strategy="default"
        )
        self.assertEqual(spec.case_id, 0)
        self.assertEqual(spec.seed, 42)
        self.assertEqual(spec.profile, "legacy")

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
        self.assertEqual(r.profile, "legacy")

    def test_crash_case_with_raw_response(self) -> None:
        r = self._make(verdict="crash", raw_response="SIP/2.0 500 Error\r\n\r\n")
        self.assertEqual(r.verdict, "crash")
        self.assertIsNotNone(r.raw_response)
        payload = r.model_dump(mode="json")
        self.assertEqual(payload["profile"], "legacy")

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
        self.assertFalse(cfg.ios_run_diagnostics)

    def test_ios_enabled_with_udid(self) -> None:
        cfg = CampaignConfig(
            target_host="127.0.0.1",
            ios_enabled=True,
            ios_udid="ABC-123",
            ios_run_diagnostics=True,
        )
        self.assertTrue(cfg.ios_enabled)
        self.assertEqual(cfg.ios_udid, "ABC-123")
        self.assertTrue(cfg.ios_run_diagnostics)

    def test_ios_not_auto_enabled_in_real_ue_direct(self) -> None:
        cfg = CampaignConfig(
            target_host="127.0.0.1",
            mode="real-ue-direct",
        )
        self.assertFalse(cfg.ios_enabled)
