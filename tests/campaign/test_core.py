import json
import tempfile
import time
import unittest
import unittest.mock
from types import SimpleNamespace
from pathlib import Path
from typing import Literal

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
from volte_mutation_fuzzer.sender.contracts import TargetEndpoint
from volte_mutation_fuzzer.sender.contracts import SocketObservation, SendReceiveResult
from volte_mutation_fuzzer.sip.catalog import SIP_CATALOG
from tests.sender._server import UDPResponder


# ---------------------------------------------------------------------------
# CaseGenerator tests
# ---------------------------------------------------------------------------


class CaseGeneratorTests(unittest.TestCase):
    def _config(self, **kwargs) -> CampaignConfig:
        defaults = dict(target_host="127.0.0.1")
        defaults.update(kwargs)
        return CampaignConfig.model_validate(defaults)

    def test_methods_generate_direct_combinations(self) -> None:
        cfg = self._config(methods=("OPTIONS", "INVITE"), max_cases=8)
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
            methods=("OPTIONS", "INVITE"), layers=("model",), max_cases=100
        )
        cases = list(CaseGenerator(cfg).generate())
        for case in cases:
            self.assertEqual(case.layer, "model")

    def test_strategy_filter_from_config(self) -> None:
        cfg = self._config(
            methods=("OPTIONS", "INVITE"), strategies=("default",), max_cases=100
        )
        cases = list(CaseGenerator(cfg).generate())
        for case in cases:
            self.assertEqual(case.strategy, "default")

    def test_methods_come_from_config(self) -> None:
        cfg = self._config(methods=("OPTIONS", "INVITE"), max_cases=100)
        cases = list(CaseGenerator(cfg).generate())
        methods_seen = {c.method for c in cases if c.response_code is None}
        self.assertEqual(methods_seen, {"OPTIONS", "INVITE"})

    def test_no_invalid_layer_strategy_combinations(self) -> None:
        cfg = self._config(methods=("OPTIONS", "INVITE"), max_cases=100)
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
            methods=("OPTIONS", "INVITE"), layers=("wire",), max_cases=100
        )
        cases = list(CaseGenerator(cfg).generate())
        for case in cases:
            self.assertEqual(case.strategy, "default")

    def test_round_cycling_repeats_combos_with_new_seeds(self) -> None:
        """After exhausting unique combos, generator cycles with new seeds."""
        cfg = self._config(
            methods=("OPTIONS",),
            layers=("wire",),
            strategies=("default",),
            max_cases=10,
        )
        cases = list(CaseGenerator(cfg).generate())
        self.assertEqual(len(cases), 10)
        # All should be OPTIONS/wire/default
        for c in cases:
            self.assertEqual(c.method, "OPTIONS")
            self.assertEqual(c.layer, "wire")
            self.assertEqual(c.strategy, "default")
        # Seeds should all be unique and sequential
        seeds = [c.seed for c in cases]
        self.assertEqual(seeds, list(range(10)))

    def test_round_cycling_identity_only_in_first_round(self) -> None:
        """Identity baseline appears only in round 0 for template mode."""
        cfg = self._config(
            methods=("INVITE",),
            layers=("wire",),
            strategies=("identity", "default"),
            mt_invite_template="a31",
            mode="real-ue-direct",
            target_msisdn="111111",
            impi="001010000123511",
            ipsec_mode="null",
            max_cases=10,
        )
        cases = list(CaseGenerator(cfg).generate())
        self.assertEqual(len(cases), 10)
        # First case is identity
        self.assertEqual(cases[0].strategy, "identity")
        # Remaining are default (identity not repeated)
        for c in cases[1:]:
            self.assertEqual(c.strategy, "default")

    def test_unlimited_mode_generates_many_cases(self) -> None:
        """max_cases=0 generates indefinitely (we just check it yields > combos)."""
        cfg = self._config(
            methods=("OPTIONS",),
            layers=("wire",),
            strategies=("default",),
            max_cases=0,
        )
        gen = CaseGenerator(cfg).generate()
        cases = [next(gen) for _ in range(50)]
        self.assertEqual(len(cases), 50)
        self.assertEqual(cases[49].case_id, 49)

    def test_response_codes_generate_related_method_cases(self) -> None:
        expected_related_methods = tuple(
            method.value for method in SIP_CATALOG.get_response(200).related_methods
        )
        n_combos = len(expected_related_methods)
        cfg = self._config(
            methods=(),
            response_codes=(200,),
            layers=("model",),
            strategies=("default",),
            max_cases=n_combos,
        )
        cases = list(CaseGenerator(cfg).generate())
        self.assertEqual(len(cases), n_combos)
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

    def test_read_all_preserves_adaptive_oracle_grace_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            store = ResultStore(path)
            campaign = CampaignResult(
                campaign_id="test123",
                started_at="2026-01-01T00:00:00Z",
                config=CampaignConfig(
                    target_host="10.20.20.8",
                    mode="real-ue-direct",
                    target_msisdn="111111",
                ),
                status="running",
            )
            store.write_header(campaign)

            header, _ = store.read_all()
            self.assertIsNone(header.config.oracle_log_grace_seconds)
            self.assertEqual(
                header.config.oracle_log_grace_seconds_for_method("OPTIONS"),
                1.0,
            )

    def test_read_case_by_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            store = ResultStore(path)
            store.write_header(self._make_campaign(str(path)))
            for i in range(5):
                store.append(self._make_case_result(i))

            result = store.read_case(3)
            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result.case_id, 3)


class CampaignExecutorWallClockTests(unittest.TestCase):
    def _make_campaign(self, path: str) -> CampaignResult:
        return CampaignResult(
            campaign_id="test123",
            started_at="2026-01-01T00:00:00Z",
            config=CampaignConfig(target_host="127.0.0.1"),
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

    def _make_config(
        self,
        host: str,
        port: int,
        *,
        methods: tuple[str, ...],
        max_cases: int,
        **kwargs,
    ) -> CampaignConfig:
        defaults = {
            "target_host": host,
            "target_port": port,
            "methods": methods,
            "max_cases": max_cases,
        }
        defaults.update(kwargs)
        return CampaignConfig.model_validate(defaults)

    def test_execute_case_records_case_wall_ms(self) -> None:
        cfg = self._make_config(
            "127.0.0.1",
            5060,
            methods=("OPTIONS",),
            max_cases=1,
        )
        executor = CampaignExecutor(cfg)
        spec = CaseSpec(
            case_id=0,
            seed=0,
            method="OPTIONS",
            layer="model",
            strategy="default",
        )
        send_result = SendReceiveResult(
            target=TargetEndpoint(host="127.0.0.1", port=5060),
            artifact_kind="packet",
            bytes_sent=120,
            outcome="success",
            responses=(
                SocketObservation(
                    status_code=200,
                    reason_phrase="OK",
                    raw_text="SIP/2.0 200 OK\r\n\r\n",
                    classification="success",
                ),
            ),
            send_started_at=100.1,
            send_completed_at=100.2,
        )

        with unittest.mock.patch.object(
            executor._sender,
            "send_artifact",
            return_value=send_result,
        ), unittest.mock.patch.object(
            executor._oracle,
            "evaluate",
            return_value=SimpleNamespace(
                verdict="normal",
                reason="ok",
                response_code=200,
                elapsed_ms=100.0,
                process_alive=True,
                details={},
            ),
        ), unittest.mock.patch(
            "volte_mutation_fuzzer.campaign.core.time.monotonic",
            side_effect=[10.0, 10.9],
        ):
            result = executor._execute_case(spec)

        self.assertEqual(result.case_wall_ms, 900.0)

    def test_execute_case_uses_method_specific_oracle_grace(self) -> None:
        cfg = self._make_config(
            "10.20.20.8",
            5060,
            mode="real-ue-direct",
            methods=("OPTIONS",),
            target_msisdn="111111",
            impi="001010000123511",
            ipsec_mode="null",
            pcap_enabled=False,
            max_cases=1,
            layers=("wire",),
            strategies=("default",),
        )
        executor = CampaignExecutor(cfg)
        spec = CaseSpec(
            case_id=0,
            seed=0,
            method="OPTIONS",
            layer="wire",
            strategy="default",
        )
        send_result = SendReceiveResult(
            target=TargetEndpoint(
                host="10.20.20.8",
                port=5060,
                mode="real-ue-direct",
                msisdn="111111",
                ipsec_mode="null",
                bind_container="pcscf",
            ),
            artifact_kind="wire",
            bytes_sent=100,
            outcome="success",
            responses=(
                SocketObservation(
                    status_code=200,
                    reason_phrase="OK",
                    raw_text="SIP/2.0 200 OK\r\n\r\n",
                    classification="success",
                ),
            ),
            send_started_at=1.0,
            send_completed_at=1.1,
        )

        with unittest.mock.patch.object(
            executor,
            "_resolve_ports_cached",
            return_value=(8100, 8101),
        ), unittest.mock.patch.object(
            executor._mutator,
            "mutate_editable",
            return_value=SimpleNamespace(
                final_layer="wire",
                wire_text="OPTIONS sip:111111@example.com SIP/2.0\r\n\r\n",
                packet_bytes=None,
                records=(),
            ),
        ), unittest.mock.patch.object(
            executor._sender,
            "send_artifact",
            return_value=send_result,
        ), unittest.mock.patch.object(
            executor._oracle,
            "evaluate",
            return_value=SimpleNamespace(
                verdict="normal",
                reason="ok",
                response_code=200,
                elapsed_ms=100.0,
                process_alive=True,
                details={},
            ),
        ) as evaluate_mock:
            executor._execute_case(spec)

        context = evaluate_mock.call_args.args[1]
        self.assertEqual(context.log_grace_seconds, 1.0)

    def test_execute_case_uses_explicit_oracle_grace_override(self) -> None:
        cfg = self._make_config(
            "10.20.20.8",
            5060,
            mode="real-ue-direct",
            methods=("OPTIONS",),
            target_msisdn="111111",
            impi="001010000123511",
            ipsec_mode="null",
            pcap_enabled=False,
            max_cases=1,
            oracle_log_grace_seconds=6.5,
        )
        executor = CampaignExecutor(cfg)
        spec = CaseSpec(
            case_id=0,
            seed=0,
            method="OPTIONS",
            layer="wire",
            strategy="default",
        )
        send_result = SendReceiveResult(
            target=TargetEndpoint(
                host="10.20.20.8",
                port=5060,
                mode="real-ue-direct",
                msisdn="111111",
                ipsec_mode="null",
                bind_container="pcscf",
            ),
            artifact_kind="packet",
            bytes_sent=100,
            outcome="success",
            responses=(
                SocketObservation(
                    status_code=200,
                    reason_phrase="OK",
                    raw_text="SIP/2.0 200 OK\r\n\r\n",
                    classification="success",
                ),
            ),
            send_started_at=1.0,
            send_completed_at=1.1,
        )

        with unittest.mock.patch.object(
            executor._sender,
            "send_artifact",
            return_value=send_result,
        ), unittest.mock.patch.object(
            executor._oracle,
            "evaluate",
            return_value=SimpleNamespace(
                verdict="normal",
                reason="ok",
                response_code=200,
                elapsed_ms=100.0,
                process_alive=True,
                details={},
            ),
        ) as evaluate_mock:
            executor._execute_case(spec)

        context = evaluate_mock.call_args.args[1]
        self.assertEqual(context.log_grace_seconds, 6.5)

    def test_execute_case_uses_method_specific_oracle_grace_in_dialog_path(
        self,
    ) -> None:
        cfg = self._make_config(
            "127.0.0.1",
            5060,
            mode="real-ue-direct",
            methods=("BYE",),
            pcap_enabled=False,
            max_cases=1,
        )
        executor = CampaignExecutor(cfg)
        spec = CaseSpec(
            case_id=0,
            seed=0,
            method="BYE",
            layer="model",
            strategy="default",
        )
        send_result = SendReceiveResult(
            target=TargetEndpoint(host="127.0.0.1", port=5060),
            artifact_kind="packet",
            bytes_sent=120,
            outcome="success",
            responses=(
                SocketObservation(
                    status_code=200,
                    reason_phrase="OK",
                    raw_text="SIP/2.0 200 OK\r\n\r\n",
                    classification="success",
                ),
            ),
            send_started_at=100.1,
            send_completed_at=100.2,
        )
        fake_exchange = SimpleNamespace(
            setup_succeeded=True,
            fuzz_result=SimpleNamespace(send_result=send_result),
            error=None,
        )

        with unittest.mock.patch(
            "volte_mutation_fuzzer.campaign.core.DialogOrchestrator.execute",
            return_value=fake_exchange,
        ), unittest.mock.patch.object(
            executor._oracle,
            "evaluate",
            return_value=SimpleNamespace(
                verdict="normal",
                reason="ok",
                response_code=200,
                elapsed_ms=100.0,
                process_alive=True,
                details={},
            ),
        ) as evaluate_mock:
            executor._execute_case(spec)

        context = evaluate_mock.call_args.args[1]
        self.assertEqual(context.log_grace_seconds, 2.0)

    def test_execute_mt_template_case_records_wall_time_after_evidence_collection(
        self,
    ) -> None:
        cfg = self._make_config(
            "10.20.20.8",
            5060,
            mode="real-ue-direct",
            methods=("INVITE",),
            target_msisdn="111111",
            impi="001010000123511",
            mt_invite_template="a31",
            ipsec_mode="null",
            max_cases=1,
            layers=("wire",),
            strategies=("default",),
        )
        executor = CampaignExecutor(cfg)
        spec = CaseSpec(
            case_id=0,
            seed=0,
            method="INVITE",
            layer="wire",
            strategy="default",
        )
        invite_wire = (
            "INVITE sip:111111@example.com SIP/2.0\r\n"
            "CSeq: 1 INVITE\r\n"
            "\r\n"
        )
        send_result = SendReceiveResult(
            target=TargetEndpoint(
                host="10.20.20.8",
                port=5060,
                mode="real-ue-direct",
                msisdn="111111",
                ipsec_mode="null",
                bind_container="pcscf",
            ),
            artifact_kind="wire",
            bytes_sent=100,
            outcome="success",
            responses=(
                SocketObservation(
                    status_code=200,
                    reason_phrase="OK",
                    raw_text="SIP/2.0 200 OK\r\n\r\n",
                    classification="success",
                ),
            ),
            send_started_at=1.0,
            send_completed_at=1.1,
        )

        with unittest.mock.patch.object(
            executor,
            "_resolve_ports_cached",
            return_value=(8100, 8101),
        ), unittest.mock.patch(
            "volte_mutation_fuzzer.campaign.core.build_default_slots",
            return_value={},
        ), unittest.mock.patch(
            "volte_mutation_fuzzer.campaign.core.render_mt_invite",
            return_value=invite_wire,
        ), unittest.mock.patch.object(
            executor._mutator,
            "mutate_editable",
            return_value=SimpleNamespace(
                final_layer="wire",
                wire_text=invite_wire,
                packet_bytes=None,
                records=(),
            ),
        ), unittest.mock.patch.object(
            executor,
            "_teardown_invite",
            return_value=[],
        ), unittest.mock.patch.object(
            executor._sender,
            "send_artifact",
            return_value=send_result,
        ), unittest.mock.patch.object(
            executor._oracle,
            "evaluate",
            return_value=SimpleNamespace(
                verdict="normal",
                reason="ok",
                response_code=200,
                elapsed_ms=100.0,
                process_alive=True,
                details={},
            ),
        ), unittest.mock.patch.object(
            executor._evidence,
            "collect",
            side_effect=lambda *args, **kwargs: time.monotonic(),
        ), unittest.mock.patch(
            "volte_mutation_fuzzer.campaign.core.time.monotonic",
            side_effect=[101.0, 102.5],
        ):
            result = executor._execute_mt_template_case(
                spec,
                timestamp=1234.5,
                case_started_monotonic=100.0,
            )

        self.assertEqual(result.case_wall_ms, 2500.0)

    def test_dialog_case_records_case_wall_ms(self) -> None:
        cfg = self._make_config(
            "127.0.0.1",
            5060,
            methods=("BYE",),
            max_cases=1,
        )
        executor = CampaignExecutor(cfg)
        spec = CaseSpec(
            case_id=0,
            seed=0,
            method="BYE",
            layer="model",
            strategy="default",
        )
        send_result = SendReceiveResult(
            target=TargetEndpoint(host="127.0.0.1", port=5060),
            artifact_kind="packet",
            bytes_sent=120,
            outcome="success",
            responses=(
                SocketObservation(
                    status_code=200,
                    reason_phrase="OK",
                    raw_text="SIP/2.0 200 OK\r\n\r\n",
                    classification="success",
                ),
            ),
            send_started_at=100.1,
            send_completed_at=100.2,
        )

        fake_exchange = SimpleNamespace(
            setup_succeeded=True,
            fuzz_result=SimpleNamespace(send_result=send_result),
            error=None,
        )

        with unittest.mock.patch.object(
            executor._oracle,
            "evaluate",
            return_value=SimpleNamespace(
                verdict="normal",
                reason="ok",
                response_code=200,
                elapsed_ms=100.0,
                process_alive=True,
                details={},
            ),
        ), unittest.mock.patch(
            "volte_mutation_fuzzer.campaign.core.DialogOrchestrator.execute",
            return_value=fake_exchange,
        ), unittest.mock.patch(
            "volte_mutation_fuzzer.campaign.core.time.monotonic",
            side_effect=[10.0, 10.9],
        ):
            result = executor._execute_case(spec)

        self.assertEqual(result.case_wall_ms, 900.0)

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
    def _make_config(self, host: str | None, port: int, **kwargs) -> CampaignConfig:
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
        return CampaignConfig.model_validate(defaults)

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
            out_dir = tmpdir
            cfg = self._make_config(
                responder.host,
                responder.port,
                results_dir=out_dir, output_name="test",
            )
            executor = CampaignExecutor(cfg)
            result = executor.run()

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.summary.total, 4)
        self.assertIsNotNone(result.completed_at)

    def test_run_waits_for_pending_pcap_exports_before_return(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = self._make_config(
                "127.0.0.1",
                5060,
                methods=("OPTIONS",),
                max_cases=1,
                cooldown_seconds=0.0,
                results_dir=tmpdir,
                output_name="test",
            )
            executor = CampaignExecutor(cfg)
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
                executor,
                "_execute_case",
                return_value=fake_case,
            ), unittest.mock.patch(
                "volte_mutation_fuzzer.campaign.core.PcapCapture.wait_for_pending_exports"
            ) as wait_mock:
                executor.run()

        wait_mock.assert_called_once_with()

    def test_run_waits_for_pending_pcap_exports_on_keyboard_interrupt(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = self._make_config(
                "127.0.0.1",
                5060,
                methods=("OPTIONS",),
                max_cases=1,
                cooldown_seconds=0.0,
                results_dir=tmpdir,
                output_name="test",
            )
            executor = CampaignExecutor(cfg)

            with unittest.mock.patch.object(
                executor,
                "_execute_case",
                side_effect=KeyboardInterrupt,
            ), unittest.mock.patch(
                "volte_mutation_fuzzer.campaign.core.PcapCapture.wait_for_pending_exports"
            ) as wait_mock, unittest.mock.patch(
                "volte_mutation_fuzzer.campaign.core.HtmlReportGenerator.generate",
                return_value=Path(tmpdir) / "report.html",
            ):
                result = executor.run()

        self.assertEqual(result.status, "aborted")
        wait_mock.assert_called_once_with()

    def test_snapshot_profile_for_verdict_maps_expected_profiles(self) -> None:
        cases = (
            ("normal", "light"),
            ("suspicious", "full"),
            ("crash", "full"),
            ("stack_failure", "full"),
        )

        for verdict, expected_profile in cases:
            with self.subTest(verdict=verdict):
                self.assertEqual(
                    CampaignExecutor._snapshot_profile_for_verdict(verdict),
                    expected_profile,
                )

    def test_execute_case_propagates_oracle_details(self) -> None:
        cfg = self._make_config(
            "127.0.0.1",
            5060,
            methods=("OPTIONS",),
            max_cases=1,
        )
        executor = CampaignExecutor(cfg)
        spec = CaseSpec(
            case_id=0,
            seed=0,
            method="OPTIONS",
            layer="model",
            strategy="default",
        )
        send_result = SendReceiveResult(
            target=TargetEndpoint(host="127.0.0.1", port=5060),
            artifact_kind="packet",
            bytes_sent=120,
            outcome="timeout",
            responses=(),
            send_started_at=100.1,
            send_completed_at=100.2,
        )

        with unittest.mock.patch.object(
            executor._sender,
            "send_artifact",
            return_value=send_result,
        ), unittest.mock.patch.object(
            executor._oracle,
            "evaluate",
            return_value=SimpleNamespace(
                verdict="timeout",
                reason="no response received within timeout",
                response_code=None,
                elapsed_ms=12.5,
                process_alive=None,
                details={
                    "adb_warning": {
                        "severity": "warning",
                        "matched_line": "IMS deregist triggered by network change",
                    }
                },
            ),
        ):
            result = executor._execute_case(spec)

        adb_warning = result.details.get("adb_warning")
        assert isinstance(adb_warning, dict)
        self.assertEqual(adb_warning["severity"], "warning")
        self.assertIn("IMS deregist", str(adb_warning["matched_line"]))

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
            out_dir = tmpdir
            cfg = self._make_config(
                responder.host,
                responder.port,
                results_dir=out_dir, output_name="test",
            )
            executor = CampaignExecutor(cfg)
            result = executor.run()

        self.assertGreater(result.summary.normal, 0)

    def test_run_returns_timeout_verdict_for_silent_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = tmpdir
            cfg = self._make_config(
                "127.0.0.1",
                19999,
                methods=("OPTIONS", "INVITE"),
                max_cases=2,
                results_dir=out_dir, output_name="test",
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
            out_dir = tmpdir
            cfg = self._make_config(
                responder.host,
                responder.port,
                methods=("OPTIONS", "INVITE", "MESSAGE"),
                max_cases=3,
                results_dir=out_dir, output_name="test",
            )
            executor = CampaignExecutor(cfg)
            executor.run()

            store = ResultStore(Path(out_dir) / "test" / "campaign.jsonl")
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
            out_dir = tmpdir
            cfg = self._make_config(
                responder.host,
                responder.port,
                methods=("OPTIONS",),
                results_dir=out_dir, output_name="test",
                max_cases=1,
            )
            executor = CampaignExecutor(cfg)
            executor.run()

            store = ResultStore(Path(out_dir) / "test" / "campaign.jsonl")
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

    def test_reproduction_cmd_uses_msisdn_when_target_host_missing(self) -> None:
        cfg = self._make_config(
            None,
            5060,
            mode="real-ue-direct",
            methods=("OPTIONS",),
            target_msisdn="111111",
            impi="001010000123511",
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

        self.assertNotIn("--target-host None", cmd)
        self.assertIn("--target-msisdn 111111", cmd)

    def test_mt_template_reproduction_cmd_uses_msisdn_when_target_host_missing(self) -> None:
        cfg = self._make_config(
            None,
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
        cmd = executor._build_mt_template_reproduction_cmd(
            CaseSpec(
                case_id=0,
                seed=7,
                method="INVITE",
                layer="wire",
                strategy="default",
            )
        )

        self.assertNotIn("--target-host None", cmd)
        self.assertIn("--target-msisdn 111111", cmd)
        self.assertIn("--mt-invite-template a31", cmd)

    def test_unknown_verdict_prints_error_to_stderr(self) -> None:
        import io
        from unittest.mock import patch as mock_patch

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = tmpdir
            cfg = self._make_config(
                "127.0.0.1",
                19998,
                methods=("OPTIONS",),
                max_cases=1,
                results_dir=out_dir, output_name="test",
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
            out_dir = tmpdir
            cfg = self._make_config(
                "127.0.0.1",
                5060,
                methods=("OPTIONS",),
                max_cases=1,
                results_dir=out_dir, output_name="test",
                crash_analysis=True,
            )
            crash_analysis_dir = str(Path(out_dir) / "test" / "crash_analysis")
            analyzer = CampaignCrashAnalyzer(
                output_dir=crash_analysis_dir,
                enabled=True,
                source_name=str(Path(out_dir) / "test" / "campaign.jsonl"),
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
                setattr(
                    executor,
                    "_execute_case",
                    unittest.mock.Mock(return_value=fake_case),
                )
                executor.run()

            self.assertEqual(analyze_mock.call_count, 1)
            report_mock.assert_called_once()
            self.assertTrue(Path(crash_analysis_dir).exists())

    def test_init_threads_ipsec_mode_into_target_endpoint(self) -> None:
        cfg = self._make_config(
            "10.20.20.8",
            5060,
            mode="real-ue-direct",
            methods=("INVITE",),
            target_msisdn="111111",
            impi="001010000123511",
            mt_invite_template="a31",
            ipsec_mode="native",
        )

        executor = CampaignExecutor(cfg)

        self.assertEqual(executor._target.ipsec_mode, "native")

    def test_init_ios_enabled_wires_ios_oracle(self) -> None:
        cfg = self._make_config(
            "127.0.0.1",
            5060,
            methods=("OPTIONS",),
            max_cases=1,
            ios_enabled=True,
            adb_enabled=False,
        )

        executor = CampaignExecutor(cfg)

        self.assertIsNotNone(executor._ios_collector)
        self.assertIsNone(executor._adb_collector)
        self.assertIsNotNone(executor._oracle._ios_oracle)

    def test_init_wires_both_adb_and_ios_oracles_when_enabled(self) -> None:
        cfg = self._make_config(
            "127.0.0.1",
            5060,
            methods=("OPTIONS",),
            max_cases=1,
            ios_enabled=True,
            adb_enabled=True,
        )

        executor = CampaignExecutor(cfg)

        self.assertIsNotNone(executor._adb_collector)
        self.assertIsNotNone(executor._ios_collector)
        self.assertIsNotNone(executor._oracle._adb_oracle)
        self.assertIsNotNone(executor._oracle._ios_oracle)

    def test_run_starts_and_stops_ios_collector(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = self._make_config(
                "127.0.0.1",
                5060,
                methods=("OPTIONS",),
                max_cases=1,
                cooldown_seconds=0.0,
                results_dir=tmpdir,
                output_name="test",
                ios_enabled=True,
                adb_enabled=False,
            )
            executor = CampaignExecutor(cfg)
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
                executor._ios_collector,
                "start",
            ) as start_mock, unittest.mock.patch.object(
                executor._ios_collector,
                "stop",
            ) as stop_mock:
                setattr(
                    executor,
                    "_execute_case",
                    unittest.mock.Mock(return_value=fake_case),
                )
                executor.run()

            start_mock.assert_called_once()
            stop_mock.assert_called_once()

    def test_init_real_ue_msisdn_target_does_not_force_default_port(self) -> None:
        cfg = self._make_config(
            None,
            5060,
            mode="real-ue-direct",
            methods=("INVITE",),
            target_msisdn="111111",
            impi="001010000123511",
            mt_invite_template="a31",
            ipsec_mode="native",
        )

        executor = CampaignExecutor(cfg)

        self.assertIsNone(executor._target.port)

    def test_native_mt_template_builds_native_target_and_preserves_raw_response(self) -> None:
        cfg = self._make_config(
            "10.20.20.8",
            5060,
            mode="real-ue-direct",
            methods=("INVITE",),
            target_msisdn="111111",
            impi="001010000123511",
            mt_invite_template="a31",
            ipsec_mode="native",
            adb_enabled=True,
            max_cases=1,
            layers=("wire",),
            strategies=("identity",),
        )
        executor = CampaignExecutor(cfg)
        spec = CaseSpec(
            case_id=0,
            seed=7,
            method="INVITE",
            layer="wire",
            strategy="identity",
        )

        invite_wire = (
            "INVITE sip:111111@example.com SIP/2.0\r\n"
            "CSeq: 1 INVITE\r\n"
            "\r\n"
        )
        provisional = SocketObservation(
            source="pcscf-log",
            status_code=180,
            reason_phrase="Ringing",
            raw_text="SIP/2.0 180 Ringing\r\n\r\n",
            classification="provisional",
        )
        cancel_ok = SendReceiveResult(
            target=TargetEndpoint(
                host="10.20.20.8",
                port=5060,
                mode="real-ue-direct",
            ),
            artifact_kind="wire",
            bytes_sent=10,
            outcome="success",
            responses=(
                SocketObservation(
                    status_code=200,
                    reason_phrase="OK",
                    raw_text="SIP/2.0 200 OK\r\n\r\n",
                    classification="success",
                ),
            ),
            send_started_at=1.0,
            send_completed_at=1.1,
        )

        with unittest.mock.patch.object(
            executor,
            "_resolve_ports_cached",
            return_value=(8100, 8101),
        ), unittest.mock.patch(
            "volte_mutation_fuzzer.campaign.core.build_default_slots",
            return_value={},
        ), unittest.mock.patch(
            "volte_mutation_fuzzer.campaign.core.render_mt_invite",
            return_value=invite_wire,
        ), unittest.mock.patch.object(
            executor._mutator,
            "mutate_editable",
            return_value=SimpleNamespace(
                final_layer="wire",
                wire_text=invite_wire,
                packet_bytes=None,
                records=(),
            ),
        ), unittest.mock.patch.object(
            executor._oracle,
            "evaluate",
            return_value=SimpleNamespace(
                verdict="stack_failure",
                reason="adb crash detected",
                response_code=180,
                elapsed_ms=12.5,
                process_alive=True,
            ),
        ), unittest.mock.patch(
            "volte_mutation_fuzzer.adb.core.AdbConnector.take_snapshot",
            return_value=SimpleNamespace(),
        ) as snapshot_mock, unittest.mock.patch(
            "volte_mutation_fuzzer.campaign.core.time.time",
            return_value=1234.5,
        ), unittest.mock.patch.object(
            executor._sender,
            "send_artifact",
            side_effect=[
                SendReceiveResult(
                    target=TargetEndpoint(
                        host="10.20.20.8",
                        port=5060,
                        mode="real-ue-direct",
                        msisdn="111111",
                        ipsec_mode="native",
                        bind_container="pcscf",
                    ),
                    artifact_kind="wire",
                    bytes_sent=100,
                    outcome="success",
                    responses=(provisional,),
                    send_started_at=1.0,
                    send_completed_at=1.1,
                ),
                cancel_ok,
            ],
        ) as send_mock:
            result = executor._execute_mt_template_case(
                spec,
                timestamp=1234.5,
                case_started_monotonic=1234.0,
            )

        self.assertEqual(result.raw_response, "SIP/2.0 180 Ringing\r\n\r\n")
        self.assertEqual(send_mock.call_count, 2)
        self.assertEqual(snapshot_mock.call_count, 1)
        self.assertEqual(snapshot_mock.call_args.kwargs["collector"], executor._adb_collector)
        self.assertEqual(snapshot_mock.call_args.kwargs["profile"], "full")
        mt_target = send_mock.call_args_list[0].args[1]
        self.assertEqual(mt_target.ipsec_mode, "native")
        self.assertEqual(mt_target.bind_container, "pcscf")
        self.assertEqual(mt_target.host, "10.20.20.8")
        self.assertEqual(mt_target.port, 8100)
        self.assertIsNone(mt_target.bind_port)
        self.assertIsNone(mt_target.source_ip)

    def test_native_mt_template_preserves_raw_final_response(self) -> None:
        cfg = self._make_config(
            "10.20.20.8",
            5060,
            mode="real-ue-direct",
            methods=("INVITE",),
            target_msisdn="111111",
            impi="001010000123511",
            mt_invite_template="a31",
            ipsec_mode="native",
            max_cases=1,
            layers=("wire",),
            strategies=("identity",),
        )
        executor = CampaignExecutor(cfg)
        spec = CaseSpec(
            case_id=0,
            seed=7,
            method="INVITE",
            layer="wire",
            strategy="identity",
        )

        invite_wire = (
            "INVITE sip:111111@example.com SIP/2.0\r\n"
            "CSeq: 1 INVITE\r\n"
            "\r\n"
        )
        final_response = SocketObservation(
            source="pcscf-log",
            status_code=200,
            reason_phrase="OK",
            raw_text="SIP/2.0 200 OK\r\n\r\n",
            classification="success",
        )

        with unittest.mock.patch.object(
            executor,
            "_resolve_ports_cached",
            return_value=(8100, 8101),
        ), unittest.mock.patch(
            "volte_mutation_fuzzer.campaign.core.build_default_slots",
            return_value={},
        ), unittest.mock.patch(
            "volte_mutation_fuzzer.campaign.core.render_mt_invite",
            return_value=invite_wire,
        ), unittest.mock.patch.object(
            executor._mutator,
            "mutate_editable",
            return_value=SimpleNamespace(
                final_layer="wire",
                wire_text=invite_wire,
                packet_bytes=None,
                records=(),
            ),
        ), unittest.mock.patch.object(
            executor._oracle,
            "evaluate",
            return_value=SimpleNamespace(
                verdict="normal",
                reason="ok",
                response_code=200,
                elapsed_ms=12.5,
                process_alive=True,
            ),
        ), unittest.mock.patch.object(
            executor._sender,
            "send_artifact",
            return_value=SendReceiveResult(
                target=TargetEndpoint(
                    host="10.20.20.8",
                    port=5060,
                    mode="real-ue-direct",
                    msisdn="111111",
                    ipsec_mode="native",
                    bind_container="pcscf",
                ),
                artifact_kind="wire",
                bytes_sent=100,
                outcome="success",
                responses=(final_response,),
                send_started_at=1.0,
                send_completed_at=1.1,
            ),
        ):
            result = executor._execute_mt_template_case(
                spec,
                timestamp=1234.5,
                case_started_monotonic=1234.0,
            )

        self.assertEqual(result.raw_response, "SIP/2.0 200 OK\r\n\r\n")

    def test_native_mt_template_reproduction_cmd_omits_mt_local_port(self) -> None:
        cfg = self._make_config(
            "10.20.20.8",
            5060,
            mode="real-ue-direct",
            methods=("INVITE",),
            target_msisdn="111111",
            impi="001010000123511",
            mt_invite_template="a31",
            ipsec_mode="native",
            mt_local_port=15100,
        )
        executor = CampaignExecutor(cfg)
        cmd = executor._build_mt_template_reproduction_cmd(
            CaseSpec(
                case_id=0,
                seed=7,
                method="INVITE",
                layer="wire",
                strategy="default",
            )
        )

        self.assertIn("--ipsec-mode native", cmd)
        self.assertNotIn("--mt-local-port", cmd)

    def test_non_native_raw_response_is_kept_for_evidence_verdicts(self) -> None:
        final_response = SocketObservation(
            source="pcscf-log",
            status_code=500,
            reason_phrase="Server Error",
            raw_text="SIP/2.0 500 Server Error\r\n\r\n",
            classification="server_error",
        )
        send_result = SendReceiveResult(
            target=TargetEndpoint(
                host="10.20.20.8",
                port=5060,
                mode="real-ue-direct",
                ipsec_mode="null",
                bind_container="pcscf",
            ),
            artifact_kind="wire",
            bytes_sent=100,
            outcome="success",
            responses=(final_response,),
            send_started_at=1.0,
            send_completed_at=1.1,
        )

        for ipsec_mode in ("null", "bypass"):
            cfg = self._make_config(
                "10.20.20.8",
                5060,
                mode="real-ue-direct",
                methods=("INVITE",),
                ipsec_mode=ipsec_mode,
            )
            executor = CampaignExecutor(cfg)
            for verdict in ("suspicious", "crash", "stack_failure"):
                with self.subTest(ipsec_mode=ipsec_mode, verdict=verdict):
                    self.assertEqual(
                        executor._raw_response_from_send_result(verdict, send_result),
                        "SIP/2.0 500 Server Error\r\n\r\n",
                    )

    def test_mt_template_teardown_uses_mutated_wire_text(self) -> None:
        cfg = self._make_config(
            "10.20.20.8",
            5060,
            mode="real-ue-direct",
            methods=("INVITE",),
            target_msisdn="111111",
            impi="001010000123511",
            mt_invite_template="a31",
            ipsec_mode="null",
            max_cases=1,
            layers=("wire",),
            strategies=("identity",),
        )
        executor = CampaignExecutor(cfg)
        spec = CaseSpec(
            case_id=0,
            seed=7,
            method="INVITE",
            layer="wire",
            strategy="identity",
        )

        original_wire = (
            "INVITE sip:original@example.com SIP/2.0\r\n"
            "CSeq: 1 INVITE\r\n"
            "\r\n"
        )
        mutated_wire = (
            "INVITE sip:mutated@example.com SIP/2.0\r\n"
            "CSeq: 9 INVITE\r\n"
            "\r\n"
        )
        provisional = SocketObservation(
            source="pcscf-log",
            status_code=180,
            reason_phrase="Ringing",
            raw_text="SIP/2.0 180 Ringing\r\n\r\n",
            classification="provisional",
        )
        cancel_ok = SendReceiveResult(
            target=TargetEndpoint(
                host="10.20.20.8",
                port=5060,
                mode="real-ue-direct",
                ipsec_mode="null",
                bind_container="pcscf",
            ),
            artifact_kind="wire",
            bytes_sent=10,
            outcome="success",
            responses=(
                SocketObservation(
                    status_code=200,
                    reason_phrase="OK",
                    raw_text="SIP/2.0 200 OK\r\n\r\n",
                    classification="success",
                ),
            ),
            send_started_at=1.0,
            send_completed_at=1.1,
        )

        with unittest.mock.patch.object(
            executor,
            "_resolve_ports_cached",
            return_value=(8100, 8101),
        ), unittest.mock.patch(
            "volte_mutation_fuzzer.campaign.core.build_default_slots",
            return_value={},
        ), unittest.mock.patch(
            "volte_mutation_fuzzer.campaign.core.render_mt_invite",
            return_value=original_wire,
        ), unittest.mock.patch.object(
            executor._mutator,
            "mutate_editable",
            return_value=SimpleNamespace(
                final_layer="wire",
                wire_text=mutated_wire,
                packet_bytes=None,
                records=(),
            ),
        ), unittest.mock.patch.object(
            executor._oracle,
            "evaluate",
            return_value=SimpleNamespace(
                verdict="normal",
                reason="ok",
                response_code=180,
                elapsed_ms=12.5,
                process_alive=True,
            ),
        ), unittest.mock.patch.object(
            executor._sender,
            "send_artifact",
            side_effect=[
                SendReceiveResult(
                    target=TargetEndpoint(
                        host="10.20.20.8",
                        port=5060,
                        mode="real-ue-direct",
                        ipsec_mode="null",
                        bind_container="pcscf",
                    ),
                    artifact_kind="wire",
                    bytes_sent=100,
                    outcome="success",
                    responses=(provisional,),
                    send_started_at=1.0,
                    send_completed_at=1.1,
                ),
                cancel_ok,
            ],
        ) as send_mock:
            executor._execute_mt_template_case(
                spec,
                timestamp=1234.5,
                case_started_monotonic=1234.0,
            )

        self.assertEqual(send_mock.call_count, 2)
        cancel_artifact = send_mock.call_args_list[1].args[0]
        self.assertEqual(
            cancel_artifact.wire_text,
            "CANCEL sip:mutated@example.com SIP/2.0\r\nCSeq: 9 CANCEL\r\n\r\n",
        )

    def test_mt_template_teardown_uses_mutated_byte_payload(self) -> None:
        cfg = self._make_config(
            "10.20.20.8",
            5060,
            mode="real-ue-direct",
            methods=("INVITE",),
            target_msisdn="111111",
            impi="001010000123511",
            mt_invite_template="a31",
            ipsec_mode="null",
            max_cases=1,
            layers=("wire",),
            strategies=("identity",),
        )
        executor = CampaignExecutor(cfg)
        spec = CaseSpec(
            case_id=0,
            seed=7,
            method="INVITE",
            layer="wire",
            strategy="identity",
        )

        original_wire = (
            "INVITE sip:original@example.com SIP/2.0\r\n"
            "CSeq: 1 INVITE\r\n"
            "\r\n"
        )
        mutated_bytes = (
            b"INVITE sip:mutated@example.com SIP/2.0\r\n"
            b"CSeq: 9 INVITE\r\n"
            b"\r\n"
        )
        provisional = SocketObservation(
            source="pcscf-log",
            status_code=180,
            reason_phrase="Ringing",
            raw_text="SIP/2.0 180 Ringing\r\n\r\n",
            classification="provisional",
        )
        cancel_ok = SendReceiveResult(
            target=TargetEndpoint(
                host="10.20.20.8",
                port=5060,
                mode="real-ue-direct",
                ipsec_mode="null",
                bind_container="pcscf",
            ),
            artifact_kind="wire",
            bytes_sent=10,
            outcome="success",
            responses=(
                SocketObservation(
                    status_code=200,
                    reason_phrase="OK",
                    raw_text="SIP/2.0 200 OK\r\n\r\n",
                    classification="success",
                ),
            ),
            send_started_at=1.0,
            send_completed_at=1.1,
        )

        with unittest.mock.patch.object(
            executor,
            "_resolve_ports_cached",
            return_value=(8100, 8101),
        ), unittest.mock.patch(
            "volte_mutation_fuzzer.campaign.core.build_default_slots",
            return_value={},
        ), unittest.mock.patch(
            "volte_mutation_fuzzer.campaign.core.render_mt_invite",
            return_value=original_wire,
        ), unittest.mock.patch.object(
            executor._mutator,
            "mutate_editable",
            return_value=SimpleNamespace(
                final_layer="byte",
                wire_text=None,
                packet_bytes=mutated_bytes,
                records=(),
            ),
        ), unittest.mock.patch.object(
            executor._oracle,
            "evaluate",
            return_value=SimpleNamespace(
                verdict="normal",
                reason="ok",
                response_code=180,
                elapsed_ms=12.5,
                process_alive=True,
            ),
        ), unittest.mock.patch.object(
            executor._sender,
            "send_artifact",
            side_effect=[
                SendReceiveResult(
                    target=TargetEndpoint(
                        host="10.20.20.8",
                        port=5060,
                        mode="real-ue-direct",
                        ipsec_mode="null",
                        bind_container="pcscf",
                    ),
                    artifact_kind="bytes",
                    bytes_sent=100,
                    outcome="success",
                    responses=(provisional,),
                    send_started_at=1.0,
                    send_completed_at=1.1,
                ),
                cancel_ok,
            ],
        ) as send_mock:
            executor._execute_mt_template_case(
                spec,
                timestamp=1234.5,
                case_started_monotonic=1234.0,
            )

        self.assertEqual(send_mock.call_count, 2)
        cancel_artifact = send_mock.call_args_list[1].args[0]
        self.assertEqual(
            cancel_artifact.wire_text,
            "CANCEL sip:mutated@example.com SIP/2.0\r\nCSeq: 9 CANCEL\r\n\r\n",
        )

    def test_response_reproduction_cmd_prefers_msisdn_and_cli_flags(self) -> None:
        cfg = self._make_config(
            "10.20.20.8",
            5060,
            mode="real-ue-direct",
            methods=(),
            response_codes=(200,),
            target_msisdn="111111",
            impi="001010000123511",
            ipsec_mode="null",
        )
        executor = CampaignExecutor(cfg)
        cmd = executor._build_reproduction_cmd(
            CaseSpec(
                case_id=0,
                seed=7,
                method="INVITE",
                layer="model",
                strategy="default",
                response_code=200,
                related_method="INVITE",
            )
        )

        self.assertIn("--mode real-ue-direct", cmd)
        self.assertIn("--target-msisdn 111111", cmd)
        self.assertIn("--ipsec-mode null", cmd)
        self.assertNotIn("--target-host 10.20.20.8", cmd)
        self.assertNotIn("--bind-container", cmd)
        self.assertNotIn("--bind-port", cmd)

    def test_request_reproduction_cmd_prefers_msisdn_for_real_ue_direct(self) -> None:
        cfg = self._make_config(
            "10.20.20.8",
            5060,
            mode="real-ue-direct",
            methods=("OPTIONS",),
            target_msisdn="111111",
            impi="001010000123511",
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
        self.assertIn("--target-msisdn 111111", cmd)
        self.assertIn("--ipsec-mode null", cmd)
        self.assertNotIn("--target-host 10.20.20.8", cmd)
        self.assertNotIn("--bind-container", cmd)


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
            out_dir = tmpdir
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
                results_dir=out_dir, output_name="test",
            )
            executor = CampaignExecutor(cfg)

            # Mock _execute_case to always return timeout
            call_count = [0]
            def fake_execute(spec: CaseSpec) -> CaseResult:
                call_count[0] += 1
                return self._make_timeout_case(spec.case_id)

            setattr(executor, "_execute_case", fake_execute)

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


# ---------------------------------------------------------------------------
# INVITE teardown tests
# ---------------------------------------------------------------------------


class InviteTeardownTests(unittest.TestCase):
    """Tests for _teardown_invite reliable CANCEL logic."""

    def _make_executor(self) -> CampaignExecutor:
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        cfg = CampaignConfig(
            target_host="10.20.20.8",
            target_port=5060,
            target_msisdn="111111",
            impi="001010000123511",
            mode="real-ue-direct",
            ipsec_mode="null",
            mt_invite_template="a31",
            methods=("INVITE",),
            layers=("wire",),
            strategies=("identity",),
            max_cases=1,
            timeout_seconds=1.0,
            cooldown_seconds=0.0,
            check_process=False,
            adb_enabled=False,
            pcap_enabled=False,
            results_dir=tmpdir.name, output_name="test",
        )
        return CampaignExecutor(cfg)

    @staticmethod
    def _make_target() -> TargetEndpoint:
        return TargetEndpoint(
            host="10.20.20.8",
            port=5060,
            mode="real-ue-direct",
        )

    @staticmethod
    def _make_send_result(status_codes: list[int]) -> "SendReceiveResult":
        from volte_mutation_fuzzer.sender.contracts import (
            SendReceiveResult,
            SocketObservation,
        )

        def _classify(code: int) -> Literal[
            "provisional",
            "success",
            "client_error",
            "server_error",
            "invalid",
        ]:
            if 100 <= code < 200:
                return "provisional"
            if 200 <= code < 300:
                return "success"
            if 400 <= code < 500:
                return "client_error"
            if 500 <= code < 600:
                return "server_error"
            return "invalid"

        responses = tuple(
            SocketObservation(
                status_code=code,
                reason_phrase="OK",
                classification=_classify(code),
            )
            for code in status_codes
        )
        return SendReceiveResult(
            target=TargetEndpoint(host="10.20.20.8", port=5060, mode="real-ue-direct"),
            artifact_kind="wire",
            bytes_sent=100,
            outcome="success",
            responses=responses,
            send_started_at=time.time(),
            send_completed_at=time.time(),
        )

    def test_skips_cancel_when_no_response(self) -> None:
        """No responses (timeout) → CANCEL skipped."""
        executor = self._make_executor()
        send_result = self._make_send_result([])
        events = executor._teardown_invite(
            "INVITE sip:foo\r\nCSeq: 1 INVITE\r\n\r\n",
            self._make_target(),
            send_result,
            executor._config,
        )
        self.assertEqual(events, ["teardown:skipped:no-response"])

    def test_skips_cancel_when_final_only(self) -> None:
        """Got 486 Busy without provisional → CANCEL skipped."""
        executor = self._make_executor()
        send_result = self._make_send_result([486])
        events = executor._teardown_invite(
            "INVITE sip:foo\r\nCSeq: 1 INVITE\r\n\r\n",
            self._make_target(),
            send_result,
            executor._config,
        )
        self.assertEqual(events, ["teardown:skipped:final-only"])

    def test_sends_cancel_on_provisional_and_succeeds(self) -> None:
        """Got 100+180 → sends CANCEL, gets 200 OK → teardown ok."""
        executor = self._make_executor()
        send_result = self._make_send_result([100, 180])

        cancel_200 = self._make_send_result([200])

        executor._sender = unittest.mock.Mock()
        executor._sender.send_artifact.return_value = cancel_200

        events = executor._teardown_invite(
            "INVITE sip:foo\r\nCSeq: 1 INVITE\r\n\r\n",
            self._make_target(),
            send_result,
            executor._config,
        )
        self.assertEqual(len(events), 1)
        self.assertIn("teardown:cancel-ok:attempt=1", events[0])
        executor._sender.send_artifact.assert_called_once()

    def test_retries_cancel_on_timeout(self) -> None:
        """CANCEL gets no useful response → retries up to max."""
        executor = self._make_executor()
        send_result = self._make_send_result([100, 180])

        # All CANCEL attempts return empty responses (timeout)
        empty_result = self._make_send_result([])
        executor._sender = unittest.mock.Mock()
        executor._sender.send_artifact.return_value = empty_result

        events = executor._teardown_invite(
            "INVITE sip:foo\r\nCSeq: 1 INVITE\r\n\r\n",
            self._make_target(),
            send_result,
            executor._config,
        )
        self.assertTrue(any("cancel-failed" in e for e in events))
        from volte_mutation_fuzzer.campaign.core import _CANCEL_MAX_RETRIES
        self.assertEqual(executor._sender.send_artifact.call_count, _CANCEL_MAX_RETRIES)

    def test_retries_cancel_on_exception(self) -> None:
        """CANCEL send raises exception → retries, then fails."""
        executor = self._make_executor()
        send_result = self._make_send_result([100, 180])

        executor._sender = unittest.mock.Mock()
        executor._sender.send_artifact.side_effect = OSError("network error")

        events = executor._teardown_invite(
            "INVITE sip:foo\r\nCSeq: 1 INVITE\r\n\r\n",
            self._make_target(),
            send_result,
            executor._config,
        )
        self.assertTrue(any("cancel-error" in e for e in events))
        self.assertTrue(any("cancel-failed" in e for e in events))

    def test_cancel_succeeds_on_487(self) -> None:
        """CANCEL gets 487 Request Terminated → teardown ok."""
        executor = self._make_executor()
        send_result = self._make_send_result([100, 180])

        cancel_487 = self._make_send_result([487])
        executor._sender = unittest.mock.Mock()
        executor._sender.send_artifact.return_value = cancel_487

        events = executor._teardown_invite(
            "INVITE sip:foo\r\nCSeq: 1 INVITE\r\n\r\n",
            self._make_target(),
            send_result,
            executor._config,
        )
        self.assertEqual(len(events), 1)
        self.assertIn("teardown:cancel-ok:attempt=1", events[0])
        self.assertIn("code=487", events[0])
