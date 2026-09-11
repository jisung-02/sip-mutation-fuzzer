import json
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from types import SimpleNamespace

from volte_mutation_fuzzer.campaign.contracts import (
    CampaignConfig,
    CaseSpec,
    CorpusEntry,
    load_corpus_entries,
)
from volte_mutation_fuzzer.campaign.core import CampaignExecutor, CaseGenerator
from volte_mutation_fuzzer.campaign.evidence import promote_corpus
from volte_mutation_fuzzer.sender.contracts import (
    SendReceiveResult,
    SocketObservation,
    TargetEndpoint,
)

OPTIONS_SEED = (
    b"OPTIONS sip:111111@10.20.20.8 SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP 10.20.20.3:5060;branch=z9hG4bK-test\r\n"
    b"From: <sip:222222@ims.test>;tag=fromtag\r\n"
    b"To: <sip:111111@ims.test>\r\n"
    b"Call-ID: corpus-test-1@10.20.20.3\r\n"
    b"CSeq: 1 OPTIONS\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)

MESSAGE_SEED = (
    b"MESSAGE sip:111111@10.20.20.8 SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP 10.20.20.3:5060;branch=z9hG4bK-msg\r\n"
    b"From: <sip:222222@ims.test>;tag=fromtag\r\n"
    b"To: <sip:111111@ims.test>\r\n"
    b"Call-ID: corpus-test-2@10.20.20.3\r\n"
    b"CSeq: 1 MESSAGE\r\n"
    b"Content-Length: 3\r\n"
    b"\r\n"
    b"abc"
)


class _CorpusDirMixin:
    def _make_corpus_dir(self) -> Path:
        tmp = tempfile.TemporaryDirectory(suffix="vmf-corpus")
        self.addCleanup(tmp.cleanup)
        corpus_dir = Path(tmp.name)
        (corpus_dir / "01_options.sip").write_bytes(OPTIONS_SEED)
        (corpus_dir / "02_message.bin").write_bytes(MESSAGE_SEED)
        return corpus_dir

    def _build_config(self, corpus_dir: Path, **overrides) -> CampaignConfig:
        defaults = dict(
            mode="real-ue-direct",
            target_host="10.20.20.8",
            target_msisdn="111111",
            corpus_dir=str(corpus_dir),
            max_cases=2,
        )
        defaults.update(overrides)
        return CampaignConfig(**defaults)


class LoadCorpusEntriesTests(unittest.TestCase):
    def _make_corpus_dir(self) -> Path:
        tmp = tempfile.TemporaryDirectory(suffix="vmf-corpus")
        self.addCleanup(tmp.cleanup)
        corpus_dir = Path(tmp.name)
        (corpus_dir / "01_options.sip").write_bytes(OPTIONS_SEED)
        (corpus_dir / "02_message.bin").write_bytes(MESSAGE_SEED)
        return corpus_dir

    def test_loads_sorted_entries_with_start_line_methods(self) -> None:
        entries = load_corpus_entries(self._make_corpus_dir())
        self.assertEqual(
            [(e.name, e.method) for e in entries],
            [("01_options.sip", "OPTIONS"), ("02_message.bin", "MESSAGE")],
        )
        self.assertEqual(entries[0].data, OPTIONS_SEED)

    def test_skips_hidden_and_unrecognized_files(self) -> None:
        with tempfile.TemporaryDirectory(suffix="vmf-corpus") as tmp:
            corpus_dir = Path(tmp)
            (corpus_dir / "01_options.sip").write_bytes(OPTIONS_SEED)
            (corpus_dir / ".DS_Store").write_bytes(b"junk")
            (corpus_dir / "notes.md").write_text("not a packet")
            entries = load_corpus_entries(corpus_dir)
        self.assertEqual([e.name for e in entries], ["01_options.sip"])

    def test_empty_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(suffix="vmf-corpus") as tmp:
            with self.assertRaisesRegex(ValueError, "no packet files"):
                load_corpus_entries(Path(tmp))

    def test_invalid_start_line_names_the_file(self) -> None:
        with tempfile.TemporaryDirectory(suffix="vmf-corpus") as tmp:
            corpus_dir = Path(tmp)
            (corpus_dir / "bad.sip").write_bytes(b"not-a-sip-packet\r\n\r\n")
            with self.assertRaisesRegex(ValueError, "bad.sip"):
                load_corpus_entries(corpus_dir)

    def test_empty_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(suffix="vmf-corpus") as tmp:
            corpus_dir = Path(tmp)
            (corpus_dir / "empty.sip").write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "empty.sip"):
                load_corpus_entries(corpus_dir)


class CorpusConfigValidationTests(_CorpusDirMixin, unittest.TestCase):
    def test_defaults_collapse_layers_and_strategies(self) -> None:
        config = self._build_config(self._make_corpus_dir())
        self.assertEqual(config.layers, ("byte",))
        self.assertEqual(config.strategies, ("default",))
        self.assertEqual(config.methods, ("OPTIONS", "MESSAGE"))
        self.assertEqual(config.ipsec_mode, "null")

    def test_requires_real_ue_direct_mode(self) -> None:
        with self.assertRaisesRegex(ValueError, "requires mode='real-ue-direct'"):
            self._build_config(self._make_corpus_dir(), mode="softphone")

    def test_requires_target_msisdn(self) -> None:
        with self.assertRaisesRegex(ValueError, "requires target_msisdn"):
            self._build_config(self._make_corpus_dir(), target_msisdn=None)

    def test_mutually_exclusive_with_packet_file(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".sip", delete=False) as fh:
            fh.write(OPTIONS_SEED)
            packet_path = fh.name
        self.addCleanup(lambda: Path(packet_path).unlink(missing_ok=True))
        with self.assertRaisesRegex(ValueError, "mutually exclusive with --packet-file"):
            self._build_config(self._make_corpus_dir(), packet_file=packet_path)

    def test_mutually_exclusive_with_mt(self) -> None:
        with self.assertRaisesRegex(ValueError, "mutually exclusive with --mt"):
            self._build_config(self._make_corpus_dir(), mt=True)

    def test_rejects_non_byte_layers(self) -> None:
        with self.assertRaisesRegex(ValueError, "supports layers: byte, auto"):
            self._build_config(
                self._make_corpus_dir(),
                layers=("model", "wire", "byte"),
            )

    def test_explicit_byte_layer_and_strategies_pass_through(self) -> None:
        config = self._build_config(
            self._make_corpus_dir(),
            layers=("byte",),
            strategies=("identity", "tail_chop_1"),
        )
        self.assertEqual(config.layers, ("byte",))
        self.assertEqual(config.strategies, ("identity", "tail_chop_1"))

    def test_rejects_non_byte_strategies(self) -> None:
        with self.assertRaisesRegex(ValueError, "byte-layer strategies only"):
            self._build_config(
                self._make_corpus_dir(),
                strategies=("state_breaker",),
            )

    def test_methods_default_to_corpus_methods(self) -> None:
        config = self._build_config(self._make_corpus_dir())
        self.assertEqual(config.methods, ("OPTIONS", "MESSAGE"))

    def test_explicit_missing_method_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "no seed for method"):
            self._build_config(self._make_corpus_dir(), methods=("INVITE",))

    def test_rejects_missing_directory(self) -> None:
        with self.assertRaisesRegex(ValueError, "not found or not a directory"):
            self._build_config(Path("/nonexistent/vmf-corpus-dir"))


class CorpusCaseGeneratorTests(_CorpusDirMixin, unittest.TestCase):
    def test_layers_collapse_to_byte_when_corpus_dir_set(self) -> None:
        config = self._build_config(
            self._make_corpus_dir(),
            layers=("byte",),
            strategies=("default", "identity"),
            methods=("OPTIONS",),
        )
        specs = list(CaseGenerator(config).generate())
        self.assertTrue(specs)
        self.assertTrue(all(spec.layer == "byte" for spec in specs))
        strategies = {spec.strategy for spec in specs}
        self.assertEqual(strategies, {"default", "identity"})


class CorpusExecutionTests(_CorpusDirMixin, unittest.TestCase):
    """End-to-end behaviour of ``--corpus-dir`` through the campaign executor.

    Critical contracts:
    - identity sends the seed bytes verbatim with zero mutation records
    - default mutates the seed and records the operators
    - seed-derived entry selection is stable across replays
    """

    def _build_executor(
        self, strategies: tuple[str, ...] = ("default",)
    ) -> CampaignExecutor:
        config = self._build_config(
            self._make_corpus_dir(),
            methods=("OPTIONS",),
            strategies=strategies,
        )
        with tempfile.TemporaryDirectory(suffix="vmf-results") as tmp:
            executor = CampaignExecutor(
                config.model_copy(update={"results_dir": tmp})
            )
        return executor

    def _send_result(self) -> SendReceiveResult:
        return SendReceiveResult(
            target=TargetEndpoint(
                host="10.20.20.8",
                port=8100,
                mode="real-ue-direct",
                msisdn="111111",
                ipsec_mode="null",
                bind_container="pcscf",
            ),
            artifact_kind="bytes",
            bytes_sent=len(OPTIONS_SEED),
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

    def _execute_with_mocked_send(self, executor: CampaignExecutor, spec: CaseSpec):
        captured: dict[str, object] = {}

        def _capture_send_artifact(artifact, _target, **_kwargs):
            captured["packet_bytes"] = artifact.packet_bytes
            return self._send_result()

        with (
            unittest.mock.patch.object(
                executor,
                "_resolve_ports_live",
                return_value=(8100, 8101),
            ),
            unittest.mock.patch.object(
                executor._sender,
                "send_artifact",
                side_effect=_capture_send_artifact,
            ),
            unittest.mock.patch.object(
                executor._oracle,
                "evaluate",
                return_value=SimpleNamespace(
                    verdict="normal",
                    reason="ok",
                    response_code=200,
                    elapsed_ms=10.0,
                    process_alive=True,
                    details={},
                ),
            ),
            unittest.mock.patch.object(
                executor,
                "_persist_case_artifacts",
                side_effect=lambda _spec, case_result, **_kwargs: case_result,
            ),
        ):
            result = executor._execute_case(spec)
        return result, captured

    def test_execute_case_dispatches_to_corpus_path(self) -> None:
        executor = self._build_executor()
        with unittest.mock.patch.object(
            executor,
            "_execute_corpus_case",
            wraps=executor._execute_corpus_case,
        ) as corpus_spy:
            spec = CaseSpec(
                case_id=0, seed=0, method="OPTIONS", layer="byte", strategy="identity"
            )
            self._execute_with_mocked_send(executor, spec)
            corpus_spy.assert_called_once()

    def test_identity_sends_seed_bytes_verbatim(self) -> None:
        executor = self._build_executor(strategies=("identity",))
        spec = CaseSpec(
            case_id=0, seed=0, method="OPTIONS", layer="byte", strategy="identity"
        )
        result, captured = self._execute_with_mocked_send(executor, spec)

        self.assertEqual(captured["packet_bytes"], OPTIONS_SEED)
        self.assertEqual(result.mutation_ops, ())
        self.assertIn("--corpus-dir", result.reproduction_cmd)
        self.assertIn("--strategy identity", result.reproduction_cmd)

    def test_default_strategy_mutates_seed_and_records_ops(self) -> None:
        executor = self._build_executor(strategies=("default",))
        spec = CaseSpec(
            case_id=0, seed=7, method="OPTIONS", layer="byte", strategy="default"
        )
        result, captured = self._execute_with_mocked_send(executor, spec)

        self.assertNotEqual(captured["packet_bytes"], OPTIONS_SEED)
        self.assertTrue(result.mutation_ops)

    def test_same_seed_selects_same_entry_and_mutation(self) -> None:
        executor = self._build_executor()
        spec = CaseSpec(
            case_id=3, seed=11, method="OPTIONS", layer="byte", strategy="default"
        )
        _, first = self._execute_with_mocked_send(executor, spec)
        _, second = self._execute_with_mocked_send(executor, spec)
        self.assertEqual(first["packet_bytes"], second["packet_bytes"])

    def test_missing_corpus_seed_returns_unknown(self) -> None:
        executor = self._build_executor()
        spec = CaseSpec(
            case_id=0, seed=0, method="INVITE", layer="byte", strategy="identity"
        )
        result = executor._execute_corpus_case(spec, 1.0, 1.0)
        self.assertEqual(result.verdict, "unknown")
        self.assertIn("no corpus seed", result.reason)

    def test_select_corpus_entry_is_seed_deterministic(self) -> None:
        executor = self._build_executor()
        executor._corpus_entries = (
            CorpusEntry(name="a.sip", method="OPTIONS", data=b"A"),
            CorpusEntry(name="b.sip", method="OPTIONS", data=b"B"),
            CorpusEntry(name="c.bin", method="MESSAGE", data=b"C"),
        )
        spec = CaseSpec(
            case_id=0, seed=0, method="OPTIONS", layer="byte", strategy="identity"
        )
        selected = [executor._select_corpus_entry(spec) for _ in range(3)]
        self.assertEqual([entry.name for entry in selected], ["a.sip"] * 3)
        odd_spec = spec.model_copy(update={"seed": 1})
        self.assertEqual(executor._select_corpus_entry(odd_spec).name, "b.sip")
        invite_spec = spec.model_copy(update={"method": "INVITE"})
        self.assertIsNone(executor._select_corpus_entry(invite_spec))


class PromoteCorpusTests(unittest.TestCase):
    def _make_campaign(self) -> Path:
        tmp = tempfile.TemporaryDirectory(suffix="vmf-campaign")
        self.addCleanup(tmp.cleanup)
        campaign_dir = Path(tmp.name)
        interesting = campaign_dir / "interesting"

        # suspicious case with binary payload (sent.bin)
        case_1 = interesting / "case_000001"
        case_1.mkdir(parents=True)
        (case_1 / "sent.bin").write_bytes(b"OPTIONS binary\x00payload\r\n\r\n")
        # crash case with text payload (sent.sip)
        case_2 = interesting / "case_000002"
        case_2.mkdir(parents=True)
        (case_2 / "sent.sip").write_text("MESSAGE text payload\r\n\r\n")
        # normal case — must NOT be promoted even if evidence exists
        case_3 = interesting / "case_000003"
        case_3.mkdir(parents=True)
        (case_3 / "sent.sip").write_text("OPTIONS normal\r\n\r\n")

        rows = [
            {"type": "header"},
            {
                "type": "case",
                "case_id": 1,
                "method": "OPTIONS",
                "verdict": "suspicious",
                "strategy": "default",
                "profile": "legacy",
                "layer": "byte",
                "seed": 1,
                "response_code": 500,
                "reason": "server error",
            },
            {
                "type": "case",
                "case_id": 2,
                "method": "MESSAGE",
                "verdict": "crash",
                "strategy": "tail_chop_1",
                "profile": "legacy",
                "layer": "byte",
                "seed": 2,
                "response_code": None,
                "reason": "process died",
            },
            {
                "type": "case",
                "case_id": 3,
                "method": "OPTIONS",
                "verdict": "normal",
                "strategy": "identity",
                "profile": "legacy",
                "layer": "byte",
                "seed": 3,
                "response_code": 200,
                "reason": "ok",
            },
            {
                "type": "case",
                "case_id": 4,
                "method": "OPTIONS",
                "verdict": "suspicious",
                "strategy": "default",
                "profile": "legacy",
                "layer": "byte",
                "seed": 4,
                "response_code": 500,
                "reason": "no evidence dir for this one",
            },
        ]
        jsonl_path = campaign_dir / "campaign.jsonl"
        with jsonl_path.open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")
        return jsonl_path

    def test_promotes_only_interesting_cases_with_evidence(self) -> None:
        jsonl_path = self._make_campaign()
        with tempfile.TemporaryDirectory(suffix="vmf-out") as tmp:
            out_dir = Path(tmp)
            count, returned_dir = promote_corpus(jsonl_path, out_dir)
            self.assertEqual(returned_dir, out_dir)
            self.assertEqual(count, 2)

            promoted_files = sorted(
                path.name for path in out_dir.iterdir() if path.suffix != ".json"
            )
            self.assertEqual(
                promoted_files,
                ["case_000001_OPTIONS.bin", "case_000002_MESSAGE.sip"],
            )
            self.assertEqual(
                (out_dir / "case_000001_OPTIONS.bin").read_bytes(),
                b"OPTIONS binary\x00payload\r\n\r\n",
            )
            manifest = json.loads((out_dir / "manifest.json").read_text())
            self.assertEqual(manifest["promoted_count"], 2)
            self.assertEqual(manifest["skipped_no_evidence"], 1)
            self.assertEqual(
                [entry["file"] for entry in manifest["promoted"]],
                ["case_000001_OPTIONS.bin", "case_000002_MESSAGE.sip"],
            )

    def test_promoted_corpus_is_loadable_and_skips_manifest(self) -> None:
        jsonl_path = self._make_campaign()
        promote_corpus(jsonl_path)
        entries = load_corpus_entries(jsonl_path.parent / "corpus")
        self.assertEqual([entry.method for entry in entries], ["OPTIONS", "MESSAGE"])

    def test_default_output_dir_is_campaign_corpus(self) -> None:
        jsonl_path = self._make_campaign()
        count, out_dir = promote_corpus(jsonl_path)
        self.assertEqual(count, 2)
        self.assertEqual(out_dir, jsonl_path.parent / "corpus")
        self.assertTrue(out_dir.is_dir())


class CorpusSpliceTests(_CorpusDirMixin, unittest.TestCase):
    """`--strategy splice` corpus campaigns cross two seeds per case."""

    def _make_two_seed_corpus(self) -> Path:
        tmp = tempfile.TemporaryDirectory(suffix="vmf-corpus2")
        self.addCleanup(tmp.cleanup)
        corpus_dir = Path(tmp.name)
        (corpus_dir / "01_options.sip").write_bytes(OPTIONS_SEED)
        (corpus_dir / "02_options_alt.sip").write_bytes(
            OPTIONS_SEED.replace(b"corpus-test-1", b"corpus-test-9")
        )
        return corpus_dir

    def _make_single_seed_corpus(self) -> Path:
        tmp = tempfile.TemporaryDirectory(suffix="vmf-corpus1")
        self.addCleanup(tmp.cleanup)
        corpus_dir = Path(tmp.name)
        (corpus_dir / "01_options.sip").write_bytes(OPTIONS_SEED)
        return corpus_dir

    def _build_executor(self, corpus_dir: Path) -> CampaignExecutor:
        config = self._build_config(
            corpus_dir,
            methods=("OPTIONS",),
            strategies=("splice",),
        )
        with tempfile.TemporaryDirectory(suffix="vmf-results") as tmp:
            return CampaignExecutor(config.model_copy(update={"results_dir": tmp}))

    def test_splice_requires_corpus_dir(self) -> None:
        with self.assertRaisesRegex(ValueError, "requires --corpus-dir"):
            CampaignConfig(
                mode="real-ue-direct",
                target_host="10.20.20.8",
                target_msisdn="111111",
                methods=("OPTIONS",),
                layers=("byte",),
                strategies=("splice",),
            )

    def test_splice_accepted_with_corpus_dir(self) -> None:
        config = self._build_config(
            self._make_corpus_dir(), methods=("OPTIONS",), strategies=("splice",)
        )
        self.assertEqual(config.strategies, ("splice",))

    def test_splice_end_to_end_crosses_two_seeds(self) -> None:
        executor = self._build_executor(self._make_two_seed_corpus())
        spec = CaseSpec(
            case_id=0, seed=4, method="OPTIONS", layer="byte", strategy="splice"
        )

        from volte_mutation_fuzzer.mutator.core import SIPMutator

        primary = executor._select_corpus_entry(spec)
        assert primary is not None
        partner = executor._select_splice_partner(spec, primary)
        assert partner is not None
        self.assertNotEqual(primary.name, partner.name)
        expected = SIPMutator().splice_packet_bytes(
            primary.data, partner.data, seed=spec.seed, profile=spec.profile
        )

        captured: dict[str, object] = {}

        def _capture_send_artifact(artifact, _target, **_kwargs):
            captured["packet_bytes"] = artifact.packet_bytes
            return SendReceiveResult(
                target=TargetEndpoint(
                    host="10.20.20.8",
                    port=8100,
                    mode="real-ue-direct",
                    msisdn="111111",
                    ipsec_mode="null",
                    bind_container="pcscf",
                ),
                artifact_kind="bytes",
                bytes_sent=len(expected.packet_bytes or b""),
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

        with (
            unittest.mock.patch.object(
                executor,
                "_resolve_ports_live",
                return_value=(8100, 8101),
            ),
            unittest.mock.patch.object(
                executor._sender,
                "send_artifact",
                side_effect=_capture_send_artifact,
            ),
            unittest.mock.patch.object(
                executor._oracle,
                "evaluate",
                return_value=SimpleNamespace(
                    verdict="normal",
                    reason="ok",
                    response_code=200,
                    elapsed_ms=10.0,
                    process_alive=True,
                    details={},
                ),
            ),
            unittest.mock.patch.object(
                executor,
                "_persist_case_artifacts",
                side_effect=lambda _spec, case_result, **_kwargs: case_result,
            ),
        ):
            result = executor._execute_case(spec)

        self.assertEqual(captured["packet_bytes"], expected.packet_bytes)
        self.assertTrue(
            any(op.startswith("splice(") for op in result.mutation_ops),
            result.mutation_ops,
        )
        self.assertIn("--strategy splice", result.reproduction_cmd)

    def test_splice_with_single_seed_returns_unknown(self) -> None:
        executor = self._build_executor(self._make_single_seed_corpus())
        spec = CaseSpec(
            case_id=0, seed=0, method="OPTIONS", layer="byte", strategy="splice"
        )
        result = executor._execute_corpus_case(spec, 1.0, 1.0)
        self.assertEqual(result.verdict, "unknown")
        self.assertIn("at least two corpus seeds", result.reason)
        self.assertEqual(result.error, "corpus-splice-partner-missing")

    def test_splice_partner_selection_is_seed_deterministic_and_differs(
        self,
    ) -> None:
        executor = self._build_executor(self._make_corpus_dir())
        executor._corpus_entries = (
            CorpusEntry(name="a.sip", method="OPTIONS", data=b"A\r\n\r\n"),
            CorpusEntry(name="b.sip", method="OPTIONS", data=b"B\r\n\r\n"),
            CorpusEntry(name="c.sip", method="OPTIONS", data=b"C\r\n\r\n"),
        )
        spec = CaseSpec(
            case_id=0, seed=0, method="OPTIONS", layer="byte", strategy="splice"
        )
        for seed in range(12):
            probe = spec.model_copy(update={"seed": seed})
            primary = executor._select_corpus_entry(probe)
            partner = executor._select_splice_partner(probe, primary)
            assert primary is not None and partner is not None
            self.assertNotEqual(primary.name, partner.name)


if __name__ == "__main__":
    unittest.main()
