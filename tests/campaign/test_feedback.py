import tempfile
import unittest
import unittest.mock
from typing import Any

from volte_mutation_fuzzer.campaign.contracts import CampaignConfig, CaseSpec
from volte_mutation_fuzzer.campaign.core import CampaignExecutor
from volte_mutation_fuzzer.campaign.contracts import CorpusEntry


def _config(**overrides: Any) -> CampaignConfig:
    defaults: dict[str, Any] = dict(
        mode="real-ue-direct",
        target_host="10.20.20.8",
        target_msisdn="111111",
        methods=("OPTIONS",),
        layers=("byte",),
        strategies=("identity",),
        max_cases=4,
    )
    defaults.update(overrides)
    return CampaignConfig(**defaults)


def _spec(
    case_id: int, *, method: str = "OPTIONS", seed: int | None = None
) -> CaseSpec:
    return CaseSpec(
        case_id=case_id,
        seed=case_id if seed is None else seed,
        method=method,
        layer="byte",
        strategy="identity",
    )


class RuntimePromotionTests(unittest.TestCase):
    def _executor(self, **overrides) -> CampaignExecutor:
        with tempfile.TemporaryDirectory(suffix="vmf-results") as tmp:
            return CampaignExecutor(
                _config(**overrides).model_copy(update={"results_dir": tmp})
            )

    def _persist(self, executor, *, verdict, payload, case_id=0):
        spec = _spec(case_id)
        case_result = unittest.mock.MagicMock()
        case_result.case_id = case_id
        case_result.verdict = verdict
        case_result.model_copy = lambda **_kwargs: case_result
        with (
            unittest.mock.patch.object(
                executor, "_capture_adb_snapshot", return_value=None
            ),
            unittest.mock.patch.object(
                executor, "_capture_ios_snapshot", return_value=None
            ),
            unittest.mock.patch.object(executor._evidence, "collect"),
        ):
            executor._persist_case_artifacts(
                spec,
                case_result,
                sent_payload=payload,
                timestamp=1.0,
                case_started_monotonic=1.0,
            )

    def test_interesting_bytes_payload_is_promoted(self) -> None:
        executor = self._executor()
        payload = b"OPTIONS mutated\x00payload\r\n\r\n"
        self._persist(executor, verdict="suspicious", payload=payload, case_id=3)

        seed_path = executor.campaign_dir / "corpus" / "case_000003_OPTIONS.bin"
        self.assertTrue(seed_path.is_file())
        self.assertEqual(seed_path.read_bytes(), payload)
        self.assertIsNotNone(executor._last_seed)
        last_seed = executor._last_seed
        assert last_seed is not None
        self.assertEqual(last_seed.method, "OPTIONS")

    def test_string_payload_promoted_as_sip(self) -> None:
        executor = self._executor()
        self._persist(
            executor, verdict="crash", payload="INVITE text\r\n\r\n", case_id=7
        )
        self.assertTrue(
            (executor.campaign_dir / "corpus" / "case_000007_OPTIONS.sip").is_file()
        )

    def test_normal_verdict_is_not_promoted(self) -> None:
        executor = self._executor()
        self._persist(executor, verdict="normal", payload=b"x" * 32)
        self.assertIsNone(executor._last_seed)
        self.assertFalse((executor.campaign_dir / "corpus").exists())

    def test_feedback_disabled_skips_promotion(self) -> None:
        executor = self._executor(feedback_enabled=False)
        self._persist(executor, verdict="suspicious", payload=b"y" * 32)
        self.assertIsNone(executor._last_seed)
        self.assertFalse((executor.campaign_dir / "corpus").exists())

    def test_none_payload_is_skipped(self) -> None:
        executor = self._executor()
        self._persist(executor, verdict="suspicious", payload=None)
        self.assertIsNone(executor._last_seed)


class LastSeedContinuationTests(unittest.TestCase):
    def _executor(self, **overrides) -> CampaignExecutor:
        with tempfile.TemporaryDirectory(suffix="vmf-results") as tmp:
            return CampaignExecutor(
                _config(**overrides).model_copy(update={"results_dir": tmp})
            )

    def _with_last_seed(self, executor, *, method="OPTIONS") -> None:
        executor._last_seed = CorpusEntry(
            name="case_000001_OPTIONS.bin", method=method, data=b"promoted"
        )

    def test_even_case_continues_from_last_seed(self) -> None:
        executor = self._executor()
        self._with_last_seed(executor)
        selected = executor._select_corpus_entry(_spec(4))
        self.assertIsNotNone(selected)
        assert selected is not None
        self.assertEqual(selected.name, "case_000001_OPTIONS.bin")

    def test_odd_case_rotates_static_corpus(self) -> None:
        executor = self._executor()
        self._with_last_seed(executor)
        selected = executor._select_corpus_entry(_spec(5))
        self.assertIsNone(selected)  # no static corpus configured

    def test_method_mismatch_ignores_last_seed(self) -> None:
        executor = self._executor()
        self._with_last_seed(executor, method="INVITE")
        selected = executor._select_corpus_entry(_spec(4))
        self.assertIsNone(selected)

    def test_feedback_disabled_ignores_last_seed(self) -> None:
        executor = self._executor(feedback_enabled=False)
        self._with_last_seed(executor)
        selected = executor._select_corpus_entry(_spec(4))
        self.assertIsNone(selected)

    def test_no_last_seed_falls_back_to_rotation(self) -> None:
        executor = self._executor()
        executor._corpus_entries = (
            CorpusEntry(name="a.sip", method="OPTIONS", data=b"A"),
        )
        selected = executor._select_corpus_entry(_spec(4))
        assert selected is not None
        self.assertEqual(selected.name, "a.sip")


if __name__ == "__main__":
    unittest.main()
