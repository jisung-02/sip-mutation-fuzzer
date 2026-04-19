import json
import tempfile
import unittest
from pathlib import Path

from volte_mutation_fuzzer.analysis.crash_analyzer import CampaignCrashAnalyzer
from volte_mutation_fuzzer.campaign.contracts import CaseResult


class CampaignCrashAnalyzerTests(unittest.TestCase):
    def _make_case(self, verdict: str = "normal", **kwargs) -> CaseResult:
        payload = {
            "case_id": 0,
            "seed": 0,
            "method": "OPTIONS",
            "layer": "model",
            "strategy": "default",
            "mutation_ops": (),
            "verdict": verdict,
            "reason": "ok",
            "elapsed_ms": 12.5,
            "reproduction_cmd": "uv run fuzzer ...",
            "timestamp": 1.0,
            "pcap_path": None,
        }
        payload.update(kwargs)
        return CaseResult.model_validate(payload)

    def test_normal_case_only_updates_totals(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CampaignCrashAnalyzer(
                output_dir=tmpdir,
                enabled=True,
                source_name="results/campaign.jsonl",
            )

            crash_case = analyzer.analyze_case_immediately(self._make_case())

            self.assertIsNone(crash_case)
            self.assertEqual(analyzer.stats["total_cases"], 1)
            self.assertEqual(analyzer.stats["crashes"], 0)
            self.assertEqual(analyzer.crash_cases, [])

    def test_crash_case_creates_live_and_final_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CampaignCrashAnalyzer(
                output_dir=tmpdir,
                enabled=True,
                source_name="results/campaign.jsonl",
            )

            crash_case = analyzer.analyze_case_immediately(
                self._make_case(
                    verdict="crash",
                    reason="SIGSEGV while parsing malformed packet",
                )
            )

            self.assertIsNotNone(crash_case)
            assert crash_case is not None
            self.assertEqual(crash_case.crash_category, "memory_corruption")
            self.assertTrue((Path(tmpdir) / "live_summary.txt").exists())

            report_file, json_file = analyzer.generate_final_report() or (None, None)
            self.assertIsNotNone(report_file)
            self.assertIsNotNone(json_file)
            assert report_file is not None
            assert json_file is not None
            self.assertTrue(Path(report_file).exists())
            self.assertTrue(Path(json_file).exists())

            payload = json.loads(Path(json_file).read_text(encoding="utf-8"))
            self.assertEqual(payload["statistics"]["crashes"], 1)
