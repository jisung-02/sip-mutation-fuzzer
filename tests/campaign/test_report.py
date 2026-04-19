"""Tests for HtmlReportGenerator."""

import tempfile
import unittest
from pathlib import Path

from volte_mutation_fuzzer.campaign.contracts import (
    CampaignConfig,
    CampaignResult,
    CampaignSummary,
    CaseResult,
)
from volte_mutation_fuzzer.campaign.core import ResultStore
from volte_mutation_fuzzer.campaign.report import HtmlReportGenerator


def _make_case(case_id: int, verdict: str, **kwargs) -> CaseResult:
    defaults = dict(
        case_id=case_id,
        seed=case_id,
        method="INVITE",
        layer="wire",
        strategy="default",
        verdict=verdict,
        reason=f"test {verdict}",
        elapsed_ms=42.0 + case_id,
        reproduction_cmd=f"uv run fuzzer campaign run --seed-start {case_id} --max-cases 1",
        timestamp=1000000.0 + case_id,
        case_wall_ms=900.0 + case_id,
        response_code=180 if verdict == "normal" else None,
        mutation_ops=("flip_char(Via)",) if verdict != "normal" else (),
    )
    defaults.update(kwargs)
    return CaseResult.model_validate(defaults)


def _write_campaign(tmpdir: str, cases: list[CaseResult]) -> Path:
    """Write a minimal campaign JSONL file and return its path."""
    out = Path(tmpdir) / "campaign.jsonl"
    config = CampaignConfig(target_host="127.0.0.1", max_cases=len(cases))
    summary_data = {"total": len(cases)}
    for v in ("normal", "suspicious", "timeout", "crash", "stack_failure", "infra_failure", "unknown"):
        summary_data[v] = sum(1 for c in cases if c.verdict == v)
    summary = CampaignSummary(**summary_data)

    store = ResultStore(out)
    header = CampaignResult(
        campaign_id="test123",
        started_at="2026-04-13T10:00:00Z",
        completed_at="2026-04-13T10:30:00Z",
        status="completed",
        config=config,
        summary=summary,
    )
    store.write_header(header)
    for c in cases:
        store.append(c)
    store.write_footer(header)
    return out


class HtmlReportGeneratorTests(unittest.TestCase):
    def test_generates_html_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cases = [
                _make_case(0, "normal"),
                _make_case(1, "normal"),
                _make_case(2, "suspicious"),
                _make_case(3, "timeout"),
                _make_case(4, "crash"),
            ]
            jsonl_path = _write_campaign(tmpdir, cases)

            gen = HtmlReportGenerator(jsonl_path)
            report_path = gen.generate()

            self.assertTrue(report_path.exists())
            content = report_path.read_text(encoding="utf-8")

            # Basic structure checks
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("test123", content)
            self.assertIn("completed", content)

    def test_contains_verdict_statistics(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cases = [
                _make_case(0, "normal"),
                _make_case(1, "suspicious"),
                _make_case(2, "crash"),
            ]
            jsonl_path = _write_campaign(tmpdir, cases)
            content = HtmlReportGenerator(jsonl_path).generate().read_text()

            self.assertIn("normal", content)
            self.assertIn("suspicious", content)
            self.assertIn("crash", content)

    def test_contains_cases_table(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cases = [_make_case(i, "normal") for i in range(5)]
            jsonl_path = _write_campaign(tmpdir, cases)
            content = HtmlReportGenerator(jsonl_path).generate().read_text()

            self.assertIn("cases-table", content)
            self.assertIn("INVITE", content)
            self.assertIn("seed", content.lower())

    def test_cases_table_renders_warning_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cases = [
                _make_case(
                    0,
                    "timeout",
                    details={
                        "adb_warning": {
                            "severity": "warning",
                            "matched_line": "IMS deregist triggered by network change",
                        }
                    },
                )
            ]
            jsonl_path = _write_campaign(tmpdir, cases)
            content = HtmlReportGenerator(jsonl_path).generate().read_text()

            self.assertIn("Context", content)
            self.assertIn("ADB warning", content)
            self.assertIn("IMS deregist triggered by network change", content)

    def test_cases_table_renders_wall_ms(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cases = [_make_case(0, "normal")]
            jsonl_path = _write_campaign(tmpdir, cases)
            content = HtmlReportGenerator(jsonl_path).generate().read_text()

            self.assertIn("Wall", content)
            self.assertIn("900", content)

    def test_interesting_cases_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cases = [
                _make_case(0, "normal"),
                _make_case(1, "suspicious", raw_response="SIP/2.0 400 Bad\r\n\r\n"),
            ]
            jsonl_path = _write_campaign(tmpdir, cases)

            # Create interesting dir with evidence
            interesting_dir = Path(tmpdir) / "interesting" / "case_000001"
            interesting_dir.mkdir(parents=True)
            (interesting_dir / "sent.sip").write_text("INVITE sip:test\r\n\r\n")
            (interesting_dir / "response.sip").write_text("SIP/2.0 400 Bad\r\n\r\n")
            (interesting_dir / "mutation_ops.txt").write_text("flip_char(Via)\n")

            content = HtmlReportGenerator(jsonl_path).generate().read_text()

            self.assertIn("Interesting Cases", content)
            self.assertIn("Sent SIP", content)
            self.assertIn("Response SIP", content)

    def test_contains_svg_charts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cases = [_make_case(0, "normal"), _make_case(1, "timeout")]
            jsonl_path = _write_campaign(tmpdir, cases)
            content = HtmlReportGenerator(jsonl_path).generate().read_text()

            self.assertIn("<svg", content)
            self.assertIn("circle", content)

    def test_contains_filter_js(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cases = [_make_case(0, "normal")]
            jsonl_path = _write_campaign(tmpdir, cases)
            content = HtmlReportGenerator(jsonl_path).generate().read_text()

            self.assertIn("filterTable", content)
            self.assertIn("verdict-filter", content)

    def test_contains_config_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cases = [_make_case(0, "normal")]
            jsonl_path = _write_campaign(tmpdir, cases)
            content = HtmlReportGenerator(jsonl_path).generate().read_text()

            self.assertIn("CampaignConfig", content)
            self.assertIn("127.0.0.1", content)

    def test_custom_output_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cases = [_make_case(0, "normal")]
            jsonl_path = _write_campaign(tmpdir, cases)
            custom_path = Path(tmpdir) / "custom_report.html"

            gen = HtmlReportGenerator(jsonl_path)
            result = gen.generate(output_path=custom_path)

            self.assertEqual(result, custom_path)
            self.assertTrue(custom_path.exists())

    def test_reproduction_cmd_in_interesting_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cases = [_make_case(0, "crash")]
            jsonl_path = _write_campaign(tmpdir, cases)
            content = HtmlReportGenerator(jsonl_path).generate().read_text()

            self.assertIn("Reproduction", content)
            self.assertIn("--seed-start 0", content)
