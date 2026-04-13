"""Tests for ConsoleProgressReporter."""

import io
import sys
import unittest

from volte_mutation_fuzzer.campaign.contracts import CampaignSummary, CaseResult, CaseSpec
from volte_mutation_fuzzer.campaign.dashboard import ConsoleProgressReporter


def _make_spec(case_id: int = 0) -> CaseSpec:
    return CaseSpec(
        case_id=case_id, seed=case_id, method="INVITE", layer="wire", strategy="default"
    )


def _make_result(case_id: int = 0, verdict: str = "normal") -> CaseResult:
    return CaseResult(
        case_id=case_id,
        seed=case_id,
        method="INVITE",
        layer="wire",
        strategy="default",
        verdict=verdict,
        reason=f"test {verdict}",
        elapsed_ms=42.0,
        reproduction_cmd="uv run fuzzer ...",
        timestamp=0.0,
        response_code=180 if verdict == "normal" else None,
    )


class ConsoleProgressReporterTests(unittest.TestCase):
    def _capture(self) -> io.StringIO:
        buf = io.StringIO()
        self._orig_stderr = sys.stderr
        sys.stderr = buf
        return buf

    def _restore(self) -> None:
        sys.stderr = self._orig_stderr

    def test_first_case_prints_summary_block(self) -> None:
        buf = self._capture()
        try:
            reporter = ConsoleProgressReporter(
                total_cases=10, campaign_id="test1", summary_interval=5
            )
            summary = CampaignSummary(total=1, normal=1)
            reporter.on_case_complete(_make_spec(0), _make_result(0), summary)
            output = buf.getvalue()
        finally:
            self._restore()

        self.assertIn("test1", output)
        self.assertIn("1/10", output)
        self.assertIn("normal", output)

    def test_non_interval_case_prints_single_line(self) -> None:
        buf = self._capture()
        try:
            reporter = ConsoleProgressReporter(
                total_cases=10, campaign_id="test2", summary_interval=5
            )
            summary = CampaignSummary(total=1, normal=1)
            # First case prints block
            reporter.on_case_complete(_make_spec(0), _make_result(0), summary)
            buf.truncate(0)
            buf.seek(0)

            # Second case should print single line only
            summary = CampaignSummary(total=2, normal=2)
            reporter.on_case_complete(_make_spec(1), _make_result(1), summary)
            output = buf.getvalue()
        finally:
            self._restore()

        self.assertIn("[2/10]", output)
        # Should NOT contain the summary separator
        self.assertNotIn("---", output)

    def test_crash_verdict_prints_alert(self) -> None:
        buf = self._capture()
        try:
            reporter = ConsoleProgressReporter(
                total_cases=10, campaign_id="test3", summary_interval=100
            )
            summary = CampaignSummary(total=1, crash=1)
            reporter.on_case_complete(
                _make_spec(0), _make_result(0, verdict="crash"), summary
            )
            output = buf.getvalue()
        finally:
            self._restore()

        self.assertIn("CRASH", output)

    def test_stack_failure_prints_alert(self) -> None:
        buf = self._capture()
        try:
            reporter = ConsoleProgressReporter(
                total_cases=10, campaign_id="test4", summary_interval=100
            )
            summary = CampaignSummary(total=1, stack_failure=1)
            reporter.on_case_complete(
                _make_spec(0), _make_result(0, verdict="stack_failure"), summary
            )
            output = buf.getvalue()
        finally:
            self._restore()

        self.assertIn("STACK_FAILURE", output)
        self.assertIn("reproduction", output)

    def test_finalize_prints_final_summary(self) -> None:
        buf = self._capture()
        try:
            reporter = ConsoleProgressReporter(
                total_cases=10, campaign_id="test5"
            )
            summary = CampaignSummary(total=5, normal=3, timeout=2)
            reporter.finalize(summary, "completed")
            output = buf.getvalue()
        finally:
            self._restore()

        self.assertIn("test5", output)
        self.assertIn("completed", output)
        self.assertIn("Total: 5", output)

    def test_adb_status_shown_when_enabled(self) -> None:
        buf = self._capture()
        try:
            reporter = ConsoleProgressReporter(
                total_cases=10,
                campaign_id="test6",
                adb_enabled=True,
                pcap_enabled=True,
                pcap_interface="br-volte",
                summary_interval=1,
            )
            summary = CampaignSummary(total=1, normal=1)
            reporter.on_case_complete(
                _make_spec(0), _make_result(0), summary, adb_healthy=True
            )
            output = buf.getvalue()
        finally:
            self._restore()

        self.assertIn("ADB: OK", output)
        self.assertIn("Pcap: ON (br-volte)", output)

    def test_circuit_breaker_message(self) -> None:
        buf = self._capture()
        try:
            reporter = ConsoleProgressReporter(
                total_cases=10, campaign_id="test7"
            )
            reporter.on_circuit_breaker("SA expired")
            output = buf.getvalue()
        finally:
            self._restore()

        self.assertIn("CIRCUIT BREAKER", output)
        self.assertIn("SA expired", output)
