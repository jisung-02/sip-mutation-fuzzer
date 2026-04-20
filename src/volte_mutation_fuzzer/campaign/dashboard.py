"""Real-time console progress reporter for campaign runs."""

import sys
import time

from volte_mutation_fuzzer.campaign.contracts import CampaignSummary, CaseResult, CaseSpec


_VERDICT_ORDER: tuple[str, ...] = (
    "normal",
    "suspicious",
    "timeout",
    "crash",
    "stack_failure",
    "infra_failure",
    "unknown",
)


def _format_duration(seconds: float) -> str:
    h, rem = divmod(int(seconds), 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def _pct(count: int, total: int) -> str:
    if total == 0:
        return "0%"
    return f"{count * 100 / total:.0f}%"


class ConsoleProgressReporter:
    """Prints a compact progress block to stderr during campaign execution."""

    def __init__(
        self,
        total_cases: int,
        campaign_id: str,
        *,
        adb_enabled: bool = False,
        pcap_enabled: bool = False,
        pcap_interface: str = "any",
        summary_interval: int = 10,
    ) -> None:
        self._total = total_cases
        self._campaign_id = campaign_id
        self._adb_enabled = adb_enabled
        self._pcap_enabled = pcap_enabled
        self._pcap_interface = pcap_interface
        self._summary_interval = summary_interval
        self._start_time = time.monotonic()
        self._case_count = 0
        self._last_line = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def on_case_complete(
        self,
        spec: CaseSpec,
        result: CaseResult,
        summary: CampaignSummary,
        *,
        adb_healthy: bool | None = None,
    ) -> None:
        """Called after each case is executed and stored."""
        self._case_count += 1

        # Build the "last case" line (always printed)
        self._last_line = self._format_case_line(spec, result)

        # Print full summary block every N cases, plus on the first case
        if self._case_count == 1 or self._case_count % self._summary_interval == 0:
            self._print_summary_block(summary, adb_healthy)
        else:
            # Just print the single case line
            self._print(self._last_line)

        # Always print alerts for notable verdicts
        self._print_alerts(result)

    def on_circuit_breaker(self, reason: str) -> None:
        self._print(f"  ** CIRCUIT BREAKER: {reason}")

    def on_adb_warning(self, dead_buffers: frozenset[str]) -> None:
        self._print(
            f"  ** ADB WARNING: dead buffers: {','.join(sorted(dead_buffers))}"
        )

    def finalize(self, summary: CampaignSummary, status: str) -> None:
        """Print final summary after campaign ends."""
        elapsed = time.monotonic() - self._start_time
        rate = summary.total / elapsed if elapsed > 0 else 0.0

        self._print("")
        self._print(
            f"=== Campaign {self._campaign_id} {status} ==="
        )
        self._print(
            f"  Total: {summary.total}  |  "
            f"Elapsed: {_format_duration(elapsed)}  |  "
            f"Rate: {rate:.2f}/s"
        )
        self._print(self._format_verdict_line(summary))
        self._print("")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _print_summary_block(
        self, summary: CampaignSummary, adb_healthy: bool | None
    ) -> None:
        elapsed = time.monotonic() - self._start_time
        rate = self._case_count / elapsed if elapsed > 0 else 0.0

        self._print("")
        total_str = str(self._total) if self._total > 0 else "\u221e"
        self._print(
            f"--- {self._campaign_id}  "
            f"{self._case_count}/{total_str}  |  "
            f"{_format_duration(elapsed)}  |  "
            f"{rate:.2f}/s ---"
        )
        self._print(self._format_verdict_line(summary))
        self._print(self._format_status_line(adb_healthy))
        self._print(self._last_line)

    def _format_verdict_line(self, summary: CampaignSummary) -> str:
        total = summary.total
        parts: list[str] = []
        for v in _VERDICT_ORDER:
            count = getattr(summary, v, 0)
            if count > 0 or v in ("normal", "suspicious", "timeout"):
                parts.append(f"{v} {count}({_pct(count, total)})")
        return "  " + "  ".join(parts)

    def _format_status_line(self, adb_healthy: bool | None) -> str:
        parts: list[str] = []
        if self._adb_enabled:
            if adb_healthy is None:
                parts.append("ADB: ?")
            elif adb_healthy:
                parts.append("ADB: OK")
            else:
                parts.append("ADB: UNHEALTHY")
        if self._pcap_enabled:
            parts.append(f"Pcap: ON ({self._pcap_interface})")
        return "  " + "  |  ".join(parts) if parts else ""

    def _format_case_line(self, spec: CaseSpec, result: CaseResult) -> str:
        target_label = spec.method
        if spec.response_code is not None:
            related = spec.related_method or spec.method
            target_label = f"{spec.response_code}/{related}"

        total_str = str(self._total) if self._total > 0 else "\u221e"
        code_str = f" {result.response_code}," if result.response_code else ""
        return (
            f"  [{spec.case_id + 1}/{total_str}] "
            f"{target_label} {spec.profile}:{spec.layer}/{spec.strategy} seed={spec.seed} "
            f"-> {result.verdict} ({code_str}{result.elapsed_ms:.0f}ms)"
        )

    def _print_alerts(self, result: CaseResult) -> None:
        if result.verdict == "crash":
            self._print(f"  !! CRASH: {result.reproduction_cmd}")
        elif result.verdict == "stack_failure":
            self._print(f"  !! STACK_FAILURE: {result.reason}")
            self._print(f"     reproduction: {result.reproduction_cmd}")
        elif result.verdict == "unknown":
            self._print(f"  ** ERROR: {result.reason}")
        elif result.verdict == "infra_failure":
            self._print(f"  ** INFRA: {result.reason}")

    def _print(self, text: str) -> None:
        print(text, file=sys.stderr)
