from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from volte_mutation_fuzzer.campaign.contracts import CaseResult

_IMPORTANT_VERDICTS = frozenset({"crash", "stack_failure", "suspicious"})
_VERDICT_STATS_KEYS = {
    "crash": "crashes",
    "stack_failure": "stack_failures",
    "suspicious": "suspicious",
}


@dataclass
class CrashCase:
    """Detailed crash case information."""

    case_id: int
    verdict: str
    reason: str
    method: str
    layer: str
    strategy: str
    mutation_ops: list[str]
    elapsed_ms: float
    response_code: int | None
    pcap_path: str | None
    timestamp: float
    packet_summary: str | None = None
    crash_category: str | None = None


class PacketAnalyzer:
    """Analyze pcap files for packet content."""

    @staticmethod
    def analyze_pcap(pcap_path: str) -> str | None:
        if not pcap_path or not Path(pcap_path).exists():
            return None

        try:
            result = subprocess.run(
                ["tcpdump", "-r", pcap_path, "-A", "-c", "1", "src", "172.22.0.21"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except Exception as exc:
            return f"pcap analysis error: {exc}"

        if result.returncode != 0:
            return "pcap analysis failed"

        output = result.stdout
        method_match = re.search(
            r"(INVITE|OPTIONS|REGISTER|MESSAGE|BYE|ACK|CANCEL)\s+sip:", output
        )
        uri_match = re.search(r"sip:([^@]+@[^;\s]+)", output)
        content_len_match = re.search(r"Content-Length:\s*(\d+)", output)

        anomalies: list[str] = []
        if len(output) > 5000:
            anomalies.append("oversized")
        if re.search(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\xFF]", output):
            anomalies.append("binary_data")
        if re.search(r"(.{100,})\1", output):
            anomalies.append("repetitive")

        summary_parts = [
            f"{method_match.group(1) if method_match else 'Unknown'} "
            f"{uri_match.group(1) if uri_match else 'unknown'}",
            f"len={content_len_match.group(1) if content_len_match else '0'}",
        ]
        if anomalies:
            summary_parts.append(f"anomalies={','.join(anomalies)}")
        return " | ".join(summary_parts)


class CrashCategorizer:
    """Automatic crash type classification."""

    CATEGORIES = {
        "memory_corruption": [
            r"SIGSEGV",
            r"SIGABRT",
            r"segmentation fault",
            r"double free",
            r"heap.*corruption",
            r"buffer.*overflow",
            r"use.*after.*free",
            r"null.*pointer",
        ],
        "parser_crash": [
            r"parsing.*failed",
            r"malformed.*message",
            r"invalid.*format",
            r"unexpected.*token",
            r"parse.*error",
            r"400.*bad.*request",
        ],
        "protocol_violation": [
            r"415.*unsupported.*media",
            r"481.*call.*not.*found",
            r"482.*loop.*detected",
            r"protocol.*violation",
        ],
        "resource_exhaustion": [
            r"out.*of.*memory",
            r"too.*many.*connections",
            r"resource.*limit",
            r"timeout.*exceeded",
        ],
        "authentication_error": [
            r"401.*unauthorized",
            r"403.*forbidden",
            r"authentication.*failed",
            r"invalid.*credentials",
        ],
        "state_machine_error": [
            r"invalid.*state",
            r"unexpected.*response",
            r"state.*transition.*error",
            r"dialog.*mismatch",
        ],
    }

    @classmethod
    def categorize(cls, reason: str, verdict: str) -> str:
        for category, patterns in cls.CATEGORIES.items():
            for pattern in patterns:
                if re.search(pattern, reason, re.IGNORECASE):
                    return category

        if verdict == "crash":
            return "process_crash"
        if verdict == "stack_failure":
            return "stack_trace"
        if verdict == "suspicious":
            return "protocol_error"
        return "unknown"


class CampaignCrashAnalyzer:
    """Integrated crash analyzer for campaign execution."""

    def __init__(
        self,
        output_dir: str = "crash_analysis",
        enabled: bool = True,
        source_name: str | None = None,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.enabled = enabled
        self.source_name = source_name or "campaign"
        self.analysis_start_time = time.time()
        self.crash_cases: list[CrashCase] = []
        self.packet_analyzer = PacketAnalyzer()
        self.categorizer = CrashCategorizer()
        self.stats: dict[str, Any] = {
            "total_cases": 0,
            "crashes": 0,
            "stack_failures": 0,
            "suspicious": 0,
            "categories": {},
        }

        if not self.enabled:
            return

        self.output_dir.mkdir(parents=True, exist_ok=True)
        print("[crash-analysis] enabled")
        print(f"[crash-analysis] output: {self.output_dir}")

    def analyze_case_immediately(self, case_result: CaseResult) -> CrashCase | None:
        if not self.enabled:
            return None

        self.stats["total_cases"] += 1
        verdict = case_result.verdict
        stat_key = _VERDICT_STATS_KEYS.get(verdict)
        if stat_key is not None:
            self.stats[stat_key] += 1

        if verdict not in _IMPORTANT_VERDICTS:
            return None

        crash_case = self._convert_case_result(case_result)
        self.crash_cases.append(crash_case)

        categories: dict[str, int] = self.stats["categories"]
        category = crash_case.crash_category or "unknown"
        categories[category] = categories.get(category, 0) + 1

        self._notify_crash(crash_case)
        self._update_live_report()
        return crash_case

    def generate_final_report(self) -> tuple[Path, Path] | None:
        if not self.enabled:
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_dir / f"crash_analysis_report_{timestamp}.txt"
        json_file = self.output_dir / f"crash_data_{timestamp}.json"
        total_critical = self.stats["crashes"] + self.stats["stack_failures"]

        with report_file.open("w", encoding="utf-8") as handle:
            handle.write("VOLTE FUZZER CRASH ANALYSIS REPORT\n")
            handle.write("=" * 60 + "\n")
            handle.write(
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            handle.write(f"Source: {self.source_name}\n")
            handle.write(
                f"Analysis duration: {time.time() - self.analysis_start_time:.1f}s\n\n"
            )

            handle.write("OVERALL STATISTICS:\n")
            handle.write(f"  Total cases processed: {self.stats['total_cases']}\n")
            handle.write(f"  Total crashes: {self.stats['crashes']}\n")
            handle.write(f"  Stack failures: {self.stats['stack_failures']}\n")
            handle.write(f"  Suspicious cases: {self.stats['suspicious']}\n")
            if self.stats["total_cases"] > 0:
                critical_rate = (total_critical / self.stats["total_cases"]) * 100
                handle.write(f"  Critical issue rate: {critical_rate:.2f}%\n")
            handle.write("\n")

            categories: dict[str, int] = self.stats["categories"]
            if categories:
                handle.write("CRASH CATEGORIES:\n")
                for category, count in sorted(
                    categories.items(), key=lambda item: item[1], reverse=True
                ):
                    percentage = (
                        (count / len(self.crash_cases)) * 100 if self.crash_cases else 0
                    )
                    handle.write(
                        f"  {category}: {count} cases ({percentage:.1f}%)\n"
                    )
                handle.write("\n")

            if self.crash_cases:
                handle.write("FUZZING EFFECTIVENESS:\n")
                layer_stats: dict[str, int] = {}
                strategy_stats: dict[str, int] = {}
                for crash in self.crash_cases:
                    layer_stats[crash.layer] = layer_stats.get(crash.layer, 0) + 1
                    strategy_stats[crash.strategy] = (
                        strategy_stats.get(crash.strategy, 0) + 1
                    )

                handle.write("  Most effective layers:\n")
                for layer, count in sorted(
                    layer_stats.items(), key=lambda item: item[1], reverse=True
                ):
                    handle.write(f"    {layer}: {count} crashes\n")

                handle.write("  Most effective strategies:\n")
                for strategy, count in sorted(
                    strategy_stats.items(), key=lambda item: item[1], reverse=True
                ):
                    handle.write(f"    {strategy}: {count} crashes\n")
                handle.write("\n")

                handle.write("TOP CRASH CASES:\n")
                severity_order = {"crash": 3, "stack_failure": 2, "suspicious": 1}
                sorted_crashes = sorted(
                    self.crash_cases,
                    key=lambda crash: (
                        severity_order.get(crash.verdict, 0),
                        crash.case_id,
                    ),
                    reverse=True,
                )
                for index, crash in enumerate(sorted_crashes[:10], 1):
                    handle.write(f"\n  #{index} Case {crash.case_id} ({crash.verdict}):\n")
                    handle.write(f"    Category: {crash.crash_category}\n")
                    handle.write(
                        f"    Config: {crash.method} | {crash.layer} | {crash.strategy}\n"
                    )
                    handle.write(f"    Reason: {crash.reason}\n")
                    if crash.mutation_ops:
                        handle.write(
                            f"    Mutations: {', '.join(crash.mutation_ops[:3])}\n"
                        )
                    if crash.packet_summary:
                        handle.write(f"    Packet: {crash.packet_summary}\n")
                    if crash.pcap_path:
                        handle.write(f"    Evidence: {crash.pcap_path}\n")
                    handle.write(
                        "    Timestamp: "
                        f"{datetime.fromtimestamp(crash.timestamp).strftime('%H:%M:%S')}\n"
                    )

            handle.write("\nREPRODUCTION GUIDE:\n")
            handle.write(
                "  To reproduce specific cases, use the original campaign command with:\n"
            )
            handle.write("  --seed-start <case_specific_seed> --max-cases 1\n\n")
            handle.write("  For detailed packet analysis:\n")
            handle.write("  tcpdump -r <pcap_path> -A\n")
            handle.write("  wireshark <pcap_path>\n\n")

            handle.write("RECOMMENDATIONS:\n")
            if total_critical > 0:
                handle.write(
                    "  - Focus on reproducing top crash cases for deeper analysis\n"
                )
                handle.write(
                    "  - Analyze pcap files to understand exact malformed packets\n"
                )
                handle.write(
                    "  - Use successful layer/strategy combinations for targeted fuzzing\n"
                )
            else:
                handle.write("  - No critical crashes found in this session\n")
                handle.write(
                    "  - Consider different fuzzing parameters or target methods\n"
                )
            if self.stats["suspicious"] > 0:
                handle.write(
                    "  - Investigate suspicious cases for potential security issues\n"
                )

        json_data = {
            "analysis_info": {
                "source_name": self.source_name,
                "generated_at": datetime.now().isoformat(),
                "analysis_duration_seconds": time.time() - self.analysis_start_time,
            },
            "statistics": self.stats,
            "crash_cases": [asdict(crash) for crash in self.crash_cases],
        }
        with json_file.open("w", encoding="utf-8") as handle:
            json.dump(json_data, handle, indent=2, ensure_ascii=False)

        print(f"[crash-analysis] reports saved: {report_file} {json_file}")
        return report_file, json_file

    def print_live_stats(self, force: bool = False) -> None:
        if not self.enabled:
            return

        total_critical = self.stats["crashes"] + self.stats["stack_failures"]
        if force or (self.crash_cases and len(self.crash_cases) % 10 == 0):
            print(
                f"[crash-analysis] live: {self.stats['total_cases']} cases | "
                f"{total_critical} critical"
            )

    def _convert_case_result(self, case_result: CaseResult) -> CrashCase:
        packet_summary = None
        if case_result.pcap_path:
            packet_summary = self.packet_analyzer.analyze_pcap(case_result.pcap_path)

        mutation_ops = case_result.mutation_ops
        mutation_ops_list: list[str]
        if isinstance(mutation_ops, str):
            mutation_ops_list = [mutation_ops]
        elif isinstance(mutation_ops, (list, tuple)):
            mutation_ops_list = [str(op) for op in mutation_ops]
        else:
            mutation_ops_list = []

        return CrashCase(
            case_id=case_result.case_id,
            verdict=case_result.verdict,
            reason=case_result.reason,
            method=case_result.method,
            layer=case_result.layer,
            strategy=case_result.strategy,
            mutation_ops=mutation_ops_list,
            elapsed_ms=case_result.elapsed_ms,
            response_code=case_result.response_code,
            pcap_path=case_result.pcap_path,
            timestamp=case_result.timestamp,
            packet_summary=packet_summary,
            crash_category=self.categorizer.categorize(
                case_result.reason,
                case_result.verdict,
            ),
        )

    def _notify_crash(self, crash_case: CrashCase) -> None:
        print(
            f"[crash-analysis] detected: case={crash_case.case_id} "
            f"verdict={crash_case.verdict} category={crash_case.crash_category}"
        )
        print(
            f"  config={crash_case.method} {crash_case.layer}/{crash_case.strategy}"
        )
        print(
            "  reason="
            f"{crash_case.reason[:100]}{'...' if len(crash_case.reason) > 100 else ''}"
        )
        if crash_case.mutation_ops:
            preview = ", ".join(crash_case.mutation_ops[:3])
            suffix = "..." if len(crash_case.mutation_ops) > 3 else ""
            print(f"  mutations={preview}{suffix}")
        if crash_case.packet_summary:
            print(f"  packet={crash_case.packet_summary}")
        if crash_case.pcap_path:
            print(f"  evidence={crash_case.pcap_path}")

    def _update_live_report(self) -> None:
        live_report = self.output_dir / "live_summary.txt"
        total_critical = self.stats["crashes"] + self.stats["stack_failures"]

        with live_report.open("w", encoding="utf-8") as handle:
            handle.write("LIVE CRASH ANALYSIS SUMMARY\n")
            handle.write(
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            handle.write(f"Source: {self.source_name}\n")
            handle.write(
                f"Duration: {time.time() - self.analysis_start_time:.1f}s\n"
            )
            handle.write("=" * 50 + "\n\n")
            handle.write("STATISTICS:\n")
            handle.write(f"  Total cases: {self.stats['total_cases']}\n")
            handle.write(f"  Crashes: {self.stats['crashes']}\n")
            handle.write(f"  Stack failures: {self.stats['stack_failures']}\n")
            handle.write(f"  Suspicious: {self.stats['suspicious']}\n")
            handle.write(f"  Critical: {total_critical}\n")

            categories: dict[str, int] = self.stats["categories"]
            if categories:
                handle.write("\nCRASH CATEGORIES:\n")
                for category, count in sorted(
                    categories.items(), key=lambda item: item[1], reverse=True
                ):
                    handle.write(f"  {category}: {count}\n")

            if self.crash_cases:
                handle.write("\nRECENT CRASHES (last 5):\n")
                for crash in self.crash_cases[-5:]:
                    handle.write(
                        f"  Case {crash.case_id}: "
                        f"{crash.verdict} - {crash.crash_category}\n"
                    )
                    handle.write(
                        f"    {crash.reason[:80]}"
                        f"{'...' if len(crash.reason) > 80 else ''}\n"
                    )
