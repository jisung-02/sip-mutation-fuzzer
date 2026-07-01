#!/usr/bin/env python3
# ruff: noqa: E402
"""CLI wrapper for the shared campaign crash analyzer."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

_REPO_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_REPO_SRC) not in sys.path:
    sys.path.insert(0, str(_REPO_SRC))

from pydantic import ValidationError

from volte_mutation_fuzzer.analysis.crash_analyzer import CampaignCrashAnalyzer
from volte_mutation_fuzzer.campaign.contracts import CaseResult

CrashAnalyzer = CampaignCrashAnalyzer


def _iter_new_case_results(
    jsonl_path: Path,
    start_offset: int,
) -> tuple[list[CaseResult], int]:
    if not jsonl_path.exists():
        return [], start_offset

    cases: list[CaseResult] = []
    with jsonl_path.open("r", encoding="utf-8") as handle:
        handle.seek(start_offset)
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if payload.get("type") != "case":
                continue
            payload.pop("type", None)
            try:
                cases.append(CaseResult.model_validate(payload))
            except ValidationError as exc:
                print(f"[crash-analysis] skipped invalid case record: {exc}")
        return cases, handle.tell()


def analyze_completed(jsonl_file: str, output_dir: str) -> None:
    path = Path(jsonl_file)
    analyzer = CampaignCrashAnalyzer(
        output_dir=output_dir,
        enabled=True,
        source_name=str(path),
    )

    if not path.exists():
        print(f"[crash-analysis] JSONL file not found: {path}")
        return

    offset = 0
    cases, offset = _iter_new_case_results(path, offset)
    for case in cases:
        analyzer.analyze_case_immediately(case)

    reports = analyzer.generate_final_report()
    if reports is None:
        print("[crash-analysis] analysis disabled")


def monitor_realtime(jsonl_file: str, output_dir: str, interval: float) -> None:
    path = Path(jsonl_file)
    analyzer = CampaignCrashAnalyzer(
        output_dir=output_dir,
        enabled=True,
        source_name=str(path),
    )
    offset = 0

    print(f"[crash-analysis] monitoring: {path}")
    print(f"[crash-analysis] interval: {interval}s")

    try:
        while True:
            cases, offset = _iter_new_case_results(path, offset)
            for case in cases:
                analyzer.analyze_case_immediately(case)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("[crash-analysis] stopped by user")
    finally:
        analyzer.generate_final_report()


def main() -> None:
    parser = argparse.ArgumentParser(description="VolteMutationFuzzer Crash Analyzer")
    parser.add_argument("jsonl_file", help="Path to campaign JSONL file")
    parser.add_argument(
        "-m",
        "--mode",
        choices=["realtime", "batch"],
        default="batch",
        help="Analysis mode",
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=float,
        default=2.0,
        help="Polling interval for realtime mode",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="crash_analysis",
        help="Output directory for analysis results",
    )

    args = parser.parse_args()
    if args.mode == "realtime":
        monitor_realtime(args.jsonl_file, args.output, args.interval)
        return
    analyze_completed(args.jsonl_file, args.output)


if __name__ == "__main__":
    main()
