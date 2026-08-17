"""Tests for the scripts/crash_analyzer.py CLI wrapper."""

from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from typing import Iterator

_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "crash_analyzer.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("crash_analyzer_script", _SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


crash_analyzer_script = _load_script()


@contextmanager
def _capture_stdout() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        yield buffer


class IterNewCaseResultsTests(unittest.TestCase):
    def _case_payload(self, case_id: int) -> dict:
        return {
            "case_id": case_id,
            "seed": case_id,
            "method": "OPTIONS",
            "layer": "model",
            "strategy": "default",
            "mutation_ops": (),
            "verdict": "normal",
            "reason": "ok",
            "elapsed_ms": 12.5,
            "reproduction_cmd": "uv run fuzzer ...",
            "timestamp": 1.0,
            "pcap_path": None,
        }

    def _case_line(self, case_id: int) -> str:
        return json.dumps({"type": "case", **self._case_payload(case_id)}) + "\n"

    def test_missing_file_returns_start_offset(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            cases, offset = crash_analyzer_script._iter_new_case_results(path, 7)
        self.assertEqual(cases, [])
        self.assertEqual(offset, 7)

    def test_reads_complete_case_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            path.write_text(self._case_line(0) + self._case_line(1))
            cases, offset = crash_analyzer_script._iter_new_case_results(path, 0)
            self.assertEqual([case.case_id for case in cases], [0, 1])
            self.assertEqual(offset, path.stat().st_size)

    def test_partial_line_is_reread_after_completion(self) -> None:
        # Realtime race: the poller reads while the writer is mid-append, so
        # the file temporarily ends with a fragment of the next case record.
        # The fragment must be held back (offset must not consume it) and the
        # completed line must be parsed on the next poll.
        complete_line = self._case_line(0)
        full_line = self._case_line(1)
        split = len(full_line) // 2
        fragment, remainder = full_line[:split], full_line[split:]

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            path.write_text(complete_line + fragment)

            cases, offset = crash_analyzer_script._iter_new_case_results(path, 0)
            self.assertEqual([case.case_id for case in cases], [0])
            self.assertEqual(offset, len(complete_line.encode("utf-8")))

            with path.open("a", encoding="utf-8") as handle:
                handle.write(remainder)

            cases, offset = crash_analyzer_script._iter_new_case_results(path, offset)
            self.assertEqual([case.case_id for case in cases], [1])
            self.assertEqual(offset, path.stat().st_size)

    def test_torn_tail_without_newline_is_not_consumed(self) -> None:
        # A fragment that is never completed (e.g. SIGKILL mid-append, the
        # same torn tail ResultStore.repair_torn_tail drops on resume) must
        # not advance the offset: repeated polls re-read it harmlessly.
        complete_line = self._case_line(0)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            path.write_text(complete_line + '{"type": "case", "case_i')
            for _ in range(2):
                cases, offset = crash_analyzer_script._iter_new_case_results(path, 0)
                self.assertEqual([case.case_id for case in cases], [0])
                self.assertEqual(offset, len(complete_line.encode("utf-8")))

    def test_complete_invalid_line_is_consumed_once(self) -> None:
        invalid_line = '{"type": "case", not json at all\n'
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            path.write_text(invalid_line)
            with _capture_stdout():
                cases, offset = crash_analyzer_script._iter_new_case_results(path, 0)
                self.assertEqual(cases, [])
                self.assertEqual(offset, len(invalid_line.encode("utf-8")))
                # Completed-but-corrupt lines are skipped permanently: a
                # re-poll of an unchanged file must parse nothing new.
                cases, offset = crash_analyzer_script._iter_new_case_results(
                    path, offset
                )
                self.assertEqual(cases, [])
                self.assertEqual(offset, path.stat().st_size)

    def test_non_case_records_advance_offset_without_cases(self) -> None:
        header = json.dumps({"type": "header", "campaign_id": "abc"}) + "\n"
        marker = json.dumps({"type": "resume_marker"}) + "\n"
        blank = "\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            path.write_text(header + blank + marker + self._case_line(3))
            cases, offset = crash_analyzer_script._iter_new_case_results(path, 0)
            self.assertEqual([case.case_id for case in cases], [3])
            self.assertEqual(offset, path.stat().st_size)

    def test_non_object_json_line_is_skipped(self) -> None:
        # json.loads succeeds for non-dict payloads; the old .get() on them
        # crashed the whole monitor loop.
        array_line = "[1, 2, 3]\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            path.write_text(array_line + self._case_line(0))
            cases, offset = crash_analyzer_script._iter_new_case_results(path, 0)
            self.assertEqual([case.case_id for case in cases], [0])
            self.assertEqual(offset, path.stat().st_size)


class AnalyzeCompletedTests(unittest.TestCase):
    def test_torn_tail_is_excluded_from_batch_analysis(self) -> None:
        case_payload = {
            "case_id": 0,
            "seed": 0,
            "method": "OPTIONS",
            "layer": "model",
            "strategy": "default",
            "mutation_ops": (),
            "verdict": "crash",
            "reason": "SIGSEGV while parsing malformed packet",
            "elapsed_ms": 12.5,
            "reproduction_cmd": "uv run fuzzer ...",
            "timestamp": 1.0,
            "pcap_path": None,
        }
        complete_line = json.dumps({"type": "case", **case_payload}) + "\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            path.write_text(complete_line + '{"type": "case", "case_i')
            output_dir = Path(tmpdir) / "analysis"
            with _capture_stdout():
                crash_analyzer_script.analyze_completed(str(path), str(output_dir))
            self.assertTrue((output_dir / "live_summary.txt").exists())
            self.assertTrue(list(output_dir.glob("crash_analysis_report_*.txt")))


if __name__ == "__main__":
    unittest.main()
