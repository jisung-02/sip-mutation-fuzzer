import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from volte_mutation_fuzzer.ios.crash_report import (
    describe_new_crashes,
    parse_content_timestamp,
    parse_crash_timestamp,
)


class ParseCrashTimestampTests(unittest.TestCase):
    def test_compact_time_format(self) -> None:
        ts = parse_crash_timestamp("stacks-2026-05-28-223412.ips")
        self.assertEqual(ts, datetime(2026, 5, 28, 22, 34, 12, tzinfo=timezone.utc))

    def test_dashed_time_format(self) -> None:
        ts = parse_crash_timestamp("OTAUpdate-2026-06-01-00-50-57.ips")
        self.assertEqual(ts, datetime(2026, 6, 1, 0, 50, 57, tzinfo=timezone.utc))

    def test_compact_with_fractional_suffix(self) -> None:
        ts = parse_crash_timestamp("SiriSearchFeedback-2026-06-07-024606.000.ips")
        self.assertEqual(ts, datetime(2026, 6, 7, 2, 46, 6, tzinfo=timezone.utc))

    def test_no_timestamp_returns_none(self) -> None:
        self.assertIsNone(parse_crash_timestamp("README.txt"))


class ParseContentTimestampTests(unittest.TestCase):
    def test_reads_zone_aware_header(self) -> None:
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "CommCenter-2026-06-07-031500.ips"
            p.write_text(
                json.dumps(
                    {"bug_type": "309", "timestamp": "2026-06-07 03:15:00.00 +0000"}
                )
                + "\nrest of report\n"
            )
            ts, bug = parse_content_timestamp(p)
            self.assertEqual(ts, datetime(2026, 6, 7, 3, 15, 0, tzinfo=timezone.utc))
            self.assertEqual(bug, "309")

    def test_plaintext_report_returns_none(self) -> None:
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "legacy.crash"
            p.write_text("Incident Identifier: ...\n")
            self.assertEqual(parse_content_timestamp(p), (None, None))


class DescribeNewCrashesTests(unittest.TestCase):
    def _make(self, root: Path) -> None:
        root.mkdir(parents=True, exist_ok=True)
        (root / "stacks-2026-05-28-223412.ips").write_text("old")
        (root / "JetsamEvent-2026-06-07-031600.ips").write_text(
            json.dumps({"bug_type": "298", "timestamp": "2026-06-07 03:16:00.00 +0000"})
            + "\n"
        )

    def test_excludes_baseline_names(self) -> None:
        with TemporaryDirectory() as tmp:
            crashes = Path(tmp) / "crashes"
            self._make(crashes)
            records = describe_new_crashes(
                crashes, baseline_names={"stacks-2026-05-28-223412.ips"}
            )
            self.assertEqual(
                [r.name for r in records], ["JetsamEvent-2026-06-07-031600.ips"]
            )
            self.assertEqual(records[0].bug_type, "298")
            self.assertEqual(records[0].timestamp_source, "content")

    def test_no_baseline_returns_all_sorted(self) -> None:
        with TemporaryDirectory() as tmp:
            crashes = Path(tmp) / "crashes"
            self._make(crashes)
            records = describe_new_crashes(crashes)
            # sorted oldest first: May before June
            self.assertEqual(
                [r.name for r in records],
                [
                    "stacks-2026-05-28-223412.ips",
                    "JetsamEvent-2026-06-07-031600.ips",
                ],
            )

    def test_missing_dir_returns_empty(self) -> None:
        with TemporaryDirectory() as tmp:
            self.assertEqual(describe_new_crashes(Path(tmp) / "nope"), [])


if __name__ == "__main__":
    unittest.main()
