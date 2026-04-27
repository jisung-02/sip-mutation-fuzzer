"""Tests for EvidenceCollector."""

import json
import tempfile
import unittest
from pathlib import Path

from volte_mutation_fuzzer.campaign.contracts import CaseResult
from volte_mutation_fuzzer.campaign.evidence import EvidenceCollector

REALISTIC_EVIDENCE_INVITE = "INVITE sip:111111@10.20.20.8:8100 SIP/2.0\r\n\r\n"


def _make_result(
    case_id: int = 0,
    verdict: str = "suspicious",
    raw_response: str | None = "SIP/2.0 400 Bad Request\r\n\r\n",
) -> CaseResult:
    return CaseResult(
        case_id=case_id,
        seed=42,
        method="INVITE",
        layer="wire",
        strategy="default",
        verdict=verdict,
        reason=f"test reason for {verdict}",
        elapsed_ms=123.4,
        reproduction_cmd="uv run fuzzer campaign run --seed-start 42 --max-cases 1",
        timestamp=1000000.0,
        response_code=400 if verdict == "suspicious" else None,
        raw_response=raw_response,
        mutation_ops=("insert_header(Via)", "flip_char(To)"),
    )


class EvidenceCollectorTests(unittest.TestCase):
    def test_collects_evidence_for_suspicious_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            collector = EvidenceCollector(Path(tmpdir))
            result = _make_result(verdict="suspicious")

            evidence_dir = collector.collect(
                result,
                sent_payload=REALISTIC_EVIDENCE_INVITE,
            )

            self.assertIsNotNone(evidence_dir)
            assert evidence_dir is not None
            d = Path(evidence_dir)
            self.assertTrue(d.is_dir())

            # summary.json
            summary = json.loads((d / "summary.json").read_text())
            self.assertEqual(summary["case_id"], 0)
            self.assertEqual(summary["seed"], 42)
            self.assertEqual(summary["verdict"], "suspicious")
            self.assertEqual(summary["strategy"], "default")
            self.assertIn("--seed-start 42", summary["reproduction_cmd"])

            # sent.sip
            self.assertIn("INVITE", (d / "sent.sip").read_text())

            # response.sip
            self.assertIn("400", (d / "response.sip").read_text())

            # mutation_ops.txt
            ops = (d / "mutation_ops.txt").read_text()
            self.assertIn("insert_header(Via)", ops)
            self.assertIn("flip_char(To)", ops)

    def test_summary_includes_case_details(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            collector = EvidenceCollector(Path(tmpdir))
            result = _make_result(verdict="stack_failure").model_copy(
                update={
                    "details": {
                        "adb_warning": {
                            "severity": "warning",
                            "matched_line": "IMS deregist triggered by network change",
                        }
                    }
                }
            )

            evidence_dir = collector.collect(result)

            assert evidence_dir is not None
            summary = json.loads((Path(evidence_dir) / "summary.json").read_text())
            self.assertIn("details", summary)
            self.assertEqual(summary["details"]["adb_warning"]["severity"], "warning")

    def test_collects_evidence_for_crash_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            collector = EvidenceCollector(Path(tmpdir))
            result = _make_result(verdict="crash", raw_response=None)

            evidence_dir = collector.collect(result, sent_payload="OPTIONS sip:x\r\n\r\n")
            self.assertIsNotNone(evidence_dir)
            assert evidence_dir is not None
            d = Path(evidence_dir)
            self.assertTrue((d / "summary.json").exists())
            self.assertTrue((d / "sent.sip").exists())
            self.assertFalse((d / "response.sip").exists())

    def test_collects_evidence_for_stack_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            collector = EvidenceCollector(Path(tmpdir))
            result = _make_result(verdict="stack_failure", raw_response=None)
            evidence_dir = collector.collect(result)
            self.assertIsNotNone(evidence_dir)

    def test_skips_normal_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            collector = EvidenceCollector(Path(tmpdir))
            result = _make_result(verdict="normal", raw_response=None)
            evidence_dir = collector.collect(result, sent_payload="test")
            self.assertIsNone(evidence_dir)

    def test_skips_timeout_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            collector = EvidenceCollector(Path(tmpdir))
            result = _make_result(verdict="timeout", raw_response=None)
            evidence_dir = collector.collect(result, sent_payload="test")
            self.assertIsNone(evidence_dir)

    def test_binary_payload_saved_as_bin(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            collector = EvidenceCollector(Path(tmpdir))
            result = _make_result(verdict="suspicious")
            payload = b"\x00\x01\x02INVITE sip:test"

            evidence_dir = collector.collect(result, sent_payload=payload)
            assert evidence_dir is not None
            d = Path(evidence_dir)
            self.assertTrue((d / "sent.bin").exists())
            self.assertEqual((d / "sent.bin").read_bytes(), payload)
            self.assertFalse((d / "sent.sip").exists())

    def test_pcap_copied(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a fake pcap file
            pcap_path = Path(tmpdir) / "case_000000.pcap"
            pcap_path.write_bytes(b"\xd4\xc3\xb2\xa1fake_pcap_data")

            collector = EvidenceCollector(Path(tmpdir))
            result = _make_result(verdict="crash", raw_response=None)

            evidence_dir = collector.collect(
                result, pcap_path=str(pcap_path)
            )
            assert evidence_dir is not None
            d = Path(evidence_dir)
            self.assertTrue((d / "capture.pcap").exists())
            self.assertEqual(
                (d / "capture.pcap").read_bytes(),
                b"\xd4\xc3\xb2\xa1fake_pcap_data",
            )

    def test_adb_snapshot_concatenated(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create fake adb snapshot dir
            adb_dir = Path(tmpdir) / "adb_snap"
            adb_dir.mkdir()
            (adb_dir / "main.txt").write_text("main buffer content\n")
            (adb_dir / "crash.txt").write_text("crash buffer content\n")

            collector = EvidenceCollector(Path(tmpdir))
            result = _make_result(verdict="stack_failure", raw_response=None)

            evidence_dir = collector.collect(
                result, adb_snapshot_dir=str(adb_dir)
            )
            assert evidence_dir is not None
            d = Path(evidence_dir)
            adb_log = (d / "adb_log.txt").read_text()
            self.assertIn("crash.txt", adb_log)
            self.assertIn("main.txt", adb_log)
            self.assertIn("crash buffer content", adb_log)
            self.assertIn("main buffer content", adb_log)

    def test_ios_snapshot_concatenated(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ios_dir = Path(tmpdir) / "ios_snap"
            (ios_dir / "crashes").mkdir(parents=True)
            (ios_dir / "syslog.txt").write_text("commcenter line\n")
            (ios_dir / "anomalies.json").write_text('[{"pattern":"EXC_BAD_ACCESS"}]\n')
            (ios_dir / "crashes" / "CommCenter-2026-04-15.ips").write_text("{}\n")

            collector = EvidenceCollector(Path(tmpdir))
            result = _make_result(verdict="stack_failure", raw_response=None)

            evidence_dir = collector.collect(
                result, ios_snapshot_dir=str(ios_dir)
            )
            assert evidence_dir is not None
            d = Path(evidence_dir)
            ios_log = (d / "ios_log.txt").read_text()
            self.assertIn("syslog.txt", ios_log)
            self.assertIn("anomalies.json", ios_log)
            self.assertIn("crashes/CommCenter-2026-04-15.ips", ios_log)
            self.assertIn("commcenter line", ios_log)

    def test_disabled_collector_does_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            collector = EvidenceCollector(Path(tmpdir), enabled=False)
            result = _make_result(verdict="crash")
            evidence_dir = collector.collect(result, sent_payload="test")
            self.assertIsNone(evidence_dir)

    def test_evidence_directory_structure(self) -> None:
        """Evidence is stored under interesting/case_XXXXXX/."""
        with tempfile.TemporaryDirectory() as tmpdir:
            collector = EvidenceCollector(Path(tmpdir))
            result = _make_result(case_id=31, verdict="suspicious")
            evidence_dir = collector.collect(result, sent_payload="test")
            assert evidence_dir is not None
            self.assertIn("interesting", evidence_dir)
            self.assertIn("case_000031", evidence_dir)
