import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from volte_mutation_fuzzer.capture.core import PcapCapture


class PcapCaptureTests(unittest.TestCase):
    @patch("volte_mutation_fuzzer.capture.core.subprocess_popen")
    def test_start_launches_tcpdump(self, mock_popen: MagicMock) -> None:
        capture = PcapCapture("/tmp/test.pcap", interface="eth0")

        capture.start()

        mock_popen.assert_called_once_with(
            [
                "sudo",
                "tcpdump",
                "-i",
                "eth0",
                "-w",
                "/tmp/test.pcap",
                "udp port 5060 or tcp port 5060",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    @patch("volte_mutation_fuzzer.capture.core.subprocess_popen")
    def test_stop_returns_path_when_file_exists(self, mock_popen: MagicMock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_path = Path(tmpdir) / "case.pcap"
            pcap_path.write_bytes(b"pcap")
            capture_process = MagicMock()
            capture_process.wait.return_value = 0
            tshark_process = MagicMock()
            tshark_process.returncode = 0
            tshark_process.communicate.return_value = ("pcap text\n", "")
            mock_popen.side_effect = [capture_process, tshark_process]
            capture = PcapCapture(str(pcap_path))

            capture.start()
            saved_path = capture.stop()

            capture_process.send_signal.assert_called_once()
            capture_process.wait.assert_called_once_with(timeout=3)
            tshark_process.communicate.assert_called_once_with(timeout=10)
            self.assertEqual(saved_path, str(pcap_path))
            self.assertEqual(pcap_path.with_suffix(".txt").read_text(), "pcap text\n")

    @patch("volte_mutation_fuzzer.capture.core.subprocess_popen")
    def test_stop_returns_none_when_file_missing(self, mock_popen: MagicMock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_path = Path(tmpdir) / "missing.pcap"
            capture = PcapCapture(str(pcap_path))

            capture.start()
            saved_path = capture.stop()

            self.assertIsNone(saved_path)

    @patch("volte_mutation_fuzzer.capture.core.subprocess_popen")
    def test_start_raises_if_already_running(self, mock_popen: MagicMock) -> None:
        capture = PcapCapture("/tmp/test.pcap")

        capture.start()

        with self.assertRaises(RuntimeError):
            capture.start()

        mock_popen.assert_called_once()

    @patch("volte_mutation_fuzzer.capture.core.subprocess_popen")
    def test_stop_kills_on_timeout(self, mock_popen: MagicMock) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_path = Path(tmpdir) / "case.pcap"
            process = mock_popen.return_value
            process.wait.side_effect = [
                subprocess.TimeoutExpired(cmd="tcpdump", timeout=3),
                0,
            ]
            capture = PcapCapture(str(pcap_path))

            capture.start()
            saved_path = capture.stop()

            process.kill.assert_called_once_with()
            self.assertIsNone(saved_path)

    @patch("volte_mutation_fuzzer.capture.core.subprocess_popen")
    def test_stop_kills_tshark_export_on_timeout(
        self, mock_popen: MagicMock
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_path = Path(tmpdir) / "case.pcap"
            pcap_path.write_bytes(b"pcap")
            capture_process = MagicMock()
            capture_process.wait.return_value = 0
            tshark_process = MagicMock()
            tshark_process.communicate.side_effect = [
                subprocess.TimeoutExpired(cmd="tshark", timeout=10),
                ("", ""),
            ]
            mock_popen.side_effect = [capture_process, tshark_process]
            capture = PcapCapture(str(pcap_path))

            capture.start()
            saved_path = capture.stop()

            tshark_process.kill.assert_called_once_with()
            self.assertEqual(saved_path, str(pcap_path))
            self.assertFalse(pcap_path.with_suffix(".txt").exists())
