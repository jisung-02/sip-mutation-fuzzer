import signal
import subprocess
import threading
import time
from pathlib import Path


class PcapCapture:
    def __init__(
        self,
        output_path: str,
        interface: str = "any",
        filter_expr: str = "udp port 5060 or tcp port 5060",
    ) -> None:
        self._output_path = output_path
        self._interface = interface
        self._filter_expr = filter_expr
        self._lock = threading.Lock()
        self._process: subprocess.Popen[bytes] | None = None

    def start(self) -> None:
        with self._lock:
            if self._process is not None:
                raise RuntimeError("pcap capture is already running")
            self._process = subprocess.Popen(
                [
                    "sudo",
                    "tcpdump",
                    "-i",
                    self._interface,
                    "-w",
                    self._output_path,
                    self._filter_expr,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(0.1)

    def stop(self) -> str | None:
        with self._lock:
            process = self._process
            self._process = None

            if process is not None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

        output_path = Path(self._output_path)
        if output_path.exists() and output_path.stat().st_size > 0:
            self._export_txt(output_path)
            return self._output_path
        return None

    @staticmethod
    def _export_txt(pcap_path: Path) -> None:
        """Export pcap to human-readable txt using tshark."""
        txt_path = pcap_path.with_suffix(".txt")
        try:
            result = subprocess.run(
                ["tshark", "-r", str(pcap_path), "-V"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout:
                txt_path.write_text(result.stdout, encoding="utf-8")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # tshark not installed or timeout — skip silently
            pass
