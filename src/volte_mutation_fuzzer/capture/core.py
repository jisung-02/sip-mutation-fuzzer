from concurrent.futures import Future, ThreadPoolExecutor, wait as wait_futures
import signal
import subprocess
import threading
import time
from pathlib import Path
from subprocess import Popen as subprocess_popen


class PcapCapture:
    _export_lock = threading.Lock()
    _export_executor: ThreadPoolExecutor | None = None
    _pending_exports: set[Future[None]] = set()

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
            self._process = subprocess_popen(
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
            self._schedule_txt_export(output_path)
            return self._output_path
        return None

    @classmethod
    def _schedule_txt_export(cls, pcap_path: Path) -> None:
        executor = cls._ensure_export_executor()
        future = executor.submit(cls._export_txt, pcap_path)
        with cls._export_lock:
            cls._pending_exports.add(future)
        future.add_done_callback(cls._forget_export_future)

    @classmethod
    def _ensure_export_executor(cls) -> ThreadPoolExecutor:
        with cls._export_lock:
            if cls._export_executor is None:
                cls._export_executor = ThreadPoolExecutor(
                    max_workers=1,
                    thread_name_prefix="vmf-pcap-export",
                )
            return cls._export_executor

    @classmethod
    def _forget_export_future(cls, future: Future[None]) -> None:
        with cls._export_lock:
            cls._pending_exports.discard(future)

    @classmethod
    def wait_for_pending_exports(cls, timeout: float | None = None) -> None:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            with cls._export_lock:
                pending = tuple(cls._pending_exports)
            if not pending:
                return

            remaining = None
            if deadline is not None:
                remaining = max(0.0, deadline - time.monotonic())

            done, not_done = wait_futures(pending, timeout=remaining)
            for future in done:
                future.result()
            if not_done:
                raise TimeoutError("timed out waiting for pending pcap txt exports")

    @staticmethod
    def _export_txt(pcap_path: Path) -> None:
        """Export pcap to human-readable txt using tshark."""
        txt_path = pcap_path.with_suffix(".txt")
        proc: subprocess.Popen[str] | None = None
        try:
            proc = subprocess_popen(
                ["tshark", "-r", str(pcap_path), "-V"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, _stderr = proc.communicate(timeout=10)
            if proc.returncode == 0 and stdout:
                txt_path.write_text(stdout, encoding="utf-8")
        except FileNotFoundError:
            # tshark not installed or timeout — skip silently
            pass
        except subprocess.TimeoutExpired:
            if proc is not None:
                proc.kill()
                proc.communicate()
