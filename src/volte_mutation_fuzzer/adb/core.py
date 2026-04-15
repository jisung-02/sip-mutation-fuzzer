import subprocess
import threading
import time
from collections import deque
from pathlib import Path
from queue import Empty, Queue

from volte_mutation_fuzzer.adb.contracts import (
    AdbAnomalyEvent,
    AdbCollectorConfig,
    AdbDeviceInfo,
    AdbSnapshotResult,
)
from volte_mutation_fuzzer.adb.patterns import ANOMALY_PATTERNS, AnomalyPattern


class AdbConnector:
    def __init__(self, serial: str | None = None) -> None:
        self._serial = serial

    def _adb_cmd(self, *args: str) -> list[str]:
        base = ["adb"]
        if self._serial:
            base.extend(["-s", self._serial])
        base.extend(args)
        return base

    def check_device(self) -> AdbDeviceInfo:
        target_serial = self._serial or "unknown"
        try:
            result = subprocess.run(
                self._adb_cmd("devices", "-l"),
                capture_output=True,
                text=True,
                timeout=10,
            )
        except FileNotFoundError:
            return AdbDeviceInfo(
                serial="unknown",
                state="not_found",
                error="adb not found",
            )

        selected_line: str | None = None
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("List of devices attached"):
                continue

            serial, _, remainder = line.partition("\t")
            if not remainder:
                continue

            if self._serial is not None and serial != self._serial:
                continue

            selected_line = line
            target_serial = serial
            break

        if selected_line is None:
            return AdbDeviceInfo(serial=target_serial, state="not_found")

        serial, _, remainder = selected_line.partition("\t")
        state, _, details = remainder.partition(" ")
        model: str | None = None
        for token in details.split():
            if token.startswith("model:"):
                model = token.removeprefix("model:")
                break

        return AdbDeviceInfo(serial=serial, state=state, model=model)

    def run_shell(
        self, *args: str, timeout: int = 30
    ) -> subprocess.CompletedProcess[str]:
        cmd = self._adb_cmd("shell", *args)
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    def take_snapshot(
        self, output_dir: str, *, bugreport: bool = False
    ) -> AdbSnapshotResult:
        """Capture meminfo + dmesg (and optionally bugreport) to output_dir."""
        base_dir = Path(output_dir)
        base_dir.mkdir(parents=True, exist_ok=True)
        errors: list[str] = []
        meminfo_path: str | None = None
        dmesg_path: str | None = None
        bugreport_path: str | None = None

        def _write_shell_output(filename: str, *args: str, timeout: int) -> str | None:
            path = base_dir / filename
            try:
                result = self.run_shell(*args, timeout=timeout)
            except Exception as exc:
                errors.append(f"{' '.join(args)} failed: {exc}")
                return None

            if result.returncode != 0:
                message = (
                    result.stderr.strip() or result.stdout.strip() or "unknown error"
                )
                errors.append(f"{' '.join(args)} failed: {message}")
                return None

            path.write_text(result.stdout, encoding="utf-8")
            return str(path)

        # --- IMS/telephony specific ---
        telephony_path = _write_shell_output(
            "telephony.txt", "dumpsys", "telephony.registry", timeout=30
        )
        ims_path = _write_shell_output(
            "ims.txt", "dumpsys", "ims", timeout=30
        )
        netstat_path = _write_shell_output(
            "netstat.txt", "netstat", "-tlnup", timeout=10
        )

        # --- Logcat: per-buffer + combined ---
        logcat_path: str | None = None
        logcat_buffers = ("main", "system", "radio", "crash")
        for buf in logcat_buffers:
            try:
                buf_file = base_dir / f"logcat_{buf}.txt"
                result = subprocess.run(
                    self._adb_cmd("logcat", "-d", "-b", buf),
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0 and result.stdout:
                    buf_file.write_text(result.stdout, encoding="utf-8")
            except Exception as exc:
                errors.append(f"logcat -b {buf} failed: {exc}")

        try:
            logcat_file = base_dir / "logcat_all.txt"
            result = subprocess.run(
                self._adb_cmd("logcat", "-d", "-b", ",".join(logcat_buffers)),
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0 and result.stdout:
                logcat_file.write_text(result.stdout, encoding="utf-8")
                logcat_path = str(logcat_file)
        except Exception as exc:
            errors.append(f"logcat dump failed: {exc}")

        # --- General system ---
        meminfo_path = _write_shell_output(
            "meminfo.txt", "dumpsys", "meminfo", timeout=60
        )
        dmesg_path = _write_shell_output("dmesg.txt", "dmesg", timeout=60)

        if bugreport:
            path = base_dir / "bugreport.txt"
            try:
                result = subprocess.run(
                    self._adb_cmd("bugreport"),
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if result.returncode != 0:
                    message = (
                        result.stderr.strip()
                        or result.stdout.strip()
                        or "unknown error"
                    )
                    errors.append(f"bugreport failed: {message}")
                else:
                    path.write_text(result.stdout, encoding="utf-8")
                    bugreport_path = str(path)
            except Exception as exc:
                errors.append(f"bugreport failed: {exc}")

        return AdbSnapshotResult(
            meminfo_path=meminfo_path,
            dmesg_path=dmesg_path,
            bugreport_path=bugreport_path,
            logcat_path=logcat_path,
            telephony_path=telephony_path,
            ims_path=ims_path,
            netstat_path=netstat_path,
            errors=tuple(errors),
        )


class AdbLogCollector:
    def __init__(
        self,
        config: AdbCollectorConfig | None = None,
        *,
        max_reconnect_attempts: int = 5,
        reconnect_delay: float = 5.0,
    ) -> None:
        self._config = config or AdbCollectorConfig()
        self._connector = AdbConnector(serial=self._config.serial)
        self._procs: dict[str, subprocess.Popen[str]] = {}
        self._threads: dict[str, threading.Thread] = {}
        self._queue: Queue[tuple[str, str]] = Queue()
        self._running = threading.Event()
        self._max_reconnect_attempts = max_reconnect_attempts
        self._reconnect_delay = reconnect_delay
        self._dead_buffers: set[str] = set()
        self._reconnect_count: int = 0
        self._lock = threading.Lock()

    def start(self, clear: bool = True) -> None:
        if clear:
            subprocess.run(
                self._connector._adb_cmd("logcat", "-c"),
                capture_output=True,
                timeout=10,
            )

        self.stop()
        self._running.set()
        for buffer_name in self._config.buffers:
            cmd = self._connector._adb_cmd(
                "logcat",
                "-b",
                buffer_name,
                "-v",
                self._config.log_format,
            )
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            self._procs[buffer_name] = proc
            thread = threading.Thread(
                target=self._reader_loop,
                args=(buffer_name, proc),
                daemon=True,
            )
            self._threads[buffer_name] = thread
            thread.start()

    def stop(self) -> None:
        self._running.clear()
        with self._lock:
            procs = list(self._procs.values())
        for proc in procs:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        for thread in self._threads.values():
            thread.join(timeout=5)
        with self._lock:
            self._procs.clear()
            self._dead_buffers.clear()
        self._threads.clear()

    def get_lines(
        self, max_lines: int = 1000, timeout: float = 0.0
    ) -> list[tuple[str, str]]:
        lines: list[tuple[str, str]] = []
        try:
            if timeout > 0:
                lines.append(self._queue.get(timeout=timeout))
            else:
                lines.append(self._queue.get_nowait())
        except Empty:
            return lines

        try:
            while len(lines) < max_lines:
                lines.append(self._queue.get_nowait())
        except Empty:
            pass
        return lines

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    @property
    def is_healthy(self) -> bool:
        with self._lock:
            return self._running.is_set() and len(self._dead_buffers) == 0

    @property
    def dead_buffers(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._dead_buffers)

    @property
    def reconnect_count(self) -> int:
        with self._lock:
            return self._reconnect_count

    def _reader_loop(self, buffer_name: str, proc: subprocess.Popen[str]) -> None:
        current_proc = proc
        consecutive_failures = 0

        while self._running.is_set():
            # Read from current subprocess
            got_data = False
            if current_proc.stdout is not None:
                try:
                    for line in current_proc.stdout:
                        if not self._running.is_set():
                            return
                        self._queue.put((buffer_name, line.rstrip("\n")))
                        got_data = True
                    # EOF reached — adb logcat subprocess died
                except Exception:
                    pass

            if not self._running.is_set():
                return

            # Reset failure counter only if we actually read data (healthy session)
            if got_data:
                consecutive_failures = 0

            # Reconnect attempt
            consecutive_failures += 1
            if consecutive_failures > self._max_reconnect_attempts:
                with self._lock:
                    self._dead_buffers.add(buffer_name)
                return

            # Reap the old subprocess before spawning a new one
            try:
                current_proc.wait(timeout=1)
            except Exception:
                try:
                    current_proc.kill()
                except Exception:
                    pass

            # Interruptible sleep before retry
            for _ in range(int(self._reconnect_delay * 10)):
                if not self._running.is_set():
                    return
                time.sleep(0.1)

            # Re-check _running after sleep to avoid spawning during shutdown
            if not self._running.is_set():
                return

            try:
                cmd = self._connector._adb_cmd(
                    "logcat",
                    "-b",
                    buffer_name,
                    "-v",
                    self._config.log_format,
                )
                new_proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
                with self._lock:
                    # If stop() was called while we were spawning, kill immediately
                    if not self._running.is_set():
                        try:
                            new_proc.kill()
                        except Exception:
                            pass
                        return
                    self._procs[buffer_name] = new_proc
                    self._reconnect_count += 1
                current_proc = new_proc
            except Exception:
                pass


class AdbAnomalyDetector:
    def __init__(
        self,
        patterns: tuple[AnomalyPattern, ...] | None = None,
        max_events: int = 10000,
    ) -> None:
        self._patterns = patterns or ANOMALY_PATTERNS
        self._events: deque[AdbAnomalyEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()
        self._total_lines_scanned = 0

    def feed_line(self, buffer_name: str, line: str) -> AdbAnomalyEvent | None:
        self._total_lines_scanned += 1
        for pattern in self._patterns:
            if pattern.compiled.search(line):
                event = AdbAnomalyEvent(
                    timestamp=time.time(),
                    severity=pattern.severity,
                    category=pattern.category,
                    pattern_name=pattern.name,
                    matched_pattern=pattern.regex,
                    matched_line=line[:500],
                    buffer=buffer_name,
                )
                with self._lock:
                    self._events.append(event)
                return event
        return None

    def feed_lines(self, lines: list[tuple[str, str]]) -> list[AdbAnomalyEvent]:
        results: list[AdbAnomalyEvent] = []
        for buffer_name, line in lines:
            event = self.feed_line(buffer_name, line)
            if event is not None:
                results.append(event)
        return results

    def drain_events(self) -> list[AdbAnomalyEvent]:
        with self._lock:
            events = list(self._events)
            self._events.clear()
            return events

    def peek_events(self) -> list[AdbAnomalyEvent]:
        with self._lock:
            return list(self._events)

    @property
    def total_lines_scanned(self) -> int:
        return self._total_lines_scanned
