import json
import re
import subprocess
import threading
import time
from collections import deque
from collections.abc import Iterable
from pathlib import Path
from typing import Protocol, cast

from volte_mutation_fuzzer.ios.contracts import (
    IosAnomalyEvent,
    IosCollectorConfig,
    IosDeviceInfo,
    IosSnapshotResult,
    IosSyslogLine,
)
from volte_mutation_fuzzer.ios.patterns import IOS_ANOMALY_PATTERNS
from volte_mutation_fuzzer.adb.patterns import AnomalyPattern


# idevicesyslog line format:
#   Apr 15 10:32:17 iPhone CommCenter[127] <Notice>: [IMS] Registration started
#   Apr 15 10:32:17 iPhone kernel(...)[0] <Error>: foo
_SYSLOG_LINE = re.compile(
    r"^(?P<device_ts>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+"
    r"(?P<process>\S+?)(?:\[\d+\])?\s+"
    r"(?:<(?P<level>\w+)>:?)?\s*"
    r"(?P<message>.*)$"
)


class _PopenLike(Protocol):
    stdout: Iterable[str] | None

    def wait(self, timeout: int | float | None = None) -> object: ...

    def kill(self) -> object: ...


def _parse_syslog_line(line: str, host_ts: float) -> IosSyslogLine:
    match = _SYSLOG_LINE.match(line)
    if match is None:
        return IosSyslogLine(host_ts=host_ts, line=line[:2000])
    return IosSyslogLine(
        host_ts=host_ts,
        device_ts=match.group("device_ts"),
        process=match.group("process") or "unknown",
        level=match.group("level"),
        line=line[:2000],
    )


class IosConnector:
    def __init__(self, udid: str | None = None) -> None:
        self._udid = udid

    def _cmd(self, binary: str, *args: str) -> list[str]:
        base = [binary]
        if self._udid:
            base.extend(["-u", self._udid])
        base.extend(args)
        return base

    def check_device(self) -> IosDeviceInfo:
        try:
            result = subprocess.run(
                ["idevice_id", "-l"], capture_output=True, text=True, timeout=10
            )
        except FileNotFoundError:
            return IosDeviceInfo(udid="unknown", error="libimobiledevice not found")
        except Exception as exc:
            return IosDeviceInfo(udid="unknown", error=f"idevice_id failed: {exc}")

        udids = [u.strip() for u in result.stdout.splitlines() if u.strip()]
        if not udids:
            return IosDeviceInfo(
                udid=self._udid or "unknown", error="no device connected"
            )

        target = self._udid or udids[0]
        if self._udid and self._udid not in udids:
            return IosDeviceInfo(udid=target, error="requested udid not connected")

        first_error: str | None = None

        def _query(key: str) -> str | None:
            nonlocal first_error
            try:
                result = subprocess.run(
                    self._cmd("ideviceinfo", "-k", key),
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            except Exception as exc:
                if first_error is None:
                    first_error = f"ideviceinfo {key} failed: {exc}"
                return None
            if result.returncode != 0:
                if first_error is None:
                    message = (
                        result.stderr.strip()
                        or result.stdout.strip()
                        or "non-zero exit"
                    )
                    first_error = f"ideviceinfo {key} failed: {message}"
                return None
            value = result.stdout.strip()
            return value or None

        return IosDeviceInfo(
            udid=target,
            product_type=_query("ProductType"),
            product_version=_query("ProductVersion"),
            build_version=_query("BuildVersion"),
            device_name=_query("DeviceName"),
            error=first_error,
        )

    def pull_crashes(self, output_dir: str) -> tuple[tuple[str, ...], list[str]]:
        """Run idevicecrashreport to pull new .ips files. Returns (new_files, errors)."""
        errors: list[str] = []
        target = Path(output_dir)
        target.mkdir(parents=True, exist_ok=True)
        before = {p.name for p in target.rglob("*") if p.is_file()}

        try:
            result = subprocess.run(
                self._cmd("idevicecrashreport", "-k", "-e", str(target)),
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0:
                message = (
                    result.stderr.strip() or result.stdout.strip() or "unknown error"
                )
                errors.append(f"idevicecrashreport failed: {message}")
        except FileNotFoundError:
            errors.append("idevicecrashreport not found")
        except Exception as exc:
            errors.append(f"idevicecrashreport failed: {exc}")

        after = {p.name for p in target.rglob("*") if p.is_file()}
        new_files = tuple(sorted(after - before))
        return new_files, errors

    def run_diagnostics(self, output_path: str) -> tuple[str | None, str | None]:
        """Dump idevicediagnostics output. Returns (path, error_message)."""
        try:
            result = subprocess.run(
                self._cmd("idevicediagnostics", "diagnostics", "All"),
                capture_output=True,
                text=True,
                timeout=15,
            )
        except FileNotFoundError:
            return None, "idevicediagnostics not found"
        except Exception as exc:
            return None, f"idevicediagnostics failed: {exc}"
        if result.returncode != 0:
            message = (
                result.stderr.strip() or result.stdout.strip() or "non-zero exit"
            )
            return None, f"idevicediagnostics failed: {message}"
        if not result.stdout:
            return None, "idevicediagnostics returned empty output"
        Path(output_path).write_text(result.stdout, encoding="utf-8")
        return output_path, None

    def take_snapshot(
        self,
        output_dir: str,
        *,
        collector: "IosSyslogCollector",
        syslog_since: float,
        syslog_until: float,
        detector: "IosAnomalyDetector | None" = None,
        run_diagnostics: bool = False,
    ) -> IosSnapshotResult:
        base_dir = Path(output_dir)
        base_dir.mkdir(parents=True, exist_ok=True)
        errors: list[str] = []

        lines = collector.slice(syslog_since, syslog_until)
        syslog_path = base_dir / "syslog.txt"
        syslog_path.write_text(
            "\n".join(x.line for x in lines) + ("\n" if lines else ""),
            encoding="utf-8",
        )

        def _filter_write(filename: str, processes: set[str]) -> str:
            path = base_dir / filename
            matched = [x for x in lines if x.process in processes]
            path.write_text(
                "\n".join(x.line for x in matched) + ("\n" if matched else ""),
                encoding="utf-8",
            )
            return str(path)

        commcenter_path = _filter_write("syslog_commcenter.txt", {"CommCenter"})
        springboard_path = _filter_write("syslog_springboard.txt", {"SpringBoard"})

        crashes_dir = base_dir / "crashes"
        new_crashes, crash_errors = self.pull_crashes(str(crashes_dir))
        errors.extend(crash_errors)

        diagnostics_path: str | None = None
        if run_diagnostics:
            diagnostics_path, diag_error = self.run_diagnostics(
                str(base_dir / "diagnostics.json")
            )
            if diag_error is not None:
                errors.append(diag_error)

        anomalies_path: str | None = None
        if detector is not None:
            events = detector.feed_lines(lines)
            anomalies_path = str(base_dir / "anomalies.json")
            Path(anomalies_path).write_text(
                json.dumps(
                    [e.model_dump() for e in events], ensure_ascii=False, indent=2
                ),
                encoding="utf-8",
            )

        return IosSnapshotResult(
            syslog_path=str(syslog_path),
            syslog_commcenter_path=commcenter_path,
            syslog_springboard_path=springboard_path,
            crashes_dir=str(crashes_dir),
            new_crash_files=new_crashes,
            diagnostics_path=diagnostics_path,
            anomalies_path=anomalies_path,
            errors=tuple(errors),
        )


class IosSyslogCollector:
    def __init__(
        self,
        config: IosCollectorConfig | None = None,
        *,
        max_reconnect_attempts: int = 5,
        reconnect_delay: float = 5.0,
        max_lines: int = 200_000,
    ) -> None:
        self._config = config or IosCollectorConfig()
        self._proc: subprocess.Popen[str] | None = None
        self._thread: threading.Thread | None = None
        self._running = threading.Event()
        self._lines: deque[IosSyslogLine] = deque(maxlen=max_lines)
        self._lock = threading.Lock()
        self._max_reconnect_attempts = max_reconnect_attempts
        self._reconnect_delay = reconnect_delay
        self._dead = False
        self._reconnect_count = 0

    def _cmd(self) -> list[str]:
        base = ["idevicesyslog"]
        if self._config.udid:
            base.extend(["-u", self._config.udid])
        for process in self._config.filter_processes:
            base.extend(["-p", process])
        return base

    def _accepts_process(self, process: str) -> bool:
        if not self._config.filter_processes:
            return True
        return process in self._config.filter_processes

    def start(self) -> None:
        self.stop()
        try:
            proc = subprocess.Popen(
                self._cmd(),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except Exception:
            # Popen failed (e.g. idevicesyslog missing) — leave _running
            # cleared and flag the collector dead so is_healthy reports False.
            with self._lock:
                self._dead = True
            raise
        self._running.set()
        self._proc = proc
        thread = threading.Thread(target=self._reader_loop, args=(proc,), daemon=True)
        self._thread = thread
        thread.start()

    def stop(self) -> None:
        self._running.clear()
        proc = self._proc
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._proc = None
        self._thread = None
        with self._lock:
            self._dead = False

    def _reader_loop(self, proc: object) -> None:
        current = cast(_PopenLike, proc)
        consecutive_failures = 0

        while self._running.is_set():
            got_data = False
            if current.stdout is not None:
                try:
                    for raw in current.stdout:
                        if not self._running.is_set():
                            return
                        line = raw.rstrip("\n")
                        parsed = _parse_syslog_line(line, time.time())
                        got_data = True
                        if not self._accepts_process(parsed.process):
                            continue
                        with self._lock:
                            self._lines.append(parsed)
                except Exception:
                    pass

            if not self._running.is_set():
                return

            if got_data:
                consecutive_failures = 0

            consecutive_failures += 1
            if consecutive_failures > self._max_reconnect_attempts:
                with self._lock:
                    self._dead = True
                return

            try:
                current.wait(timeout=1)
            except Exception:
                try:
                    current.kill()
                except Exception:
                    pass

            for _ in range(int(self._reconnect_delay * 10)):
                if not self._running.is_set():
                    return
                time.sleep(0.1)

            if not self._running.is_set():
                return

            try:
                new_proc = subprocess.Popen(
                    self._cmd(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
                with self._lock:
                    if not self._running.is_set():
                        try:
                            new_proc.kill()
                        except Exception:
                            pass
                        return
                    self._proc = new_proc
                    self._reconnect_count += 1
                current = new_proc
            except Exception:
                pass

    def slice(self, since_ts: float, until_ts: float) -> list[IosSyslogLine]:
        with self._lock:
            return [
                x
                for x in self._lines
                if since_ts <= x.host_ts <= until_ts
            ]

    def push_for_test(self, line: IosSyslogLine) -> None:
        """Test-only hook to inject lines without subprocess."""
        with self._lock:
            self._lines.append(line)

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    @property
    def is_healthy(self) -> bool:
        with self._lock:
            return self._running.is_set() and not self._dead

    @property
    def reconnect_count(self) -> int:
        with self._lock:
            return self._reconnect_count


class IosAnomalyDetector:
    def __init__(
        self,
        patterns: tuple[AnomalyPattern, ...] | None = None,
        max_events: int = 10_000,
    ) -> None:
        self._patterns = patterns or IOS_ANOMALY_PATTERNS
        self._events: deque[IosAnomalyEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()
        self._total_lines_scanned = 0

    def feed_line(self, entry: IosSyslogLine) -> IosAnomalyEvent | None:
        self._total_lines_scanned += 1
        for pattern in self._patterns:
            if pattern.compiled.search(entry.line):
                event = IosAnomalyEvent(
                    timestamp=entry.host_ts,
                    severity=pattern.severity,
                    category=pattern.category,
                    pattern_name=pattern.name,
                    matched_pattern=pattern.regex,
                    matched_line=entry.line[:500],
                    process=entry.process,
                )
                with self._lock:
                    self._events.append(event)
                return event
        return None

    def feed_lines(self, lines: list[IosSyslogLine]) -> list[IosAnomalyEvent]:
        results: list[IosAnomalyEvent] = []
        for entry in lines:
            event = self.feed_line(entry)
            if event is not None:
                results.append(event)
        return results

    def drain_events(self) -> list[IosAnomalyEvent]:
        with self._lock:
            events = list(self._events)
            self._events.clear()
            return events

    def peek_events(self) -> list[IosAnomalyEvent]:
        with self._lock:
            return list(self._events)

    @property
    def total_lines_scanned(self) -> int:
        return self._total_lines_scanned
