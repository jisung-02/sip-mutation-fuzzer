import os
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from collections.abc import Iterable
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
from typing import Literal, Protocol, cast

from volte_mutation_fuzzer.adb.contracts import (
    AdbAnomalyEvent,
    AdbCollectorConfig,
    AdbDeviceInfo,
    AdbSnapshotResult,
)
from volte_mutation_fuzzer.adb.patterns import ANOMALY_PATTERNS, AnomalyPattern


# Logcat 'time' format:        "MM-DD HH:MM:SS.NNN <Severity>/<Tag>( PID): <message>"
# Logcat 'threadtime' format:  "MM-DD HH:MM:SS.NNN  PID  TID <Severity> <Tag>: <message>"
# Both are common; campaigns may use either depending on collector config or
# offline log dumps. Tag extraction works for both — Samsung's real crash
# dumps from A31 came in threadtime, so missing this format meant the tag
# whitelist/blacklist gate was bypassed entirely.
_LOGCAT_LINE_RE_TIME = re.compile(
    r"^\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\s+"
    r"[VDIWEF]/(?P<tag>[^(]+?)\s*\(\s*\d+\)\s*:"
)
_LOGCAT_LINE_RE_THREADTIME = re.compile(
    r"^\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\s+"
    r"\d+\s+\d+\s+[VDIWEF]\s+(?P<tag>\S(?:[^:]*\S)?)\s*:"
)


def _load_env_tags(name: str) -> tuple[str, ...]:
    raw = os.environ.get(name, "")
    return tuple(p.strip() for p in raw.split(",") if p.strip())


# IMS / Telephony / RIL related logcat tags.  Pattern matches in
# `ims_anomaly` / `call_anomaly` categories require the source line's tag
# to start with one of these prefixes — an unrelated process emitting a
# regex-shaped log line will not promote a fuzz case verdict.
WHITELIST_TAG_PREFIXES: tuple[str, ...] = (
    "[IMS",            # Samsung native IMS log brand: [IMS6.0], [IMS5.0]
    "SIPMSG",          # SIPMSG[0,2], SIPMSG[1,3]
    "RILJ",
    "SecRIL",
    "SemImsService",
    "ImsService",
    "ImsManager",
    "ImsRegistration",
    "com.sec.imsservice",
    "com.sec.epdg",
    "com.android.phone",
    "TelephonyProvider",
    "AndroidRuntime",  # crash headers (FATAL EXCEPTION) come from here
)


# Hard-blocked logcat tags — any anomaly pattern that fires from these
# tags is treated as noise and never promotes a verdict.  These are
# Android background services that periodically log expected exceptions
# unrelated to IMS / VoLTE fuzzing.
BLACKLIST_TAGS_EXACT: frozenset[str] = frozenset({
    "BluetoothPowerStatsCollector",
    "WifiNl80211Manager",
    "NetworkStatsManager",
    "PowerStatsService",
    "KeyguardViewMediator",
})


# env override (append-only) — set via VMF_ADB_WHITELIST_TAGS / VMF_ADB_BLACKLIST_TAGS
WHITELIST_TAG_PREFIXES = WHITELIST_TAG_PREFIXES + _load_env_tags("VMF_ADB_WHITELIST_TAGS")
BLACKLIST_TAGS_EXACT = BLACKLIST_TAGS_EXACT | frozenset(_load_env_tags("VMF_ADB_BLACKLIST_TAGS"))


def _extract_logcat_tag(line: str) -> str | None:
    """Parse a logcat 'time' or 'threadtime' format line and return the tag."""
    match = _LOGCAT_LINE_RE_TIME.match(line) or _LOGCAT_LINE_RE_THREADTIME.match(line)
    if match is None:
        return None
    return match.group("tag").strip() or None


def _should_suppress_match(tag: str | None, category: str) -> bool:
    """Return True if a match from this tag/category should be ignored.

    Rules:
        - Exact-match blacklist: always suppress (BluetoothPowerStatsCollector etc.)
        - Whitelist prefix: only required for ims_anomaly / call_anomaly.
        - fatal_signal / system_anomaly: accepted regardless of source.
        - Tag unknown (line not in 'time' format): accept conservatively.
    """
    if tag is None:
        return False
    if tag in BLACKLIST_TAGS_EXACT:
        return True
    if category in ("ims_anomaly", "call_anomaly"):
        return not any(tag.startswith(prefix) for prefix in WHITELIST_TAG_PREFIXES)
    return False


def _is_sipmsg_outbound_echo(line: str, tag: str | None) -> bool:
    """Detect Samsung SIPMSG outbound-echo lines.

    A16's IMS stack logs every SIP message it sends or receives in lines
    like ``I/SIPMSG[0,2]( 2815): [-->] SIP/2.0 500 ...``.  The ``[-->]``
    arrow marks the message as outbound — it's a copy of the rejection
    the device just sent in response to our fuzz, not a sign the device
    is in trouble.  These lines can match many ims_anomaly patterns
    (sip_server_error, sip_timeout, etc.), so we filter them at line
    level before pattern matching.
    """
    if tag is None or not tag.startswith("SIPMSG"):
        return False
    return "[-->]" in line


class _PopenLike(Protocol):
    stdout: Iterable[str] | None

    def wait(self, timeout: int | float | None = None) -> object: ...

    def kill(self) -> object: ...


@dataclass(frozen=True)
class _AdbHistoryLine:
    timestamp: float
    buffer_name: str
    line: str


SnapshotProfile = Literal["light", "full"]


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

    def _write_logcat_outputs(
        self,
        base_dir: Path,
        *,
        collector: "AdbLogCollector | None",
        log_since: float | None,
        log_until: float | None,
        errors: list[str],
    ) -> str | None:
        logcat_path: str | None = None
        logcat_buffers = ("main", "system", "radio", "crash")

        if collector is not None and log_since is not None and log_until is not None:
            log_lines = collector.slice(log_since, log_until)
            combined_lines = [
                line
                for buffer_name, line in log_lines
                if buffer_name in logcat_buffers
            ]
            for buf in logcat_buffers:
                matched = [
                    line for buffer_name, line in log_lines if buffer_name == buf
                ]
                if not matched:
                    continue
                buf_file = base_dir / f"logcat_{buf}.txt"
                buf_file.write_text(
                    "\n".join(matched) + "\n",
                    encoding="utf-8",
                )
            if combined_lines:
                logcat_file = base_dir / "logcat_all.txt"
                logcat_file.write_text(
                    "\n".join(combined_lines) + "\n",
                    encoding="utf-8",
                )
                logcat_path = str(logcat_file)
            return logcat_path

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

        return logcat_path

    def take_snapshot(
        self,
        output_dir: str,
        *,
        bugreport: bool = False,
        collector: "AdbLogCollector | None" = None,
        log_since: float | None = None,
        log_until: float | None = None,
        profile: SnapshotProfile = "full",
    ) -> AdbSnapshotResult:
        """Capture an ADB snapshot to output_dir using a light or full profile."""
        if profile not in ("light", "full"):
            raise ValueError(f"unsupported snapshot profile: {profile}")
        if bugreport and profile != "full":
            raise ValueError("bugreport requires profile='full'")

        base_dir = Path(output_dir)
        base_dir.mkdir(parents=True, exist_ok=True)
        errors: list[str] = []
        bugreport_path: str | None = None

        def _write_shell_output(
            filename: str, *args: str, timeout: int
        ) -> tuple[str | None, str | None]:
            path = base_dir / filename
            try:
                result = self.run_shell(*args, timeout=timeout)
            except Exception as exc:
                return None, f"{' '.join(args)} failed: {exc}"

            if result.returncode != 0:
                message = (
                    result.stderr.strip() or result.stdout.strip() or "unknown error"
                )
                return None, f"{' '.join(args)} failed: {message}"

            path.write_text(result.stdout, encoding="utf-8")
            return str(path), None

        # --- IMS/telephony specific ---
        telephony_path: str | None = None
        ims_path: str | None = None
        netstat_path: str | None = None
        meminfo_path: str | None = None
        dmesg_path: str | None = None
        logcat_path: str | None = None

        if profile == "light":
            telephony_path, error = _write_shell_output(
                "telephony.txt", "dumpsys", "telephony.registry", timeout=30
            )
            if error is not None:
                errors.append(error)
        else:
            full_profile_shells = (
                (
                    "telephony_path",
                    "telephony.txt",
                    ("dumpsys", "telephony.registry"),
                    30,
                ),
                ("ims_path", "ims.txt", ("dumpsys", "ims"), 30),
                ("netstat_path", "netstat.txt", ("netstat", "-tlnup"), 10),
                ("meminfo_path", "meminfo.txt", ("dumpsys", "meminfo"), 60),
                ("dmesg_path", "dmesg.txt", ("dmesg",), 60),
            )
            with ThreadPoolExecutor(
                max_workers=len(full_profile_shells),
                thread_name_prefix="vmf-adb-snapshot",
            ) as executor:
                futures = {
                    name: executor.submit(
                        _write_shell_output, filename, *args, timeout=timeout
                    )
                    for name, filename, args, timeout in full_profile_shells
                }
                logcat_path = self._write_logcat_outputs(
                    base_dir,
                    collector=collector,
                    log_since=log_since,
                    log_until=log_until,
                    errors=errors,
                )
                for name, _, _, _ in full_profile_shells:
                    path, error = futures[name].result()
                    if name == "telephony_path":
                        telephony_path = path
                    elif name == "ims_path":
                        ims_path = path
                    elif name == "netstat_path":
                        netstat_path = path
                    elif name == "meminfo_path":
                        meminfo_path = path
                    elif name == "dmesg_path":
                        dmesg_path = path
                    if error is not None:
                        errors.append(error)
        if profile == "light":
            logcat_path = self._write_logcat_outputs(
                base_dir,
                collector=collector,
                log_since=log_since,
                log_until=log_until,
                errors=errors,
            )

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
        self._history: deque[_AdbHistoryLine] = deque(maxlen=200_000)
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

    def slice(self, since_ts: float, until_ts: float) -> list[tuple[str, str]]:
        with self._lock:
            return [
                (entry.buffer_name, entry.line)
                for entry in self._history
                if since_ts < entry.timestamp <= until_ts
            ]

    def push_for_test(
        self,
        buffer_name: str,
        line: str,
        *,
        timestamp: float | None = None,
    ) -> None:
        entry = _AdbHistoryLine(
            timestamp=time.time() if timestamp is None else timestamp,
            buffer_name=buffer_name,
            line=line,
        )
        with self._lock:
            self._history.append(entry)
        self._queue.put((buffer_name, line))

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

    def _reader_loop(self, buffer_name: str, proc: object) -> None:
        current_proc = cast(_PopenLike, proc)
        consecutive_failures = 0

        while self._running.is_set():
            # Read from current subprocess
            got_data = False
            if current_proc.stdout is not None:
                try:
                    for line in current_proc.stdout:
                        if not self._running.is_set():
                            return
                        text = line.rstrip("\n")
                        with self._lock:
                            self._history.append(
                                _AdbHistoryLine(
                                    timestamp=time.time(),
                                    buffer_name=buffer_name,
                                    line=text,
                                )
                            )
                        self._queue.put((buffer_name, text))
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
        # Cheap line-level suppression for SIPMSG outbound echo — these
        # lines can spuriously match several ims_anomaly patterns
        # (sip_server_error, sip_timeout, ims_reg_failure, ...).  Pre-check
        # avoids 36 regex evaluations per echoed line.
        tag = _extract_logcat_tag(line)
        if _is_sipmsg_outbound_echo(line, tag):
            return None
        for pattern in self._patterns:
            if pattern.compiled.search(line):
                if _should_suppress_match(tag, pattern.category):
                    return None
                event = AdbAnomalyEvent(
                    timestamp=time.time(),
                    severity=pattern.severity,
                    category=pattern.category,
                    pattern_name=pattern.name,
                    matched_pattern=pattern.regex,
                    matched_line=line[:500],
                    buffer=buffer_name,
                    source_tag=tag,
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
