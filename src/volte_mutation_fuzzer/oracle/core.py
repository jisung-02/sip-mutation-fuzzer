import re
import subprocess
import time
from pathlib import Path
from typing import Any, Protocol

from volte_mutation_fuzzer.oracle.contracts import (
    LogCheckResult,
    OracleContext,
    OracleVerdict,
    ProcessCheckResult,
)
from volte_mutation_fuzzer.sender.contracts import SendReceiveResult


class SupportsAdbCollector(Protocol):
    @property
    def is_healthy(self) -> bool: ...

    @property
    def is_running(self) -> bool: ...

    @property
    def dead_buffers(self) -> frozenset[str]: ...

    def get_lines(self) -> Any: ...


class SupportsIosCollector(Protocol):
    @property
    def is_healthy(self) -> bool: ...

    def slice(self, since_ts: float, until_ts: float) -> Any: ...


class SupportsEventDetector(Protocol):
    def feed_lines(self, lines: Any) -> Any: ...

    def drain_events(self) -> list[Any]: ...


class SupportsOracleCheck(Protocol):
    def check(self) -> LogCheckResult: ...


def _top_warning_details(events: list[Any], log_path: str) -> dict[str, object]:
    if not events:
        return {}
    top = events[0]
    return {
        "top_warning": {
            "pattern_name": getattr(top, "pattern_name", None),
            "matched_pattern": top.matched_pattern,
            "matched_line": top.matched_line,
            "log_path": log_path,
            "severity": top.severity,
            "warning_count": len(events),
            # source_tag flows through so post-hoc analysis can tell which
            # logcat tag fired the warning (RILJ vs SIPMSG vs unknown).
            "source_tag": getattr(top, "source_tag", None),
        }
    }


def _merge_warning_detail(
    bucket: dict[str, object],
    result: LogCheckResult,
    target_key: str,
) -> None:
    top_warning = result.details.get("top_warning")
    if isinstance(top_warning, dict) and target_key not in bucket:
        bucket[target_key] = top_warning


class SocketOracle:
    """Judges a SendReceiveResult against expected behavior for a SIP method."""

    def judge(
        self,
        send_result: SendReceiveResult,
        context: OracleContext,
    ) -> OracleVerdict:
        elapsed = send_result.duration_ms
        outcome = send_result.outcome
        final = send_result.final_response

        if outcome == "send_error":
            return OracleVerdict(
                verdict="unknown",
                reason=f"send error: {send_result.error or 'unknown infrastructure failure'}",
                elapsed_ms=elapsed,
            )

        if outcome == "timeout":
            return OracleVerdict(
                verdict="timeout",
                reason="no response received within timeout",
                elapsed_ms=elapsed,
            )

        if outcome == "invalid_response":
            return OracleVerdict(
                verdict="suspicious",
                reason="response could not be parsed as valid SIP",
                elapsed_ms=elapsed,
                details={"raw": final.raw_text if final else ""},
            )

        response_code = final.status_code if final else None
        classification = final.classification if final else None

        return OracleVerdict(
            verdict="normal",
            reason=f"outcome={outcome}, code={response_code}, classification={classification}",
            response_code=response_code,
            elapsed_ms=elapsed,
        )


class ProcessOracle:
    """Checks if a named process is alive via pgrep."""

    def __init__(self, docker_mode: bool = False) -> None:
        self._docker_mode = docker_mode

    def check(self, process_name: str) -> ProcessCheckResult:
        if self._docker_mode:
            return self._check_docker(process_name)
        return self._check_local(process_name)

    def _check_local(self, process_name: str) -> ProcessCheckResult:
        check_time = time.time()
        try:
            result = subprocess.run(
                ["pgrep", "-x", process_name],
                capture_output=True,
                timeout=5,
            )
            if result.returncode == 0:
                raw = result.stdout.decode().strip()
                pid = int(raw.splitlines()[0]) if raw else None
                return ProcessCheckResult(
                    process_name=process_name,
                    alive=True,
                    pid=pid,
                    check_time=check_time,
                )
            return ProcessCheckResult(
                process_name=process_name,
                alive=False,
                check_time=check_time,
            )
        except Exception as exc:
            return ProcessCheckResult(
                process_name=process_name,
                alive=False,
                check_time=check_time,
                error=str(exc),
            )

    def _check_docker(self, container_name: str) -> ProcessCheckResult:
        check_time = time.time()
        try:
            result = subprocess.run(
                [
                    "docker",
                    "inspect",
                    "--format={{.State.Status}}\n{{.State.Pid}}",
                    container_name,
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                error = (
                    result.stderr.strip()
                    or result.stdout.strip()
                    or f"docker inspect exited with status {result.returncode}"
                )
                return ProcessCheckResult(
                    process_name=container_name,
                    alive=False,
                    check_time=check_time,
                    error=error,
                )

            lines = result.stdout.splitlines()
            status = lines[0].strip() if lines else ""
            pid = int(lines[1].strip()) if len(lines) > 1 else 0
            return ProcessCheckResult(
                process_name=container_name,
                alive=status == "running",
                pid=pid,
                check_time=check_time,
            )
        except Exception as exc:
            return ProcessCheckResult(
                process_name=container_name,
                alive=False,
                check_time=check_time,
                error=str(exc),
            )


class LogOracle:
    """Scans a log file for stack trace / fatal error patterns."""

    DEFAULT_PATTERNS: tuple[str, ...] = (
        r"SIGSEGV",
        r"SIGABRT",
        r"Segmentation fault",
        r"Assertion failed",
        r"core dumped",
        r"backtrace",
        r"Traceback \(most recent call last\)",
        r"Exception in thread",
        r"\bFATAL\b",
        r"\bpanic:",
    )

    def __init__(
        self,
        patterns: tuple[str, ...] | None = None,
        docker_mode: bool = False,
    ) -> None:
        raw = patterns or self.DEFAULT_PATTERNS
        self._docker_mode = docker_mode
        self._compiled = re.compile("|".join(f"({p})" for p in raw), re.IGNORECASE)
        # Cache: container_name → host log file path (resolved once via docker inspect)
        self._docker_log_paths: dict[str, str | None] = {}

    def check(
        self, log_path: str, after_position: int = 0
    ) -> tuple[LogCheckResult, int]:
        """Scan log_path starting from after_position bytes.

        Returns (result, new_position) so the caller can track incremental reads.
        """
        if self._docker_mode:
            return self._check_docker(log_path, after_position)
        return self._check_file(log_path, after_position)

    def _check_file(
        self, log_path: str, after_position: int = 0
    ) -> tuple[LogCheckResult, int]:
        path = Path(log_path)
        if not path.is_file():
            return LogCheckResult(
                log_path=log_path,
                matched=False,
                error=f"log file not found: {log_path}",
            ), after_position

        try:
            size = path.stat().st_size
            if size <= after_position:
                return LogCheckResult(
                    log_path=log_path,
                    matched=False,
                    lines_scanned=0,
                ), after_position

            with path.open("r", errors="replace") as f:
                f.seek(after_position)
                new_content = f.read()
                new_position = f.tell()

            lines = new_content.splitlines()
            for line in lines:
                m = self._compiled.search(line)
                if m:
                    return LogCheckResult(
                        log_path=log_path,
                        matched=True,
                        matched_pattern=m.group(0),
                        matched_line=line[:500],
                        lines_scanned=len(lines),
                    ), new_position

            return LogCheckResult(
                log_path=log_path,
                matched=False,
                lines_scanned=len(lines),
            ), new_position

        except Exception as exc:
            return LogCheckResult(
                log_path=log_path,
                matched=False,
                error=str(exc),
            ), after_position

    def _resolve_docker_log_path(self, container_name: str) -> str | None:
        """Resolve the host-side log file path for a Docker container (cached)."""
        if container_name in self._docker_log_paths:
            return self._docker_log_paths[container_name]
        try:
            result = subprocess.run(
                [
                    "docker",
                    "inspect",
                    "--format={{.LogPath}}",
                    container_name,
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                log_path = result.stdout.strip()
                if Path(log_path).is_file():
                    self._docker_log_paths[container_name] = log_path
                    return log_path
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            pass
        self._docker_log_paths[container_name] = None
        return None

    def _check_docker(
        self, container_name: str, after_position: int = 0
    ) -> tuple[LogCheckResult, int]:
        # Try direct file read first (avoids docker logs subprocess per call)
        host_log_path = self._resolve_docker_log_path(container_name)
        if host_log_path is not None:
            return self._check_docker_logfile(
                container_name, host_log_path, after_position
            )

        # Fallback: docker logs (e.g. if docker inspect failed)
        return self._check_docker_logs_fallback(container_name, after_position)

    def _check_docker_logfile(
        self,
        container_name: str,
        host_log_path: str,
        after_position: int = 0,
    ) -> tuple[LogCheckResult, int]:
        """Read the Docker JSON log file directly, skipping docker daemon overhead."""
        import json as _json

        path = Path(host_log_path)
        if not path.is_file():
            # Log file disappeared — invalidate cache and fall back with timestamp reset
            self._docker_log_paths.pop(container_name, None)
            return self._check_docker_logs_fallback(container_name, int(time.time()))

        try:
            size = path.stat().st_size

            # First call in docker_mode passes a Unix timestamp as after_position.
            # If after_position >= file size, start from current EOF so we
            # only scan newly appended content on subsequent calls.
            if size <= after_position:
                return LogCheckResult(
                    log_path=container_name,
                    matched=False,
                    lines_scanned=0,
                ), size

            with path.open("r", errors="replace") as f:
                f.seek(after_position)
                new_content = f.read()
                new_position = f.tell()

            # Docker JSON log format: {"log":"...\n","stream":"...","time":"..."}
            lines_scanned = 0
            for raw_line in new_content.splitlines():
                if not raw_line.strip():
                    continue
                lines_scanned += 1
                try:
                    entry = _json.loads(raw_line)
                    log_text = entry.get("log", "")
                except (ValueError, TypeError):
                    log_text = raw_line
                m = self._compiled.search(log_text)
                if m:
                    return LogCheckResult(
                        log_path=container_name,
                        matched=True,
                        matched_pattern=m.group(0),
                        matched_line=log_text[:500],
                        lines_scanned=lines_scanned,
                    ), new_position

            return LogCheckResult(
                log_path=container_name,
                matched=False,
                lines_scanned=lines_scanned,
            ), new_position

        except PermissionError:
            # No permission to read Docker log file — fall back with timestamp reset
            self._docker_log_paths.pop(container_name, None)
            return self._check_docker_logs_fallback(container_name, int(time.time()))
        except Exception as exc:
            return (
                LogCheckResult(
                    log_path=container_name,
                    matched=False,
                    error=str(exc),
                ),
                after_position,
            )

    def _check_docker_logs_fallback(
        self, container_name: str, after_position: int = 0
    ) -> tuple[LogCheckResult, int]:
        """Original docker logs subprocess fallback."""
        new_position = int(time.time())
        try:
            result = subprocess.run(
                ["docker", "logs", "--since", str(after_position), container_name],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                error = (
                    result.stderr.strip()
                    or result.stdout.strip()
                    or f"docker logs exited with status {result.returncode}"
                )
                return (
                    LogCheckResult(
                        log_path=container_name,
                        matched=False,
                        error=error,
                    ),
                    after_position,
                )

            output = result.stdout
            if result.stderr:
                output = f"{output}\n{result.stderr}" if output else result.stderr

            lines = output.splitlines()
            for line in lines:
                m = self._compiled.search(line)
                if m:
                    return LogCheckResult(
                        log_path=container_name,
                        matched=True,
                        matched_pattern=m.group(0),
                        matched_line=line[:500],
                        lines_scanned=len(lines),
                    ), new_position

            return LogCheckResult(
                log_path=container_name,
                matched=False,
                lines_scanned=len(lines),
            ), new_position
        except Exception as exc:
            return (
                LogCheckResult(
                    log_path=container_name,
                    matched=False,
                    error=str(exc),
                ),
                after_position,
            )


class AdbOracle:
    """Oracle that checks ADB logcat anomaly events for crash/failure indicators."""

    def __init__(
        self,
        collector: SupportsAdbCollector,
        detector: SupportsEventDetector,
    ) -> None:
        self._collector = collector
        self._detector = detector

    def check(self) -> LogCheckResult:
        # Check collector health and report degradation
        error: str | None = None
        if hasattr(self._collector, "is_healthy") and not self._collector.is_healthy:
            dead = getattr(self._collector, "dead_buffers", frozenset())
            if dead:
                error = f"adb collector disconnected: buffers {','.join(sorted(dead))} dead"
            elif hasattr(self._collector, "is_running") and not self._collector.is_running:
                error = "adb collector stopped"

        lines = self._collector.get_lines()
        self._detector.feed_lines(lines)
        events = self._detector.drain_events()
        critical = [e for e in events if e.severity == "critical"]
        warnings = [e for e in events if e.severity == "warning"]
        details = _top_warning_details(warnings, "adb:logcat")
        if critical:
            top = critical[0]
            return LogCheckResult(
                log_path="adb:logcat",
                matched=True,
                matched_pattern=top.matched_pattern,
                matched_line=top.matched_line,
                matched_tag=getattr(top, "source_tag", None),
                lines_scanned=len(lines),
                error=error,
                details=details,
            )
        return LogCheckResult(
            log_path="adb:logcat",
            matched=False,
            lines_scanned=len(lines),
            error=error,
            details=details,
        )


class IosOracle:
    """Oracle that checks iOS syslog anomaly events for crash/failure indicators."""

    def __init__(
        self,
        collector: SupportsIosCollector,
        detector: SupportsEventDetector,
    ) -> None:
        self._collector = collector
        self._detector = detector
        self._last_check_ts: float = time.time()

    def check(self) -> LogCheckResult:
        error: str | None = None
        if hasattr(self._collector, "is_healthy") and not self._collector.is_healthy:
            error = "ios syslog collector disconnected"

        now = time.time()
        lines = self._collector.slice(self._last_check_ts, now)
        self._last_check_ts = now
        self._detector.feed_lines(lines)
        events = self._detector.drain_events()
        critical = [e for e in events if e.severity == "critical"]
        warnings = [e for e in events if e.severity == "warning"]
        details = _top_warning_details(warnings, "ios:syslog")
        if critical:
            top = critical[0]
            return LogCheckResult(
                log_path="ios:syslog",
                matched=True,
                matched_pattern=top.matched_pattern,
                matched_line=top.matched_line,
                lines_scanned=len(lines),
                error=error,
                details=details,
            )
        return LogCheckResult(
            log_path="ios:syslog",
            matched=False,
            lines_scanned=len(lines),
            error=error,
            details=details,
        )


class OracleEngine:
    """Combines SocketOracle + ProcessOracle into a single verdict."""

    def __init__(
        self,
        socket_oracle: SocketOracle | None = None,
        process_oracle: ProcessOracle | None = None,
        log_oracle: LogOracle | None = None,
        adb_oracle: SupportsOracleCheck | None = None,
        ios_oracle: SupportsOracleCheck | None = None,
        docker_mode: bool = False,
    ) -> None:
        self._socket_oracle = socket_oracle or SocketOracle()
        self._process_oracle = process_oracle or ProcessOracle(docker_mode=docker_mode)
        self._log_oracle = log_oracle
        self._adb_oracle = adb_oracle
        self._ios_oracle = ios_oracle
        self._log_position: int = int(time.time()) if docker_mode else 0
        self._evaluate_call_count: int = 0

    def evaluate(
        self,
        send_result: SendReceiveResult,
        context: OracleContext,
        *,
        process_name: str | None = None,
        log_path: str | None = None,
        process_check_interval: int = 0,
    ) -> OracleVerdict:
        verdict = self._socket_oracle.judge(send_result, context)
        log_warning_details: dict[str, object] = {}

        if log_path is not None and self._log_oracle is not None:
            log_result, self._log_position = self._log_oracle.check(
                log_path, self._log_position
            )
            if log_result.matched:
                return OracleVerdict(
                    verdict="stack_failure",
                    confidence=0.85,
                    reason=f"stack trace pattern detected in log: {log_result.matched_pattern}",
                    response_code=verdict.response_code,
                    elapsed_ms=verdict.elapsed_ms,
                    details={
                        "socket_verdict": verdict.verdict,
                        "matched_pattern": log_result.matched_pattern,
                        "matched_line": log_result.matched_line,
                        "log_path": log_path,
                    },
                )

        # Poll ADB/iOS log collectors for up to ``log_grace_seconds`` so
        # asynchronous crashes that surface a few seconds after the SIP
        # response (e.g. Samsung ``com.sec.imsservice`` throwing on CSeq
        # parse ~7 s after the 200 OK) still upgrade the verdict to
        # ``stack_failure``.  With grace=0 this collapses to the original
        # single check behavior.
        grace_end = time.monotonic() + max(context.log_grace_seconds, 0.0)
        poll_every = context.log_grace_poll_seconds
        while True:
            if self._adb_oracle is not None:
                adb_result = self._adb_oracle.check()
                _merge_warning_detail(log_warning_details, adb_result, "adb_warning")
                if adb_result.matched:
                    return OracleVerdict(
                        verdict="stack_failure",
                        confidence=0.80,
                        reason=f"ADB anomaly detected: {adb_result.matched_pattern}",
                        response_code=verdict.response_code,
                        elapsed_ms=verdict.elapsed_ms,
                        details={
                            **log_warning_details,
                            "socket_verdict": verdict.verdict,
                            "matched_pattern": adb_result.matched_pattern,
                            "matched_line": adb_result.matched_line,
                            "matched_tag": adb_result.matched_tag,
                            "log_path": "adb:logcat",
                        },
                    )

            if self._ios_oracle is not None:
                ios_result = self._ios_oracle.check()
                _merge_warning_detail(log_warning_details, ios_result, "ios_warning")
                if ios_result.matched:
                    return OracleVerdict(
                        verdict="stack_failure",
                        confidence=0.80,
                        reason=f"iOS anomaly detected: {ios_result.matched_pattern}",
                        response_code=verdict.response_code,
                        elapsed_ms=verdict.elapsed_ms,
                        details={
                            **log_warning_details,
                            "socket_verdict": verdict.verdict,
                            "matched_pattern": ios_result.matched_pattern,
                            "matched_line": ios_result.matched_line,
                            "log_path": "ios:syslog",
                        },
                    )

            if time.monotonic() >= grace_end:
                break
            time.sleep(min(poll_every, max(grace_end - time.monotonic(), 0.0)))

        if log_warning_details:
            verdict = verdict.model_copy(
                update={"details": {**verdict.details, **log_warning_details}}
            )

        self._evaluate_call_count += 1

        if process_name is None:
            return verdict

        # Optimization: skip process check on most cases to avoid docker
        # inspect subprocess overhead. Always check on timeout (likely crash),
        # and periodically on non-timeout for delayed crash detection.
        if process_check_interval > 0 and verdict.verdict != "timeout":
            if self._evaluate_call_count % process_check_interval != 0:
                return verdict

        proc = self._process_oracle.check(process_name)

        if not proc.alive:
            return OracleVerdict(
                verdict="crash",
                confidence=0.9,
                reason=f"process '{process_name}' not found after send",
                response_code=verdict.response_code,
                elapsed_ms=verdict.elapsed_ms,
                process_alive=False,
                details={
                    "socket_verdict": verdict.verdict,
                    "process_error": proc.error,
                    **verdict.details,
                },
            )

        return verdict.model_copy(update={"process_alive": True})
