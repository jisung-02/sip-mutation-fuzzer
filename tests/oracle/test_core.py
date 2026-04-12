import os
import tempfile
import time
import unittest
from unittest.mock import patch

from volte_mutation_fuzzer.adb.core import AdbAnomalyDetector
from volte_mutation_fuzzer.oracle.contracts import OracleContext
from volte_mutation_fuzzer.oracle.core import (
    AdbOracle,
    LogOracle,
    OracleEngine,
    ProcessOracle,
    SocketOracle,
)
from volte_mutation_fuzzer.sender.contracts import (
    SendReceiveResult,
    SocketObservation,
    TargetEndpoint,
)


def _make_result(
    outcome: str,
    status_code: int | None = None,
    elapsed_ms: float = 50.0,
    error: str | None = None,
) -> SendReceiveResult:
    now = time.time()
    responses: tuple[SocketObservation, ...] = ()
    if status_code is not None:
        if 100 <= status_code <= 199:
            cls = "provisional"
        elif 200 <= status_code <= 299:
            cls = "success"
        elif 300 <= status_code <= 399:
            cls = "redirection"
        elif 400 <= status_code <= 499:
            cls = "client_error"
        elif 500 <= status_code <= 599:
            cls = "server_error"
        else:
            cls = "global_error"
        responses = (
            SocketObservation(
                status_code=status_code,
                reason_phrase="Test",
                raw_size=50,
                classification=cls,
            ),
        )

    elapsed_s = elapsed_ms / 1000.0
    return SendReceiveResult(
        target=TargetEndpoint(host="127.0.0.1", port=5060),
        artifact_kind="packet",
        bytes_sent=100,
        outcome=outcome,
        responses=responses,
        send_started_at=now - elapsed_s,
        send_completed_at=now,
        error=error,
    )


class SocketOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.oracle = SocketOracle()
        self.ctx = OracleContext(method="OPTIONS")

    def test_send_error_returns_unknown(self) -> None:
        result = _make_result("send_error", error="connection refused")
        verdict = self.oracle.judge(result, self.ctx)
        self.assertEqual(verdict.verdict, "unknown")
        self.assertIn("send error", verdict.reason)

    def test_timeout_returns_timeout(self) -> None:
        result = _make_result("timeout")
        verdict = self.oracle.judge(result, self.ctx)
        self.assertEqual(verdict.verdict, "timeout")

    def test_invalid_response_returns_suspicious(self) -> None:
        result = _make_result("invalid_response")
        verdict = self.oracle.judge(result, self.ctx)
        self.assertEqual(verdict.verdict, "suspicious")

    def test_200_ok_returns_normal(self) -> None:
        result = _make_result("success", status_code=200)
        verdict = self.oracle.judge(result, self.ctx)
        self.assertEqual(verdict.verdict, "normal")
        self.assertEqual(verdict.response_code, 200)

    def test_500_returns_normal(self) -> None:
        result = _make_result("error", status_code=500)
        verdict = self.oracle.judge(result, self.ctx)
        self.assertEqual(verdict.verdict, "normal")
        self.assertEqual(verdict.response_code, 500)

    def test_600_returns_normal(self) -> None:
        result = _make_result("error", status_code=600)
        verdict = self.oracle.judge(result, self.ctx)
        self.assertEqual(verdict.verdict, "normal")

    def test_4xx_returns_normal(self) -> None:
        result = _make_result("error", status_code=404)
        verdict = self.oracle.judge(result, self.ctx)
        self.assertEqual(verdict.verdict, "normal")

    def test_elapsed_ms_propagated(self) -> None:
        result = _make_result("timeout", elapsed_ms=5000.0)
        verdict = self.oracle.judge(result, self.ctx)
        self.assertAlmostEqual(verdict.elapsed_ms, 5000.0, delta=50.0)


class ProcessOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.oracle = ProcessOracle()

    def test_alive_when_pgrep_succeeds(self) -> None:
        mock_result = type("R", (), {"returncode": 0, "stdout": b"1234\n"})()
        with patch(
            "volte_mutation_fuzzer.oracle.core.subprocess.run",
            return_value=mock_result,
        ):
            result = self.oracle.check("baresip")
        self.assertTrue(result.alive)
        self.assertEqual(result.pid, 1234)
        self.assertIsNone(result.error)

    def test_dead_when_pgrep_returns_nonzero(self) -> None:
        mock_result = type("R", (), {"returncode": 1, "stdout": b""})()
        with patch(
            "volte_mutation_fuzzer.oracle.core.subprocess.run",
            return_value=mock_result,
        ):
            result = self.oracle.check("baresip")
        self.assertFalse(result.alive)
        self.assertIsNone(result.pid)

    def test_error_on_exception(self) -> None:
        with patch(
            "volte_mutation_fuzzer.oracle.core.subprocess.run",
            side_effect=FileNotFoundError("pgrep not found"),
        ):
            result = self.oracle.check("baresip")
        self.assertFalse(result.alive)
        self.assertIsNotNone(result.error)
        self.assertIn("pgrep not found", result.error)


class ProcessOracleDockerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.oracle = ProcessOracle(docker_mode=True)

    def test_alive_when_docker_running(self) -> None:
        mock_result = type(
            "R", (), {"returncode": 0, "stdout": "running\n1234\n", "stderr": ""}
        )()
        with patch(
            "volte_mutation_fuzzer.oracle.core.subprocess.run",
            return_value=mock_result,
        ):
            result = self.oracle.check("pcscf")
        self.assertTrue(result.alive)
        self.assertEqual(result.pid, 1234)
        self.assertIsNone(result.error)

    def test_dead_when_docker_exited(self) -> None:
        mock_result = type(
            "R", (), {"returncode": 0, "stdout": "exited\n0\n", "stderr": ""}
        )()
        with patch(
            "volte_mutation_fuzzer.oracle.core.subprocess.run",
            return_value=mock_result,
        ):
            result = self.oracle.check("pcscf")
        self.assertFalse(result.alive)

    def test_error_when_docker_not_found(self) -> None:
        mock_result = type(
            "R",
            (),
            {"returncode": 1, "stdout": "", "stderr": "No such object"},
        )()
        with patch(
            "volte_mutation_fuzzer.oracle.core.subprocess.run",
            return_value=mock_result,
        ):
            result = self.oracle.check("pcscf")
        self.assertFalse(result.alive)
        self.assertIn("No such object", result.error or "")

    def test_error_on_exception(self) -> None:
        with patch(
            "volte_mutation_fuzzer.oracle.core.subprocess.run",
            side_effect=FileNotFoundError("docker not found"),
        ):
            result = self.oracle.check("pcscf")
        self.assertFalse(result.alive)
        self.assertIn("docker not found", result.error or "")


class OracleEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = OracleEngine()
        self.ctx = OracleContext(method="OPTIONS")

    def test_normal_socket_no_process_check(self) -> None:
        result = _make_result("success", status_code=200)
        verdict = self.engine.evaluate(result, self.ctx)
        self.assertEqual(verdict.verdict, "normal")
        self.assertIsNone(verdict.process_alive)

    def test_normal_socket_alive_process(self) -> None:
        alive_result = type("R", (), {"returncode": 0, "stdout": b"999\n"})()
        result = _make_result("success", status_code=200)
        with patch(
            "volte_mutation_fuzzer.oracle.core.subprocess.run",
            return_value=alive_result,
        ):
            verdict = self.engine.evaluate(result, self.ctx, process_name="baresip")
        self.assertEqual(verdict.verdict, "normal")
        self.assertTrue(verdict.process_alive)

    def test_normal_socket_dead_process_becomes_crash(self) -> None:
        dead_result = type("R", (), {"returncode": 1, "stdout": b""})()
        result = _make_result("success", status_code=200)
        with patch(
            "volte_mutation_fuzzer.oracle.core.subprocess.run",
            return_value=dead_result,
        ):
            verdict = self.engine.evaluate(result, self.ctx, process_name="baresip")
        self.assertEqual(verdict.verdict, "crash")
        self.assertFalse(verdict.process_alive)

    def test_timeout_with_alive_process_stays_timeout(self) -> None:
        alive_result = type("R", (), {"returncode": 0, "stdout": b"999\n"})()
        result = _make_result("timeout")
        with patch(
            "volte_mutation_fuzzer.oracle.core.subprocess.run",
            return_value=alive_result,
        ):
            verdict = self.engine.evaluate(result, self.ctx, process_name="baresip")
        self.assertEqual(verdict.verdict, "timeout")
        self.assertTrue(verdict.process_alive)

    def test_normal_500_with_alive_process_stays_normal(self) -> None:
        alive_result = type("R", (), {"returncode": 0, "stdout": b"999\n"})()
        result = _make_result("error", status_code=500)
        with patch(
            "volte_mutation_fuzzer.oracle.core.subprocess.run",
            return_value=alive_result,
        ):
            verdict = self.engine.evaluate(result, self.ctx, process_name="baresip")
        self.assertEqual(verdict.verdict, "normal")
        self.assertTrue(verdict.process_alive)


# ---------------------------------------------------------------------------
# LogOracle tests
# ---------------------------------------------------------------------------


class LogOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.oracle = LogOracle()

    def _write_log(self, content: str) -> str:
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
        f.write(content)
        f.close()
        return f.name

    def test_missing_file_returns_no_match_with_error(self) -> None:
        result, pos = self.oracle.check("/nonexistent/path/to.log")
        self.assertFalse(result.matched)
        self.assertIsNotNone(result.error)
        self.assertEqual(pos, 0)

    def test_empty_file_returns_no_match(self) -> None:
        path = self._write_log("")
        try:
            result, _ = self.oracle.check(path)
            self.assertFalse(result.matched)
        finally:
            os.unlink(path)

    def test_sigsegv_detected(self) -> None:
        path = self._write_log("normal line\nReceived signal SIGSEGV at 0x0\n")
        try:
            result, _ = self.oracle.check(path)
            self.assertTrue(result.matched)
            self.assertEqual(result.matched_pattern, "SIGSEGV")
            self.assertIn("SIGSEGV", result.matched_line)
        finally:
            os.unlink(path)

    def test_assertion_failed_detected(self) -> None:
        path = self._write_log("Assertion failed: x > 0, file foo.c, line 42\n")
        try:
            result, _ = self.oracle.check(path)
            self.assertTrue(result.matched)
        finally:
            os.unlink(path)

    def test_python_traceback_detected(self) -> None:
        path = self._write_log("Traceback (most recent call last):\n  File foo.py\n")
        try:
            result, _ = self.oracle.check(path)
            self.assertTrue(result.matched)
        finally:
            os.unlink(path)

    def test_go_panic_detected(self) -> None:
        path = self._write_log("goroutine 1 [running]:\npanic: runtime error\n")
        try:
            result, _ = self.oracle.check(path)
            self.assertTrue(result.matched)
        finally:
            os.unlink(path)

    def test_normal_log_no_match(self) -> None:
        path = self._write_log(
            "INFO: started\nDEBUG: processing request\nINFO: response 200\n"
        )
        try:
            result, _ = self.oracle.check(path)
            self.assertFalse(result.matched)
            self.assertEqual(result.lines_scanned, 3)
        finally:
            os.unlink(path)

    def test_incremental_read_skips_old_content(self) -> None:
        path = self._write_log("SIGSEGV old crash\n")
        try:
            result1, pos1 = self.oracle.check(path)
            self.assertTrue(result1.matched)

            # Second read from pos1 — no new content
            result2, pos2 = self.oracle.check(path, after_position=pos1)
            self.assertFalse(result2.matched)

            # Append new content with a pattern
            with open(path, "a") as f:
                f.write("new SIGABRT here\n")

            result3, _ = self.oracle.check(path, after_position=pos1)
            self.assertTrue(result3.matched)
            self.assertEqual(result3.matched_pattern, "SIGABRT")
        finally:
            os.unlink(path)

    def test_custom_patterns(self) -> None:
        oracle = LogOracle(patterns=("CUSTOM_ERROR",))
        path = self._write_log("SIGSEGV should not match\nCUSTOM_ERROR should match\n")
        try:
            result, _ = oracle.check(path)
            self.assertTrue(result.matched)
            self.assertEqual(result.matched_pattern, "CUSTOM_ERROR")
        finally:
            os.unlink(path)


class LogOracleDockerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.oracle = LogOracle(docker_mode=True)

    def test_sigsegv_in_docker_logs(self) -> None:
        mock_result = type(
            "R",
            (),
            {"returncode": 0, "stdout": "INFO\nSIGSEGV in worker\n", "stderr": ""},
        )()
        with (
            patch(
                "volte_mutation_fuzzer.oracle.core.subprocess.run",
                return_value=mock_result,
            ),
            patch(
                "volte_mutation_fuzzer.oracle.core.time.time", return_value=1700000100
            ),
        ):
            result, position = self.oracle.check("pcscf", after_position=0)
        self.assertTrue(result.matched)
        self.assertEqual(position, 1700000100)

    def test_clean_docker_logs(self) -> None:
        mock_result = type(
            "R",
            (),
            {"returncode": 0, "stdout": "INFO started\nINFO healthy\n", "stderr": ""},
        )()
        with patch(
            "volte_mutation_fuzzer.oracle.core.subprocess.run",
            return_value=mock_result,
        ):
            result, _ = self.oracle.check("pcscf", after_position=10)
        self.assertFalse(result.matched)

    def test_docker_logs_command_failure(self) -> None:
        mock_result = type(
            "R",
            (),
            {"returncode": 1, "stdout": "", "stderr": "No such container"},
        )()
        with patch(
            "volte_mutation_fuzzer.oracle.core.subprocess.run",
            return_value=mock_result,
        ):
            result, _ = self.oracle.check("pcscf", after_position=10)
        self.assertFalse(result.matched)
        self.assertIn("No such container", result.error or "")

    def test_timestamp_position_tracking(self) -> None:
        mock_result = type(
            "R", (), {"returncode": 0, "stdout": "INFO\n", "stderr": ""}
        )()
        with (
            patch(
                "volte_mutation_fuzzer.oracle.core.subprocess.run",
                return_value=mock_result,
            ) as run_mock,
            patch(
                "volte_mutation_fuzzer.oracle.core.time.time", return_value=1700000200
            ),
        ):
            _, position = self.oracle.check("pcscf", after_position=42)
        self.assertEqual(
            run_mock.call_args.args[0],
            ["docker", "logs", "--since", "42", "pcscf"],
        )
        self.assertEqual(position, 1700000200)


# ---------------------------------------------------------------------------
# OracleEngine log integration tests
# ---------------------------------------------------------------------------


class OracleEngineLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.log_oracle = LogOracle()
        self.engine = OracleEngine(log_oracle=self.log_oracle)
        self.ctx = OracleContext(method="OPTIONS")

    def _write_log(self, content: str) -> str:
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
        f.write(content)
        f.close()
        return f.name

    def test_stack_failure_when_log_has_pattern(self) -> None:
        path = self._write_log("SIGSEGV\n")
        try:
            result = _make_result("success", status_code=200)
            verdict = self.engine.evaluate(result, self.ctx, log_path=path)
            self.assertEqual(verdict.verdict, "stack_failure")
            self.assertIn("SIGSEGV", verdict.reason)
        finally:
            os.unlink(path)

    def test_no_log_oracle_ignores_log_path(self) -> None:
        engine = OracleEngine()  # no log_oracle
        result = _make_result("success", status_code=200)
        verdict = engine.evaluate(result, self.ctx, log_path="/some/path.log")
        self.assertEqual(verdict.verdict, "normal")

    def test_clean_log_falls_through_to_normal(self) -> None:
        path = self._write_log("INFO: all good\n")
        try:
            result = _make_result("success", status_code=200)
            verdict = self.engine.evaluate(result, self.ctx, log_path=path)
            self.assertEqual(verdict.verdict, "normal")
        finally:
            os.unlink(path)

    def test_stack_failure_takes_precedence_over_crash(self) -> None:
        path = self._write_log("Segmentation fault (core dumped)\n")
        try:
            dead_result = type("R", (), {"returncode": 1, "stdout": b""})()
            result = _make_result("success", status_code=200)
            with patch(
                "volte_mutation_fuzzer.oracle.core.subprocess.run",
                return_value=dead_result,
            ):
                verdict = self.engine.evaluate(
                    result, self.ctx, process_name="baresip", log_path=path
                )
            self.assertEqual(verdict.verdict, "stack_failure")
        finally:
            os.unlink(path)


class OracleEngineDockerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ctx = OracleContext(method="OPTIONS")

    def test_docker_mode_crashed_container(self) -> None:
        process_oracle = ProcessOracle(docker_mode=True)
        engine = OracleEngine(process_oracle=process_oracle, docker_mode=True)
        mock_result = type(
            "R", (), {"returncode": 0, "stdout": "exited\n0\n", "stderr": ""}
        )()
        result = _make_result("success", status_code=200)
        with patch(
            "volte_mutation_fuzzer.oracle.core.subprocess.run",
            return_value=mock_result,
        ):
            verdict = engine.evaluate(result, self.ctx, process_name="pcscf")
        self.assertEqual(verdict.verdict, "crash")
        self.assertFalse(verdict.process_alive)

    def test_docker_mode_stack_trace_in_container(self) -> None:
        log_oracle = LogOracle(docker_mode=True)
        engine = OracleEngine(log_oracle=log_oracle, docker_mode=True)
        mock_result = type(
            "R", (), {"returncode": 0, "stdout": "SIGSEGV\n", "stderr": ""}
        )()
        result = _make_result("success", status_code=200)
        with (
            patch(
                "volte_mutation_fuzzer.oracle.core.subprocess.run",
                return_value=mock_result,
            ),
            patch(
                "volte_mutation_fuzzer.oracle.core.time.time", return_value=1700000300
            ),
        ):
            verdict = engine.evaluate(result, self.ctx, log_path="pcscf")
        self.assertEqual(verdict.verdict, "stack_failure")

    def test_docker_mode_healthy(self) -> None:
        process_oracle = ProcessOracle(docker_mode=True)
        log_oracle = LogOracle(docker_mode=True)
        engine = OracleEngine(
            process_oracle=process_oracle,
            log_oracle=log_oracle,
            docker_mode=True,
        )
        result = _make_result("success", status_code=200)

        def run_side_effect(*args, **kwargs):
            command = args[0]
            if command[:2] == ["docker", "logs"]:
                return type(
                    "R", (), {"returncode": 0, "stdout": "INFO clean\n", "stderr": ""}
                )()
            return type(
                "R", (), {"returncode": 0, "stdout": "running\n1234\n", "stderr": ""}
            )()

        with (
            patch(
                "volte_mutation_fuzzer.oracle.core.subprocess.run",
                side_effect=run_side_effect,
            ),
            patch(
                "volte_mutation_fuzzer.oracle.core.time.time", return_value=1700000400
            ),
        ):
            verdict = engine.evaluate(
                result,
                self.ctx,
                process_name="pcscf",
                log_path="pcscf",
            )
        self.assertEqual(verdict.verdict, "normal")
        self.assertTrue(verdict.process_alive)


# ---------------------------------------------------------------------------
# AdbOracle and OracleEngine+AdbOracle tests
# ---------------------------------------------------------------------------


class _CollectorStub:
    def __init__(self, lines: list[tuple[str, str]]) -> None:
        self._lines = list(lines)

    def get_lines(self) -> list[tuple[str, str]]:
        lines = list(self._lines)
        self._lines.clear()
        return lines


class _UnhealthyCollectorStub:
    """Simulates an AdbLogCollector with dead buffers."""

    def __init__(
        self, lines: list[tuple[str, str]], *, dead: frozenset[str] = frozenset()
    ) -> None:
        self._lines = list(lines)
        self._dead = dead
        self.is_running = True

    @property
    def is_healthy(self) -> bool:
        return len(self._dead) == 0

    @property
    def dead_buffers(self) -> frozenset[str]:
        return self._dead

    def get_lines(self) -> list[tuple[str, str]]:
        lines = list(self._lines)
        self._lines.clear()
        return lines


class _AdbOracleStub:
    def __init__(self, matched: bool, pattern: str | None = None) -> None:
        self._matched = matched
        self._pattern = pattern

    def check(self):
        from volte_mutation_fuzzer.oracle.contracts import LogCheckResult

        return LogCheckResult(
            log_path="adb:logcat",
            matched=self._matched,
            matched_pattern=self._pattern,
            matched_line="matched line" if self._matched else None,
            lines_scanned=1 if self._matched else 0,
        )


class AdbOracleTests(unittest.TestCase):
    def test_no_events_returns_no_match(self) -> None:
        oracle = AdbOracle(_CollectorStub([]), AdbAnomalyDetector())
        result = oracle.check()
        self.assertFalse(result.matched)

    def test_critical_event_returns_match(self) -> None:
        oracle = AdbOracle(
            _CollectorStub([("crash", "Fatal signal SIGSEGV in mediaserver")]),
            AdbAnomalyDetector(),
        )
        result = oracle.check()
        self.assertTrue(result.matched)
        self.assertIn("SIGSEGV", result.matched_pattern or "")

    def test_info_only_returns_no_match(self) -> None:
        oracle = AdbOracle(
            _CollectorStub([("radio", "IMS REGISTERED on LTE")]),
            AdbAnomalyDetector(),
        )
        result = oracle.check()
        self.assertFalse(result.matched)

    def test_unhealthy_collector_reports_error(self) -> None:
        stub = _UnhealthyCollectorStub([], dead=frozenset({"main", "radio"}))
        oracle = AdbOracle(stub, AdbAnomalyDetector())
        result = oracle.check()
        self.assertFalse(result.matched)
        self.assertIsNotNone(result.error)
        self.assertIn("disconnected", result.error)
        self.assertIn("main", result.error)

    def test_healthy_collector_no_error(self) -> None:
        stub = _UnhealthyCollectorStub([])  # healthy by default
        oracle = AdbOracle(stub, AdbAnomalyDetector())
        result = oracle.check()
        self.assertIsNone(result.error)


class OracleEngineWithAdbTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ctx = OracleContext(method="OPTIONS")

    def test_adb_oracle_triggers_stack_failure_verdict(self) -> None:
        engine = OracleEngine(adb_oracle=_AdbOracleStub(True, r"SIGSEGV|signal 11"))
        verdict = engine.evaluate(_make_result("success", status_code=200), self.ctx)
        self.assertEqual(verdict.verdict, "stack_failure")
        self.assertEqual(verdict.confidence, 0.80)
        self.assertIn("ADB anomaly detected", verdict.reason)

    def test_adb_oracle_no_events_falls_through_to_normal_verdict(self) -> None:
        engine = OracleEngine(adb_oracle=_AdbOracleStub(False))
        verdict = engine.evaluate(_make_result("success", status_code=200), self.ctx)
        self.assertEqual(verdict.verdict, "normal")
