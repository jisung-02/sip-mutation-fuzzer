import time
import unittest
from unittest.mock import patch

from volte_mutation_fuzzer.oracle.contracts import OracleContext
from volte_mutation_fuzzer.oracle.core import OracleEngine, ProcessOracle, SocketOracle
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

    def test_500_returns_suspicious(self) -> None:
        result = _make_result("error", status_code=500)
        verdict = self.oracle.judge(result, self.ctx)
        self.assertEqual(verdict.verdict, "suspicious")
        self.assertEqual(verdict.response_code, 500)

    def test_600_returns_suspicious(self) -> None:
        result = _make_result("error", status_code=600)
        verdict = self.oracle.judge(result, self.ctx)
        self.assertEqual(verdict.verdict, "suspicious")

    def test_4xx_returns_normal(self) -> None:
        result = _make_result("error", status_code=404)
        verdict = self.oracle.judge(result, self.ctx)
        self.assertEqual(verdict.verdict, "normal")

    def test_slow_response_returns_suspicious(self) -> None:
        ctx = OracleContext(method="OPTIONS", slow_threshold_ms=500.0)
        result = _make_result("success", status_code=200, elapsed_ms=1000.0)
        verdict = self.oracle.judge(result, ctx)
        self.assertEqual(verdict.verdict, "suspicious")
        self.assertIn("slow", verdict.reason)

    def test_elapsed_below_slow_threshold_returns_normal(self) -> None:
        ctx = OracleContext(method="OPTIONS", slow_threshold_ms=3000.0)
        result = _make_result("success", status_code=200, elapsed_ms=100.0)
        verdict = self.oracle.judge(result, ctx)
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
        with patch("subprocess.run", return_value=mock_result):
            result = self.oracle.check("baresip")
        self.assertTrue(result.alive)
        self.assertEqual(result.pid, 1234)
        self.assertIsNone(result.error)

    def test_dead_when_pgrep_returns_nonzero(self) -> None:
        mock_result = type("R", (), {"returncode": 1, "stdout": b""})()
        with patch("subprocess.run", return_value=mock_result):
            result = self.oracle.check("baresip")
        self.assertFalse(result.alive)
        self.assertIsNone(result.pid)

    def test_error_on_exception(self) -> None:
        with patch("subprocess.run", side_effect=FileNotFoundError("pgrep not found")):
            result = self.oracle.check("baresip")
        self.assertFalse(result.alive)
        self.assertIsNotNone(result.error)
        self.assertIn("pgrep not found", result.error)


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
        with patch("subprocess.run", return_value=alive_result):
            verdict = self.engine.evaluate(result, self.ctx, process_name="baresip")
        self.assertEqual(verdict.verdict, "normal")
        self.assertTrue(verdict.process_alive)

    def test_normal_socket_dead_process_becomes_crash(self) -> None:
        dead_result = type("R", (), {"returncode": 1, "stdout": b""})()
        result = _make_result("success", status_code=200)
        with patch("subprocess.run", return_value=dead_result):
            verdict = self.engine.evaluate(result, self.ctx, process_name="baresip")
        self.assertEqual(verdict.verdict, "crash")
        self.assertFalse(verdict.process_alive)

    def test_timeout_with_alive_process_stays_timeout(self) -> None:
        alive_result = type("R", (), {"returncode": 0, "stdout": b"999\n"})()
        result = _make_result("timeout")
        with patch("subprocess.run", return_value=alive_result):
            verdict = self.engine.evaluate(result, self.ctx, process_name="baresip")
        self.assertEqual(verdict.verdict, "timeout")
        self.assertTrue(verdict.process_alive)

    def test_suspicious_with_alive_process_stays_suspicious(self) -> None:
        alive_result = type("R", (), {"returncode": 0, "stdout": b"999\n"})()
        result = _make_result("error", status_code=500)
        with patch("subprocess.run", return_value=alive_result):
            verdict = self.engine.evaluate(result, self.ctx, process_name="baresip")
        self.assertEqual(verdict.verdict, "suspicious")
        self.assertTrue(verdict.process_alive)
