import unittest

from pydantic import ValidationError

from volte_mutation_fuzzer.oracle.contracts import (
    OracleContext,
    OracleVerdict,
    ProcessCheckResult,
)


class OracleContextTests(unittest.TestCase):
    def test_defaults(self) -> None:
        ctx = OracleContext(method="OPTIONS")
        self.assertEqual(ctx.method, "OPTIONS")
        self.assertEqual(ctx.expected_outcome, "success")
        self.assertEqual(ctx.timeout_threshold_ms, 5000.0)
        self.assertEqual(ctx.slow_threshold_ms, 3000.0)

    def test_custom_thresholds(self) -> None:
        ctx = OracleContext(
            method="INVITE", timeout_threshold_ms=2000.0, slow_threshold_ms=1000.0
        )
        self.assertEqual(ctx.timeout_threshold_ms, 2000.0)
        self.assertEqual(ctx.slow_threshold_ms, 1000.0)

    def test_method_required(self) -> None:
        with self.assertRaises(ValidationError):
            OracleContext(method="")

    def test_threshold_must_be_positive(self) -> None:
        with self.assertRaises(ValidationError):
            OracleContext(method="OPTIONS", timeout_threshold_ms=0.0)
        with self.assertRaises(ValidationError):
            OracleContext(method="OPTIONS", slow_threshold_ms=-1.0)

    def test_extra_fields_forbidden(self) -> None:
        with self.assertRaises(ValidationError):
            OracleContext(method="OPTIONS", unknown_field="x")


class ProcessCheckResultTests(unittest.TestCase):
    def test_alive(self) -> None:
        r = ProcessCheckResult(
            process_name="baresip", alive=True, pid=1234, check_time=1.0
        )
        self.assertTrue(r.alive)
        self.assertEqual(r.pid, 1234)
        self.assertIsNone(r.error)

    def test_dead(self) -> None:
        r = ProcessCheckResult(process_name="baresip", alive=False, check_time=1.0)
        self.assertFalse(r.alive)
        self.assertIsNone(r.pid)

    def test_error_stored(self) -> None:
        r = ProcessCheckResult(
            process_name="baresip", alive=False, check_time=1.0, error="pgrep failed"
        )
        self.assertEqual(r.error, "pgrep failed")

    def test_process_name_required(self) -> None:
        with self.assertRaises(ValidationError):
            ProcessCheckResult(process_name="", alive=True, check_time=1.0)


class OracleVerdictTests(unittest.TestCase):
    def test_normal_verdict(self) -> None:
        v = OracleVerdict(verdict="normal", reason="ok", elapsed_ms=50.0)
        self.assertEqual(v.verdict, "normal")
        self.assertEqual(v.confidence, 1.0)
        self.assertIsNone(v.response_code)
        self.assertIsNone(v.process_alive)
        self.assertEqual(v.details, {})

    def test_all_verdict_values(self) -> None:
        for val in (
            "normal",
            "suspicious",
            "timeout",
            "crash",
            "stack_failure",
            "unknown",
        ):
            v = OracleVerdict(verdict=val, reason="test", elapsed_ms=0.0)
            self.assertEqual(v.verdict, val)

    def test_invalid_verdict(self) -> None:
        with self.assertRaises(ValidationError):
            OracleVerdict(verdict="bogus", reason="x", elapsed_ms=0.0)

    def test_confidence_bounds(self) -> None:
        with self.assertRaises(ValidationError):
            OracleVerdict(verdict="normal", reason="x", elapsed_ms=0.0, confidence=1.1)
        with self.assertRaises(ValidationError):
            OracleVerdict(verdict="normal", reason="x", elapsed_ms=0.0, confidence=-0.1)

    def test_with_response_code_and_process(self) -> None:
        v = OracleVerdict(
            verdict="suspicious",
            reason="5xx",
            elapsed_ms=100.0,
            response_code=500,
            process_alive=True,
        )
        self.assertEqual(v.response_code, 500)
        self.assertTrue(v.process_alive)
