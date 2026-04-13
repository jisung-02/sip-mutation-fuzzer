import subprocess
import unittest
from unittest.mock import patch, MagicMock

from volte_mutation_fuzzer.adb.call_state import CallState, CallStateChecker


class CallStateCheckerTests(unittest.TestCase):
    def _make_checker(self, **kwargs) -> CallStateChecker:
        return CallStateChecker(serial="FAKE123", **kwargs)

    def _mock_shell(self, stdout: str) -> MagicMock:
        result = MagicMock(spec=subprocess.CompletedProcess)
        result.stdout = stdout
        result.returncode = 0
        return result

    @patch.object(CallStateChecker, "__init__", lambda self, **kw: None)
    def _make_patched(self, stdout: str) -> CallStateChecker:
        """Create a checker with a mocked ADB connector."""
        checker = CallStateChecker.__new__(CallStateChecker)
        checker._poll_interval = 0.01
        checker._wait_timeout = 0.1
        connector = MagicMock()
        connector.run_shell.return_value = self._mock_shell(stdout)
        checker._connector = connector
        return checker

    def test_parse_idle(self) -> None:
        checker = self._make_patched(
            "  mCallState=0\n  mCallIncomingNumber=\n"
        )
        self.assertEqual(checker.get_call_state(), CallState.IDLE)

    def test_parse_ringing(self) -> None:
        checker = self._make_patched(
            "  mCallState=1\n  mCallIncomingNumber=111111\n"
        )
        self.assertEqual(checker.get_call_state(), CallState.RINGING)

    def test_parse_offhook(self) -> None:
        checker = self._make_patched(
            "  mCallState=2\n"
        )
        self.assertEqual(checker.get_call_state(), CallState.OFFHOOK)

    def test_parse_unknown_on_missing(self) -> None:
        checker = self._make_patched("some unrelated output\n")
        self.assertEqual(checker.get_call_state(), CallState.UNKNOWN)

    def test_parse_unknown_on_exception(self) -> None:
        checker = CallStateChecker.__new__(CallStateChecker)
        checker._poll_interval = 0.01
        checker._wait_timeout = 0.1
        connector = MagicMock()
        connector.run_shell.side_effect = OSError("adb not found")
        checker._connector = connector
        self.assertEqual(checker.get_call_state(), CallState.UNKNOWN)

    def test_is_idle_true(self) -> None:
        checker = self._make_patched("  mCallState=0\n")
        self.assertTrue(checker.is_idle())

    def test_is_idle_false_when_ringing(self) -> None:
        checker = self._make_patched("  mCallState=1\n")
        self.assertFalse(checker.is_idle())

    def test_wait_for_idle_already_idle(self) -> None:
        checker = self._make_patched("  mCallState=0\n")
        events = checker.wait_for_idle()
        self.assertEqual(events, [])

    def test_wait_for_idle_unknown_skips(self) -> None:
        checker = self._make_patched("no data\n")
        events = checker.wait_for_idle()
        self.assertEqual(len(events), 1)
        self.assertIn("unknown:skip-wait", events[0])

    def test_wait_for_idle_transitions_to_idle(self) -> None:
        checker = CallStateChecker.__new__(CallStateChecker)
        checker._poll_interval = 0.01
        checker._wait_timeout = 1.0
        connector = MagicMock()
        # First call: RINGING, second: RINGING, third: IDLE
        connector.run_shell.side_effect = [
            self._mock_shell("  mCallState=1\n"),
            self._mock_shell("  mCallState=1\n"),
            self._mock_shell("  mCallState=0\n"),
        ]
        checker._connector = connector
        events = checker.wait_for_idle()
        self.assertTrue(any("waiting" in e for e in events))
        self.assertTrue(any("idle-ok" in e for e in events))

    def test_wait_for_idle_timeout(self) -> None:
        checker = CallStateChecker.__new__(CallStateChecker)
        checker._poll_interval = 0.01
        checker._wait_timeout = 0.05
        connector = MagicMock()
        # Always RINGING
        connector.run_shell.return_value = self._mock_shell("  mCallState=1\n")
        checker._connector = connector
        events = checker.wait_for_idle()
        self.assertTrue(any("timeout" in e for e in events))
