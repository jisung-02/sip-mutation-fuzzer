import unittest

from volte_mutation_fuzzer.adb.patterns import ANOMALY_PATTERNS, AnomalyPattern


def _match_pattern(line: str) -> AnomalyPattern | None:
    for pattern in ANOMALY_PATTERNS:
        if pattern.compiled.search(line):
            return pattern
    return None


class AnomalyPatternsTests(unittest.TestCase):
    def test_sigsegv_matches(self) -> None:
        pattern = _match_pattern("Fatal signal SIGSEGV in vendor process")
        assert pattern is not None
        self.assertEqual(pattern.name, "SIGSEGV")
        self.assertEqual(pattern.severity, "critical")
        self.assertEqual(pattern.category, "fatal_signal")

    def test_sigabrt_matches(self) -> None:
        pattern = _match_pattern("signal 6 raised by media service")
        assert pattern is not None
        self.assertEqual(pattern.name, "SIGABRT")

    def test_tombstone_matches(self) -> None:
        pattern = _match_pattern("Tombstone written to: /data/tombstones/tombstone_01")
        assert pattern is not None
        self.assertEqual(pattern.name, "tombstone")

    def test_heap_corruption_matches(self) -> None:
        pattern = _match_pattern("Scudo ERROR: corrupted chunk header at 0x1234")
        assert pattern is not None
        self.assertEqual(pattern.name, "heap_corruption")
        self.assertEqual(pattern.severity, "critical")

    def test_ims_deregistration_matches(self) -> None:
        pattern = _match_pattern("IMS stack DEREGIST reason=radio_lost")
        assert pattern is not None
        self.assertEqual(pattern.name, "ims_deregistration")
        self.assertEqual(pattern.severity, "warning")

    def test_ims_registered_is_info(self) -> None:
        pattern = _match_pattern("IMS REGISTERED on LTE")
        assert pattern is not None
        self.assertEqual(pattern.name, "ims_registered")
        self.assertEqual(pattern.severity, "info")

    def test_normal_lines_do_not_match(self) -> None:
        self.assertIsNone(_match_pattern("Audio route changed successfully"))

    def test_telephony_crash_matches(self) -> None:
        pattern = _match_pattern("telephony service died after watchdog")
        assert pattern is not None
        self.assertEqual(pattern.name, "telephony_crash")
