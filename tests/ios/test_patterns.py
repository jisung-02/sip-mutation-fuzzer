import unittest

from volte_mutation_fuzzer.ios.patterns import IOS_ANOMALY_PATTERNS


class IosPatternTests(unittest.TestCase):
    def test_patterns_not_empty(self) -> None:
        self.assertGreater(len(IOS_ANOMALY_PATTERNS), 0)

    def test_fatal_patterns_cover_exc_and_sigabrt(self) -> None:
        names = {p.name for p in IOS_ANOMALY_PATTERNS}
        self.assertIn("EXC_BAD_ACCESS", names)
        self.assertIn("EXC_CRASH_SIGABRT", names)
        self.assertIn("report_crash_saved", names)

    def test_ims_patterns_present(self) -> None:
        names = {p.name for p in IOS_ANOMALY_PATTERNS}
        self.assertIn("ims_registration_failed", names)
        self.assertIn("ims_deregistration", names)

    def test_regex_compiles(self) -> None:
        for pattern in IOS_ANOMALY_PATTERNS:
            self.assertIsNotNone(pattern.compiled)

    def test_categories_valid(self) -> None:
        allowed = {"fatal_signal", "ims_anomaly", "call_anomaly", "system_anomaly"}
        for pattern in IOS_ANOMALY_PATTERNS:
            self.assertIn(pattern.category, allowed)

    def test_severities_valid(self) -> None:
        allowed = {"critical", "warning", "info"}
        for pattern in IOS_ANOMALY_PATTERNS:
            self.assertIn(pattern.severity, allowed)
