import unittest

from volte_mutation_fuzzer.sip.bodies.dtmf import DtmfRelayBody


class DtmfRelayBodyTests(unittest.TestCase):
    def test_render_and_default_instance(self) -> None:
        body = DtmfRelayBody.default_instance()

        self.assertEqual(body.content_type, "application/dtmf-relay")
        self.assertEqual(body.render(), "Signal=5\r\nDuration=160\r\n")

    def test_default_instance_accepts_overrides(self) -> None:
        body = DtmfRelayBody.default_instance(signal="9", duration=240)

        self.assertEqual(body.render(), "Signal=9\r\nDuration=240\r\n")
