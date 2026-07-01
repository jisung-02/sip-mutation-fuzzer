import unittest

from volte_mutation_fuzzer.sip.bodies.sms import SmsBody


class SmsBodyTests(unittest.TestCase):
    def test_render_and_default_instance(self) -> None:
        body = SmsBody.default_instance(payload="a1b2")

        self.assertEqual(body.content_type, "application/vnd.3gpp.sms")
        self.assertEqual(body.render(), "A1B2")

    def test_invalid_hex_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            SmsBody.default_instance(payload="123")
