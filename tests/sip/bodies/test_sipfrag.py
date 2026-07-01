import unittest

from volte_mutation_fuzzer.sip.bodies.sipfrag import SipfragBody


class SipfragBodyTests(unittest.TestCase):
    def test_render_and_default_instance(self) -> None:
        body = SipfragBody.default_instance()

        self.assertEqual(body.content_type, "message/sipfrag;version=2.0")
        self.assertEqual(body.render(), "SIP/2.0 200 OK")

    def test_default_instance_accepts_overrides(self) -> None:
        body = SipfragBody.default_instance(status_code=202, reason_phrase="Accepted")

        self.assertEqual(body.render(), "SIP/2.0 202 Accepted")
