import unittest

from volte_mutation_fuzzer.sip.bodies.sdp import SDPBody


class SDPBodyTests(unittest.TestCase):
    def test_default_instance_renders_valid_volte_sdp(self) -> None:
        body = SDPBody.default_instance()

        self.assertEqual(body.content_type, "application/sdp")
        rendered = body.render()

        self.assertTrue(rendered.endswith("\r\n"))
        self.assertIn("v=0\r\n", rendered)
        self.assertIn("o=- 0 0 IN IP4 0.0.0.0\r\n", rendered)
        self.assertIn("m=audio 49170 RTP/AVP 96 97\r\n", rendered)
        self.assertIn("a=rtpmap:96 AMR-WB/16000\r\n", rendered)
        self.assertIn("a=ptime:20\r\n", rendered)
        self.assertIn("a=sendrecv\r\n", rendered)

    def test_default_instance_accepts_overrides(self) -> None:
        body = SDPBody.default_instance(session_name="VoLTE")

        self.assertEqual(body.session_name, "VoLTE")
        self.assertIn("s=VoLTE\r\n", body.render())
