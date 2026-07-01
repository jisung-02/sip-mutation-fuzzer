import unittest

from volte_mutation_fuzzer.sip.bodies.dtmf import DtmfRelayBody
from volte_mutation_fuzzer.sip.bodies.multipart import MultipartBody
from volte_mutation_fuzzer.sip.bodies.plain_text import PlainTextBody


class MultipartBodyTests(unittest.TestCase):
    def test_render_and_default_instance(self) -> None:
        body = MultipartBody.default_instance(boundary="boundary-1")
        rendered = body.render()

        self.assertEqual(body.content_type, "multipart/mixed;boundary=boundary-1")
        self.assertIn("--boundary-1\r\n", rendered)
        self.assertIn("Content-Type: text/plain\r\n\r\n", rendered)
        self.assertTrue(rendered.endswith("--boundary-1--\r\n"))

    def test_render_includes_all_parts(self) -> None:
        body = MultipartBody(
            boundary="boundary-2",
            parts=[
                PlainTextBody(text="hello"),
                DtmfRelayBody(signal="7", duration=320),
            ],
        )

        rendered = body.render()
        self.assertIn("hello", rendered)
        self.assertIn("Signal=7\r\nDuration=320\r\n", rendered)
