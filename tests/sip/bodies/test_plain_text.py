import unittest

from volte_mutation_fuzzer.sip.bodies.plain_text import PlainTextBody


class PlainTextBodyTests(unittest.TestCase):
    def test_render_and_default_instance(self) -> None:
        body = PlainTextBody.default_instance()

        self.assertEqual(body.content_type, "text/plain")
        self.assertEqual(body.render(), "Hello from VoLTE mutation fuzzer.")

    def test_default_instance_accepts_overrides(self) -> None:
        body = PlainTextBody.default_instance(text="hello")

        self.assertEqual(body.render(), "hello")
