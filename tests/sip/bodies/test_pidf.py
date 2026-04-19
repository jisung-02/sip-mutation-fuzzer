import unittest
import xml.etree.ElementTree as ET

from volte_mutation_fuzzer.sip.bodies.pidf import PIdfBody, PIdfTuple


class PIdfBodyTests(unittest.TestCase):
    def test_render_and_default_instance(self) -> None:
        body = PIdfBody.default_instance()
        rendered = body.render()
        root = ET.fromstring(rendered)

        self.assertEqual(body.content_type, "application/pidf+xml")
        self.assertEqual(root.tag, "{urn:ietf:params:xml:ns:pidf}presence")
        tuple_element = root.find("{urn:ietf:params:xml:ns:pidf}tuple")
        self.assertIsNotNone(tuple_element)
        assert tuple_element is not None
        self.assertEqual(tuple_element.attrib["id"], "t1")
        self.assertIn("<basic>open</basic>", rendered)
        self.assertIn("<contact>sip:alice@example.com</contact>", rendered)

    def test_default_instance_accepts_tuple_override(self) -> None:
        body = PIdfBody.default_instance(
            tuples=(PIdfTuple(id="t2", status_basic="closed"),)
        )

        self.assertIn('id="t2"', body.render())
        self.assertIn("<basic>closed</basic>", body.render())
