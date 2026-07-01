import unittest
import xml.etree.ElementTree as ET

from volte_mutation_fuzzer.sip.bodies.ims_service import ImsServiceBody


class ImsServiceBodyTests(unittest.TestCase):
    def test_render_and_default_instance(self) -> None:
        body = ImsServiceBody.default_instance()
        rendered = body.render()
        root = ET.fromstring(rendered)

        self.assertEqual(body.content_type, "application/3gpp-ims+xml")
        self.assertEqual(root.tag, "{urn:3gpp:ns:ims:xml}ims-3gpp")
        self.assertIn("<service-type>emergency</service-type>", rendered)
        self.assertIn("<reason>Alternative service available</reason>", rendered)

    def test_default_instance_accepts_overrides(self) -> None:
        body = ImsServiceBody.default_instance(service_type="normal", reason="Retry")

        self.assertIn("<service-type>normal</service-type>", body.render())
        self.assertIn("<reason>Retry</reason>", body.render())
