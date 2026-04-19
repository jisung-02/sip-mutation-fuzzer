import unittest
import xml.etree.ElementTree as ET

from volte_mutation_fuzzer.sip.bodies.reginfo import (
    RegContact,
    ReginfoBody,
    Registration,
)


class ReginfoBodyTests(unittest.TestCase):
    def test_render_and_default_instance(self) -> None:
        body = ReginfoBody.default_instance()
        rendered = body.render()
        root = ET.fromstring(rendered)

        self.assertEqual(body.content_type, "application/reginfo+xml")
        self.assertEqual(root.tag, "{urn:ietf:params:xml:ns:reginfo}reginfo")
        registration = root.find("{urn:ietf:params:xml:ns:reginfo}registration")
        self.assertIsNotNone(registration)
        assert registration is not None
        self.assertEqual(registration.attrib["aor"], "sip:alice@example.com")
        self.assertIn("<uri>sip:alice@example.com</uri>", rendered)

    def test_default_instance_accepts_registration_override(self) -> None:
        body = ReginfoBody.default_instance(
            registrations=(
                Registration(
                    aor="sip:bob@example.com",
                    id="reg-2",
                    contacts=(
                        RegContact(
                            id="contact-2",
                            state="terminated",
                            event="deactivated",
                            uri="sip:bob@example.com",
                        ),
                    ),
                ),
            )
        )

        self.assertIn('aor="sip:bob@example.com"', body.render())
        self.assertIn('event="deactivated"', body.render())
