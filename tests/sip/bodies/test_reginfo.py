import unittest
import xml.etree.ElementTree as ET

from volte_mutation_fuzzer.sip.bodies.reginfo import (
    RegContact,
    ReginfoBody,
    Registration,
)

IMS_DOMAIN = "ims.mnc001.mcc001.3gppnetwork.org"


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
        self.assertEqual(registration.attrib["aor"], f"sip:111111@{IMS_DOMAIN}")
        self.assertIn(f"<uri>sip:111111@{IMS_DOMAIN}</uri>", rendered)

    def test_default_instance_accepts_registration_override(self) -> None:
        body = ReginfoBody.default_instance(
            registrations=(
                Registration(
                    aor=f"sip:222222@{IMS_DOMAIN}",
                    id="reg-2",
                    contacts=(
                        RegContact(
                            id="contact-2",
                            state="terminated",
                            event="deactivated",
                            uri=f"sip:222222@{IMS_DOMAIN}",
                        ),
                    ),
                ),
            )
        )

        self.assertIn(f'aor="sip:222222@{IMS_DOMAIN}"', body.render())
        self.assertIn('event="deactivated"', body.render())
