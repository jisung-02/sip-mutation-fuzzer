import unittest
import xml.etree.ElementTree as ET

from volte_mutation_fuzzer.sip.bodies.conference_info import (
    ConferenceInfoBody,
    ConferenceUser,
)

IMS_DOMAIN = "ims.mnc001.mcc001.3gppnetwork.org"


class ConferenceInfoBodyTests(unittest.TestCase):
    def test_render_and_default_instance(self) -> None:
        body = ConferenceInfoBody.default_instance(subject="Standup")
        rendered = body.render()
        root = ET.fromstring(rendered)

        self.assertEqual(body.content_type, "application/conference-info+xml")
        self.assertEqual(
            root.tag,
            "{urn:ietf:params:xml:ns:conference-info}conference-info",
        )
        self.assertIn("<subject>Standup</subject>", rendered)
        self.assertIn("<status>connected</status>", rendered)

    def test_default_instance_accepts_user_override(self) -> None:
        body = ConferenceInfoBody.default_instance(
            users=(
                ConferenceUser(
                    entity=f"sip:222222@{IMS_DOMAIN}",
                    display_text="Bob",
                    status="on-hold",
                ),
            )
        )

        self.assertIn(f'entity="sip:222222@{IMS_DOMAIN}"', body.render())
        self.assertIn("<status>on-hold</status>", body.render())
