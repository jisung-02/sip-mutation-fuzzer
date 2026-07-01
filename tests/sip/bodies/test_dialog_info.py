import unittest
import xml.etree.ElementTree as ET

from volte_mutation_fuzzer.sip.bodies.dialog_info import (
    Dialog,
    DialogInfoBody,
    DialogParticipant,
)

IMS_DOMAIN = "ims.mnc001.mcc001.3gppnetwork.org"
REALISTIC_CALL_ID = "a84b4c76e66710@pcscf.ims.mnc001.mcc001.3gppnetwork.org"


class DialogInfoBodyTests(unittest.TestCase):
    def test_render_and_default_instance(self) -> None:
        body = DialogInfoBody.default_instance()
        rendered = body.render()
        root = ET.fromstring(rendered)

        self.assertEqual(body.content_type, "application/dialog-info+xml")
        self.assertEqual(root.tag, "{urn:ietf:params:xml:ns:dialog-info}dialog-info")
        dialog = root.find("{urn:ietf:params:xml:ns:dialog-info}dialog")
        self.assertIsNotNone(dialog)
        assert dialog is not None
        self.assertEqual(dialog.attrib["call-id"], REALISTIC_CALL_ID)
        self.assertIn("<state>confirmed</state>", rendered)

    def test_default_instance_accepts_dialog_override(self) -> None:
        body = DialogInfoBody.default_instance(
            dialogs=(
                Dialog(
                    id="dialog-2",
                    call_id="b7f2a1d43caa9f1d@pcscf.ims.mnc001.mcc001.3gppnetwork.org",
                    local_tag="a73kszlfl",
                    remote_tag="1950002",
                    direction="recipient",
                    state="terminated",
                    local=DialogParticipant(identity=f"sip:222222@{IMS_DOMAIN}"),
                    remote=DialogParticipant(identity=f"sip:111111@{IMS_DOMAIN}"),
                ),
            )
        )

        self.assertIn('direction="recipient"', body.render())
        self.assertIn("<state>terminated</state>", body.render())
