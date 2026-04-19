import unittest
import xml.etree.ElementTree as ET

from volte_mutation_fuzzer.sip.bodies.dialog_info import (
    Dialog,
    DialogInfoBody,
    DialogParticipant,
)


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
        self.assertEqual(dialog.attrib["call-id"], "call-1")
        self.assertIn("<state>confirmed</state>", rendered)

    def test_default_instance_accepts_dialog_override(self) -> None:
        body = DialogInfoBody.default_instance(
            dialogs=(
                Dialog(
                    id="dialog-2",
                    call_id="call-2",
                    local_tag="local-2",
                    remote_tag="remote-2",
                    direction="recipient",
                    state="terminated",
                    local=DialogParticipant(identity="sip:bob@example.com"),
                    remote=DialogParticipant(identity="sip:alice@example.com"),
                ),
            )
        )

        self.assertIn('direction="recipient"', body.render())
        self.assertIn("<state>terminated</state>", body.render())
