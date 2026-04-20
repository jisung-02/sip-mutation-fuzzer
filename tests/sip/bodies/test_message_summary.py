import unittest

from volte_mutation_fuzzer.sip.bodies.message_summary import (
    MessageSummaryBody,
    VoiceMessageSummary,
)

IMS_DOMAIN = "ims.mnc001.mcc001.3gppnetwork.org"


class MessageSummaryBodyTests(unittest.TestCase):
    def test_render_and_default_instance(self) -> None:
        body = MessageSummaryBody.default_instance()
        rendered = body.render()

        self.assertEqual(
            body.content_type,
            "application/simple-message-summary",
        )
        self.assertIn("Messages-Waiting: yes\r\n", rendered)
        self.assertIn(
            f"Message-Account: sip:voicemail@{IMS_DOMAIN}\r\n",
            rendered,
        )
        self.assertIn("Voice-Message: 0/0\r\n", rendered)

    def test_default_instance_accepts_voice_override(self) -> None:
        body = MessageSummaryBody.default_instance(
            messages_waiting=False,
            voice_message=VoiceMessageSummary(new_messages=2, old_messages=8),
        )

        self.assertIn("Messages-Waiting: no\r\n", body.render())
        self.assertIn("Voice-Message: 2/8\r\n", body.render())
