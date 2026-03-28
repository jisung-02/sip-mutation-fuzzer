import unittest

from volte_mutation_fuzzer.mutator.editable import (
    EditableHeader,
    EditablePacketBytes,
    EditableSIPMessage,
    EditableStartLine,
)


class EditableSIPMessageTests(unittest.TestCase):
    def build_message(self) -> EditableSIPMessage:
        return EditableSIPMessage(
            start_line=EditableStartLine(text="INVITE sip:ue@example.com SIP/2.0"),
            headers=(
                EditableHeader(
                    name="Via",
                    value="SIP/2.0/UDP proxy.example.com;branch=z9",
                ),
                EditableHeader(name="Call-ID", value="call-1"),
                EditableHeader(name="CSeq", value="1 INVITE"),
            ),
            body="",
        )

    def test_render_preserves_header_order(self) -> None:
        message = EditableSIPMessage(
            start_line=EditableStartLine(text="SIP/2.0 200 OK"),
            headers=(
                EditableHeader(name="Via", value="first-hop"),
                EditableHeader(name="Max-Forwards", value="70"),
                EditableHeader(name="Call-ID", value="call-1"),
            ),
        )

        rendered_lines = message.render().split("\r\n")

        self.assertEqual(
            rendered_lines[:5],
            [
                "SIP/2.0 200 OK",
                "Via: first-hop",
                "Max-Forwards: 70",
                "Call-ID: call-1",
                "",
            ],
        )

    def test_header_values_preserve_duplicates(self) -> None:
        message = EditableSIPMessage(
            start_line=EditableStartLine(text="INVITE sip:ue@example.com SIP/2.0"),
            headers=(
                EditableHeader(name="Via", value="first-hop"),
                EditableHeader(name="Via", value="second-hop"),
                EditableHeader(name="Call-ID", value="call-1"),
            ),
        )

        rendered_lines = message.render().split("\r\n")

        self.assertEqual(message.header_values("via"), ("first-hop", "second-hop"))
        self.assertEqual(
            rendered_lines[:4],
            [
                "INVITE sip:ue@example.com SIP/2.0",
                "Via: first-hop",
                "Via: second-hop",
                "Call-ID: call-1",
            ],
        )

    def test_without_header_allows_required_header_removal(self) -> None:
        message = self.build_message()

        removed = message.without_header("Call-ID")

        self.assertEqual(removed.header_values("Call-ID"), ())
        self.assertEqual(message.header_values("Call-ID"), ("call-1",))
        self.assertEqual(
            removed.render().split("\r\n")[:4],
            [
                "INVITE sip:ue@example.com SIP/2.0",
                "Via: SIP/2.0/UDP proxy.example.com;branch=z9",
                "CSeq: 1 INVITE",
                "",
            ],
        )

    def test_render_allows_content_length_mismatch(self) -> None:
        message = EditableSIPMessage(
            start_line=EditableStartLine(text="INVITE sip:ue@example.com SIP/2.0"),
            headers=(EditableHeader(name="Call-ID", value="call-1"),),
            body="hello",
            declared_content_length=99,
        )

        rendered = message.render()

        self.assertIn("Content-Length: 99\r\n\r\nhello", rendered)

        header_owned_length = message.append_header("Content-Length", "3")
        rendered_with_explicit_header = header_owned_length.render()

        self.assertIn("Content-Length: 3\r\n\r\nhello", rendered_with_explicit_header)
        self.assertNotIn(
            "Content-Length: 99\r\nContent-Length: 3",
            rendered_with_explicit_header,
        )
        self.assertIn("Content-Length: 99\r\n\r\nhello", message.render())


class EditablePacketBytesTests(unittest.TestCase):
    def test_from_message_uses_rendered_utf8_bytes(self) -> None:
        message = EditableSIPMessage(
            start_line=EditableStartLine(text="INVITE sip:ue@example.com SIP/2.0"),
            headers=(EditableHeader(name="Call-ID", value="call-1"),),
            declared_content_length=0,
        )

        packet_bytes = EditablePacketBytes.from_message(message)

        self.assertEqual(packet_bytes.data, message.render().encode("utf-8"))

    def test_byte_edit_operations_and_bounds(self) -> None:
        packet_bytes = EditablePacketBytes(data=b"abcd")

        self.assertEqual(packet_bytes.overwrite(1, b"XY").data, b"aXYd")
        self.assertEqual(packet_bytes.insert(2, b"ZZ").data, b"abZZcd")
        self.assertEqual(packet_bytes.delete(1, 3).data, b"ad")
        self.assertEqual(packet_bytes.truncate(2).data, b"ab")

        with self.assertRaises(ValueError):
            packet_bytes.overwrite(3, b"XY")

        with self.assertRaises(ValueError):
            packet_bytes.insert(5, b"!")

        with self.assertRaises(ValueError):
            packet_bytes.delete(2, 5)

        with self.assertRaises(ValueError):
            packet_bytes.truncate(5)


if __name__ == "__main__":
    unittest.main()
