import unittest

from volte_mutation_fuzzer.mutator.editable import (
    EditableHeader,
    EditablePacketBytes,
    EditableSIPMessage,
    EditableStartLine,
    parse_editable_from_wire,
)

REALISTIC_CALL_ID = "a84b4c76e66710@pcscf.ims.mnc001.mcc001.3gppnetwork.org"
REALISTIC_REQUEST_URI = (
    "sip:001010000123511@10.20.20.8:8100;alias=10.20.20.8~8101~1"
)
REALISTIC_INVITE_START_LINE = f"INVITE {REALISTIC_REQUEST_URI} SIP/2.0"
REALISTIC_MESSAGE_START_LINE = "MESSAGE sip:222222@10.20.20.9:31800 SIP/2.0"
REALISTIC_VIA_PCSCF = (
    "SIP/2.0/UDP 172.22.0.21:15100;"
    "branch=z9hG4bK-524287-1---abcd1234;rport"
)
REALISTIC_VIA_UE = (
    "SIP/2.0/UDP 10.20.20.9:31800;"
    "branch=z9hG4bK-524287-1---efgh5678;rport"
)


class EditableSIPMessageTests(unittest.TestCase):
    def build_message(self) -> EditableSIPMessage:
        return EditableSIPMessage(
            start_line=EditableStartLine(text=REALISTIC_INVITE_START_LINE),
            headers=(
                EditableHeader(
                    name="Via",
                    value=REALISTIC_VIA_PCSCF,
                ),
                EditableHeader(name="Call-ID", value=REALISTIC_CALL_ID),
                EditableHeader(name="CSeq", value="1 INVITE"),
            ),
            body="",
        )

    def test_render_preserves_header_order(self) -> None:
        message = EditableSIPMessage(
            start_line=EditableStartLine(text="SIP/2.0 200 OK"),
            headers=(
                EditableHeader(name="Via", value=REALISTIC_VIA_PCSCF),
                EditableHeader(name="Max-Forwards", value="70"),
                EditableHeader(name="Call-ID", value=REALISTIC_CALL_ID),
            ),
        )

        rendered_lines = message.render().split("\r\n")

        self.assertEqual(
            rendered_lines[:5],
            [
                "SIP/2.0 200 OK",
                f"Via: {REALISTIC_VIA_PCSCF}",
                "Max-Forwards: 70",
                f"Call-ID: {REALISTIC_CALL_ID}",
                "",
            ],
        )

    def test_header_values_preserve_duplicates(self) -> None:
        message = EditableSIPMessage(
            start_line=EditableStartLine(text=REALISTIC_INVITE_START_LINE),
            headers=(
                EditableHeader(name="Via", value=REALISTIC_VIA_PCSCF),
                EditableHeader(name="Via", value=REALISTIC_VIA_UE),
                EditableHeader(name="Call-ID", value=REALISTIC_CALL_ID),
            ),
        )

        rendered_lines = message.render().split("\r\n")

        self.assertEqual(
            message.header_values("via"),
            (REALISTIC_VIA_PCSCF, REALISTIC_VIA_UE),
        )
        self.assertEqual(
            rendered_lines[:4],
            [
                REALISTIC_INVITE_START_LINE,
                f"Via: {REALISTIC_VIA_PCSCF}",
                f"Via: {REALISTIC_VIA_UE}",
                f"Call-ID: {REALISTIC_CALL_ID}",
            ],
        )

    def test_without_header_allows_required_header_removal(self) -> None:
        message = self.build_message()

        removed = message.without_header("Call-ID")

        self.assertEqual(removed.header_values("Call-ID"), ())
        self.assertEqual(message.header_values("Call-ID"), (REALISTIC_CALL_ID,))
        self.assertEqual(
            removed.render().split("\r\n")[:4],
            [
                REALISTIC_INVITE_START_LINE,
                f"Via: {REALISTIC_VIA_PCSCF}",
                "CSeq: 1 INVITE",
                "",
            ],
        )

    def test_render_allows_content_length_mismatch(self) -> None:
        message = EditableSIPMessage(
            start_line=EditableStartLine(text=REALISTIC_INVITE_START_LINE),
            headers=(EditableHeader(name="Call-ID", value=REALISTIC_CALL_ID),),
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

    def test_render_supports_custom_header_separator(self) -> None:
        message = EditableSIPMessage(
            start_line=EditableStartLine(text=REALISTIC_INVITE_START_LINE),
            headers=(
                EditableHeader(name="X-Custom", value="value", separator=" = "),
            ),
        )

        self.assertIn("X-Custom = value", message.render())
        self.assertNotIn("X-Custom: value", message.render())

    def test_custom_header_separator_does_not_round_trip_through_parser(self) -> None:
        message = EditableSIPMessage(
            start_line=EditableStartLine(text=REALISTIC_INVITE_START_LINE),
            headers=(
                EditableHeader(name="X-Custom", value="value", separator=" = "),
                EditableHeader(name="Via", value=REALISTIC_VIA_PCSCF),
            ),
        )

        parsed = parse_editable_from_wire(message.render())

        self.assertEqual(
            parsed.start_line.text,
            REALISTIC_INVITE_START_LINE,
        )
        self.assertEqual(parsed.header_values("Via"), (REALISTIC_VIA_PCSCF,))
        self.assertEqual(parsed.header_values("X-Custom"), ())

    def test_render_can_drop_final_blank_line(self) -> None:
        message = EditableSIPMessage(
            start_line=EditableStartLine(text=REALISTIC_INVITE_START_LINE),
            headers=(EditableHeader(name="Call-ID", value=REALISTIC_CALL_ID),),
            body="hello",
            emit_final_blank_line=False,
        )

        self.assertEqual(
            message.render(),
            (
                f"{REALISTIC_INVITE_START_LINE}\r\n"
                f"Call-ID: {REALISTIC_CALL_ID}\r\n"
                "hello"
            ),
        )

    def test_render_supports_lf_only_line_endings(self) -> None:
        message = EditableSIPMessage(
            start_line=EditableStartLine(text=REALISTIC_INVITE_START_LINE),
            headers=(EditableHeader(name="Call-ID", value=REALISTIC_CALL_ID),),
            body="hello",
            line_ending="\n",
        )

        self.assertEqual(
            message.render(),
            (
                f"{REALISTIC_INVITE_START_LINE}\n"
                f"Call-ID: {REALISTIC_CALL_ID}\n\n"
                "hello"
            ),
        )


class EditablePacketBytesTests(unittest.TestCase):
    def test_from_message_uses_rendered_utf8_bytes(self) -> None:
        message = EditableSIPMessage(
            start_line=EditableStartLine(text=REALISTIC_INVITE_START_LINE),
            headers=(EditableHeader(name="Call-ID", value=REALISTIC_CALL_ID),),
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

    def test_append_and_tail_delete_helpers(self) -> None:
        packet_bytes = EditablePacketBytes(data=b"abcd")

        self.assertEqual(packet_bytes.append(b"ef").data, b"abcdef")
        self.assertEqual(packet_bytes.tail_delete(2).data, b"ab")

        with self.assertRaises(ValueError):
            packet_bytes.tail_delete(5)


if __name__ == "__main__":
    unittest.main()
