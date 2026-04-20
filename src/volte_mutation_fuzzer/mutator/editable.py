from collections.abc import Iterable
from typing import Self

from pydantic import BaseModel, ConfigDict, Field

_CRLF = "\r\n"
_CONTENT_LENGTH_HEADER = "Content-Length"


class EditableStartLine(BaseModel):
    """Editable raw SIP start-line used by wire-level mutations."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    text: str

    def render(self) -> str:
        return self.text


class EditableHeader(BaseModel):
    """Ordered editable header entry that preserves duplicates and unknown names.

    The ``separator`` field is render-only and is intended for malformed wire
    output. Non-default separators are not guaranteed to round-trip through
    ``parse_editable_from_wire()``, which only recognizes canonical ``:`` header
    syntax.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    name: str
    value: str
    separator: str = Field(
        default=": ",
        description=(
            "Render-only header separator for malformed wire output; "
            "non-default values are not guaranteed to round-trip through "
            "parse_editable_from_wire()."
        ),
    )

    def render(self) -> str:
        return f"{self.name}{self.separator}{self.value}"


class EditableSIPMessage(BaseModel):
    """Editable SIP wire representation that tolerates malformed header states."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    start_line: EditableStartLine
    headers: tuple[EditableHeader, ...] = Field(default_factory=tuple)
    body: str = ""
    declared_content_length: int | None = Field(default=None, ge=0)
    line_ending: str = "\r\n"
    emit_final_blank_line: bool = True
    extra_blank_lines_after_headers: int = Field(default=0, ge=0)

    def header_values(self, name: str) -> tuple[str, ...]:
        header_name = _header_name_key(name)
        return tuple(
            header.value
            for header in self.headers
            if _header_name_key(header.name) == header_name
        )

    def without_header(self, name: str) -> Self:
        header_name = _header_name_key(name)
        filtered_headers = tuple(
            header
            for header in self.headers
            if _header_name_key(header.name) != header_name
        )
        return self.model_copy(update={"headers": filtered_headers})

    def append_header(self, name: str, value: str) -> Self:
        updated_headers = (*self.headers, EditableHeader(name=name, value=value))
        return self.model_copy(update={"headers": updated_headers})

    def replace_headers(
        self,
        headers: Iterable[EditableHeader],
    ) -> Self:
        return self.model_copy(update={"headers": tuple(headers)})

    def render(self) -> str:
        rendered_headers = [header.render() for header in self.headers]
        if self.declared_content_length is not None and not self.header_values(
            _CONTENT_LENGTH_HEADER
        ):
            rendered_headers.append(
                f"{_CONTENT_LENGTH_HEADER}: {self.declared_content_length}"
            )

        rendered_lines = [self.start_line.render(), *rendered_headers]
        rendered = self.line_ending.join(rendered_lines)
        rendered += self.line_ending

        blank_line_count = self.extra_blank_lines_after_headers
        if self.emit_final_blank_line:
            blank_line_count += 1
        rendered += self.line_ending * blank_line_count
        return rendered + self.body


class EditablePacketBytes(BaseModel):
    """Editable byte buffer used by byte-level mutations."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    data: bytes = b""

    @classmethod
    def from_message(cls, message: EditableSIPMessage) -> Self:
        return cls(data=message.render().encode("utf-8"))

    def overwrite(self, offset: int, value: bytes) -> Self:
        _validate_offset(offset, upper_bound=len(self.data), allow_endpoint=False)
        end = offset + len(value)
        if end > len(self.data):
            raise ValueError("overwrite range exceeds data length")
        updated = self.data[:offset] + value + self.data[end:]
        return self.model_copy(update={"data": updated})

    def insert(self, offset: int, value: bytes) -> Self:
        _validate_offset(offset, upper_bound=len(self.data), allow_endpoint=True)
        updated = self.data[:offset] + value + self.data[offset:]
        return self.model_copy(update={"data": updated})

    def append(self, value: bytes) -> Self:
        return self.model_copy(update={"data": self.data + value})

    def delete(self, start: int, end: int) -> Self:
        _validate_range(start, end, upper_bound=len(self.data))
        updated = self.data[:start] + self.data[end:]
        return self.model_copy(update={"data": updated})

    def tail_delete(self, count: int) -> Self:
        if count < 0 or count > len(self.data):
            raise ValueError("tail delete count must be within current data bounds")
        return self.model_copy(update={"data": self.data[: len(self.data) - count]})

    def truncate(self, length: int) -> Self:
        if length < 0 or length > len(self.data):
            raise ValueError("truncate length must be within current data bounds")
        return self.model_copy(update={"data": self.data[:length]})


def parse_editable_from_wire(wire_text: str) -> EditableSIPMessage:
    """Parse a raw SIP wire-text string into an ``EditableSIPMessage``.

    This preserves canonical SIP-style header lines, including common folded-header
    cases, 3GPP P-* headers, Record-Route, Accept-Contact, and similar wire text so
    the result can be fed directly into wire/byte mutation paths without needing a
    packet definition from the SIP catalog. Malformed render-only output such as
    custom header separators is not guaranteed to round-trip back through this
    parser.

    Header folding (continuation lines starting with SP or HT) is handled by
    appending the continuation to the preceding header value.
    """
    if not wire_text:
        return EditableSIPMessage(
            start_line=EditableStartLine(text=""),
            headers=(),
            body="",
            declared_content_length=None,
        )

    # Normalise line endings to CRLF then split
    normalized = wire_text.replace("\r\n", "\n").replace("\r", "\n")
    if "\n\n" in normalized:
        header_section, body = normalized.split("\n\n", 1)
    else:
        header_section = normalized
        body = ""

    raw_lines = header_section.split("\n")
    if not raw_lines:
        return EditableSIPMessage(
            start_line=EditableStartLine(text=""),
            headers=(),
            body=body,
            declared_content_length=None,
        )

    start_line_text = raw_lines[0]
    headers: list[EditableHeader] = []
    declared_content_length: int | None = None

    for line in raw_lines[1:]:
        if not line:
            continue
        # Header folding: continuation line starts with SP or HT
        if line and line[0] in (" ", "\t") and headers:
            folded = headers[-1]
            headers[-1] = EditableHeader(
                name=folded.name,
                value=folded.value + " " + line.strip(),
            )
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        header = EditableHeader(name=name.strip(), value=value.strip())
        headers.append(header)
        if name.strip().casefold() == "content-length":
            try:
                declared_content_length = int(value.strip())
            except ValueError:
                pass

    # Re-normalise body line endings to CRLF for consistency
    body_crlf = body.replace("\n", _CRLF)

    return EditableSIPMessage(
        start_line=EditableStartLine(text=start_line_text),
        headers=tuple(headers),
        body=body_crlf,
        declared_content_length=declared_content_length,
    )


def _header_name_key(name: str) -> str:
    return name.strip().casefold()


def _validate_offset(offset: int, *, upper_bound: int, allow_endpoint: bool) -> None:
    max_offset = upper_bound if allow_endpoint else upper_bound - 1
    if offset < 0 or offset > max_offset:
        raise ValueError("offset is out of bounds")


def _validate_range(start: int, end: int, *, upper_bound: int) -> None:
    if start < 0 or end < start or end > upper_bound:
        raise ValueError("byte range is out of bounds")


__all__ = [
    "EditableHeader",
    "EditablePacketBytes",
    "EditableSIPMessage",
    "EditableStartLine",
    "parse_editable_from_wire",
]
