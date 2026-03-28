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
    """Ordered editable header entry that preserves duplicates and unknown names."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    name: str
    value: str

    def render(self) -> str:
        return f"{self.name}: {self.value}"


class EditableSIPMessage(BaseModel):
    """Editable SIP wire representation that tolerates malformed header states."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    start_line: EditableStartLine
    headers: tuple[EditableHeader, ...] = Field(default_factory=tuple)
    body: str = ""
    declared_content_length: int | None = Field(default=None, ge=0)

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

        rendered_sections = [self.start_line.render(), *rendered_headers, ""]
        return _CRLF.join(rendered_sections) + _CRLF + self.body


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

    def delete(self, start: int, end: int) -> Self:
        _validate_range(start, end, upper_bound=len(self.data))
        updated = self.data[:start] + self.data[end:]
        return self.model_copy(update={"data": updated})

    def truncate(self, length: int) -> Self:
        if length < 0 or length > len(self.data):
            raise ValueError("truncate length must be within current data bounds")
        return self.model_copy(update={"data": self.data[:length]})


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
]
