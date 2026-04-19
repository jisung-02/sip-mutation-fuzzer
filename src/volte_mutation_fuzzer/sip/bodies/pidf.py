from __future__ import annotations

from datetime import UTC, datetime
from typing import ClassVar, Literal, Self
from xml.sax.saxutils import escape, quoteattr

from pydantic import BaseModel, ConfigDict, Field

from volte_mutation_fuzzer.sip.bodies import SIPBody


class PIdfTuple(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    status_basic: Literal["open", "closed"] = "open"
    contact_uri: str | None = None
    timestamp: datetime | None = None


class PIdfBody(SIPBody):
    content_type: ClassVar[str] = "application/pidf+xml"

    entity: str = Field(min_length=1)
    tuples: tuple[PIdfTuple, ...] = Field(min_length=1)

    def render(self) -> str:
        lines = [
            (
                "<presence xmlns="
                f"{quoteattr('urn:ietf:params:xml:ns:pidf')} "
                f"entity={quoteattr(self.entity)}>"
            ),
        ]
        for pidf_tuple in self.tuples:
            lines.append(f"  <tuple id={quoteattr(pidf_tuple.id)}>")
            lines.append("    <status>")
            lines.append(f"      <basic>{escape(pidf_tuple.status_basic)}</basic>")
            lines.append("    </status>")
            if pidf_tuple.contact_uri is not None:
                lines.append(f"    <contact>{escape(pidf_tuple.contact_uri)}</contact>")
            if pidf_tuple.timestamp is not None:
                timestamp = pidf_tuple.timestamp.astimezone(UTC).replace(microsecond=0)
                lines.append(f"    <timestamp>{timestamp.isoformat()}</timestamp>")
            lines.append("  </tuple>")
        lines.append("</presence>")
        return "\r\n".join(lines)

    @classmethod
    def default_instance(cls, **kwargs: object) -> Self:
        defaults: dict[str, object] = {
            "entity": "sip:alice@example.com",
            "tuples": (PIdfTuple(id="t1", contact_uri="sip:alice@example.com"),),
        }
        defaults.update(kwargs)
        return cls.model_validate(defaults)
