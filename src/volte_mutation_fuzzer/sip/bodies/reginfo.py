from __future__ import annotations

from typing import ClassVar, Literal, Self
from xml.sax.saxutils import escape, quoteattr

from pydantic import BaseModel, ConfigDict, Field

from volte_mutation_fuzzer.sip.bodies import SIPBody


class RegContact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    state: Literal["active", "terminated"] = "active"
    event: Literal["registered", "refreshed", "deactivated"] = "registered"
    uri: str = Field(min_length=1)


class Registration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    aor: str = Field(min_length=1)
    id: str = Field(min_length=1)
    state: Literal["active", "terminated"] = "active"
    contacts: tuple[RegContact, ...] = Field(min_length=1)


class ReginfoBody(SIPBody):
    content_type: ClassVar[str] = "application/reginfo+xml"

    version: int = 0
    state: Literal["full", "partial"] = "full"
    registrations: tuple[Registration, ...] = Field(min_length=1)

    def render(self) -> str:
        lines = [
            (
                "<reginfo xmlns="
                f"{quoteattr('urn:ietf:params:xml:ns:reginfo')} "
                f"version={quoteattr(str(self.version))} "
                f"state={quoteattr(self.state)}>"
            ),
        ]
        for registration in self.registrations:
            lines.append(
                "  <registration "
                f"aor={quoteattr(registration.aor)} "
                f"id={quoteattr(registration.id)} "
                f"state={quoteattr(registration.state)}>"
            )
            for contact in registration.contacts:
                lines.append(
                    "    <contact "
                    f"id={quoteattr(contact.id)} "
                    f"state={quoteattr(contact.state)} "
                    f"event={quoteattr(contact.event)}>"
                )
                lines.append(f"      <uri>{escape(contact.uri)}</uri>")
                lines.append("    </contact>")
            lines.append("  </registration>")
        lines.append("</reginfo>")
        return "\r\n".join(lines)

    @classmethod
    def default_instance(cls, **kwargs: object) -> Self:
        defaults: dict[str, object] = {
            "registrations": (
                Registration(
                    aor="sip:alice@example.com",
                    id="reg-1",
                    contacts=(
                        RegContact(
                            id="contact-1",
                            uri="sip:alice@example.com",
                        ),
                    ),
                ),
            ),
        }
        defaults.update(kwargs)
        return cls.model_validate(defaults)
