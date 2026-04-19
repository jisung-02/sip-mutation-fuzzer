from __future__ import annotations

from typing import ClassVar, Literal, Self
from xml.sax.saxutils import escape, quoteattr

from pydantic import BaseModel, ConfigDict, Field

from volte_mutation_fuzzer.sip.bodies import SIPBody


class ConferenceUser(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity: str = Field(min_length=1)
    display_text: str = Field(min_length=1)
    status: Literal["connected", "disconnected", "on-hold"] = "connected"


class ConferenceInfoBody(SIPBody):
    content_type: ClassVar[str] = "application/conference-info+xml"

    version: int = 0
    state: Literal["full", "partial"] = "full"
    entity: str = Field(min_length=1)
    subject: str | None = None
    users: tuple[ConferenceUser, ...] = Field(min_length=1)

    def render(self) -> str:
        lines = [
            (
                "<conference-info xmlns="
                f"{quoteattr('urn:ietf:params:xml:ns:conference-info')} "
                f"version={quoteattr(str(self.version))} "
                f"state={quoteattr(self.state)} "
                f"entity={quoteattr(self.entity)}>"
            ),
        ]
        if self.subject is not None:
            lines.append("  <conference-description>")
            lines.append(f"    <subject>{escape(self.subject)}</subject>")
            lines.append("  </conference-description>")
        lines.append("  <users>")
        for user in self.users:
            lines.append(f"    <user entity={quoteattr(user.entity)}>")
            lines.append(
                f"      <display-text>{escape(user.display_text)}</display-text>"
            )
            lines.append(f"      <status>{escape(user.status)}</status>")
            lines.append("    </user>")
        lines.append("  </users>")
        lines.append("</conference-info>")
        return "\r\n".join(lines)

    @classmethod
    def default_instance(cls, **kwargs: object) -> Self:
        defaults: dict[str, object] = {
            "entity": "sip:conf@example.com",
            "users": (
                ConferenceUser(
                    entity="sip:alice@example.com",
                    display_text="Alice",
                ),
            ),
        }
        defaults.update(kwargs)
        return cls.model_validate(defaults)
