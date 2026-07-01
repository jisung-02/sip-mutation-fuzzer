from __future__ import annotations

from typing import ClassVar, Self
from xml.sax.saxutils import escape, quoteattr

from pydantic import Field

from volte_mutation_fuzzer.sip.bodies import SIPBody


class ImsServiceBody(SIPBody):
    content_type: ClassVar[str] = "application/3gpp-ims+xml"

    service_type: str = Field(default="emergency", min_length=1)
    reason: str = Field(default="Alternative service available", min_length=1)

    def render(self) -> str:
        lines = [
            f"<ims-3gpp xmlns={quoteattr('urn:3gpp:ns:ims:xml')}>",
            "  <service-info>",
            f"    <service-type>{escape(self.service_type)}</service-type>",
            f"    <reason>{escape(self.reason)}</reason>",
            "  </service-info>",
            "</ims-3gpp>",
        ]
        return "\r\n".join(lines)

    @classmethod
    def default_instance(cls, **kwargs) -> Self:
        return cls(**kwargs)
