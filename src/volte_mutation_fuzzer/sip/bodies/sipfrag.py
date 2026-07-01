from __future__ import annotations

from typing import ClassVar, Self

from pydantic import Field

from volte_mutation_fuzzer.sip.bodies import SIPBody


class SipfragBody(SIPBody):
    content_type: ClassVar[str] = "message/sipfrag;version=2.0"

    sip_version: str = "SIP/2.0"
    status_code: int = Field(default=200, ge=100, le=699)
    reason_phrase: str = Field(default="OK", min_length=1)

    def render(self) -> str:
        return f"{self.sip_version} {self.status_code} {self.reason_phrase}"

    @classmethod
    def default_instance(cls, **kwargs) -> Self:
        return cls(**kwargs)
