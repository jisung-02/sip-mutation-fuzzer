from __future__ import annotations

from typing import ClassVar, Self

from pydantic import Field

from volte_mutation_fuzzer.sip.bodies import SIPBody


class DtmfRelayBody(SIPBody):
    content_type: ClassVar[str] = "application/dtmf-relay"

    signal: str = Field(default="5", min_length=1)
    duration: int = Field(default=160, ge=0)

    def render(self) -> str:
        return f"Signal={self.signal}\r\nDuration={self.duration}\r\n"

    @classmethod
    def default_instance(cls, **kwargs) -> Self:
        return cls(**kwargs)
