from __future__ import annotations

from typing import ClassVar, Self

from pydantic import Field

from volte_mutation_fuzzer.sip.bodies import SIPBody


class PlainTextBody(SIPBody):
    content_type: ClassVar[str] = "text/plain"

    text: str = Field(default="Hello from VoLTE mutation fuzzer.")

    def render(self) -> str:
        return self.text

    @classmethod
    def default_instance(cls, **kwargs) -> Self:
        return cls(**kwargs)
