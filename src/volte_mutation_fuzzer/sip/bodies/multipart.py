from __future__ import annotations

from typing import Self
from uuid import uuid4

from pydantic import ConfigDict, Field

from volte_mutation_fuzzer.sip.bodies import SIPBody
from volte_mutation_fuzzer.sip.bodies.plain_text import PlainTextBody


class MultipartBody(SIPBody):
    model_config = ConfigDict(extra="forbid")

    parts: list[SIPBody] = Field(min_length=1)
    boundary: str = Field(default_factory=lambda: f"boundary-{uuid4().hex}")

    @property
    def content_type(self) -> str:
        return f"multipart/mixed;boundary={self.boundary}"

    def render(self) -> str:
        lines: list[str] = []
        for part in self.parts:
            lines.extend(
                (
                    f"--{self.boundary}",
                    f"Content-Type: {part.content_type}",
                    "",
                    part.render(),
                )
            )
        lines.append(f"--{self.boundary}--")
        return "\r\n".join(lines) + "\r\n"

    @classmethod
    def default_instance(cls, **kwargs: object) -> Self:
        defaults: dict[str, object] = {
            "parts": [PlainTextBody.default_instance()],
        }
        defaults.update(kwargs)
        return cls.model_validate(defaults)
