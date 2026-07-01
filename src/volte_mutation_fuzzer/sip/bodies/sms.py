from __future__ import annotations

from typing import ClassVar, Self

from pydantic import Field, field_validator

from volte_mutation_fuzzer.sip.bodies import SIPBody


class SmsBody(SIPBody):
    content_type: ClassVar[str] = "application/vnd.3gpp.sms"

    payload: str = Field(default="01020304", min_length=2)

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value: str) -> str:
        if len(value) % 2 != 0:
            raise ValueError("payload must contain an even number of hex characters")
        try:
            bytes.fromhex(value)
        except ValueError as error:
            raise ValueError("payload must be valid hex") from error
        return value.upper()

    def render(self) -> str:
        return self.payload

    @classmethod
    def default_instance(cls, **kwargs) -> Self:
        return cls(**kwargs)
