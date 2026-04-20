from __future__ import annotations

from typing import ClassVar, Self

from pydantic import BaseModel, ConfigDict, Field

from volte_mutation_fuzzer.sip.bodies import SIPBody


class VoiceMessageSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    new_messages: int = Field(default=0, ge=0)
    old_messages: int = Field(default=0, ge=0)


class MessageSummaryBody(SIPBody):
    content_type: ClassVar[str] = "application/simple-message-summary"

    messages_waiting: bool = True
    message_account: str = Field(
        default="sip:voicemail@ims.mnc001.mcc001.3gppnetwork.org", min_length=1
    )
    voice_message: VoiceMessageSummary | None = Field(
        default_factory=VoiceMessageSummary
    )

    def render(self) -> str:
        lines = [
            f"Messages-Waiting: {'yes' if self.messages_waiting else 'no'}",
            f"Message-Account: {self.message_account}",
        ]
        if self.voice_message is not None:
            lines.append(
                "Voice-Message: "
                f"{self.voice_message.new_messages}/{self.voice_message.old_messages}"
            )
        return "\r\n".join(lines) + "\r\n"

    @classmethod
    def default_instance(cls, **kwargs) -> Self:
        return cls(**kwargs)
