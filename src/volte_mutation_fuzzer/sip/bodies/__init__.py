from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar, Self, TypeAlias

from pydantic import BaseModel, ConfigDict


class SIPBody(BaseModel, ABC):
    model_config = ConfigDict(extra="forbid")

    content_type: ClassVar[str]

    @abstractmethod
    def render(self) -> str:
        """Serialize the body into SIP wire-format text."""

    @classmethod
    @abstractmethod
    def default_instance(cls, **kwargs) -> Self:
        """Return a minimal valid instance suitable for generation."""


from .conference_info import ConferenceInfoBody, ConferenceUser  # noqa: E402
from .dialog_info import Dialog, DialogInfoBody, DialogParticipant  # noqa: E402
from .dtmf import DtmfRelayBody  # noqa: E402
from .ims_service import ImsServiceBody  # noqa: E402
from .message_summary import MessageSummaryBody, VoiceMessageSummary  # noqa: E402
from .multipart import MultipartBody  # noqa: E402
from .pidf import PIdfBody, PIdfTuple  # noqa: E402
from .plain_text import PlainTextBody  # noqa: E402
from .reginfo import RegContact, ReginfoBody, Registration  # noqa: E402
from .sdp import (  # noqa: E402
    SDPBody,
    SDPConnection,
    SDPMediaDescription,
    SDPOrigin,
    SDPTiming,
)
from .sipfrag import SipfragBody  # noqa: E402
from .sms import SmsBody  # noqa: E402

BodyModel: TypeAlias = (
    ConferenceInfoBody
    | DialogInfoBody
    | DtmfRelayBody
    | ImsServiceBody
    | MessageSummaryBody
    | MultipartBody
    | PIdfBody
    | PlainTextBody
    | ReginfoBody
    | SDPBody
    | SipfragBody
    | SmsBody
)

__all__ = [
    "BodyModel",
    "ConferenceInfoBody",
    "ConferenceUser",
    "Dialog",
    "DialogInfoBody",
    "DialogParticipant",
    "DtmfRelayBody",
    "ImsServiceBody",
    "MessageSummaryBody",
    "MultipartBody",
    "PIdfBody",
    "PIdfTuple",
    "PlainTextBody",
    "RegContact",
    "Registration",
    "ReginfoBody",
    "SDPBody",
    "SDPConnection",
    "SDPMediaDescription",
    "SDPOrigin",
    "SDPTiming",
    "SIPBody",
    "SipfragBody",
    "SmsBody",
    "VoiceMessageSummary",
]
