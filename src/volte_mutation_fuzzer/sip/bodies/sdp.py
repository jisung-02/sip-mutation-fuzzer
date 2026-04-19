from __future__ import annotations

from typing import ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field

from volte_mutation_fuzzer.sip.bodies import SIPBody


class SDPOrigin(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = "-"
    sess_id: int = 0
    sess_version: int = 0
    net_type: Literal["IN"] = "IN"
    addr_type: Literal["IP4", "IP6"] = "IP4"
    address: str = "0.0.0.0"


class SDPConnection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    net_type: Literal["IN"] = "IN"
    addr_type: Literal["IP4", "IP6"] = "IP4"
    address: str = "0.0.0.0"


class SDPTiming(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start: int = 0
    stop: int = 0


class SDPMediaDescription(BaseModel):
    model_config = ConfigDict(extra="forbid")

    media: Literal["audio", "video", "application", "text"] = "audio"
    port: int = Field(default=49170, ge=0, le=65535)
    proto: str = "RTP/AVP"
    formats: tuple[int, ...] = Field(default=(96, 97), min_length=1)
    attributes: tuple[str, ...] = (
        "rtpmap:96 AMR-WB/16000",
        "rtpmap:97 AMR/8000",
        "fmtp:97 mode-set=0,2,5,7",
        "ptime:20",
        "sendrecv",
    )


class SDPBody(SIPBody):
    content_type: ClassVar[str] = "application/sdp"

    version: int = 0
    origin: SDPOrigin = Field(default_factory=SDPOrigin)
    session_name: str = "-"
    connection: SDPConnection = Field(default_factory=SDPConnection)
    timing: SDPTiming = Field(default_factory=SDPTiming)
    media_descriptions: tuple[SDPMediaDescription, ...] = Field(min_length=1)

    def render(self) -> str:
        lines = [
            f"v={self.version}",
            (
                f"o={self.origin.username} {self.origin.sess_id} "
                f"{self.origin.sess_version} {self.origin.net_type} "
                f"{self.origin.addr_type} {self.origin.address}"
            ),
            f"s={self.session_name}",
            (
                f"c={self.connection.net_type} "
                f"{self.connection.addr_type} {self.connection.address}"
            ),
            f"t={self.timing.start} {self.timing.stop}",
        ]
        for media_description in self.media_descriptions:
            rendered_formats = " ".join(
                str(payload_type) for payload_type in media_description.formats
            )
            lines.append(
                "m="
                f"{media_description.media} {media_description.port} "
                f"{media_description.proto} {rendered_formats}"
            )
            lines.extend(f"a={attribute}" for attribute in media_description.attributes)
        return "\r\n".join(lines) + "\r\n"

    @classmethod
    def default_instance(cls, **kwargs: object) -> Self:
        defaults: dict[str, object] = {
            "media_descriptions": (SDPMediaDescription(),),
        }
        defaults.update(kwargs)
        return cls.model_validate(defaults)
