from __future__ import annotations

from typing import ClassVar, Literal, Self
from xml.sax.saxutils import escape, quoteattr

from pydantic import BaseModel, ConfigDict, Field

from volte_mutation_fuzzer.sip.bodies import SIPBody


class DialogParticipant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity: str = Field(min_length=1)


class Dialog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    call_id: str = Field(min_length=1)
    local_tag: str = Field(min_length=1)
    remote_tag: str = Field(min_length=1)
    direction: Literal["initiator", "recipient"] = "initiator"
    state: str = "confirmed"
    local: DialogParticipant
    remote: DialogParticipant


class DialogInfoBody(SIPBody):
    content_type: ClassVar[str] = "application/dialog-info+xml"

    version: int = 0
    state: Literal["full", "partial"] = "full"
    entity: str = Field(min_length=1)
    dialogs: tuple[Dialog, ...] = Field(min_length=1)

    def render(self) -> str:
        lines = [
            (
                "<dialog-info xmlns="
                f"{quoteattr('urn:ietf:params:xml:ns:dialog-info')} "
                f"version={quoteattr(str(self.version))} "
                f"state={quoteattr(self.state)} "
                f"entity={quoteattr(self.entity)}>"
            ),
        ]
        for dialog in self.dialogs:
            lines.append(
                "  <dialog "
                f"id={quoteattr(dialog.id)} "
                f"call-id={quoteattr(dialog.call_id)} "
                f"local-tag={quoteattr(dialog.local_tag)} "
                f"remote-tag={quoteattr(dialog.remote_tag)} "
                f"direction={quoteattr(dialog.direction)}>"
            )
            lines.append(f"    <state>{escape(dialog.state)}</state>")
            lines.append("    <local>")
            lines.append(f"      <identity>{escape(dialog.local.identity)}</identity>")
            lines.append("    </local>")
            lines.append("    <remote>")
            lines.append(f"      <identity>{escape(dialog.remote.identity)}</identity>")
            lines.append("    </remote>")
            lines.append("  </dialog>")
        lines.append("</dialog-info>")
        return "\r\n".join(lines)

    @classmethod
    def default_instance(cls, **kwargs: object) -> Self:
        defaults: dict[str, object] = {
            "entity": "sip:111111@ims.mnc001.mcc001.3gppnetwork.org",
            "dialogs": (
                Dialog(
                    id="dialog-1",
                    call_id="a84b4c76e66710@pcscf.ims.mnc001.mcc001.3gppnetwork.org",
                    local_tag="9fxced76sl",
                    remote_tag="873294202",
                    local=DialogParticipant(
                        identity="sip:111111@ims.mnc001.mcc001.3gppnetwork.org"
                    ),
                    remote=DialogParticipant(
                        identity="sip:remote@ims.mnc001.mcc001.3gppnetwork.org"
                    ),
                ),
            ),
        }
        defaults.update(kwargs)
        return cls.model_validate(defaults)
