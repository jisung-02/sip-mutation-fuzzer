from typing import Any, Literal, Self, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from volte_mutation_fuzzer.sip.requests import SIPRequest
from volte_mutation_fuzzer.sip.responses import SIPResponse

PacketModel: TypeAlias = SIPRequest | SIPResponse


class MutationConfig(BaseModel):
    """Execution settings shared by the mutator service, CLI, and tests."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    seed: int | None = Field(default=None, ge=0)
    strategy: str = Field(default="default", min_length=1)
    layer: Literal["model", "wire", "byte", "auto"] = "auto"
    max_operations: int = Field(default=1, ge=1)
    preserve_valid_model: bool = True

    @field_validator("strategy", mode="before")
    @classmethod
    def _normalize_strategy(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        return stripped or None


class MutationTarget(BaseModel):
    """Explicit location selector describing where a mutation should apply."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    layer: Literal["model", "wire", "byte"]
    path: str = Field(min_length=1)
    alias: str | None = None
    operator_hint: str | None = None

    @field_validator("path", "alias", "operator_hint", mode="before")
    @classmethod
    def _normalize_text(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        return stripped or None


class MutationRecord(BaseModel):
    """Structured record describing one applied mutation operation."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    layer: Literal["model", "wire", "byte"]
    target: MutationTarget
    operator: str = Field(min_length=1)
    before: Any = None
    after: Any = None
    note: str | None = None

    @field_validator("operator", "note", mode="before")
    @classmethod
    def _normalize_text(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        return stripped or None

    @model_validator(mode="after")
    def _ensure_target_layer_matches(self) -> Self:
        if self.layer != self.target.layer:
            raise ValueError("record layer must match target.layer")
        return self


class MutatedCase(BaseModel):
    """Final mutator result bundle spanning model, wire, and byte outputs."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    original_packet: PacketModel
    mutated_packet: PacketModel | None = None
    wire_text: str | None = None
    packet_bytes: bytes | None = None
    records: tuple[MutationRecord, ...] = Field(default_factory=tuple)
    seed: int | None = Field(default=None, ge=0)
    strategy: str = Field(default="default", min_length=1)
    final_layer: Literal["model", "wire", "byte"]

    @field_validator("strategy", mode="before")
    @classmethod
    def _normalize_strategy(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        return stripped or None

    @model_validator(mode="after")
    def _ensure_layer_artifact_exists(self) -> Self:
        if self.final_layer == "model" and self.mutated_packet is None:
            raise ValueError("model results require mutated_packet")
        if self.final_layer == "wire" and self.wire_text is None:
            raise ValueError("wire results require wire_text")
        if self.final_layer == "byte" and self.packet_bytes is None:
            raise ValueError("byte results require packet_bytes")
        return self


__all__ = [
    "MutatedCase",
    "MutationConfig",
    "MutationRecord",
    "MutationTarget",
    "PacketModel",
]
