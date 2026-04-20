from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from volte_mutation_fuzzer.sender.contracts import SendReceiveResult


class DialogScenarioType(StrEnum):
    """Supported dialog scenario types."""

    invite_dialog = "invite_dialog"
    invite_cancel = "invite_cancel"
    invite_ack = "invite_ack"
    invite_prack = "invite_prack"


class DialogStep(BaseModel):
    """One step in a dialog scenario."""

    model_config = ConfigDict(extra="forbid")

    method: str
    role: Literal["send", "expect"]
    is_fuzz_target: bool = False
    body_kind: str | None = None
    event_package: str | None = None
    info_package: str | None = None
    expect_status_min: int | None = None
    expect_status_max: int | None = None

    @field_validator("body_kind", "event_package", "info_package", mode="before")
    @classmethod
    def _normalize_text(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        return stripped or None


class DialogScenario(BaseModel):
    """Blueprint for a multi-message dialog fuzzing exchange."""

    model_config = ConfigDict(extra="forbid")

    scenario_type: DialogScenarioType
    fuzz_method: str
    setup_steps: tuple[DialogStep, ...]
    fuzz_step: DialogStep
    teardown_steps: tuple[DialogStep, ...] = ()


class DialogStepResult(BaseModel):
    """Result of one step in a dialog exchange."""

    model_config = ConfigDict(extra="forbid")

    step_index: int
    method: str
    role: Literal["send", "expect"]
    send_result: SendReceiveResult | None = None
    profile: str | None = None
    strategy: str | None = None
    success: bool
    error: str | None = None


class DialogExchangeResult(BaseModel):
    """Full result of a dialog fuzzing exchange."""

    model_config = ConfigDict(extra="forbid")

    scenario_type: DialogScenarioType
    setup_results: tuple[DialogStepResult, ...] = ()
    fuzz_result: DialogStepResult | None = None
    teardown_results: tuple[DialogStepResult, ...] = ()
    setup_succeeded: bool
    error: str | None = None


__all__ = [
    "DialogExchangeResult",
    "DialogScenario",
    "DialogScenarioType",
    "DialogStep",
    "DialogStepResult",
]
