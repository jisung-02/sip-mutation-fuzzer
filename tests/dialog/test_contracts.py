import pytest
from pydantic import ValidationError

from volte_mutation_fuzzer.dialog.contracts import (
    DialogExchangeResult,
    DialogScenario,
    DialogScenarioType,
    DialogStep,
    DialogStepResult,
)


class TestDialogStep:
    def test_send_step(self) -> None:
        step = DialogStep(method="INVITE", role="send")
        assert step.method == "INVITE"
        assert step.role == "send"
        assert step.is_fuzz_target is False

    def test_expect_step(self) -> None:
        step = DialogStep(
            method="INVITE",
            role="expect",
            expect_status_min=200,
            expect_status_max=299,
        )
        assert step.expect_status_min == 200
        assert step.expect_status_max == 299

    def test_fuzz_target_flag(self) -> None:
        step = DialogStep(method="BYE", role="send", is_fuzz_target=True)
        assert step.is_fuzz_target is True

    def test_invalid_role(self) -> None:
        with pytest.raises(ValidationError):
            DialogStep(method="BYE", role="invalid")  # type: ignore[arg-type]

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            DialogStep(method="BYE", role="send", unknown_field="x")  # type: ignore[call-arg]


class TestDialogScenario:
    def test_basic_construction(self) -> None:
        scenario = DialogScenario(
            scenario_type=DialogScenarioType.invite_dialog,
            fuzz_method="BYE",
            setup_steps=(
                DialogStep(
                    method="INVITE",
                    role="send",
                    expect_status_min=200,
                    expect_status_max=299,
                ),
                DialogStep(method="ACK", role="send"),
            ),
            fuzz_step=DialogStep(method="BYE", role="send", is_fuzz_target=True),
            teardown_steps=(),
        )
        assert scenario.fuzz_method == "BYE"
        assert len(scenario.setup_steps) == 2
        assert scenario.fuzz_step.is_fuzz_target is True

    def test_default_empty_teardown(self) -> None:
        scenario = DialogScenario(
            scenario_type=DialogScenarioType.invite_cancel,
            fuzz_method="CANCEL",
            setup_steps=(),
            fuzz_step=DialogStep(method="CANCEL", role="send", is_fuzz_target=True),
        )
        assert scenario.teardown_steps == ()


class TestDialogStepResult:
    def test_successful_result(self) -> None:
        result = DialogStepResult(
            step_index=0,
            method="INVITE",
            role="send",
            success=True,
        )
        assert result.success is True
        assert result.error is None

    def test_failed_result(self) -> None:
        result = DialogStepResult(
            step_index=1,
            method="ACK",
            role="send",
            success=False,
            error="timeout",
        )
        assert result.success is False
        assert result.error == "timeout"


class TestDialogExchangeResult:
    def test_setup_failed(self) -> None:
        result = DialogExchangeResult(
            scenario_type=DialogScenarioType.invite_dialog,
            setup_succeeded=False,
            error="INVITE got 486",
        )
        assert result.setup_succeeded is False
        assert result.fuzz_result is None
        assert result.setup_results == ()

    def test_successful_exchange(self) -> None:
        fuzz = DialogStepResult(
            step_index=2,
            method="BYE",
            role="send",
            success=True,
        )
        result = DialogExchangeResult(
            scenario_type=DialogScenarioType.invite_dialog,
            setup_results=(
                DialogStepResult(
                    step_index=0, method="INVITE", role="send", success=True
                ),
                DialogStepResult(step_index=1, method="ACK", role="send", success=True),
            ),
            fuzz_result=fuzz,
            setup_succeeded=True,
        )
        assert result.setup_succeeded is True
        assert result.fuzz_result is not None
        assert result.fuzz_result.method == "BYE"
