"""Dialog scenario registry — maps SIP methods to their fuzzing scenarios."""

from volte_mutation_fuzzer.dialog.contracts import (
    DialogScenario,
    DialogScenarioType,
    DialogStep,
)

# Methods that use the full INVITE→200→ACK→[target]→BYE pattern
_INVITE_DIALOG_METHODS = frozenset({"BYE", "UPDATE", "REFER", "INFO"})

# Stateless methods — no dialog setup needed
_STATELESS_METHODS = frozenset(
    {"OPTIONS", "INVITE", "MESSAGE", "REGISTER", "SUBSCRIBE", "PUBLISH", "NOTIFY"}
)

_INFO_DEFAULT_PACKAGE = "dtmf"


def _build_invite_dialog(method: str) -> DialogScenario:
    """INVITE→200 OK→ACK→[target]→expect any → BYE (unless target is BYE)."""
    teardown: tuple[DialogStep, ...] = ()
    if method != "BYE":
        teardown = (DialogStep(method="BYE", role="send"),)

    info_package = _INFO_DEFAULT_PACKAGE if method == "INFO" else None

    return DialogScenario(
        scenario_type=DialogScenarioType.invite_dialog,
        fuzz_method=method,
        setup_steps=(
            DialogStep(
                method="INVITE",
                role="send",
                expect_status_min=200,
                expect_status_max=299,
            ),
            DialogStep(method="ACK", role="send"),
        ),
        fuzz_step=DialogStep(
            method=method,
            role="send",
            is_fuzz_target=True,
            info_package=info_package,
        ),
        teardown_steps=teardown,
    )


def _build_invite_cancel() -> DialogScenario:
    """INVITE→expect 1xx→[CANCEL]→expect 2xx(CANCEL)."""
    return DialogScenario(
        scenario_type=DialogScenarioType.invite_cancel,
        fuzz_method="CANCEL",
        setup_steps=(
            DialogStep(
                method="INVITE",
                role="send",
                expect_status_min=100,
                expect_status_max=199,
            ),
        ),
        fuzz_step=DialogStep(
            method="CANCEL",
            role="send",
            is_fuzz_target=True,
        ),
        teardown_steps=(),
    )


def _build_invite_ack() -> DialogScenario:
    """INVITE→expect 2xx→[ACK]→BYE (teardown)."""
    return DialogScenario(
        scenario_type=DialogScenarioType.invite_ack,
        fuzz_method="ACK",
        setup_steps=(
            DialogStep(
                method="INVITE",
                role="send",
                expect_status_min=200,
                expect_status_max=299,
            ),
        ),
        fuzz_step=DialogStep(
            method="ACK",
            role="send",
            is_fuzz_target=True,
        ),
        teardown_steps=(DialogStep(method="BYE", role="send"),),
    )


def _build_invite_prack() -> DialogScenario:
    """INVITE→expect 1xx→[PRACK]."""
    return DialogScenario(
        scenario_type=DialogScenarioType.invite_prack,
        fuzz_method="PRACK",
        setup_steps=(
            DialogStep(
                method="INVITE",
                role="send",
                expect_status_min=100,
                expect_status_max=199,
            ),
        ),
        fuzz_step=DialogStep(
            method="PRACK",
            role="send",
            is_fuzz_target=True,
        ),
        teardown_steps=(),
    )


def scenario_for_method(method: str) -> DialogScenario | None:
    """Return the dialog scenario for the given SIP method.

    Returns None for stateless methods that do not require dialog setup.
    """
    if method in _STATELESS_METHODS:
        return None
    if method in _INVITE_DIALOG_METHODS:
        return _build_invite_dialog(method)
    if method == "CANCEL":
        return _build_invite_cancel()
    if method == "ACK":
        return _build_invite_ack()
    if method == "PRACK":
        return _build_invite_prack()
    return None


__all__ = ["scenario_for_method"]
