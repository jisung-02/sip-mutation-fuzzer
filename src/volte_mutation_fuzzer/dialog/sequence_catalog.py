"""Sequence-mode scenario catalog — transaction/dialog state attack patterns.

These scenarios exist because single-packet mutation cannot express state
bugs: retransmitted transactions, teardown before provisional responses, and
duplicate teardowns are ordering anomalies, not payload anomalies. Each
scenario is a flat list of :class:`SequenceStep` primitives (send, optionally
mutated, optionally repeated) executed against one dialog context.

All scenarios are INVITE-dialog based and carry their own cleanup steps so a
campaign does not leave the UE ringing.
"""

from volte_mutation_fuzzer.dialog.contracts import SequenceScenario, SequenceStep


def _invite_retransmit() -> SequenceScenario:
    return SequenceScenario(
        name="invite_retransmit",
        description=(
            "Send the same (mutated) INVITE N times back-to-back before any "
            "teardown — stresses duplicate-transaction handling in the UE and "
            "the network side. Cleanup: CANCEL."
        ),
        steps=(
            SequenceStep(method="INVITE", mutate=True, repeat=2, delay_seconds=0.0),
            SequenceStep(method="CANCEL", delay_seconds=0.5),
        ),
    )


def _invite_early_bye() -> SequenceScenario:
    return SequenceScenario(
        name="invite_early_bye",
        description=(
            "MUTATED INVITE immediately followed by a MUTATED BYE in the same "
            "dialog, without waiting for any provisional response — teardown "
            "before the dialog exists on the far side. Cleanup: CANCEL in case "
            "the BYE was rejected as unreachable."
        ),
        steps=(
            SequenceStep(method="INVITE", mutate=True),
            SequenceStep(method="BYE", mutate=True, delay_seconds=0.0),
            SequenceStep(method="CANCEL", delay_seconds=0.5),
        ),
    )


def _invite_double_bye() -> SequenceScenario:
    return SequenceScenario(
        name="invite_double_bye",
        description=(
            "Establish a dialog with a plain INVITE/ACK, then send a MUTATED "
            "BYE twice — the second BYE targets an already-terminated dialog."
        ),
        steps=(
            SequenceStep(method="INVITE"),
            SequenceStep(method="ACK"),
            SequenceStep(method="BYE", mutate=True),
            SequenceStep(method="BYE", mutate=True, delay_seconds=0.2),
        ),
    )


def _cancel_retransmit() -> SequenceScenario:
    return SequenceScenario(
        name="cancel_retransmit",
        description=(
            "Plain INVITE, then the same MUTATED CANCEL sent twice in a row — "
            "duplicate cancellation of one pending transaction."
        ),
        steps=(
            SequenceStep(method="INVITE"),
            SequenceStep(method="CANCEL", mutate=True, repeat=2, delay_seconds=0.0),
        ),
    )


_BUILDERS = {
    "invite_retransmit": _invite_retransmit,
    "invite_early_bye": _invite_early_bye,
    "invite_double_bye": _invite_double_bye,
    "cancel_retransmit": _cancel_retransmit,
}

SEQUENCE_SCENARIO_NAMES: tuple[str, ...] = tuple(sorted(_BUILDERS))


def build_sequence_scenario(
    name: str,
    *,
    repeat_override: int | None = None,
) -> SequenceScenario:
    """Build a catalog scenario by name.

    ``repeat_override`` replaces the ``repeat`` of every repeated step (steps
    with ``repeat > 1``), so ``--repeats N`` scales retransmission pressure
    without editing the catalog.
    """
    builder = _BUILDERS.get(name.strip().lower())
    if builder is None:
        raise ValueError(
            f"unknown sequence scenario: {name} "
            f"(available: {', '.join(SEQUENCE_SCENARIO_NAMES)})"
        )
    scenario = builder()
    if repeat_override is None or repeat_override < 1:
        return scenario
    steps = tuple(
        step.model_copy(update={"repeat": repeat_override})
        if step.repeat > 1
        else step
        for step in scenario.steps
    )
    return scenario.model_copy(update={"steps": steps})


__all__ = [
    "SEQUENCE_SCENARIO_NAMES",
    "build_sequence_scenario",
]
