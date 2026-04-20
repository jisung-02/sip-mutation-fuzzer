"""Explicit SIP request completion registry."""

from dataclasses import dataclass
from enum import StrEnum

from volte_mutation_fuzzer.sip.common import SIPMethod
from volte_mutation_fuzzer.sip.requests import REQUEST_MODELS_BY_METHOD


class PacketCompletionTier(StrEnum):
    """How far a request method is complete in the current stack."""

    runtime_complete = "runtime_complete"
    generator_complete = "generator_complete"


class PacketRuntimePath(StrEnum):
    """Honest runtime paths that can be exercised in the current codebase."""

    stateless = "stateless"
    invite_dialog = "invite_dialog"
    invite_ack = "invite_ack"
    invite_cancel = "invite_cancel"
    invite_prack = "invite_prack"
    unsupported = "unsupported"


class PacketBaselineScope(StrEnum):
    """Baseline scope used when validating a method completion tier."""

    real_ue_baseline = "real_ue_baseline"
    invite_dialog = "invite_dialog"
    stateless = "stateless"
    generator_only = "generator_only"


@dataclass(frozen=True, slots=True)
class PacketCompletion:
    tier: PacketCompletionTier
    runtime_path: PacketRuntimePath
    baseline_scope: PacketBaselineScope
    note: str


PACKET_COMPLETENESS: dict[SIPMethod, PacketCompletion] = {
    SIPMethod.INVITE: PacketCompletion(
        tier=PacketCompletionTier.runtime_complete,
        runtime_path=PacketRuntimePath.stateless,
        baseline_scope=PacketBaselineScope.real_ue_baseline,
        note="Primary real-UE baseline for inbound INVITE handling.",
    ),
    SIPMethod.ACK: PacketCompletion(
        tier=PacketCompletionTier.runtime_complete,
        runtime_path=PacketRuntimePath.invite_ack,
        baseline_scope=PacketBaselineScope.invite_dialog,
        note="Exercises the ACK leg after a successful INVITE transaction.",
    ),
    SIPMethod.BYE: PacketCompletion(
        tier=PacketCompletionTier.runtime_complete,
        runtime_path=PacketRuntimePath.invite_dialog,
        baseline_scope=PacketBaselineScope.invite_dialog,
        note="Uses the established INVITE dialog teardown path.",
    ),
    SIPMethod.CANCEL: PacketCompletion(
        tier=PacketCompletionTier.runtime_complete,
        runtime_path=PacketRuntimePath.invite_cancel,
        baseline_scope=PacketBaselineScope.invite_dialog,
        note="Uses the early-dialog INVITE cancellation path.",
    ),
    SIPMethod.INFO: PacketCompletion(
        tier=PacketCompletionTier.runtime_complete,
        runtime_path=PacketRuntimePath.invite_dialog,
        baseline_scope=PacketBaselineScope.invite_dialog,
        note="Routes through the established INVITE dialog path.",
    ),
    SIPMethod.MESSAGE: PacketCompletion(
        tier=PacketCompletionTier.runtime_complete,
        runtime_path=PacketRuntimePath.stateless,
        baseline_scope=PacketBaselineScope.stateless,
        note="Stateless MESSAGE handling is exercised directly in runtime flows.",
    ),
    SIPMethod.NOTIFY: PacketCompletion(
        tier=PacketCompletionTier.generator_complete,
        runtime_path=PacketRuntimePath.unsupported,
        baseline_scope=PacketBaselineScope.generator_only,
        note="Generator coverage exists, but there is no honest runtime path yet.",
    ),
    SIPMethod.OPTIONS: PacketCompletion(
        tier=PacketCompletionTier.runtime_complete,
        runtime_path=PacketRuntimePath.stateless,
        baseline_scope=PacketBaselineScope.stateless,
        note="Stateless OPTIONS handling is available in runtime flows.",
    ),
    SIPMethod.PRACK: PacketCompletion(
        tier=PacketCompletionTier.runtime_complete,
        runtime_path=PacketRuntimePath.invite_prack,
        baseline_scope=PacketBaselineScope.invite_dialog,
        note="Exercises the reliable provisional response path.",
    ),
    SIPMethod.PUBLISH: PacketCompletion(
        tier=PacketCompletionTier.generator_complete,
        runtime_path=PacketRuntimePath.unsupported,
        baseline_scope=PacketBaselineScope.generator_only,
        note="Generator coverage exists, but runtime support is not modeled yet.",
    ),
    SIPMethod.REFER: PacketCompletion(
        tier=PacketCompletionTier.runtime_complete,
        runtime_path=PacketRuntimePath.invite_dialog,
        baseline_scope=PacketBaselineScope.invite_dialog,
        note="Uses the INVITE dialog referral path.",
    ),
    SIPMethod.REGISTER: PacketCompletion(
        tier=PacketCompletionTier.generator_complete,
        runtime_path=PacketRuntimePath.unsupported,
        baseline_scope=PacketBaselineScope.generator_only,
        note="Generator coverage exists, but runtime handling is not modeled yet.",
    ),
    SIPMethod.SUBSCRIBE: PacketCompletion(
        tier=PacketCompletionTier.runtime_complete,
        runtime_path=PacketRuntimePath.stateless,
        baseline_scope=PacketBaselineScope.stateless,
        note="Initial SUBSCRIBE transactions can be exercised directly in runtime flows.",
    ),
    SIPMethod.UPDATE: PacketCompletion(
        tier=PacketCompletionTier.runtime_complete,
        runtime_path=PacketRuntimePath.invite_dialog,
        baseline_scope=PacketBaselineScope.invite_dialog,
        note="Uses the established INVITE dialog update path.",
    ),
}


def _validate_registry() -> None:
    expected_methods = set(REQUEST_MODELS_BY_METHOD)
    registered_methods = set(PACKET_COMPLETENESS)
    if registered_methods != expected_methods:
        missing = sorted(method.value for method in expected_methods - registered_methods)
        extra = sorted(method.value for method in registered_methods - expected_methods)
        raise RuntimeError(
            "packet completeness registry is out of sync with REQUEST_MODELS_BY_METHOD"
            f" (missing={missing}, extra={extra})"
        )


_validate_registry()

RUNTIME_COMPLETE_METHODS: tuple[SIPMethod, ...] = tuple(
    method
    for method, completion in PACKET_COMPLETENESS.items()
    if completion.tier is PacketCompletionTier.runtime_complete
)

GENERATOR_COMPLETE_METHODS: tuple[SIPMethod, ...] = tuple(
    method
    for method, completion in PACKET_COMPLETENESS.items()
    if completion.tier is PacketCompletionTier.generator_complete
)


def get_packet_completion(method: SIPMethod) -> PacketCompletion:
    return PACKET_COMPLETENESS[method]


__all__ = [
    "GENERATOR_COMPLETE_METHODS",
    "PACKET_COMPLETENESS",
    "PacketBaselineScope",
    "PacketCompletion",
    "PacketCompletionTier",
    "PacketRuntimePath",
    "RUNTIME_COMPLETE_METHODS",
    "get_packet_completion",
]
