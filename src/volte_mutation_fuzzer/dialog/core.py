"""DialogOrchestrator — multi-step SIP dialog execution for stateful fuzzing."""

import socket
import time

from volte_mutation_fuzzer.dialog.contracts import (
    DialogExchangeResult,
    DialogScenario,
    DialogScenarioType,
    DialogStep,
    DialogStepResult,
)
from volte_mutation_fuzzer.dialog.state_extractor import (
    extract_dialog_state_from_responses,
)
from volte_mutation_fuzzer.generator.contracts import DialogContext, RequestSpec
from volte_mutation_fuzzer.generator.core import SIPGenerator
from volte_mutation_fuzzer.mutator.contracts import MutationConfig, MutatedCase
from volte_mutation_fuzzer.mutator.core import SIPMutator
from volte_mutation_fuzzer.sender.contracts import (
    CorrelationKey,
    DeliveryOutcome,
    SendArtifact,
    SendReceiveResult,
    SocketObservation,
    TargetEndpoint,
)
from volte_mutation_fuzzer.sender.core import read_udp_observations
from volte_mutation_fuzzer.sip.common import SIPMethod
from volte_mutation_fuzzer.sip.render import render_packet_bytes

_MAX_TEARDOWN_RESPONSES = 4


class DialogOrchestrator:
    """Executes a multi-step SIP dialog scenario for stateful fuzzing.

    Manages a single UDP socket for the entire dialog so that all messages
    share the same source port — required for the target to correlate them.

    Setup and teardown messages are sent without mutation. Only the designated
    fuzz target step receives the mutated payload.
    """

    def __init__(
        self,
        generator: SIPGenerator,
        mutator: SIPMutator,
        target: TargetEndpoint,
    ) -> None:
        self._generator = generator
        self._mutator = mutator
        self._target = target

    def execute(
        self,
        scenario: DialogScenario,
        mutation_config: MutationConfig,
    ) -> DialogExchangeResult:
        """Run the full dialog scenario and return the exchange result."""
        assert self._target.host is not None
        assert self._target.port is not None

        context = DialogContext()
        setup_results: list[DialogStepResult] = []

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self._target.timeout_seconds)

            # --- Setup phase ---
            for idx, step in enumerate(scenario.setup_steps):
                result = self._run_step(sock, step, idx, context, mutation_config=None)
                setup_results.append(result)

                if not result.success:
                    return DialogExchangeResult(
                        scenario_type=scenario.scenario_type,
                        setup_results=tuple(setup_results),
                        setup_succeeded=False,
                        error=result.error or "setup step failed",
                    )

                if step.method == "INVITE" and result.send_result is not None:
                    if (
                        scenario.scenario_type == DialogScenarioType.invite_prack
                        and any(
                            self._is_final_invite_response(
                                observation,
                                expected_call_id=result.send_result.correlation_key.call_id,
                            )
                            for observation in result.send_result.responses
                        )
                    ):
                        return DialogExchangeResult(
                            scenario_type=scenario.scenario_type,
                            setup_results=tuple(setup_results),
                            setup_succeeded=False,
                            error="final INVITE response already received for PRACK",
                        )

                    extract_dialog_state_from_responses(
                        result.send_result.responses,
                        context,
                    )

                    if (
                        scenario.scenario_type == DialogScenarioType.invite_prack
                        and context.reliable_invite_rseq is None
                    ):
                        return DialogExchangeResult(
                            scenario_type=scenario.scenario_type,
                            setup_results=tuple(setup_results),
                            setup_succeeded=False,
                            error="reliable provisional response required for PRACK",
                        )

            # --- Fuzz phase ---
            fuzz_step_idx = len(setup_results)
            fuzz_result = self._run_step(
                sock,
                scenario.fuzz_step,
                fuzz_step_idx,
                context,
                mutation_config=mutation_config,
            )

            # --- Teardown phase (best-effort) ---
            teardown_results: list[DialogStepResult] = []
            teardown_offset = fuzz_step_idx + 1
            for idx, step in enumerate(scenario.teardown_steps, start=teardown_offset):
                try:
                    td_result = self._run_step(
                        sock, step, idx, context, mutation_config=None
                    )
                    teardown_results.append(td_result)
                except Exception:
                    # teardown failures do not affect the fuzz verdict
                    break

        return DialogExchangeResult(
            scenario_type=scenario.scenario_type,
            setup_results=tuple(setup_results),
            fuzz_result=fuzz_result,
            teardown_results=tuple(teardown_results),
            setup_succeeded=True,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_step(
        self,
        sock: socket.socket,
        step: DialogStep,
        step_index: int,
        context: DialogContext,
        *,
        mutation_config: MutationConfig | None,
    ) -> DialogStepResult:
        """Execute one dialog step — either send (with optional mutation) or expect."""
        if step.role == "expect":
            return self._expect_step(sock, step, step_index)
        return self._send_step(sock, step, step_index, context, mutation_config)

    def _send_step(
        self,
        sock: socket.socket,
        step: DialogStep,
        step_index: int,
        context: DialogContext,
        mutation_config: MutationConfig | None,
    ) -> DialogStepResult:
        """Generate (and optionally mutate) a request, send it, and collect responses."""
        # Forward the mutation seed into baseline generation so seeded
        # dialog scenarios are byte-reproducible. Without this, the
        # generator falls back to ``uuid4`` for every Via branch / Call-ID
        # / tag in the setup → fuzz → teardown sequence, defeating
        # campaign-level determinism for dialog runtime methods.
        baseline_seed = mutation_config.seed if mutation_config is not None else None
        try:
            packet = self._generator.generate_request(
                self._build_request_spec(step),
                context,
                seed=baseline_seed,
            )
        except Exception as exc:
            return DialogStepResult(
                step_index=step_index,
                method=step.method,
                role="send",
                success=False,
                error=f"generate_request failed: {exc}",
            )

        # Apply mutation only on the fuzz target step
        mutated: MutatedCase | None = None
        if step.is_fuzz_target and mutation_config is not None:
            try:
                mutated = self._mutator.mutate(packet, mutation_config)
            except Exception as exc:
                return DialogStepResult(
                    step_index=step_index,
                    method=step.method,
                    role="send",
                    success=False,
                    error=f"mutate failed: {exc}",
                )

        resolved_profile = getattr(mutated, "profile", None)
        resolved_strategy = getattr(mutated, "strategy", None)

        # Build payload
        if mutated is not None:
            artifact = self._artifact_from_mutated(mutated)
            payload = self._build_payload(artifact)
            correlation_key = CorrelationKey(
                call_id=getattr(packet, "call_id", None),
                cseq_method=SIPMethod(step.method),
                cseq_sequence=getattr(getattr(packet, "cseq", None), "sequence", None),
            )
        else:
            payload = render_packet_bytes(packet)
            correlation_key = CorrelationKey(
                call_id=getattr(packet, "call_id", None),
                cseq_method=SIPMethod(step.method),
                cseq_sequence=getattr(getattr(packet, "cseq", None), "sequence", None),
            )

        assert self._target.host is not None
        assert self._target.port is not None

        started_at = time.time()
        try:
            sock.sendto(payload, (self._target.host, self._target.port))
        except OSError as exc:
            return DialogStepResult(
                step_index=step_index,
                method=step.method,
                role="send",
                success=False,
                profile=resolved_profile,
                strategy=resolved_strategy,
                error=f"sendto failed: {exc}",
            )

        # Collect responses for this send step
        # ACK does not generate a response per RFC 3261
        if step.method == "ACK":
            observations: list[SocketObservation] = []
        else:
            observations = read_udp_observations(sock, collect_all_responses=True)

        finished_at = time.time()
        send_result = self._build_send_result(
            payload, observations, correlation_key, started_at, finished_at
        )

        # For setup send steps that expect a response, check it
        if step.expect_status_min is not None:
            ok = self._check_response(
                observations,
                step.expect_status_min,
                step.expect_status_max,
            )
            if not ok:
                final = send_result.final_response
                got = final.status_code if final else None
                return DialogStepResult(
                    step_index=step_index,
                    method=step.method,
                    role="send",
                    send_result=send_result,
                    profile=resolved_profile,
                    strategy=resolved_strategy,
                    success=False,
                    error=f"expected {step.expect_status_min}-{step.expect_status_max}, got {got}",
                )

        return DialogStepResult(
            step_index=step_index,
            method=step.method,
            role="send",
            send_result=send_result,
            profile=resolved_profile,
            strategy=resolved_strategy,
            success=True,
        )

    @staticmethod
    def _build_request_spec(step: DialogStep) -> RequestSpec:
        return RequestSpec(
            method=SIPMethod(step.method),
            body_kind=step.body_kind,
            event_package=step.event_package,
            info_package=step.info_package,
        )

    def _expect_step(
        self,
        sock: socket.socket,
        step: DialogStep,
        step_index: int,
    ) -> DialogStepResult:
        """Wait for and validate a response without sending anything."""
        try:
            observations = read_udp_observations(sock, collect_all_responses=True)
        except Exception as exc:
            return DialogStepResult(
                step_index=step_index,
                method=step.method,
                role="expect",
                success=False,
                error=f"receive failed: {exc}",
            )

        if not observations:
            return DialogStepResult(
                step_index=step_index,
                method=step.method,
                role="expect",
                success=False,
                error="timeout waiting for response",
            )

        send_result = self._build_send_result(
            b"", observations, CorrelationKey(), time.time(), time.time()
        )

        if step.expect_status_min is not None:
            ok = self._check_response(
                observations,
                step.expect_status_min,
                step.expect_status_max,
            )
            if not ok:
                final = send_result.final_response
                got = final.status_code if final else None
                return DialogStepResult(
                    step_index=step_index,
                    method=step.method,
                    role="expect",
                    send_result=send_result,
                    success=False,
                    error=f"expected {step.expect_status_min}-{step.expect_status_max}, got {got}",
                )

        return DialogStepResult(
            step_index=step_index,
            method=step.method,
            role="expect",
            send_result=send_result,
            success=True,
        )

    @staticmethod
    def _check_response(
        observations: list[SocketObservation],
        status_min: int,
        status_max: int | None,
    ) -> bool:
        """Return True if any observation falls within the expected status range."""
        hi = status_max if status_max is not None else status_min
        for obs in observations:
            if obs.status_code is not None and status_min <= obs.status_code <= hi:
                return True
        return False

    @staticmethod
    def _is_final_invite_response(
        observation: SocketObservation,
        *,
        expected_call_id: str | None,
    ) -> bool:
        if observation.status_code is None or observation.status_code < 200:
            return False

        cseq_header = observation.headers.get("cseq")
        if cseq_header is None:
            return False

        cseq_parts = cseq_header.strip().split()
        if len(cseq_parts) < 2 or cseq_parts[1].upper() != "INVITE":
            return False

        call_id = observation.headers.get("call-id")
        if (
            expected_call_id is not None
            and call_id is not None
            and call_id.strip() != expected_call_id
        ):
            return False

        return True

    @staticmethod
    def _artifact_from_mutated(mutated: MutatedCase) -> SendArtifact:
        if mutated.final_layer == "wire" and mutated.wire_text is not None:
            return SendArtifact.from_wire_text(mutated.wire_text)
        if mutated.final_layer == "byte" and mutated.packet_bytes is not None:
            return SendArtifact.from_packet_bytes(mutated.packet_bytes)
        packet = mutated.mutated_packet or mutated.original_packet
        return SendArtifact.from_packet(packet)

    @staticmethod
    def _build_payload(artifact: SendArtifact) -> bytes:
        if artifact.packet is not None:
            return render_packet_bytes(artifact.packet)
        if artifact.wire_text is not None:
            return artifact.wire_text.encode("utf-8")
        assert artifact.packet_bytes is not None
        return artifact.packet_bytes

    @staticmethod
    def _resolve_outcome(
        observations: list[SocketObservation],
    ) -> DeliveryOutcome:
        if not observations:
            return "timeout"
        selected = next(
            (o for o in reversed(observations) if o.classification != "provisional"),
            observations[-1],
        )
        if selected.classification == "success":
            return "success"
        if selected.classification == "provisional":
            return "provisional"
        if selected.classification == "invalid":
            return "invalid_response"
        return "error"

    def _build_send_result(
        self,
        payload: bytes,
        observations: list[SocketObservation],
        correlation_key: CorrelationKey,
        started_at: float,
        finished_at: float,
    ) -> SendReceiveResult:
        return SendReceiveResult(
            target=self._target,
            artifact_kind="packet",
            correlation_key=correlation_key,
            bytes_sent=len(payload),
            outcome=self._resolve_outcome(observations),
            responses=tuple(observations),
            send_started_at=started_at,
            send_completed_at=finished_at,
        )


__all__ = ["DialogOrchestrator"]
