import unittest
from types import SimpleNamespace
from unittest import mock

from volte_mutation_fuzzer.dialog.contracts import DialogStep
from volte_mutation_fuzzer.dialog.contracts import DialogStepResult
from volte_mutation_fuzzer.dialog.core import DialogOrchestrator
from volte_mutation_fuzzer.dialog.scenarios import scenario_for_method
from volte_mutation_fuzzer.generator.contracts import DialogContext
from volte_mutation_fuzzer.generator.contracts import GeneratorSettings
from volte_mutation_fuzzer.generator.core import SIPGenerator
from volte_mutation_fuzzer.mutator.contracts import MutationConfig
from volte_mutation_fuzzer.mutator.core import SIPMutator
from volte_mutation_fuzzer.sender.contracts import SendArtifact
from volte_mutation_fuzzer.sender.contracts import SendReceiveResult
from volte_mutation_fuzzer.sender.contracts import SocketObservation
from volte_mutation_fuzzer.sender.contracts import TargetEndpoint

from tests.dialog._dialog_server import (
    DialogUDPResponder,
    make_180_ringing,
    make_200_ok,
    make_200_ok_generic,
    make_486_busy,
)


def _make_target(host: str, port: int) -> TargetEndpoint:
    return TargetEndpoint(host=host, port=port, transport="UDP", timeout_seconds=1.0)


def _make_components() -> tuple[SIPGenerator, SIPMutator]:
    generator = SIPGenerator(GeneratorSettings())
    mutator = SIPMutator()
    return generator, mutator


class TestInviteDialogBye(unittest.TestCase):
    """Full INVITE→200→ACK→BYE(mutated)→200 exchange."""

    def setUp(self) -> None:
        self.server = DialogUDPResponder(
            responses_by_method={
                "INVITE": make_200_ok(),
                "ACK": b"",  # no response to ACK
                "BYE": make_200_ok_generic("BYE"),
            }
        )
        self.server.start()
        self.addCleanup(self.server.close)

    def test_setup_succeeds_and_fuzz_result_present(self) -> None:
        generator, mutator = _make_components()
        scenario = scenario_for_method("BYE")
        assert scenario is not None
        target = _make_target(self.server.host, self.server.port)
        orchestrator = DialogOrchestrator(generator, mutator, target)
        mutation_config = MutationConfig(seed=42, strategy="default", layer="model")

        exchange = orchestrator.execute(scenario, mutation_config)

        assert exchange.setup_succeeded is True
        assert exchange.fuzz_result is not None
        assert exchange.fuzz_result.method == "BYE"
        # INVITE + ACK setup
        assert len(exchange.setup_results) == 2

    def test_invite_was_sent(self) -> None:
        generator, mutator = _make_components()
        scenario = scenario_for_method("BYE")
        assert scenario is not None
        target = _make_target(self.server.host, self.server.port)
        orchestrator = DialogOrchestrator(generator, mutator, target)
        mutation_config = MutationConfig(seed=1, strategy="default", layer="model")

        orchestrator.execute(scenario, mutation_config)

        methods_received = []
        for payload in self.server.received_payloads:
            first_line = payload.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
            methods_received.append(first_line.split(" ", 1)[0])
        assert "INVITE" in methods_received
        assert "BYE" in methods_received

    def test_fuzz_step_carries_resolved_metadata_on_success(self) -> None:
        generator, mutator = _make_components()
        target = _make_target(self.server.host, self.server.port)
        orchestrator = DialogOrchestrator(generator, mutator, target)
        step = DialogStep(method="BYE", role="send", is_fuzz_target=True)
        packet = SimpleNamespace(
            call_id="a84b4c76e66710@pcscf.ims.mnc001.mcc001.3gppnetwork.org",
            cseq=SimpleNamespace(sequence=1),
        )
        mutated = SimpleNamespace(
            profile="delivery_preserving",
            strategy="final_crlf_loss",
        )
        sock = mock.Mock()
        mutation_config = MutationConfig(seed=42, strategy="default", layer="model")

        with mock.patch.object(
            generator,
            "generate_request",
            return_value=packet,
        ), mock.patch.object(
            mutator,
            "mutate",
            return_value=mutated,
        ), mock.patch.object(
            orchestrator,
            "_artifact_from_mutated",
            return_value=SendArtifact.from_wire_text("BYE sip:test SIP/2.0\r\n\r\n"),
        ), mock.patch(
            "volte_mutation_fuzzer.dialog.core.read_udp_observations",
            return_value=[],
        ):
            result = orchestrator._send_step(
                sock,
                step,
                0,
                DialogContext(),
                mutation_config=mutation_config,
            )

        assert result.success is True
        assert result.profile == "delivery_preserving"
        assert result.strategy == "final_crlf_loss"

    def test_fuzz_step_carries_resolved_metadata_on_send_failure(self) -> None:
        generator, mutator = _make_components()
        target = _make_target(self.server.host, self.server.port)
        orchestrator = DialogOrchestrator(generator, mutator, target)
        step = DialogStep(method="BYE", role="send", is_fuzz_target=True)
        packet = SimpleNamespace(
            call_id="a84b4c76e66710@pcscf.ims.mnc001.mcc001.3gppnetwork.org",
            cseq=SimpleNamespace(sequence=1),
        )
        mutated = SimpleNamespace(
            profile="delivery_preserving",
            strategy="final_crlf_loss",
        )
        sock = mock.Mock()
        sock.sendto.side_effect = OSError("send failed")
        mutation_config = MutationConfig(seed=42, strategy="default", layer="model")

        with mock.patch.object(
            generator,
            "generate_request",
            return_value=packet,
        ), mock.patch.object(
            mutator,
            "mutate",
            return_value=mutated,
        ), mock.patch.object(
            orchestrator,
            "_artifact_from_mutated",
            return_value=SendArtifact.from_wire_text("BYE sip:test SIP/2.0\r\n\r\n"),
        ):
            result = orchestrator._send_step(
                sock,
                step,
                0,
                DialogContext(),
                mutation_config=mutation_config,
            )

        assert result.success is False
        assert result.profile == "delivery_preserving"
        assert result.strategy == "final_crlf_loss"
        assert "sendto failed" in (result.error or "")


class TestInviteDialogUpdate(unittest.TestCase):
    """INVITE→200→ACK→UPDATE(mutated)→200→BYE(teardown)→200."""

    def setUp(self) -> None:
        self.server = DialogUDPResponder(
            responses_by_method={
                "INVITE": make_200_ok(),
                "ACK": b"",
                "UPDATE": make_200_ok_generic("UPDATE"),
                "BYE": make_200_ok_generic("BYE"),
            }
        )
        self.server.start()
        self.addCleanup(self.server.close)

    def test_update_exchange_succeeds(self) -> None:
        generator, mutator = _make_components()
        scenario = scenario_for_method("UPDATE")
        assert scenario is not None
        target = _make_target(self.server.host, self.server.port)
        orchestrator = DialogOrchestrator(generator, mutator, target)
        mutation_config = MutationConfig(seed=10, strategy="default", layer="model")

        exchange = orchestrator.execute(scenario, mutation_config)

        assert exchange.setup_succeeded is True
        assert exchange.fuzz_result is not None
        assert exchange.fuzz_result.method == "UPDATE"
        # Teardown BYE should be present
        assert len(exchange.teardown_results) >= 1


class TestInviteCancel(unittest.TestCase):
    """INVITE→180(provisional)→CANCEL(mutated)→200."""

    def setUp(self) -> None:
        # For CANCEL: INVITE must get a provisional (1xx) first
        self.server = DialogUDPResponder(
            responses_by_method={
                "INVITE": make_180_ringing(),
                "CANCEL": make_200_ok_generic("CANCEL"),
            }
        )
        self.server.start()
        self.addCleanup(self.server.close)

    def test_cancel_exchange_succeeds(self) -> None:
        generator, mutator = _make_components()
        scenario = scenario_for_method("CANCEL")
        assert scenario is not None
        target = _make_target(self.server.host, self.server.port)
        orchestrator = DialogOrchestrator(generator, mutator, target)
        mutation_config = MutationConfig(seed=5, strategy="default", layer="model")

        exchange = orchestrator.execute(scenario, mutation_config)

        assert exchange.setup_succeeded is True
        assert exchange.fuzz_result is not None
        assert exchange.fuzz_result.method == "CANCEL"


class TestInviteAck(unittest.TestCase):
    """INVITE→200→ACK(mutated)→BYE(teardown)."""

    def setUp(self) -> None:
        self.server = DialogUDPResponder(
            responses_by_method={
                "INVITE": make_200_ok(),
                "ACK": b"",
                "BYE": make_200_ok_generic("BYE"),
            }
        )
        self.server.start()
        self.addCleanup(self.server.close)

    def test_ack_exchange_succeeds(self) -> None:
        generator, mutator = _make_components()
        scenario = scenario_for_method("ACK")
        assert scenario is not None
        target = _make_target(self.server.host, self.server.port)
        orchestrator = DialogOrchestrator(generator, mutator, target)
        mutation_config = MutationConfig(seed=99, strategy="default", layer="model")

        exchange = orchestrator.execute(scenario, mutation_config)

        assert exchange.setup_succeeded is True
        assert exchange.fuzz_result is not None
        assert exchange.fuzz_result.method == "ACK"


class TestSetupFailureInviteRejected(unittest.TestCase):
    """INVITE → 486 Busy Here → setup_succeeded=False."""

    def setUp(self) -> None:
        self.server = DialogUDPResponder(
            responses_by_method={"INVITE": make_486_busy()}
        )
        self.server.start()
        self.addCleanup(self.server.close)

    def test_setup_fails_on_4xx(self) -> None:
        generator, mutator = _make_components()
        scenario = scenario_for_method("BYE")
        assert scenario is not None
        target = _make_target(self.server.host, self.server.port)
        orchestrator = DialogOrchestrator(generator, mutator, target)
        mutation_config = MutationConfig(seed=0, strategy="default", layer="model")

        exchange = orchestrator.execute(scenario, mutation_config)

        assert exchange.setup_succeeded is False
        assert exchange.fuzz_result is None
        assert exchange.error is not None


class TestSetupFailureInviteTimeout(unittest.TestCase):
    """INVITE gets no response → setup_succeeded=False."""

    def setUp(self) -> None:
        # Server sends nothing for INVITE
        self.server = DialogUDPResponder(responses_by_method={})
        self.server.start()
        self.addCleanup(self.server.close)

    def test_setup_fails_on_timeout(self) -> None:
        generator, mutator = _make_components()
        scenario = scenario_for_method("BYE")
        assert scenario is not None
        target = _make_target(self.server.host, self.server.port)
        target = target.model_copy(update={"timeout_seconds": 0.3})
        orchestrator = DialogOrchestrator(generator, mutator, target)
        mutation_config = MutationConfig(seed=0, strategy="default", layer="model")

        exchange = orchestrator.execute(scenario, mutation_config)

        assert exchange.setup_succeeded is False
        assert exchange.fuzz_result is None


class TestInvitePrackEarlyDialogState(unittest.TestCase):
    def test_execute_seeds_prack_context_from_provisional_invite_response(self) -> None:
        generator, mutator = _make_components()
        scenario = scenario_for_method("PRACK")
        assert scenario is not None
        target = _make_target("127.0.0.1", 5060)
        orchestrator = DialogOrchestrator(generator, mutator, target)
        mutation_config = MutationConfig(seed=7, strategy="default", layer="model")

        provisional = SocketObservation(
            status_code=183,
            reason_phrase="Session Progress",
            headers={
                "to": "<sip:111111@ims.mnc001.mcc001.3gppnetwork.org>;tag=early-183",
                "contact": "<sip:111111@10.0.0.9:5088;transport=udp>",
                "record-route": (
                    "<sip:pcscf1.ims.mnc001.mcc001.3gppnetwork.org;lr>,"
                    "<sip:pcscf2.ims.mnc001.mcc001.3gppnetwork.org;lr>"
                ),
                "require": "100rel",
                "rseq": "73",
                "cseq": "41 INVITE",
            },
            body="",
            raw_text="SIP/2.0 183 Session Progress\r\n\r\n",
            raw_size=0,
            classification="provisional",
        )
        invite_result = SendReceiveResult(
            target=target,
            artifact_kind="packet",
            bytes_sent=128,
            outcome="provisional",
            responses=(provisional,),
            send_started_at=10.0,
            send_completed_at=10.1,
        )
        captured_contexts: list[DialogContext] = []

        def run_step(
            _sock: object,
            step: DialogStep,
            step_index: int,
            context: DialogContext,
            *,
            mutation_config: MutationConfig | None,
        ):
            if step.method == "INVITE":
                return DialogStepResult(
                    step_index=step_index,
                    method="INVITE",
                    role="send",
                    send_result=invite_result,
                    success=True,
                    error=None,
                )
            if step.method == "PRACK":
                captured_contexts.append(context.model_copy(deep=True))
                return DialogStepResult(
                    step_index=step_index,
                    method="PRACK",
                    role="send",
                    send_result=None,
                    success=True,
                    error=None,
                )
            raise AssertionError(f"unexpected step {step.method}")

        socket_factory = mock.MagicMock()
        socket_context = mock.MagicMock()
        socket_context.__enter__.return_value = socket_factory
        socket_context.__exit__.return_value = False

        with mock.patch(
            "volte_mutation_fuzzer.dialog.core.socket.socket",
            return_value=socket_context,
        ), mock.patch.object(orchestrator, "_run_step", side_effect=run_step):
            exchange = orchestrator.execute(scenario, mutation_config)

        assert exchange.setup_succeeded is True
        assert len(captured_contexts) == 1
        context = captured_contexts[0]
        assert context.local_tag == "early-183"
        assert context.request_uri is not None
        assert context.request_uri.host == "10.0.0.9"
        assert context.request_uri.port == 5088
        assert len(context.route_set) == 2
        assert context.route_set[0].host == "pcscf2.ims.mnc001.mcc001.3gppnetwork.org"
        assert context.reliable_invite_rseq == 73
        assert context.reliable_invite_cseq == 41

    def test_execute_rejects_non_reliable_provisional_for_prack(self) -> None:
        generator, mutator = _make_components()
        scenario = scenario_for_method("PRACK")
        assert scenario is not None
        target = _make_target("127.0.0.1", 5060)
        orchestrator = DialogOrchestrator(generator, mutator, target)
        mutation_config = MutationConfig(seed=8, strategy="default", layer="model")

        provisional = SocketObservation(
            status_code=183,
            reason_phrase="Session Progress",
            headers={
                "to": "<sip:111111@ims.mnc001.mcc001.3gppnetwork.org>;tag=early-183",
                "contact": "<sip:111111@10.0.0.9:5088;transport=udp>",
                "record-route": (
                    "<sip:pcscf1.ims.mnc001.mcc001.3gppnetwork.org;lr>,"
                    "<sip:pcscf2.ims.mnc001.mcc001.3gppnetwork.org;lr>"
                ),
                "cseq": "41 INVITE",
            },
            body="",
            raw_text="SIP/2.0 183 Session Progress\r\n\r\n",
            raw_size=0,
            classification="provisional",
        )
        invite_result = SendReceiveResult(
            target=target,
            artifact_kind="packet",
            bytes_sent=128,
            outcome="provisional",
            responses=(provisional,),
            send_started_at=10.0,
            send_completed_at=10.1,
        )

        def run_step(
            _sock: object,
            step: DialogStep,
            step_index: int,
            context: DialogContext,
            *,
            mutation_config: MutationConfig | None,
        ):
            if step.method == "INVITE":
                return DialogStepResult(
                    step_index=step_index,
                    method="INVITE",
                    role="send",
                    send_result=invite_result,
                    success=True,
                    error=None,
                )
            raise AssertionError(f"unexpected step {step.method}")

        socket_factory = mock.MagicMock()
        socket_context = mock.MagicMock()
        socket_context.__enter__.return_value = socket_factory
        socket_context.__exit__.return_value = False

        with mock.patch(
            "volte_mutation_fuzzer.dialog.core.socket.socket",
            return_value=socket_context,
        ), mock.patch.object(orchestrator, "_run_step", side_effect=run_step):
            exchange = orchestrator.execute(scenario, mutation_config)

        assert exchange.setup_succeeded is False
        assert exchange.fuzz_result is None
        assert exchange.error == "reliable provisional response required for PRACK"

    def test_execute_rejects_prack_when_final_invite_response_already_arrived(
        self,
    ) -> None:
        generator, mutator = _make_components()
        scenario = scenario_for_method("PRACK")
        assert scenario is not None
        target = _make_target("127.0.0.1", 5060)
        orchestrator = DialogOrchestrator(generator, mutator, target)
        mutation_config = MutationConfig(seed=9, strategy="default", layer="model")

        reliable_provisional = SocketObservation(
            status_code=183,
            reason_phrase="Session Progress",
            headers={
                "to": "<sip:111111@ims.mnc001.mcc001.3gppnetwork.org>;tag=early-183",
                "contact": "<sip:111111@10.0.0.9:5088;transport=udp>",
                "record-route": (
                    "<sip:pcscf1.ims.mnc001.mcc001.3gppnetwork.org;lr>,"
                    "<sip:pcscf2.ims.mnc001.mcc001.3gppnetwork.org;lr>"
                ),
                "require": "100rel",
                "rseq": "73",
                "cseq": "41 INVITE",
            },
            body="",
            raw_text="SIP/2.0 183 Session Progress\r\n\r\n",
            raw_size=0,
            classification="provisional",
        )
        final_response = SocketObservation(
            status_code=200,
            reason_phrase="OK",
            headers={
                "to": "<sip:111111@ims.mnc001.mcc001.3gppnetwork.org>;tag=final-200",
                "contact": "<sip:111111@10.0.0.9:5090;transport=udp>",
                "cseq": "41 INVITE",
            },
            body="",
            raw_text="SIP/2.0 200 OK\r\n\r\n",
            raw_size=0,
            classification="success",
        )
        invite_result = SendReceiveResult(
            target=target,
            artifact_kind="packet",
            bytes_sent=128,
            outcome="success",
            responses=(reliable_provisional, final_response),
            send_started_at=10.0,
            send_completed_at=10.1,
        )

        def run_step(
            _sock: object,
            step: DialogStep,
            step_index: int,
            context: DialogContext,
            *,
            mutation_config: MutationConfig | None,
        ):
            if step.method == "INVITE":
                return DialogStepResult(
                    step_index=step_index,
                    method="INVITE",
                    role="send",
                    send_result=invite_result,
                    success=True,
                    error=None,
                )
            raise AssertionError(f"unexpected step {step.method}")

        socket_factory = mock.MagicMock()
        socket_context = mock.MagicMock()
        socket_context.__enter__.return_value = socket_factory
        socket_context.__exit__.return_value = False

        with mock.patch(
            "volte_mutation_fuzzer.dialog.core.socket.socket",
            return_value=socket_context,
        ), mock.patch.object(orchestrator, "_run_step", side_effect=run_step):
            exchange = orchestrator.execute(scenario, mutation_config)

        assert exchange.setup_succeeded is False
        assert exchange.fuzz_result is None
        assert exchange.error == "final INVITE response already received for PRACK"

    def test_execute_allows_prack_when_reliable_provisional_is_followed_by_invalid_noise(
        self,
    ) -> None:
        generator, mutator = _make_components()
        scenario = scenario_for_method("PRACK")
        assert scenario is not None
        target = _make_target("127.0.0.1", 5060)
        orchestrator = DialogOrchestrator(generator, mutator, target)
        mutation_config = MutationConfig(seed=10, strategy="default", layer="model")

        reliable_provisional = SocketObservation(
            status_code=183,
            reason_phrase="Session Progress",
            headers={
                "to": "<sip:111111@ims.mnc001.mcc001.3gppnetwork.org>;tag=early-183",
                "contact": "<sip:111111@10.0.0.9:5088;transport=udp>",
                "record-route": (
                    "<sip:pcscf1.ims.mnc001.mcc001.3gppnetwork.org;lr>,"
                    "<sip:pcscf2.ims.mnc001.mcc001.3gppnetwork.org;lr>"
                ),
                "require": "100rel",
                "rseq": "73",
                "cseq": "41 INVITE",
            },
            body="",
            raw_text="SIP/2.0 183 Session Progress\r\n\r\n",
            raw_size=0,
            classification="provisional",
        )
        invalid_noise = SocketObservation(
            status_code=None,
            reason_phrase=None,
            headers={},
            body="",
            raw_text="not sip at all",
            raw_size=len("not sip at all"),
            classification="invalid",
        )
        invite_result = SendReceiveResult(
            target=target,
            artifact_kind="packet",
            bytes_sent=128,
            outcome="invalid_response",
            responses=(reliable_provisional, invalid_noise),
            send_started_at=10.0,
            send_completed_at=10.1,
        )
        captured_contexts: list[DialogContext] = []

        def run_step(
            _sock: object,
            step: DialogStep,
            step_index: int,
            context: DialogContext,
            *,
            mutation_config: MutationConfig | None,
        ):
            if step.method == "INVITE":
                return DialogStepResult(
                    step_index=step_index,
                    method="INVITE",
                    role="send",
                    send_result=invite_result,
                    success=True,
                    error=None,
                )
            if step.method == "PRACK":
                captured_contexts.append(context.model_copy(deep=True))
                return DialogStepResult(
                    step_index=step_index,
                    method="PRACK",
                    role="send",
                    send_result=None,
                    success=True,
                    error=None,
                )
            raise AssertionError(f"unexpected step {step.method}")

        socket_factory = mock.MagicMock()
        socket_context = mock.MagicMock()
        socket_context.__enter__.return_value = socket_factory
        socket_context.__exit__.return_value = False

        with mock.patch(
            "volte_mutation_fuzzer.dialog.core.socket.socket",
            return_value=socket_context,
        ), mock.patch.object(orchestrator, "_run_step", side_effect=run_step):
            exchange = orchestrator.execute(scenario, mutation_config)

        assert exchange.setup_succeeded is True
        assert exchange.error is None
        assert exchange.fuzz_result is not None
        assert exchange.fuzz_result.method == "PRACK"
        assert len(captured_contexts) == 1
        assert captured_contexts[0].reliable_invite_rseq == 73

    def test_execute_allows_prack_when_reliable_provisional_is_followed_by_unrelated_valid_final(
        self,
    ) -> None:
        generator, mutator = _make_components()
        scenario = scenario_for_method("PRACK")
        assert scenario is not None
        target = _make_target("127.0.0.1", 5060)
        orchestrator = DialogOrchestrator(generator, mutator, target)
        mutation_config = MutationConfig(seed=11, strategy="default", layer="model")

        reliable_provisional = SocketObservation(
            status_code=183,
            reason_phrase="Session Progress",
            headers={
                "to": "<sip:111111@ims.mnc001.mcc001.3gppnetwork.org>;tag=early-183",
                "contact": "<sip:111111@10.0.0.9:5088;transport=udp>",
                "record-route": (
                    "<sip:pcscf1.ims.mnc001.mcc001.3gppnetwork.org;lr>,"
                    "<sip:pcscf2.ims.mnc001.mcc001.3gppnetwork.org;lr>"
                ),
                "require": "100rel",
                "rseq": "73",
                "cseq": "41 INVITE",
            },
            body="",
            raw_text="SIP/2.0 183 Session Progress\r\n\r\n",
            raw_size=0,
            classification="provisional",
        )
        unrelated_final = SocketObservation(
            status_code=200,
            reason_phrase="OK",
            headers={
                "call-id": "other-call@pcscf.ims.mnc001.mcc001.3gppnetwork.org",
                "cseq": "5 OPTIONS",
            },
            body="",
            raw_text="SIP/2.0 200 OK\r\nCSeq: 5 OPTIONS\r\n\r\n",
            raw_size=0,
            classification="success",
        )
        invite_result = SendReceiveResult(
            target=target,
            artifact_kind="packet",
            bytes_sent=128,
            outcome="success",
            responses=(reliable_provisional, unrelated_final),
            send_started_at=10.0,
            send_completed_at=10.1,
        )
        captured_contexts: list[DialogContext] = []

        def run_step(
            _sock: object,
            step: DialogStep,
            step_index: int,
            context: DialogContext,
            *,
            mutation_config: MutationConfig | None,
        ):
            if step.method == "INVITE":
                return DialogStepResult(
                    step_index=step_index,
                    method="INVITE",
                    role="send",
                    send_result=invite_result,
                    success=True,
                    error=None,
                )
            if step.method == "PRACK":
                captured_contexts.append(context.model_copy(deep=True))
                return DialogStepResult(
                    step_index=step_index,
                    method="PRACK",
                    role="send",
                    send_result=None,
                    success=True,
                    error=None,
                )
            raise AssertionError(f"unexpected step {step.method}")

        socket_factory = mock.MagicMock()
        socket_context = mock.MagicMock()
        socket_context.__enter__.return_value = socket_factory
        socket_context.__exit__.return_value = False

        with mock.patch(
            "volte_mutation_fuzzer.dialog.core.socket.socket",
            return_value=socket_context,
        ), mock.patch.object(orchestrator, "_run_step", side_effect=run_step):
            exchange = orchestrator.execute(scenario, mutation_config)

        assert exchange.setup_succeeded is True
        assert exchange.error is None
        assert exchange.fuzz_result is not None
        assert exchange.fuzz_result.method == "PRACK"
        assert len(captured_contexts) == 1
        assert captured_contexts[0].reliable_invite_rseq == 73
