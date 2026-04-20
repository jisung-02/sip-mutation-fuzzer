import json
import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from tests.sender._server import TCPResponder, UDPResponder
from volte_mutation_fuzzer.generator.cli import app
from volte_mutation_fuzzer.sender.contracts import SendReceiveResult, TargetEndpoint
from volte_mutation_fuzzer.sender.real_ue import ResolvedRealUETarget, RouteCheckResult

REALISTIC_CALL_ID = "a84b4c76e66710@pcscf.ims.mnc001.mcc001.3gppnetwork.org"
REALISTIC_LOCAL_TAG = "9fxced76sl"
REALISTIC_CONTEXT_JSON = (
    f'{{"call_id":"{REALISTIC_CALL_ID}","local_tag":"{REALISTIC_LOCAL_TAG}","local_cseq":1}}'
)
REALISTIC_OPTIONS_WIRE = "OPTIONS sip:111111@10.20.20.8:8100 SIP/2.0\r\nContent-Length: 0\r\n\r\n"
REALISTIC_MT_INVITE = (
    "INVITE sip:111111@10.20.20.8:8100;alias=10.20.20.8~8101~1 SIP/2.0\r\n"
    "Content-Length: 0\r\n\r\n"
)


class SIPSenderCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_send_request_command_generates_and_sends_packet(self) -> None:
        responder = UDPResponder(
            responses=(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n",)
        )
        responder.start()
        self.addCleanup(responder.close)

        result = self.runner.invoke(
            app,
            [
                "send",
                "request",
                "OPTIONS",
                "--target-host",
                responder.host,
                "--target-port",
                str(responder.port),
                "--timeout",
                "0.5",
            ],
        )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["artifact_kind"], "packet")
        self.assertEqual(payload["outcome"], "success")
        self.assertEqual(payload["responses"][-1]["status_code"], 200)

    def test_send_response_command_accepts_native_ipsec_mode(self) -> None:
        responder = UDPResponder(
            responses=(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n",)
        )
        responder.start()
        self.addCleanup(responder.close)

        result = self.runner.invoke(
            app,
            [
                "send",
                "response",
                "200",
                "OPTIONS",
                "--context",
                REALISTIC_CONTEXT_JSON,
                "--target-host",
                responder.host,
                "--target-port",
                str(responder.port),
                "--ipsec-mode",
                "native",
                "--timeout",
                "0.5",
            ],
        )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["outcome"], "success")
        self.assertEqual(payload["target"]["ipsec_mode"], "native")

    def test_send_response_command_accepts_softphone_null_and_bypass_ipsec_modes(
        self,
    ) -> None:
        responder = UDPResponder(
            responses=(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n",)
        )
        responder.start()
        self.addCleanup(responder.close)

        for ipsec_mode in ("null", "bypass"):
            with self.subTest(ipsec_mode=ipsec_mode):
                with patch(
                    "volte_mutation_fuzzer.sender.core.SIPSenderReactor.send_packet",
                    side_effect=lambda packet, target, collect_all_responses=False: SendReceiveResult(
                        target=target,
                        artifact_kind="packet",
                        bytes_sent=0,
                        outcome="success",
                        send_started_at=0.0,
                        send_completed_at=0.0,
                    ),
                ) as mock_send_packet:
                    result = self.runner.invoke(
                        app,
                        [
                            "send",
                            "response",
                            "200",
                            "OPTIONS",
                            "--context",
                            REALISTIC_CONTEXT_JSON,
                            "--target-host",
                            responder.host,
                            "--target-port",
                            str(responder.port),
                            "--ipsec-mode",
                            ipsec_mode,
                            "--timeout",
                            "0.5",
                        ],
                    )

                self.assertEqual(result.exit_code, 0, msg=result.output)
                payload = json.loads(result.stdout)
                self.assertEqual(payload["outcome"], "success")
                called_target = mock_send_packet.call_args.args[1]
                self.assertEqual(called_target.mode, "softphone")
                self.assertEqual(called_target.ipsec_mode, ipsec_mode)
                self.assertIsNone(called_target.bind_container)

    def test_send_response_command_shapes_real_ue_null_and_bypass_targets(self) -> None:
        for ipsec_mode in ("null", "bypass"):
            with self.subTest(ipsec_mode=ipsec_mode):
                with patch(
                    "volte_mutation_fuzzer.sender.core.SIPSenderReactor.send_artifact",
                    side_effect=lambda artifact, target, collect_all_responses=False: SendReceiveResult(
                        target=target,
                        artifact_kind=artifact.artifact_kind,
                        bytes_sent=0,
                        outcome="success",
                        send_started_at=0.0,
                        send_completed_at=0.0,
                    ),
                ) as mock_send_artifact:
                    result = self.runner.invoke(
                        app,
                        [
                            "send",
                            "response",
                            "200",
                            "OPTIONS",
                            "--context",
                            REALISTIC_CONTEXT_JSON,
                            "--mode",
                            "real-ue-direct",
                            "--target-msisdn",
                            "111111",
                            "--ipsec-mode",
                            ipsec_mode,
                            "--timeout",
                            "0.5",
                        ],
                    )

                self.assertEqual(result.exit_code, 0, msg=result.output)
                called_target = mock_send_artifact.call_args.args[1]
                self.assertEqual(called_target.mode, "real-ue-direct")
                self.assertEqual(called_target.ipsec_mode, ipsec_mode)
                self.assertEqual(called_target.bind_container, "pcscf")
                self.assertIsNone(called_target.source_ip)

    def test_send_packet_command_accepts_generator_packet_json_from_stdin(self) -> None:
        baseline_result = self.runner.invoke(app, ["request", "OPTIONS"])
        self.assertEqual(baseline_result.exit_code, 0, msg=baseline_result.output)

        responder = UDPResponder(
            responses=(b"SIP/2.0 486 Busy Here\r\nContent-Length: 0\r\n\r\n",)
        )
        responder.start()
        self.addCleanup(responder.close)

        result = self.runner.invoke(
            app,
            [
                "send",
                "packet",
                "--target-host",
                responder.host,
                "--target-port",
                str(responder.port),
                "--timeout",
                "0.5",
            ],
            input=baseline_result.stdout,
        )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["outcome"], "error")
        self.assertEqual(payload["responses"][-1]["status_code"], 486)

    def test_send_packet_command_accepts_raw_wire_text(self) -> None:
        responder = UDPResponder(
            responses=(b"SIP/2.0 180 Ringing\r\nContent-Length: 0\r\n\r\n",)
        )
        responder.start()
        self.addCleanup(responder.close)

        result = self.runner.invoke(
            app,
            [
                "send",
                "packet",
                "--target-host",
                responder.host,
                "--target-port",
                str(responder.port),
                "--timeout",
                "0.5",
            ],
            input=REALISTIC_OPTIONS_WIRE,
        )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["artifact_kind"], "wire")
        self.assertEqual(payload["outcome"], "provisional")

    def test_send_packet_command_accepts_native_ipsec_mode(self) -> None:
        responder = UDPResponder(
            responses=(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n",)
        )
        responder.start()
        self.addCleanup(responder.close)

        result = self.runner.invoke(
            app,
            [
                "send",
                "packet",
                "--target-host",
                responder.host,
                "--target-port",
                str(responder.port),
                "--ipsec-mode",
                "native",
                "--timeout",
                "0.5",
            ],
            input=REALISTIC_OPTIONS_WIRE,
        )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["outcome"], "success")
        self.assertEqual(payload["target"]["ipsec_mode"], "native")

    def test_send_packet_command_rejects_host_only_native_real_ue_invocation(
        self,
    ) -> None:
        result = self.runner.invoke(
            app,
            [
                "send",
                "packet",
                "--mode",
                "real-ue-direct",
                "--target-host",
                "127.0.0.1",
                "--ipsec-mode",
                "native",
                "--timeout",
                "0.5",
            ],
            input=REALISTIC_OPTIONS_WIRE,
        )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("requires --target-msisdn", result.output)

    def test_send_packet_command_shapes_real_ue_null_and_bypass_targets(self) -> None:
        for ipsec_mode in ("null", "bypass"):
            with self.subTest(ipsec_mode=ipsec_mode):
                with patch(
                    "volte_mutation_fuzzer.sender.core.SIPSenderReactor.send_artifact",
                    side_effect=lambda artifact, target, collect_all_responses=False: SendReceiveResult(
                        target=target,
                        artifact_kind=artifact.artifact_kind,
                        bytes_sent=0,
                        outcome="success",
                        send_started_at=0.0,
                        send_completed_at=0.0,
                    ),
                ) as mock_send_artifact:
                    result = self.runner.invoke(
                        app,
                        [
                            "send",
                            "packet",
                            "--mode",
                            "real-ue-direct",
                            "--target-msisdn",
                            "111111",
                            "--ipsec-mode",
                            ipsec_mode,
                            "--timeout",
                            "0.5",
                        ],
                        input=REALISTIC_OPTIONS_WIRE,
                    )

                self.assertEqual(result.exit_code, 0, msg=result.output)
                called_target = mock_send_artifact.call_args.args[1]
                self.assertEqual(called_target.mode, "real-ue-direct")
                self.assertEqual(called_target.ipsec_mode, ipsec_mode)
                self.assertEqual(called_target.bind_container, "pcscf")
                self.assertIsNone(called_target.source_ip)

    @patch(
        "volte_mutation_fuzzer.sender.core.check_route_to_target",
        return_value=RouteCheckResult(True, "loopback"),
    )
    def test_send_request_direct_mode_supports_explicit_target_host(
        self, _mock_route: object
    ) -> None:
        responder = UDPResponder(
            responses=(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n",)
        )
        responder.start()
        self.addCleanup(responder.close)

        result = self.runner.invoke(
            app,
            [
                "send",
                "request",
                "OPTIONS",
                "--mode",
                "real-ue-direct",
                "--target-host",
                responder.host,
                "--target-port",
                str(responder.port),
                "--timeout",
                "0.5",
            ],
        )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["outcome"], "success")
        self.assertEqual(payload["target"]["host"], responder.host)
        self.assertEqual(payload["target"]["mode"], "real-ue-direct")

    @patch(
        "volte_mutation_fuzzer.sender.core.check_route_to_target",
        return_value=RouteCheckResult(True, "loopback"),
    )
    def test_send_request_direct_mode_rejects_host_only_native_invocation(
        self, _mock_route: object
    ) -> None:
        result = self.runner.invoke(
            app,
            [
                "send",
                "request",
                "OPTIONS",
                "--mode",
                "real-ue-direct",
                "--target-host",
                "127.0.0.1",
                "--ipsec-mode",
                "native",
                "--timeout",
                "0.5",
            ],
        )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("requires --target-msisdn", result.output)

    @patch(
        "volte_mutation_fuzzer.sender.core.check_route_to_target",
        return_value=RouteCheckResult(True, "loopback"),
    )
    def test_send_request_direct_mode_resolves_msisdn(
        self, _mock_route: object
    ) -> None:
        responder = UDPResponder(
            responses=(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n",)
        )
        responder.start()
        self.addCleanup(responder.close)

        def _resolve(
            target: TargetEndpoint, impi: str | None = None
        ) -> ResolvedRealUETarget:
            self.assertIsNone(target.port)
            return ResolvedRealUETarget(
                host=responder.host,
                port=responder.port,
                label="msisdn:222222",
                observer_events=(
                    f"resolver:test:222222->{responder.host}:{responder.port}",
                ),
            )

        with patch(
            "volte_mutation_fuzzer.sender.core.RealUEDirectResolver.resolve",
            side_effect=_resolve,
        ):
            result = self.runner.invoke(
                app,
                [
                    "send",
                    "request",
                    "OPTIONS",
                    "--mode",
                    "real-ue-direct",
                    "--target-msisdn",
                    "222222",
                    "--timeout",
                    "0.5",
                ],
            )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["outcome"], "success")
        self.assertEqual(payload["target"]["msisdn"], "222222")
        self.assertEqual(payload["target"]["host"], responder.host)
        self.assertIn(
            f"resolver:test:222222->{responder.host}:{responder.port}",
            payload["observer_events"],
        )

    def test_send_request_mt_direct_mode_rejects_host_only_invocation(self) -> None:
        result = self.runner.invoke(
            app,
            [
                "send",
                "request",
                "OPTIONS",
                "--mode",
                "real-ue-direct",
                "--mt",
                "--target-host",
                "127.0.0.1",
                "--impi",
                "001010000123511",
                "--timeout",
                "0.5",
            ],
        )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("requires --target-msisdn", result.output)

    def test_send_request_mt_direct_mode_uses_native_ipsec_target_shape(
        self,
    ) -> None:
        with (
            patch(
                "volte_mutation_fuzzer.generator.mt_packet.build_mt_packet",
                return_value=REALISTIC_MT_INVITE,
            ),
            patch(
                "volte_mutation_fuzzer.sender.real_ue.RealUEDirectResolver.resolve",
                return_value=ResolvedRealUETarget(
                    host="10.20.20.8",
                    port=5060,
                    label="msisdn:111111",
                    observer_events=("resolver:test:111111->10.20.20.8:5060",),
                ),
            ),
            patch(
                "volte_mutation_fuzzer.sender.real_ue.RealUEDirectResolver.resolve_protected_ports",
                return_value=(15100, 15101),
            ),
            patch(
                "volte_mutation_fuzzer.sender.core.SIPSenderReactor.send_artifact",
                side_effect=lambda _artifact, target, collect_all_responses=False: SendReceiveResult(
                    target=target,
                    artifact_kind="wire",
                    bytes_sent=0,
                    outcome="success",
                    send_started_at=0.0,
                    send_completed_at=0.0,
                ),
            ) as mock_send_artifact,
        ):
            result = self.runner.invoke(
                app,
                [
                    "send",
                    "request",
                    "OPTIONS",
                    "--mode",
                    "real-ue-direct",
                    "--mt",
                    "--target-msisdn",
                    "111111",
                    "--impi",
                    "001010000123511",
                    "--ipsec-mode",
                    "native",
                    "--timeout",
                    "0.5",
                ],
            )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["outcome"], "success")
        called_artifact = mock_send_artifact.call_args.args[0]
        called_target = mock_send_artifact.call_args.args[1]
        self.assertFalse(called_artifact.preserve_via)
        self.assertFalse(called_artifact.preserve_contact)
        self.assertEqual(called_target.ipsec_mode, "native")
        self.assertEqual(called_target.bind_container, "pcscf")
        self.assertIsNone(called_target.source_ip)
        self.assertIsNone(called_target.bind_port)

    def test_send_request_mt_direct_mode_uses_pcscf_bind_port_for_null_and_bypass(
        self,
    ) -> None:
        for ipsec_mode in ("null", "bypass"):
            with self.subTest(ipsec_mode=ipsec_mode):
                with (
                    patch(
                        "volte_mutation_fuzzer.generator.mt_packet.build_mt_packet",
                        return_value=REALISTIC_MT_INVITE,
                    ),
                    patch(
                        "volte_mutation_fuzzer.sender.real_ue.RealUEDirectResolver.resolve",
                        return_value=ResolvedRealUETarget(
                            host="10.20.20.8",
                            port=5060,
                            label="msisdn:111111",
                            observer_events=(
                                "resolver:test:111111->10.20.20.8:5060",
                            ),
                        ),
                    ),
                    patch(
                        "volte_mutation_fuzzer.sender.real_ue.RealUEDirectResolver.resolve_protected_ports",
                        return_value=(15100, 15101),
                    ),
                    patch(
                        "volte_mutation_fuzzer.sender.core.SIPSenderReactor.send_artifact",
                        side_effect=lambda _artifact, target, collect_all_responses=False: SendReceiveResult(
                            target=target,
                            artifact_kind="wire",
                            bytes_sent=0,
                            outcome="success",
                            send_started_at=0.0,
                            send_completed_at=0.0,
                        ),
                    ) as mock_send_artifact,
                ):
                    result = self.runner.invoke(
                        app,
                        [
                            "send",
                            "request",
                            "OPTIONS",
                            "--mode",
                            "real-ue-direct",
                            "--mt",
                            "--target-msisdn",
                            "111111",
                            "--impi",
                            "001010000123511",
                            "--ipsec-mode",
                            ipsec_mode,
                            "--timeout",
                            "0.5",
                        ],
                    )

                self.assertEqual(result.exit_code, 0, msg=result.output)
                payload = json.loads(result.stdout)
                self.assertEqual(payload["outcome"], "success")
                called_target = mock_send_artifact.call_args.args[1]
                self.assertEqual(called_target.ipsec_mode, ipsec_mode)
                self.assertEqual(called_target.bind_container, "pcscf")
                self.assertIsNone(called_target.source_ip)
                self.assertEqual(called_target.bind_port, 15100)

    def test_send_request_direct_mode_rejects_target_host_and_msisdn_together(
        self,
    ) -> None:
        result = self.runner.invoke(
            app,
            [
                "send",
                "request",
                "OPTIONS",
                "--mode",
                "real-ue-direct",
                "--target-host",
                "127.0.0.1",
                "--target-msisdn",
                "222222",
            ],
        )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("exactly one of host or msisdn", result.output)

    @patch(
        "volte_mutation_fuzzer.sender.core.check_route_to_target",
        return_value=RouteCheckResult(True, "loopback"),
    )
    def test_send_request_direct_mode_allows_tcp(
        self, _mock_route: object
    ) -> None:
        responder = TCPResponder(
            response=b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"
        )
        responder.start()
        self.addCleanup(responder.close)

        result = self.runner.invoke(
            app,
            [
                "send",
                "request",
                "OPTIONS",
                "--mode",
                "real-ue-direct",
                "--target-host",
                responder.host,
                "--target-port",
                str(responder.port),
                "--transport",
                "TCP",
                "--timeout",
                "0.5",
            ],
        )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["outcome"], "success")


if __name__ == "__main__":
    unittest.main()
