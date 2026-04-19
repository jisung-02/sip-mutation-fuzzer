import re
import socket
import unittest
from unittest.mock import patch

from volte_mutation_fuzzer.generator.contracts import GeneratorSettings, RequestSpec
from volte_mutation_fuzzer.generator.core import SIPGenerator
from volte_mutation_fuzzer.sender.contracts import (
    SendArtifact,
    SocketObservation,
    TargetEndpoint,
)
from volte_mutation_fuzzer.sender.core import SIPSenderReactor
from volte_mutation_fuzzer.sender.real_ue import RouteCheckResult
from volte_mutation_fuzzer.sip.common import SIPMethod
from tests.sender._server import TCPResponder, UDPResponder


class SIPSenderReactorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.generator = SIPGenerator(GeneratorSettings())
        self.reactor = SIPSenderReactor()
        self.packet = self.generator.generate_request(
            RequestSpec(method=SIPMethod.OPTIONS), None
        )

    def test_send_packet_udp_returns_success_with_correlation_key(self) -> None:
        responder = UDPResponder(
            responses=(
                b"SIP/2.0 200 OK\r\n"
                b"Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bK-1\r\n"
                b"Call-ID: call-1\r\n"
                b"CSeq: 1 OPTIONS\r\n"
                b"Content-Length: 0\r\n"
                b"\r\n",
            )
        )
        responder.start()
        self.addCleanup(responder.close)

        result = self.reactor.send_packet(
            self.packet,
            TargetEndpoint(
                host=responder.host, port=responder.port, timeout_seconds=0.5
            ),
        )

        self.assertEqual(result.outcome, "success")
        self.assertEqual(result.correlation_key.call_id, self.packet.call_id)
        self.assertEqual(result.correlation_key.cseq_method, self.packet.cseq.method)
        self.assertEqual(result.responses[-1].status_code, 200)
        self.assertGreater(result.bytes_sent, 0)
        self.assertEqual(len(responder.received_payloads), 1)

    def test_send_udp_collect_all_responses_keeps_provisional_and_final(self) -> None:
        responder = UDPResponder(
            responses=(
                b"SIP/2.0 180 Ringing\r\n"
                b"Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bK-1\r\n"
                b"Content-Length: 0\r\n"
                b"\r\n",
                b"SIP/2.0 486 Busy Here\r\n"
                b"Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bK-1\r\n"
                b"Content-Length: 0\r\n"
                b"\r\n",
            ),
            delay_seconds=0.01,
        )
        responder.start()
        self.addCleanup(responder.close)

        result = self.reactor.send_packet(
            self.packet,
            TargetEndpoint(
                host=responder.host, port=responder.port, timeout_seconds=0.2
            ),
            collect_all_responses=True,
        )

        self.assertEqual(result.outcome, "error")
        self.assertEqual(
            [item.classification for item in result.responses],
            ["provisional", "client_error"],
        )
        self.assertEqual(
            result.final_response.status_code if result.final_response else None, 486
        )

    def test_send_packet_to_silent_udp_target_times_out(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            host, port = sock.getsockname()

        result = self.reactor.send_packet(
            self.packet,
            TargetEndpoint(host=host, port=port, timeout_seconds=0.05),
        )

        self.assertEqual(result.outcome, "timeout")
        self.assertEqual(result.responses, ())
        self.assertIsNone(result.final_response)

    def test_send_wire_text_tcp_reads_success_response(self) -> None:
        responder = TCPResponder(
            response=b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"
        )
        responder.start()
        self.addCleanup(responder.close)

        result = self.reactor.send_artifact(
            SendArtifact.from_wire_text(
                "OPTIONS sip:ue@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n"
            ),
            TargetEndpoint(
                host=responder.host,
                port=responder.port,
                transport="TCP",
                timeout_seconds=0.5,
            ),
        )

        self.assertEqual(result.outcome, "success")
        self.assertEqual(result.responses[-1].status_code, 200)
        self.assertEqual(len(responder.received_payloads), 1)

    @patch(
        "volte_mutation_fuzzer.sender.core.check_route_to_target",
        return_value=RouteCheckResult(True, "loopback"),
    )
    def test_send_real_ue_direct_rewrites_wire_via_and_contact(
        self, _mock_route: object
    ) -> None:
        responder = UDPResponder(
            responses=(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n",)
        )
        responder.start()
        self.addCleanup(responder.close)

        wire_text = (
            "OPTIONS sip:ue@example.com SIP/2.0\r\n"
            "Via: SIP/2.0/UDP proxy.example.com:5060;branch=z9hG4bK-1\r\n"
            "Contact: <sip:attacker@203.0.113.10:5090>\r\n"
            "Content-Length: 0\r\n\r\n"
        )
        result = self.reactor.send_artifact(
            SendArtifact.from_wire_text(wire_text),
            TargetEndpoint(
                mode="real-ue-direct",
                host=responder.host,
                port=responder.port,
                timeout_seconds=0.5,
            ),
        )

        self.assertEqual(result.outcome, "success")
        self.assertEqual(result.target.host, responder.host)
        self.assertEqual(result.target.port, responder.port)
        received_text = responder.received_payloads[0].decode("utf-8")
        self.assertRegex(
            received_text,
            re.compile(r"Via: SIP/2\.0/UDP 127\.0\.0\.1:\d+;branch=z9hG4bK-1;rport"),
        )
        self.assertRegex(
            received_text,
            re.compile(r"Contact: <sip:attacker@127\.0\.0\.1:\d+>"),
        )
        self.assertIn("route-check:ok:loopback", result.observer_events)
        self.assertTrue(
            any(
                event.startswith("direct-local:127.0.0.1:")
                for event in result.observer_events
            )
        )


    @patch(
        "volte_mutation_fuzzer.sender.core.check_route_to_target",
        return_value=RouteCheckResult(False, "no route to host"),
    )
    def test_send_real_ue_direct_route_failure_returns_send_error(
        self, _mock_route: object
    ) -> None:
        result = self.reactor.send_artifact(
            SendArtifact.from_wire_text(
                "OPTIONS sip:ue@example.com SIP/2.0\r\n"
                "Via: SIP/2.0/UDP proxy.example.com:5060;branch=z9hG4bK-1\r\n"
                "Content-Length: 0\r\n\r\n"
            ),
            TargetEndpoint(
                mode="real-ue-direct",
                host="127.0.0.1",
                port=5060,
                timeout_seconds=0.2,
            ),
        )

        self.assertEqual(result.outcome, "send_error")
        self.assertEqual(result.bytes_sent, 0)
        self.assertIn("route check failed", result.error or "")
        self.assertIn("route-check:missing:no route to host", result.observer_events)

    def test_send_real_ue_direct_native_uses_native_ipsec_observer_path(self) -> None:
        artifact = SendArtifact.from_wire_text(
            "INVITE sip:ue@example.com SIP/2.0\r\n"
            "Call-ID: call-123\r\n"
            "CSeq: 42 INVITE\r\n"
            "Via: SIP/2.0/UDP proxy.example.com:5060;branch=z9hG4bK-abc123\r\n"
            "Contact: <sip:attacker@203.0.113.10:5090>\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        target = TargetEndpoint(
            mode="real-ue-direct",
            host=None,
            msisdn="111111",
            ipsec_mode="native",
            bind_container="legacy-netns",
            timeout_seconds=0.5,
        )

        with (
            patch(
                "volte_mutation_fuzzer.sender.core.RealUEDirectResolver.resolve",
                return_value=type(
                    "ResolvedTarget",
                    (),
                    {
                        "host": "10.20.20.8",
                        "port": 5060,
                        "label": "msisdn:111111",
                        "observer_events": ("resolver:static:10.20.20.8:5060",),
                    },
                )(),
            ) as mock_resolve,
            patch(
                "volte_mutation_fuzzer.sender.core.RealUEDirectResolver.resolve_protected_ports",
                return_value=(8100, 8101),
            ) as mock_resolve_ports,
            patch(
                "volte_mutation_fuzzer.sender.core.check_route_to_target",
                side_effect=AssertionError("route-check should not run for native IPsec"),
            ),
            patch(
                "volte_mutation_fuzzer.sender.core.setup_route_to_target",
                side_effect=AssertionError("route-setup should not run for native IPsec"),
            ),
            patch(
                "volte_mutation_fuzzer.sender.core.resolve_native_ipsec_session",
                return_value=type(
                    "Session",
                    (),
                    {
                        "ue_ip": "10.20.20.8",
                        "pcscf_ip": "172.22.0.21",
                        "port_map": {8100: 5103},
                        "observer_events": ("native-ipsec:port-map:8100->5103",),
                        "pcscf_port_for": staticmethod(lambda _ue_port: 5103),
                    },
                )(),
            ) as mock_resolve_session,
            patch(
                "volte_mutation_fuzzer.sender.core.preflight_native_ipsec_target",
                return_value=type(
                    "Preflight",
                    (),
                    {
                        "pcscf_port": 5103,
                        "observer_events": (
                            "native-ipsec:preflight:ok:pcscf",
                            "native-ipsec:tuple:172.22.0.21:5103->10.20.20.8:8100",
                        ),
                    },
                )(),
            ) as mock_preflight,
            patch(
                "volte_mutation_fuzzer.sender.core.time.monotonic",
                side_effect=[100.0, 100.1, 100.35],
            ),
            patch(
                "volte_mutation_fuzzer.sender.core.prepare_real_ue_direct_payload",
                return_value=(
                    b"normalized-payload",
                    ("direct-normalization:native",),
                ),
            ) as mock_prepare,
            patch(
                "volte_mutation_fuzzer.sender.core.send_via_native_ipsec",
                return_value=type(
                    "NativeSendResult",
                    (),
                    {
                        "payload_size": len(b"normalized-payload"),
                        "observer_events": (
                            "native-ipsec:send:ok",
                            "native-ipsec:tuple:172.22.0.21:5103->10.20.20.8:8100",
                        ),
                    },
                )(),
            ) as mock_send,
            patch(
                "volte_mutation_fuzzer.sender.core.observe_pcscf_log_responses",
                return_value=(
                    SocketObservation(
                        source="pcscf-log",
                        remote_host="10.20.20.8",
                        remote_port=8100,
                        status_code=200,
                        reason_phrase="OK",
                        headers={},
                        body="",
                        raw_text="SIP/2.0 200 OK",
                        raw_size=len("SIP/2.0 200 OK"),
                        classification="success",
                    ),
                ),
            ) as mock_observe,
        ):
            result = self.reactor.send_artifact(
                artifact,
                target,
                collect_all_responses=False,
            )

        self.assertEqual(result.outcome, "success")
        self.assertEqual(result.bytes_sent, len(b"normalized-payload"))
        self.assertEqual(result.target.host, "10.20.20.8")
        self.assertEqual(result.target.port, 8100)
        self.assertEqual(len(result.responses), 1)
        self.assertEqual(result.responses[0].status_code, 200)
        self.assertIsNotNone(result.final_response)
        assert result.final_response is not None
        self.assertEqual(result.final_response.status_code, 200)
        self.assertIn("resolver:static:10.20.20.8:5060", result.observer_events)
        self.assertIn("native-ipsec:preflight:ok:pcscf", result.observer_events)
        self.assertIn("native-ipsec:send:ok", result.observer_events)
        self.assertTrue(
            any(event.startswith("native-ipsec:tuple:172.22.0.21:5103->10.20.20.8:8100") for event in result.observer_events)
        )
        mock_resolve.assert_called_once()
        mock_resolve_ports.assert_called_once_with("111111")
        mock_resolve_session.assert_called_once_with(
            ue_ip="10.20.20.8",
            pcscf_container="legacy-netns",
            env=self.reactor._env,
        )
        mock_preflight.assert_called_once()
        self.assertEqual(mock_preflight.call_args.kwargs["ue_port"], 8100)
        mock_send.assert_called_once_with(
            container="legacy-netns",
            src_ip="172.22.0.21",
            src_port=5103,
            dst_ip="10.20.20.8",
            dst_port=8100,
            payload=b"normalized-payload",
            timeout_seconds=0.4,
        )
        mock_prepare.assert_called_once_with(
            artifact,
            local_host="172.22.0.21",
            local_port=5103,
            rewrite_via=True,
            rewrite_contact=True,
        )
        mock_observe.assert_called_once_with(
            container="legacy-netns",
            since=mock_observe.call_args.kwargs["since"],
            ue_ip="10.20.20.8",
            ue_port=8100,
            correlation=mock_observe.call_args.kwargs["correlation"],
            timeout_seconds=0.15,
            poll_interval_seconds=0.15,
            collect_all_responses=False,
            observer_events=mock_observe.call_args.kwargs["observer_events"],
        )
        self.assertEqual(mock_observe.call_args.kwargs["container"], "legacy-netns")
        self.assertEqual(mock_observe.call_args.kwargs["ue_ip"], "10.20.20.8")
        self.assertEqual(mock_observe.call_args.kwargs["ue_port"], 8100)
        self.assertEqual(mock_observe.call_args.kwargs["collect_all_responses"], False)
        self.assertEqual(mock_observe.call_args.kwargs["timeout_seconds"], 0.15)
        self.assertAlmostEqual(
            mock_observe.call_args.kwargs["poll_interval_seconds"], 0.15
        )
        self.assertRegex(
            mock_observe.call_args.kwargs["since"],
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$",
        )

    def test_send_real_ue_direct_native_marks_low_confidence_packet_bytes(self) -> None:
        artifact = SendArtifact.from_packet_bytes(b"\xff\xfe\x00\x01not-sip")
        target = TargetEndpoint(
            mode="real-ue-direct",
            host=None,
            msisdn="111111",
            ipsec_mode="native",
            bind_container="legacy-netns",
            timeout_seconds=0.5,
        )

        with (
            patch(
                "volte_mutation_fuzzer.sender.core.RealUEDirectResolver.resolve",
                return_value=type(
                    "ResolvedTarget",
                    (),
                    {
                        "host": "10.20.20.8",
                        "port": 5060,
                        "label": "msisdn:111111",
                        "observer_events": (),
                    },
                )(),
            ),
            patch(
                "volte_mutation_fuzzer.sender.core.RealUEDirectResolver.resolve_protected_ports",
                return_value=(8100, 8101),
            ),
            patch(
                "volte_mutation_fuzzer.sender.core.resolve_native_ipsec_session",
                return_value=type(
                    "Session",
                    (),
                    {
                        "ue_ip": "10.20.20.8",
                        "pcscf_ip": "172.22.0.21",
                        "port_map": {8100: 5103},
                        "observer_events": (),
                        "pcscf_port_for": staticmethod(lambda _ue_port: 5103),
                    },
                )(),
            ),
            patch(
                "volte_mutation_fuzzer.sender.core.preflight_native_ipsec_target",
                return_value=type(
                    "Preflight",
                    (),
                    {
                        "pcscf_port": 5103,
                        "observer_events": (),
                    },
                )(),
            ),
            patch(
                "volte_mutation_fuzzer.sender.core.prepare_real_ue_direct_payload",
                return_value=(
                    b"normalized-payload",
                    ("direct-normalization:bytes-unmodified",),
                ),
            ),
            patch(
                "volte_mutation_fuzzer.sender.core.send_via_native_ipsec",
                return_value=type(
                    "NativeSendResult",
                    (),
                    {"payload_size": len(b"normalized-payload"), "observer_events": ()},
                )(),
            ),
            patch(
                "volte_mutation_fuzzer.sender.core.observe_pcscf_log_responses",
                return_value=(),
            ),
        ):
            result = self.reactor.send_artifact(
                artifact,
                target,
                collect_all_responses=False,
            )

        self.assertEqual(result.outcome, "timeout")
        self.assertIn("correlation:fallback:tuple-only", result.observer_events)
        self.assertIn("correlation:low-confidence", result.observer_events)

    def test_send_real_ue_direct_native_preserves_trail_on_native_send_failure(
        self,
    ) -> None:
        artifact = SendArtifact.from_wire_text(
            "INVITE sip:ue@example.com SIP/2.0\r\n"
            "Call-ID: call-123\r\n"
            "CSeq: 42 INVITE\r\n"
            "Via: SIP/2.0/UDP proxy.example.com:5060;branch=z9hG4bK-abc123\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )
        target = TargetEndpoint(
            mode="real-ue-direct",
            host=None,
            msisdn="111111",
            ipsec_mode="native",
            bind_container="legacy-netns",
            timeout_seconds=0.5,
        )

        with (
            patch(
                "volte_mutation_fuzzer.sender.core.RealUEDirectResolver.resolve",
                return_value=type(
                    "ResolvedTarget",
                    (),
                    {
                        "host": "10.20.20.8",
                        "port": 5060,
                        "label": "msisdn:111111",
                        "observer_events": ("resolver:static:10.20.20.8:5060",),
                    },
                )(),
            ),
            patch(
                "volte_mutation_fuzzer.sender.core.RealUEDirectResolver.resolve_protected_ports",
                return_value=(8100, 8101),
            ),
            patch(
                "volte_mutation_fuzzer.sender.core.resolve_native_ipsec_session",
                return_value=type(
                    "Session",
                    (),
                    {
                        "ue_ip": "10.20.20.8",
                        "pcscf_ip": "172.22.0.21",
                        "port_map": {8100: 5103},
                        "observer_events": ("native-ipsec:port-map:8100->5103",),
                        "pcscf_port_for": staticmethod(lambda _ue_port: 5103),
                    },
                )(),
            ),
            patch(
                "volte_mutation_fuzzer.sender.core.preflight_native_ipsec_target",
                return_value=type(
                    "Preflight",
                    (),
                    {
                        "pcscf_port": 5103,
                        "observer_events": (
                            "native-ipsec:preflight:ok:legacy-netns",
                            "native-ipsec:tuple:172.22.0.21:5103->10.20.20.8:8100",
                        ),
                    },
                )(),
            ),
            patch(
                "volte_mutation_fuzzer.sender.core.prepare_real_ue_direct_payload",
                return_value=(b"normalized-payload", ("direct-normalization:native",)),
            ),
            patch(
                "volte_mutation_fuzzer.sender.core.send_via_native_ipsec",
                side_effect=(
                    __import__(
                        "volte_mutation_fuzzer.sender.ipsec_native",
                        fromlist=["NativeIPsecError"],
                    ).NativeIPsecError(
                        "native injector exploded", observer_events=("native-ipsec:send:failed",)
                    )
                ),
            ),
            patch(
                "volte_mutation_fuzzer.sender.core.observe_pcscf_log_responses",
                side_effect=AssertionError("observer should not run after send failure"),
            ),
        ):
            result = self.reactor.send_artifact(
                artifact,
                target,
                collect_all_responses=False,
            )

        self.assertEqual(result.outcome, "send_error")
        self.assertIn("native injector exploded", result.error or "")
        self.assertIn("resolver:static:10.20.20.8:5060", result.observer_events)
        self.assertIn("native-ipsec:port-map:8100->5103", result.observer_events)
        self.assertIn("native-ipsec:preflight:ok:legacy-netns", result.observer_events)
        self.assertEqual(result.target.host, "10.20.20.8")
        self.assertEqual(result.target.port, 8100)


if __name__ == "__main__":
    unittest.main()
