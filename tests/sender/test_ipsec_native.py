import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from volte_mutation_fuzzer.sender.contracts import SendArtifact, SocketObservation
from volte_mutation_fuzzer.sender.real_ue import (
    RealUEDirectResolutionError,
    ResolvedNativeIPsecSession,
)


class NativeIPsecCorrelationTests(unittest.TestCase):
    def test_extract_correlation_from_wire_text_parses_headers(self) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            extract_correlation_from_artifact,
        )

        artifact = SendArtifact.from_wire_text(
            "INVITE sip:ue@example.com SIP/2.0\r\n"
            "Call-ID: call-123\r\n"
            "CSeq: 42 INVITE\r\n"
            "Via: SIP/2.0/UDP proxy.example.com:5060;branch=z9hG4bK-abc123\r\n"
            "\r\n"
        )

        correlation = extract_correlation_from_artifact(artifact)

        self.assertEqual(correlation.call_id, "call-123")
        self.assertEqual(correlation.cseq_method, "INVITE")
        self.assertEqual(correlation.cseq_sequence, 42)
        self.assertEqual(correlation.via_branch, "z9hG4bK-abc123")
        self.assertEqual(correlation.confidence, "high")

    def test_extract_correlation_from_malformed_bytes_falls_back_low_confidence(
        self,
    ) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            extract_correlation_from_artifact,
        )

        artifact = SendArtifact.from_packet_bytes(b"\xff\xfe\x00\x01not-sip")

        correlation = extract_correlation_from_artifact(artifact)

        self.assertIsNone(correlation.call_id)
        self.assertIsNone(correlation.cseq_method)
        self.assertIsNone(correlation.cseq_sequence)
        self.assertIsNone(correlation.via_branch)
        self.assertEqual(correlation.confidence, "low")

    def test_extract_correlation_from_packet_without_identifiers_is_low_confidence(
        self,
    ) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            extract_correlation_from_artifact,
        )

        artifact = SendArtifact.model_construct(
            packet=SimpleNamespace(call_id=None, cseq=None, via=()),
            wire_text=None,
            packet_bytes=None,
            preserve_via=False,
            preserve_contact=False,
        )

        correlation = extract_correlation_from_artifact(artifact)

        self.assertIsNone(correlation.call_id)
        self.assertIsNone(correlation.cseq_method)
        self.assertIsNone(correlation.cseq_sequence)
        self.assertIsNone(correlation.via_branch)
        self.assertEqual(correlation.confidence, "low")


class NativeIPsecPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.session = ResolvedNativeIPsecSession(
            ue_ip="10.20.20.8",
            pcscf_ip="172.22.0.21",
            port_map={8100: 5103},
            observer_events=("native-ipsec:port-map:8100->5103",),
        )

    def test_preflight_returns_pcscf_port_and_events(self) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            preflight_native_ipsec_target,
        )

        with patch(
            "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["docker"],
                returncode=0,
                stdout="ok\n",
                stderr="",
            ),
        ) as mock_run:
            preflight = preflight_native_ipsec_target(
                session=self.session,
                ue_ip="10.20.20.8",
                ue_port=8100,
                container="pcscf",
            )

        self.assertEqual(preflight.pcscf_port, 5103)
        self.assertEqual(
            preflight.observer_events,
            (
                "native-ipsec:preflight:ok:pcscf",
                "native-ipsec:tuple:172.22.0.21:5103->10.20.20.8:8100",
            ),
        )
        mock_run.assert_called_once()

    def test_preflight_rejects_unknown_ue_port(self) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            preflight_native_ipsec_target,
        )

        with self.assertRaises(RealUEDirectResolutionError) as ctx:
            preflight_native_ipsec_target(
                session=self.session,
                ue_ip="10.20.20.8",
                ue_port=9999,
                container="pcscf",
            )

        self.assertIn("could not map UE protected port 9999", str(ctx.exception))

    def test_preflight_wraps_docker_invocation_errors(self) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            preflight_native_ipsec_target,
        )

        with patch(
            "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
            side_effect=FileNotFoundError("docker not found"),
        ):
            with self.assertRaises(RealUEDirectResolutionError) as ctx:
                preflight_native_ipsec_target(
                    session=self.session,
                    ue_ip="10.20.20.8",
                    ue_port=8100,
                    container="pcscf",
                )

        self.assertIn("raw socket unavailable", str(ctx.exception))


class NativeIPsecObserverTests(unittest.TestCase):
    def test_low_confidence_observer_ignores_unrelated_status_lines_without_tuple_hints(
        self,
    ) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            ArtifactCorrelation,
            observe_pcscf_log_responses,
        )

        correlation = ArtifactCorrelation(
            call_id=None,
            cseq_method=None,
            cseq_sequence=None,
            via_branch=None,
            confidence="low",
        )
        log_output = (
            "SIP/2.0 200 OK Call-ID: unrelated CSeq: 9 INVITE Via: SIP/2.0/UDP proxy.example.com:5060;branch=z9hG4bK-unrelated\n"
        )

        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=args[0],
                returncode=0,
                stdout=log_output,
                stderr="",
            )

        with (
            patch("volte_mutation_fuzzer.sender.ipsec_native.subprocess.run", side_effect=fake_run),
            patch(
                "volte_mutation_fuzzer.sender.ipsec_native.time.monotonic",
                side_effect=[0.0, 0.0, 0.6],
            ),
            patch("volte_mutation_fuzzer.sender.ipsec_native.time.sleep"),
        ):
            observations = observe_pcscf_log_responses(
                container="pcscf",
                since="2026-04-19T00:00:00Z",
                ue_ip="10.20.20.8",
                ue_port=8100,
                correlation=correlation,
                timeout_seconds=0.5,
                poll_interval_seconds=0.1,
                collect_all_responses=False,
            )

        self.assertEqual(observations, ())

    def test_observer_does_not_match_prefix_sharing_dialog_ids(self) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            ArtifactCorrelation,
            observe_pcscf_log_responses,
        )

        correlation = ArtifactCorrelation(
            call_id="call-123",
            cseq_method="INVITE",
            cseq_sequence=42,
            via_branch="z9hG4bK-abc123",
            confidence="high",
        )
        log_output = (
            "SIP/2.0 200 OK Call-ID: call-1234 CSeq: 42 INVITE "
            "Via: SIP/2.0/UDP 172.22.0.21:5103;branch=z9hG4bK-abc1234\n"
        )

        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=args[0],
                returncode=0,
                stdout=log_output,
                stderr="",
            )

        with (
            patch("volte_mutation_fuzzer.sender.ipsec_native.subprocess.run", side_effect=fake_run),
            patch(
                "volte_mutation_fuzzer.sender.ipsec_native.time.monotonic",
                side_effect=[0.0, 0.0, 0.6],
            ),
            patch("volte_mutation_fuzzer.sender.ipsec_native.time.sleep"),
        ):
            observations = observe_pcscf_log_responses(
                container="pcscf",
                since="2026-04-19T00:00:00Z",
                ue_ip="10.20.20.8",
                ue_port=8100,
                correlation=correlation,
                timeout_seconds=0.5,
                poll_interval_seconds=0.1,
                collect_all_responses=False,
            )

        self.assertEqual(observations, ())

    def test_observer_parses_exact_header_values(self) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            ArtifactCorrelation,
            observe_pcscf_log_responses,
        )

        correlation = ArtifactCorrelation(
            call_id="call-123",
            cseq_method="INVITE",
            cseq_sequence=42,
            via_branch="z9hG4bK-abc123",
            confidence="high",
        )
        log_output = (
            "SIP/2.0 200 OK Call-ID: call-123 CSeq: 42 INVITE Via: SIP/2.0/UDP 172.22.0.21:5103;branch=z9hG4bK-abc123\n"
        )

        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=args[0],
                returncode=0,
                stdout=log_output,
                stderr="",
            )

        with (
            patch("volte_mutation_fuzzer.sender.ipsec_native.subprocess.run", side_effect=fake_run),
            patch(
                "volte_mutation_fuzzer.sender.ipsec_native.time.monotonic",
                side_effect=[0.0, 0.0],
            ),
            patch("volte_mutation_fuzzer.sender.ipsec_native.time.sleep"),
        ):
            observations = observe_pcscf_log_responses(
                container="pcscf",
                since="2026-04-19T00:00:00Z",
                ue_ip="10.20.20.8",
                ue_port=8100,
                correlation=correlation,
                timeout_seconds=0.5,
                poll_interval_seconds=0.1,
                collect_all_responses=False,
            )

        self.assertEqual(len(observations), 1)
        self.assertEqual(
            observations[0].headers,
            {
                "call-id": "call-123",
                "cseq": "42 INVITE",
                "via": "SIP/2.0/UDP 172.22.0.21:5103;branch=z9hG4bK-abc123",
            },
        )
        self.assertEqual(observations[0].source, "pcscf-log")

    def test_observer_returns_pcscf_log_observations(self) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            ArtifactCorrelation,
            observe_pcscf_log_responses,
        )

        correlation = ArtifactCorrelation(
            call_id="call-123",
            cseq_method="INVITE",
            cseq_sequence=42,
            via_branch="z9hG4bK-abc123",
            confidence="high",
        )
        log_output = (
            "SIP/2.0 180 Ringing Call-ID: call-123 CSeq: 42 INVITE Via: branch=z9hG4bK-abc123\n"
            "SIP/2.0 200 OK Call-ID: call-123 CSeq: 42 INVITE Via: branch=z9hG4bK-abc123\n"
        )

        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=args[0],
                returncode=0,
                stdout=log_output,
                stderr="",
            )

        with (
            patch("volte_mutation_fuzzer.sender.ipsec_native.subprocess.run", side_effect=fake_run),
            patch(
                "volte_mutation_fuzzer.sender.ipsec_native.time.monotonic",
                side_effect=[0.0, 0.0],
            ),
            patch("volte_mutation_fuzzer.sender.ipsec_native.time.sleep"),
        ):
            observations = observe_pcscf_log_responses(
                container="pcscf",
                since="2026-04-19T00:00:00Z",
                ue_ip="10.20.20.8",
                ue_port=8100,
                correlation=correlation,
                timeout_seconds=0.5,
                poll_interval_seconds=0.1,
                collect_all_responses=False,
            )

        self.assertGreaterEqual(len(observations), 1)
        self.assertEqual(observations[-1].source, "pcscf-log")
        self.assertEqual(observations[-1].remote_host, "10.20.20.8")
        self.assertEqual(observations[-1].remote_port, 8100)
        self.assertEqual(observations[-1].classification, "success")
        self.assertEqual(observations[-1].status_code, 200)

    def test_observer_polls_until_final_response(self) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            ArtifactCorrelation,
            observe_pcscf_log_responses,
        )

        correlation = ArtifactCorrelation(
            call_id="call-123",
            cseq_method="INVITE",
            cseq_sequence=42,
            via_branch=None,
            confidence="high",
        )
        provisional_output = (
            "SIP/2.0 180 Ringing Call-ID: call-123 CSeq: 42 INVITE\n"
        )
        final_output = (
            "SIP/2.0 180 Ringing Call-ID: call-123 CSeq: 42 INVITE\n"
            "SIP/2.0 200 OK Call-ID: call-123 CSeq: 42 INVITE\n"
        )
        outputs = [provisional_output, final_output]

        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=args[0],
                returncode=0,
                stdout=outputs.pop(0),
                stderr="",
            )

        with (
            patch("volte_mutation_fuzzer.sender.ipsec_native.subprocess.run", side_effect=fake_run),
            patch(
                "volte_mutation_fuzzer.sender.ipsec_native.time.monotonic",
                side_effect=[0.0, 0.0, 0.1, 0.1, 0.6],
            ),
            patch("volte_mutation_fuzzer.sender.ipsec_native.time.sleep"),
        ):
            observations = observe_pcscf_log_responses(
                container="pcscf",
                since="2026-04-19T00:00:00Z",
                ue_ip="10.20.20.8",
                ue_port=8100,
                correlation=correlation,
                timeout_seconds=0.5,
                poll_interval_seconds=0.1,
                collect_all_responses=False,
            )

        self.assertEqual([obs.status_code for obs in observations], [180, 200])
        self.assertEqual(len(outputs), 0)

    def test_observer_gracefully_handles_docker_errors(self) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            ArtifactCorrelation,
            observe_pcscf_log_responses,
        )

        correlation = ArtifactCorrelation(
            call_id="call-123",
            cseq_method="INVITE",
            cseq_sequence=42,
            via_branch=None,
            confidence="high",
        )

        with (
            patch(
                "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
                side_effect=TimeoutError("docker logs timed out"),
            ),
            patch(
                "volte_mutation_fuzzer.sender.ipsec_native.time.monotonic",
                side_effect=[0.0, 0.0, 0.6],
            ),
        ):
            observations = observe_pcscf_log_responses(
                container="pcscf",
                since="2026-04-19T00:00:00Z",
                ue_ip="10.20.20.8",
                ue_port=8100,
                correlation=correlation,
                timeout_seconds=0.5,
                poll_interval_seconds=0.1,
                collect_all_responses=False,
            )

        self.assertEqual(observations, ())

    def test_observer_records_docker_timeout_events(self) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            ArtifactCorrelation,
            observe_pcscf_log_responses,
        )

        correlation = ArtifactCorrelation(
            call_id="call-123",
            cseq_method="INVITE",
            cseq_sequence=42,
            via_branch=None,
            confidence="high",
        )
        observer_events: list[str] = []

        with (
            patch(
                "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd=["docker", "logs"], timeout=0.2),
            ),
            patch(
                "volte_mutation_fuzzer.sender.ipsec_native.time.monotonic",
                side_effect=[0.0, 0.0, 0.6],
            ),
        ):
            observations = observe_pcscf_log_responses(
                container="pcscf",
                since="2026-04-19T00:00:00Z",
                ue_ip="10.20.20.8",
                ue_port=8100,
                correlation=correlation,
                timeout_seconds=0.5,
                poll_interval_seconds=0.1,
                collect_all_responses=False,
                observer_events=observer_events,
            )

        self.assertEqual(observations, ())
        self.assertIn(
            "native-ipsec:observe:docker-logs-error:TimeoutExpired",
            observer_events,
        )


class NativeIPsecSendTests(unittest.TestCase):
    def test_send_via_native_ipsec_uses_docker_exec_driver(self) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import send_via_native_ipsec

        with patch(
            "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["docker"],
                returncode=0,
                stdout="",
                stderr="",
            ),
        ) as mock_run:
            result = send_via_native_ipsec(
                container="pcscf",
                src_ip="172.22.0.21",
                src_port=5103,
                dst_ip="10.20.20.8",
                dst_port=8100,
                payload=b"INVITE sip:ue@example.com SIP/2.0\r\n\r\n",
                timeout_seconds=1.0,
            )

        self.assertEqual(result.payload_size, len(b"INVITE sip:ue@example.com SIP/2.0\r\n\r\n"))
        self.assertIn("native-ipsec:send:ok", result.observer_events)
        self.assertIn(
            "native-ipsec:tuple:172.22.0.21:5103->10.20.20.8:8100",
            result.observer_events,
        )
        mock_run.assert_called_once()

    def test_send_via_native_ipsec_wraps_docker_errors(self) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            NativeIPsecError,
            send_via_native_ipsec,
        )

        with patch(
            "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
            side_effect=TimeoutError("docker exec timed out"),
        ):
            with self.assertRaises(NativeIPsecError) as ctx:
                send_via_native_ipsec(
                    container="pcscf",
                    src_ip="172.22.0.21",
                    src_port=5103,
                    dst_ip="10.20.20.8",
                    dst_port=8100,
                    payload=b"INVITE sip:ue@example.com SIP/2.0\r\n\r\n",
                    timeout_seconds=1.0,
                )

        self.assertIn("docker exec timed out", str(ctx.exception))
        self.assertIn(
            "native-ipsec:send:failed:TimeoutError",
            ctx.exception.observer_events,
        )


class NativeIPsecSocketObservationTests(unittest.TestCase):
    def test_pcscf_log_source_is_allowed(self) -> None:
        observation = SocketObservation(
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
        )

        self.assertEqual(observation.source, "pcscf-log")


if __name__ == "__main__":
    unittest.main()
