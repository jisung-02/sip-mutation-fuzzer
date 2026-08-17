import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from volte_mutation_fuzzer.sender.contracts import SendArtifact, SocketObservation
from volte_mutation_fuzzer.sender.real_ue import (
    RealUEDirectResolutionError,
    ResolvedNativeIPsecSession,
)

IMS_DOMAIN = "ims.mnc001.mcc001.3gppnetwork.org"
PCSCF_HOST = f"pcscf.{IMS_DOMAIN}"
REALISTIC_REQUEST_URI = "sip:111111@10.20.20.8:8100"
REALISTIC_CALL_ID = "a84b4c76e66710@pcscf.ims.mnc001.mcc001.3gppnetwork.org"
REALISTIC_NEIGHBOR_CALL_ID = "a84b4c76e66710a@pcscf.ims.mnc001.mcc001.3gppnetwork.org"
REALISTIC_VIA_BRANCH = "z9hG4bK-abc123"
REALISTIC_NEIGHBOR_BRANCH = "z9hG4bK-abc1234"


class NativeIPsecCorrelationTests(unittest.TestCase):
    def test_extract_correlation_from_wire_text_parses_headers(self) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            extract_correlation_from_artifact,
        )

        artifact = SendArtifact.from_wire_text(
            f"INVITE {REALISTIC_REQUEST_URI} SIP/2.0\r\n"
            f"Call-ID: {REALISTIC_CALL_ID}\r\n"
            "CSeq: 42 INVITE\r\n"
            f"Via: SIP/2.0/UDP {PCSCF_HOST}:5060;branch={REALISTIC_VIA_BRANCH}\r\n"
            "\r\n"
        )

        correlation = extract_correlation_from_artifact(artifact)

        self.assertEqual(correlation.call_id, REALISTIC_CALL_ID)
        self.assertEqual(correlation.cseq_method, "INVITE")
        self.assertEqual(correlation.cseq_sequence, 42)
        self.assertEqual(correlation.via_branch, REALISTIC_VIA_BRANCH)
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
                "native-ipsec:preflight:transport:udp",
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
        log_output = f"SIP/2.0 200 OK Call-ID: unrelated CSeq: 9 INVITE Via: SIP/2.0/UDP {PCSCF_HOST}:5060;branch=z9hG4bK-unrelated\n"

        def fake_run(*args, **_kwargs):
            return subprocess.CompletedProcess(
                args=args[0],
                returncode=0,
                stdout=log_output,
                stderr="",
            )

        with (
            patch(
                "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
                side_effect=fake_run,
            ),
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
            call_id=REALISTIC_CALL_ID,
            cseq_method="INVITE",
            cseq_sequence=42,
            via_branch=REALISTIC_VIA_BRANCH,
            confidence="high",
        )
        log_output = (
            f"SIP/2.0 200 OK Call-ID: {REALISTIC_NEIGHBOR_CALL_ID} CSeq: 42 INVITE "
            f"Via: SIP/2.0/UDP 172.22.0.21:5103;branch={REALISTIC_NEIGHBOR_BRANCH}\n"
        )

        def fake_run(*args, **_kwargs):
            return subprocess.CompletedProcess(
                args=args[0],
                returncode=0,
                stdout=log_output,
                stderr="",
            )

        with (
            patch(
                "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
                side_effect=fake_run,
            ),
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
            call_id=REALISTIC_CALL_ID,
            cseq_method="INVITE",
            cseq_sequence=42,
            via_branch=REALISTIC_VIA_BRANCH,
            confidence="high",
        )
        log_output = f"SIP/2.0 200 OK Call-ID: {REALISTIC_CALL_ID} CSeq: 42 INVITE Via: SIP/2.0/UDP 172.22.0.21:5103;branch={REALISTIC_VIA_BRANCH}\n"

        def fake_run(*args, **_kwargs):
            return subprocess.CompletedProcess(
                args=args[0],
                returncode=0,
                stdout=log_output,
                stderr="",
            )

        with (
            patch(
                "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
                side_effect=fake_run,
            ),
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
                "call-id": REALISTIC_CALL_ID,
                "cseq": "42 INVITE",
                "via": f"SIP/2.0/UDP 172.22.0.21:5103;branch={REALISTIC_VIA_BRANCH}",
            },
        )
        self.assertEqual(observations[0].source, "pcscf-log")

    def test_observer_returns_pcscf_log_observations(self) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            ArtifactCorrelation,
            observe_pcscf_log_responses,
        )

        correlation = ArtifactCorrelation(
            call_id=REALISTIC_CALL_ID,
            cseq_method="INVITE",
            cseq_sequence=42,
            via_branch=REALISTIC_VIA_BRANCH,
            confidence="high",
        )
        log_output = (
            f"SIP/2.0 180 Ringing Call-ID: {REALISTIC_CALL_ID} CSeq: 42 INVITE Via: branch={REALISTIC_VIA_BRANCH}\n"
            f"SIP/2.0 200 OK Call-ID: {REALISTIC_CALL_ID} CSeq: 42 INVITE Via: branch={REALISTIC_VIA_BRANCH}\n"
        )

        def fake_run(*args, **_kwargs):
            return subprocess.CompletedProcess(
                args=args[0],
                returncode=0,
                stdout=log_output,
                stderr="",
            )

        with (
            patch(
                "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
                side_effect=fake_run,
            ),
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
            call_id=REALISTIC_CALL_ID,
            cseq_method="INVITE",
            cseq_sequence=42,
            via_branch=None,
            confidence="high",
        )
        provisional_output = (
            f"SIP/2.0 180 Ringing Call-ID: {REALISTIC_CALL_ID} CSeq: 42 INVITE\n"
        )
        final_output = (
            f"SIP/2.0 180 Ringing Call-ID: {REALISTIC_CALL_ID} CSeq: 42 INVITE\n"
            f"SIP/2.0 200 OK Call-ID: {REALISTIC_CALL_ID} CSeq: 42 INVITE\n"
        )
        outputs = [provisional_output, final_output]

        def fake_run(*args, **_kwargs):
            return subprocess.CompletedProcess(
                args=args[0],
                returncode=0,
                stdout=outputs.pop(0),
                stderr="",
            )

        with (
            patch(
                "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
                side_effect=fake_run,
            ),
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
            call_id=REALISTIC_CALL_ID,
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
            call_id=REALISTIC_CALL_ID,
            cseq_method="INVITE",
            cseq_sequence=42,
            via_branch=None,
            confidence="high",
        )
        observer_events: list[str] = []

        with (
            patch(
                "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
                side_effect=subprocess.TimeoutExpired(
                    cmd=["docker", "logs"], timeout=0.2
                ),
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
                payload=f"INVITE {REALISTIC_REQUEST_URI} SIP/2.0\r\n\r\n".encode(
                    "utf-8"
                ),
                timeout_seconds=1.0,
            )

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
                    payload=f"INVITE {REALISTIC_REQUEST_URI} SIP/2.0\r\n\r\n".encode(
                        "utf-8"
                    ),
                    timeout_seconds=1.0,
                )

        self.assertIn("docker exec timed out", str(ctx.exception))
        self.assertIn(
            "native-ipsec:send:failed:TimeoutError",
            ctx.exception.observer_events,
        )


class NativeIPsecUdpDriverKeepaliveFilterTests(unittest.TestCase):
    """Driver script must skip CRLF / CRLFCRLF SIP keepalive datagrams.

    Regression: 2026-04-27 INVITE Pixel campaign had 12/13 timeouts where
    pcap showed substantial UE → fuzzer ESP responses (1278B + 738B) ~15ms
    after a 78-byte ESP keepalive. The driver did one ``recvfrom``,
    caught the 4-byte CRLF keepalive, and exited — fuzzer parsed the
    empty datagram as an invalid SIP message → no observation → timeout.
    """

    def _driver_script(self) -> str:
        from volte_mutation_fuzzer.sender.ipsec_native import _UDP_DRIVER_SCRIPT

        return _UDP_DRIVER_SCRIPT

    def test_driver_imports_time_for_deadline_loop(self) -> None:
        # Without ``time``, ``time.monotonic()`` in the deadline loop
        # raises NameError inside the docker exec'd driver.
        self.assertIn("import time", self._driver_script())

    def test_driver_uses_deadline_loop_not_single_recvfrom(self) -> None:
        script = self._driver_script()
        self.assertIn("deadline = time.monotonic() + timeout_seconds", script)
        # The keepalive filter must continue rather than emit on empty.
        self.assertIn('data.strip(b"\\r\\n\\t "):', script)
        self.assertIn("continue", script)

    def test_driver_emits_zero_length_marker_on_no_real_response(self) -> None:
        # When the deadline expires with only keepalives received,
        # ``result_data`` stays None and the driver must still emit the
        # 4-byte zero length marker so the parent's frame parser sees an
        # explicit empty result rather than a stalled stdin.
        script = self._driver_script()
        self.assertIn("if result_data is None:", script)
        self.assertIn('(0).to_bytes(4, "big")', script)


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


class NullModeEalgSwapTests(unittest.TestCase):
    """Selector-aware SA targeting and failure visibility for null mode."""

    PCSCF_IP = "172.22.0.21"
    UE_IP = "10.20.20.8"

    # Two outbound SAs with identical src/dst (the IMS per-UE reality),
    # distinguished only by selector ports, with the SPI on the real
    # iproute2 ``proto esp spi 0x… reqid …`` line and keys in the dump.
    XFRM_DUMP = (
        "src 172.22.0.21 dst 10.20.20.8\n"
        "\tsel src 172.22.0.21/32 dst 10.20.20.8/32 sport 5001 dport 5100\n"
        "\tproto esp spi 0xc0000002 reqid 1 mode transport\n"
        "\treplay-window 32\n"
        "\tauth-trunc hmac(sha256) 0x0011223344556677\n"
        "\tenc cbc(aes) 0x445566778899aabb\n"
        "\n"
        "src 172.22.0.21 dst 10.20.20.8\n"
        "\tsel src 172.22.0.21/32 dst 10.20.20.8/32 sport 6101 dport 6100\n"
        "\tproto esp spi 0xc0000001 reqid 2 mode transport\n"
        "\treplay-window 32\n"
        "\tauth-trunc hmac(sha256) 0x99aabbccddeeff00\n"
        "\tenc cbc(aes) 0xddeeff0011223344\n"
    )

    @staticmethod
    def _run_result(stdout: str = "", returncode: int = 0):
        return subprocess.CompletedProcess(
            args=["docker"], returncode=returncode, stdout=stdout, stderr=""
        )

    def test_save_targets_sa_matching_send_tuple(self) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            _save_and_null_outbound_ealg,
        )

        with patch(
            "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
            side_effect=[
                self._run_result(stdout=self.XFRM_DUMP),
                self._run_result(),
            ],
        ) as mock_run:
            swap = _save_and_null_outbound_ealg(
                container="pcscf",
                src_ip=self.PCSCF_IP,
                dst_ip=self.UE_IP,
                src_port=6101,
                dst_port=6100,
            )

        self.assertIsNotNone(swap)
        assert swap is not None
        self.assertEqual(swap.spi, "0xc0000001")
        self.assertEqual(swap.original_enc_tail, "cbc(aes) 0xddeeff0011223344")
        update_cmd = mock_run.call_args_list[1].args[0]
        self.assertEqual(update_cmd[update_cmd.index("spi") + 1], "0xc0000001")
        self.assertEqual(update_cmd[update_cmd.index("enc") + 1], "null")

    def test_save_refuses_ambiguous_sas_without_matching_selector(self) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            _save_and_null_outbound_ealg,
        )

        with patch(
            "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
            side_effect=[self._run_result(stdout=self.XFRM_DUMP)],
        ) as mock_run:
            swap = _save_and_null_outbound_ealg(
                container="pcscf",
                src_ip=self.PCSCF_IP,
                dst_ip=self.UE_IP,
                src_port=1234,
                dst_port=5678,
            )

        self.assertIsNone(swap)
        mock_run.assert_called_once()  # no null update was issued

    def test_save_returns_none_when_null_update_fails(self) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            _save_and_null_outbound_ealg,
        )

        with patch(
            "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
            side_effect=[
                self._run_result(stdout=self.XFRM_DUMP),
                self._run_result(returncode=1),
            ],
        ):
            swap = _save_and_null_outbound_ealg(
                container="pcscf",
                src_ip=self.PCSCF_IP,
                dst_ip=self.UE_IP,
                src_port=6101,
                dst_port=6100,
            )

        self.assertIsNone(swap)

    def test_restore_uses_saved_spi_and_splits_enc_tail(self) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            NullEalgSwap,
            _restore_outbound_ealg,
        )

        swap = NullEalgSwap(
            spi="0xc0000001", original_enc_tail="cbc(aes) 0xddeeff0011223344"
        )

        with patch(
            "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
            return_value=self._run_result(),
        ) as mock_run:
            restored = _restore_outbound_ealg(
                container="pcscf",
                src_ip=self.PCSCF_IP,
                dst_ip=self.UE_IP,
                swap=swap,
            )

        self.assertTrue(restored)
        mock_run.assert_called_once()  # no re-query by src/dst
        cmd = mock_run.call_args.args[0]
        self.assertEqual(cmd[cmd.index("spi") + 1], "0xc0000001")
        enc_idx = cmd.index("enc")
        self.assertEqual(cmd[enc_idx + 1], "cbc(aes)")
        self.assertEqual(cmd[enc_idx + 2], "0xddeeff0011223344")

    def test_restore_reports_failure(self) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            NullEalgSwap,
            _restore_outbound_ealg,
        )

        with patch(
            "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
            return_value=self._run_result(returncode=1),
        ):
            restored = _restore_outbound_ealg(
                container="pcscf",
                src_ip=self.PCSCF_IP,
                dst_ip=self.UE_IP,
                swap=NullEalgSwap(
                    spi="0xc0000001", original_enc_tail="cbc(aes) 0xddeeff0011223344"
                ),
            )

        self.assertFalse(restored)

    def test_send_null_mode_wires_swap_and_restore_events(self) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import send_via_native_ipsec

        calls: list[list[str]] = []

        def _dispatch(cmd, **_kwargs):
            calls.append(cmd)
            if "xfrm" in cmd:
                if "update" in cmd:
                    return self._run_result()
                return self._run_result(stdout=self.XFRM_DUMP)
            return self._run_result()  # in-container driver proc

        with patch(
            "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
            side_effect=_dispatch,
        ):
            result = send_via_native_ipsec(
                container="pcscf",
                src_ip=self.PCSCF_IP,
                src_port=6101,
                dst_ip=self.UE_IP,
                dst_port=6100,
                payload=b"INVITE sip:user@host SIP/2.0\r\n\r\n",
                timeout_seconds=1.0,
                ipsec_mode="null",
            )

        # query → null update → driver → restore update
        self.assertEqual(len(calls), 4)
        self.assertIn("update", calls[1])
        self.assertIn("python3", calls[2])
        self.assertIn("update", calls[3])
        self.assertIn(
            "native-ipsec:null-mode:ealg-saved:cbc(aes):0xc0000001",
            result.observer_events,
        )
        self.assertIn(
            "native-ipsec:null-mode:restore-ok:0xc0000001", result.observer_events
        )

    def test_send_null_mode_surfaces_restore_failure_and_still_restores_on_error(
        self,
    ) -> None:
        from volte_mutation_fuzzer.sender.ipsec_native import (
            NativeIPsecError,
            send_via_native_ipsec,
        )

        update_results = [
            self._run_result(),  # null swap succeeds
            self._run_result(returncode=1),  # restore fails
        ]
        calls: list[list[str]] = []

        def _dispatch(cmd, **_kwargs):
            calls.append(cmd)
            if "xfrm" in cmd:
                if "update" in cmd:
                    return update_results.pop(0)
                return self._run_result(stdout=self.XFRM_DUMP)
            return self._run_result()  # driver succeeds

        with patch(
            "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
            side_effect=_dispatch,
        ):
            result = send_via_native_ipsec(
                container="pcscf",
                src_ip=self.PCSCF_IP,
                src_port=6101,
                dst_ip=self.UE_IP,
                dst_port=6100,
                payload=b"INVITE sip:user@host SIP/2.0\r\n\r\n",
                timeout_seconds=1.0,
                ipsec_mode="null",
            )

        self.assertIn(
            "native-ipsec:null-mode:restore-failed:0xc0000001",
            result.observer_events,
        )

        # Same wiring on the exception path: the restore runs before the
        # error is raised and its outcome is attached to the error events.
        update_results = [self._run_result(), self._run_result()]

        def _dispatch_error(cmd, **_kwargs):
            calls.append(cmd)
            if "xfrm" in cmd:
                if "update" in cmd:
                    return update_results.pop(0)
                return self._run_result(stdout=self.XFRM_DUMP)
            raise TimeoutError("docker exec timed out")

        with patch(
            "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
            side_effect=_dispatch_error,
        ):
            with self.assertRaises(NativeIPsecError) as ctx:
                send_via_native_ipsec(
                    container="pcscf",
                    src_ip=self.PCSCF_IP,
                    src_port=6101,
                    dst_ip=self.UE_IP,
                    dst_port=6100,
                    payload=b"INVITE sip:user@host SIP/2.0\r\n\r\n",
                    timeout_seconds=1.0,
                    ipsec_mode="null",
                )

        self.assertIn(
            "native-ipsec:null-mode:restore-ok:0xc0000001",
            ctx.exception.observer_events,
        )


if __name__ == "__main__":
    unittest.main()
