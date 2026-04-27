import subprocess
import unittest
from unittest.mock import patch

from volte_mutation_fuzzer.sender.contracts import SendArtifact, TargetEndpoint
from volte_mutation_fuzzer.sender.real_ue import (
    RealUEDirectResolver,
    RouteCheckResult,
    ResolvedNativeIPsecSession,
    RealUEDirectResolutionError,
    check_ipsec_sa_alive,
    check_route_to_target,
    prepare_real_ue_direct_payload,
    resolve_native_ipsec_session,
)

IMS_DOMAIN = "ims.mnc001.mcc001.3gppnetwork.org"
PCSCF_HOST = f"pcscf.{IMS_DOMAIN}"
REALISTIC_REQUEST_URI = "sip:111111@10.20.20.8:8100"


class RealUEDirectHelperTests(unittest.TestCase):
    def test_resolver_prefers_kamctl_contact_for_msisdn(self) -> None:
        resolver = RealUEDirectResolver(
            {
                "VMF_REAL_UE_SCSCF_CONTAINER": "scscf",
                "VMF_REAL_UE_PCSCF_CONTAINER": "pcscf",
            }
        )
        target = TargetEndpoint(mode="real-ue-direct", msisdn="222222")

        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["docker"],
                returncode=0,
                stdout=(
                    "AOR: sip:222222@ims.mnc001.mcc001.3gppnetwork.org\n"
                    "    Contact: <sip:001010000123512@10.20.20.2:5072>;expires=300\n"
                ),
                stderr="",
            ),
        ):
            resolved = resolver.resolve(target)

        self.assertEqual(resolved.host, "10.20.20.2")
        self.assertEqual(resolved.port, 5072)
        self.assertEqual(
            resolved.observer_events,
            ("resolver:scscf-kamctl:222222->10.20.20.2:5072",),
        )

    def test_check_route_to_target_uses_darwin_route_get(self) -> None:
        with (
            patch(
                "volte_mutation_fuzzer.sender.real_ue.platform.system",
                return_value="Darwin",
            ),
            patch(
                "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    args=["route"],
                    returncode=0,
                    stdout="route to: 10.20.20.2\ngateway: 127.0.0.1\n",
                    stderr="",
                ),
            ) as mock_run,
        ):
            result = check_route_to_target("10.20.20.2")

        self.assertEqual(result, RouteCheckResult(True, "route to: 10.20.20.2"))
        mock_run.assert_called_once()
        self.assertEqual(
            mock_run.call_args.args[0],
            ["route", "-n", "get", "10.20.20.2"],
        )

    def test_prepare_real_ue_direct_payload_rewrites_wire_routing_headers(self) -> None:
        wire_text = (
            f"OPTIONS {REALISTIC_REQUEST_URI} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {PCSCF_HOST}:5060;branch=z9hG4bK-1\r\n"
            "Contact: <sip:attacker@203.0.113.10:5090>\r\n"
            "Content-Length: 0\r\n\r\n"
        )

        payload, events = prepare_real_ue_direct_payload(
            SendArtifact.from_wire_text(wire_text),
            local_host="127.0.0.1",
            local_port=43210,
        )
        rendered = payload.decode("utf-8")

        self.assertIn(
            "Via: SIP/2.0/UDP 127.0.0.1:43210;branch=z9hG4bK-1;rport",
            rendered,
        )
        self.assertIn("Contact: <sip:attacker@127.0.0.1:43210>", rendered)
        self.assertEqual(
            events,
            (
                "direct-normalization:wire:via",
                "direct-normalization:wire:contact",
            ),
        )

    def test_prepare_real_ue_direct_payload_keeps_bytes_unmodified(self) -> None:
        original = (
            f"INVITE {REALISTIC_REQUEST_URI} SIP/2.0\r\nContent-Length: 0\r\n\r\n"
        ).encode("utf-8")
        payload, events = prepare_real_ue_direct_payload(
            SendArtifact.from_packet_bytes(original),
            local_host="127.0.0.1",
            local_port=43210,
        )

        self.assertEqual(payload, original)
        self.assertEqual(events, ("direct-normalization:bytes-unmodified",))

    def test_resolve_protected_ports_prefers_matching_msisdn_from_logs(self) -> None:
        resolver = RealUEDirectResolver()

        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["docker"],
                returncode=0,
                stdout=(
                    "Term UE connection information : IP is 10.20.20.8 and Port is 8100\n"
                    "Term UE connection information : IP is 10.20.20.9 and Port is 7000\n"
                ),
                stderr="",
            ),
        ) as mock_run:
            port_pc, port_ps = resolver.resolve_protected_ports(
                "111111", ue_ip="10.20.20.8",
            )

        self.assertEqual((port_pc, port_ps), (8100, 8101))
        mock_run.assert_called_once_with(
            ["docker", "logs", "pcscf", "--since", "5m"],
            capture_output=True,
            text=True,
            timeout=15.0,
            check=False,
        )

    def test_resolve_protected_ports_xfrm_reads_non_adjacent_pair_from_dport(self) -> None:
        """iPhone 16e returns non-adjacent (port_pc, port_ps) pairs.

        Real capture from `docker exec pcscf ip xfrm state` for UE 10.20.20.2 / PCSCF 172.22.0.21:
        - UE→PCSCF dport=5100 → sport=61008 = UE server port (port_ps)
        - UE→PCSCF dport=6100 → sport=63193 = UE client port (port_pc)

        Strategy 1 (P-CSCF logs) returns nothing here, forcing Strategy 2 (xfrm).
        Correct return is (63193, 61008); current implementation returns
        (min({63193, 61008}), min+1) = (61008, 61009) which is wrong on both axes.
        """
        resolver = RealUEDirectResolver(env={"VMF_REAL_UE_PCSCF_IP": "172.22.0.21"})

        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            side_effect=(
                subprocess.CompletedProcess(
                    args=["docker"],
                    returncode=0,
                    stdout="",
                    stderr="",
                ),
                subprocess.CompletedProcess(
                    args=["docker"],
                    returncode=0,
                    stdout=(
                        "src 10.20.20.2 dst 172.22.0.21\n"
                        "\tproto esp spi 0x00001000 reqid 4096 mode transport\n"
                        "\tsel src 10.20.20.2/32 dst 172.22.0.21/32 sport 61008 dport 5100\n"
                        "src 172.22.0.21 dst 10.20.20.2\n"
                        "\tproto esp spi 0x0bf223f6 reqid 200418294 mode transport\n"
                        "\tsel src 172.22.0.21/32 dst 10.20.20.2/32 sport 6100 dport 63193\n"
                        "src 172.22.0.21 dst 10.20.20.2\n"
                        "\tproto esp spi 0x00b82e27 reqid 12070439 mode transport\n"
                        "\tsel src 172.22.0.21/32 dst 10.20.20.2/32 sport 5100 dport 61008\n"
                        "src 10.20.20.2 dst 172.22.0.21\n"
                        "\tproto esp spi 0x00001001 reqid 4097 mode transport\n"
                        "\tsel src 10.20.20.2/32 dst 172.22.0.21/32 sport 63193 dport 6100\n"
                    ),
                    stderr="",
                ),
            ),
        ):
            port_pc, port_ps = resolver.resolve_protected_ports(
                "111111", ue_ip="10.20.20.2",
            )

        self.assertEqual((port_pc, port_ps), (63193, 61008))

    def test_resolve_protected_ports_reads_both_ports_from_security_client_header(self) -> None:
        """Kamailio P-CSCF log lines carry port-c and port-s in Security-Client.

        The header gives the authoritative pair without any +1 estimation:
            Security-Client=ipsec-3gpp;...;port-c=63193;port-s=61008;...

        Current implementation only parses `Term UE connection` lines and falls
        through to Strategy 2. We deliberately mock Strategy 2 with a
        *different* port pair (50000/50001) so that any implementation that
        ignores the Security-Client header and falls back to xfrm parsing
        yields a wrong answer instead of accidentally matching.
        """
        resolver = RealUEDirectResolver(env={"VMF_REAL_UE_PCSCF_IP": "172.22.0.21"})

        # Verbatim line shape captured from the running pcscf container during
        # an iPhone 16e REGISTER (multiple algorithm offers comma-joined inside
        # the same Security-Client header — production format).
        security_client_log = (
            "97(139) NOTICE: {2 2 REGISTER wEi6kYXGzbA39Qqpf6MDkUU4 REGISTER_reply} "
            "<script>: Security-Client=ipsec-3gpp;alg=hmac-md5-96;ealg=aes-cbc;mod=trans;"
            "port-c=63193;port-s=61008;prot=esp;spi-c=200418294;spi-s=12070439,"
            "ipsec-3gpp;alg=hmac-md5-96;ealg=null;mod=trans;port-c=63193;port-s=61008;"
            "prot=esp;spi-c=200418294;spi-s=12070439,"
            "ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;mod=trans;port-c=63193;port-s=61008;"
            "prot=esp;spi-c=200418294;spi-s=12070439,"
            "ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=63193;port-s=61008;"
            "prot=esp;spi-c=200418294;spi-s=12070439\n"
        )

        # Decoy xfrm output — different port pair so a fallback-only
        # implementation returns (50000, 50001) and the assertion fails loudly.
        decoy_xfrm = (
            "src 10.20.20.2 dst 172.22.0.21\n"
            "\tproto esp spi 0x00001000 reqid 4096 mode transport\n"
            "\tsel src 10.20.20.2/32 dst 172.22.0.21/32 sport 50001 dport 5100\n"
            "src 10.20.20.2 dst 172.22.0.21\n"
            "\tproto esp spi 0x00001001 reqid 4097 mode transport\n"
            "\tsel src 10.20.20.2/32 dst 172.22.0.21/32 sport 50000 dport 6100\n"
        )

        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            side_effect=(
                subprocess.CompletedProcess(
                    args=["docker"],
                    returncode=0,
                    stdout=security_client_log,
                    stderr="",
                ),
                subprocess.CompletedProcess(
                    args=["docker"],
                    returncode=0,
                    stdout=decoy_xfrm,
                    stderr="",
                ),
            ),
        ):
            port_pc, port_ps = resolver.resolve_protected_ports(
                "111111", ue_ip="10.20.20.2",
            )

        self.assertEqual((port_pc, port_ps), (63193, 61008))

    def test_resolve_protected_ports_prefers_matching_msisdn_from_xfrm(self) -> None:
        resolver = RealUEDirectResolver()

        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            side_effect=(
                subprocess.CompletedProcess(
                    args=["docker"],
                    returncode=0,
                    stdout="",
                    stderr="",
                ),
                subprocess.CompletedProcess(
                    args=["docker"],
                    returncode=0,
                    stdout=(
                        "src 172.22.0.21 dst 10.20.20.9\n"
                        "\tproto esp spi 0xaaaa reqid 1 mode transport\n"
                        "\tsel src 172.22.0.21/32 dst 10.20.20.9/32 sport 5105 dport 7000\n"
                        "src 10.20.20.9 dst 172.22.0.21\n"
                        "\tproto esp spi 0xbbbb reqid 2 mode transport\n"
                        "\tsel src 10.20.20.9/32 dst 172.22.0.21/32 sport 7000 dport 5105\n"
                        "src 172.22.0.21 dst 10.20.20.8\n"
                        "\tproto esp spi 0xcccc reqid 3 mode transport\n"
                        "\tsel src 172.22.0.21/32 dst 10.20.20.8/32 sport 5103 dport 8100\n"
                        "src 10.20.20.8 dst 172.22.0.21\n"
                        "\tproto esp spi 0xdddd reqid 4 mode transport\n"
                        "\tsel src 10.20.20.8/32 dst 172.22.0.21/32 sport 8100 dport 5103\n"
                    ),
                    stderr="",
                ),
            ),
        ) as mock_run:
            port_pc, port_ps = resolver.resolve_protected_ports(
                "111111", ue_ip="10.20.20.8",
            )

        self.assertEqual((port_pc, port_ps), (8100, 8101))
        self.assertEqual(mock_run.call_count, 2)
        self.assertEqual(
            mock_run.call_args_list[0].args[0],
            ["docker", "logs", "pcscf", "--since", "5m"],
        )
        self.assertEqual(
            mock_run.call_args_list[1].args[0],
            ["docker", "exec", "pcscf", "ip", "xfrm", "state"],
        )


class IPsecSACheckTests(unittest.TestCase):
    """Tests for check_ipsec_sa_alive()."""

    _XFRM_OUTPUT_WITH_UE_SA = (
        "src 10.20.20.8 dst 172.22.0.21\n"
        "\tproto esp spi 0xc3a2b100 reqid 1 mode transport\n"
        "\tsel src 10.20.20.8/32 dst 172.22.0.21/32 sport 5100 dport 5060\n"
        "src 172.22.0.21 dst 10.20.20.8\n"
        "\tproto esp spi 0xd4b3c200 reqid 2 mode transport\n"
        "\tsel src 172.22.0.21/32 dst 10.20.20.8/32 sport 5060 dport 5100\n"
    )

    _XFRM_OUTPUT_NO_UE_SA = (
        "src 172.22.0.21 dst 172.22.0.1\n"
        "\tproto esp spi 0xaabb reqid 1 mode transport\n"
        "\tsel src 172.22.0.21/32 dst 172.22.0.1/32\n"
    )

    def test_alive_when_ue_sa_exists(self) -> None:
        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["docker"], returncode=0,
                stdout=self._XFRM_OUTPUT_WITH_UE_SA, stderr="",
            ),
        ):
            status = check_ipsec_sa_alive()
        self.assertTrue(status.alive)
        self.assertGreaterEqual(status.sa_count, 1)

    def test_not_alive_when_no_ue_sa(self) -> None:
        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["docker"], returncode=0,
                stdout=self._XFRM_OUTPUT_NO_UE_SA, stderr="",
            ),
        ):
            status = check_ipsec_sa_alive()
        self.assertFalse(status.alive)
        self.assertEqual(status.sa_count, 0)

    def test_not_alive_when_empty_output(self) -> None:
        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["docker"], returncode=0, stdout="", stderr="",
            ),
        ):
            status = check_ipsec_sa_alive()
        self.assertFalse(status.alive)

    def test_not_alive_on_command_failure(self) -> None:
        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["docker"], returncode=1, stdout="", stderr="not found",
            ),
        ):
            status = check_ipsec_sa_alive()
        self.assertFalse(status.alive)
        self.assertIn("not found", status.detail)

    def test_not_alive_on_exception(self) -> None:
        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            side_effect=FileNotFoundError("docker not found"),
        ):
            status = check_ipsec_sa_alive()
        self.assertFalse(status.alive)
        self.assertIn("docker not found", status.detail)


class NativeIPsecSessionResolverTests(unittest.TestCase):
    _XFRM_OUTPUT = (
        "src 172.22.0.21 dst 10.20.20.8\n"
        "\tproto esp spi 0x1111 reqid 1 mode transport\n"
        "\tsel src 172.22.0.21/32 dst 10.20.20.8/32 sport 5103 dport 8100\n"
        "src 10.20.20.8 dst 172.22.0.21\n"
        "\tproto esp spi 0x2222 reqid 2 mode transport\n"
        "\tsel src 10.20.20.8/32 dst 172.22.0.21/32 sport 8100 dport 5103\n"
        "src 172.22.0.21 dst 10.20.20.8\n"
        "\tproto esp spi 0x3333 reqid 3 mode transport\n"
        "\tsel src 172.22.0.21/32 dst 10.20.20.8/32 sport 5104 dport 8101\n"
    )

    def test_resolves_native_session_and_port_map(self) -> None:
        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["docker"],
                returncode=0,
                stdout=self._XFRM_OUTPUT,
                stderr="",
            ),
        ) as mock_run:
            session = resolve_native_ipsec_session(
                ue_ip="10.20.20.8",
                env={"VMF_REAL_UE_PCSCF_IP": "172.22.0.21"},
            )

        self.assertIsInstance(session, ResolvedNativeIPsecSession)
        self.assertEqual(session.ue_ip, "10.20.20.8")
        self.assertEqual(session.pcscf_ip, "172.22.0.21")
        self.assertEqual(session.port_map, {8100: 5103, 8101: 5104})
        self.assertEqual(
            session.observer_events,
            (
                "native-ipsec:port-map:8100->5103",
                "native-ipsec:port-map:8101->5104",
            ),
        )
        self.assertEqual(session.pcscf_port_for(8100), 5103)
        mock_run.assert_called_once_with(
            ["docker", "exec", "pcscf", "ip", "xfrm", "state"],
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
        )

    def test_resolve_native_session_errors_when_no_matching_tuples_exist(self) -> None:
        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["docker"],
                returncode=0,
                stdout=(
                    "src 10.20.20.8 dst 172.22.0.21\n"
                    "\tproto esp spi 0x2222 reqid 2 mode transport\n"
                    "\tsel src 10.20.20.8/32 dst 172.22.0.21/32 sport 8100 dport 5103\n"
                ),
                stderr="",
            ),
        ):
            with self.assertRaises(RealUEDirectResolutionError) as ctx:
                resolve_native_ipsec_session(
                    ue_ip="10.20.20.8",
                    env={"VMF_REAL_UE_PCSCF_IP": "172.22.0.21"},
                )

        self.assertIn("no matching native IPsec tuples", str(ctx.exception))

    def test_pcscf_port_for_raises_on_unknown_ue_port(self) -> None:
        session = ResolvedNativeIPsecSession(
            ue_ip="10.20.20.8",
            pcscf_ip="172.22.0.21",
            port_map={8100: 5103},
            observer_events=(),
        )

        with self.assertRaises(RealUEDirectResolutionError) as ctx:
            session.pcscf_port_for(9999)

        self.assertIn("unknown UE protected port 9999", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
