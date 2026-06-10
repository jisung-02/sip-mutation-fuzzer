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
        self.assertEqual(resolved.impi, "001010000123512")
        self.assertEqual(
            resolved.observer_events,
            ("resolver:scscf-kamctl:222222->10.20.20.2:5072",),
        )

    def test_resolver_returns_impi_from_pcscf_register_contact(self) -> None:
        resolver = RealUEDirectResolver()
        target = TargetEndpoint(mode="real-ue-direct", msisdn="111111")

        def fake_run(args, **kwargs):
            if args == ["docker", "exec", "pcscf", "ip", "xfrm", "state"]:
                return subprocess.CompletedProcess(
                    args=args,
                    returncode=0,
                    stdout=(
                        "src 10.20.20.5 dst 172.22.0.21\n"
                        "\tproto esp spi 0x00001004 reqid 4100 mode transport\n"
                        "\tsel src 10.20.20.5/32 dst 172.22.0.21/32 sport 49168 dport 5102\n"
                    ),
                    stderr="",
                )
            if args[:5] == ["docker", "exec", "scscf", "kamctl", "ul"]:
                return subprocess.CompletedProcess(
                    args=args, returncode=1, stdout="", stderr=""
                )
            if args[:5] == ["docker", "exec", "pcscf", "kamctl", "ul"]:
                return subprocess.CompletedProcess(
                    args=args, returncode=1, stdout="", stderr=""
                )
            if args[:4] == ["docker", "exec", "mysql", "mysql"]:
                return subprocess.CompletedProcess(
                    args=args, returncode=1, stdout="", stderr=""
                )
            if args == ["docker", "logs", "pcscf", "--tail", "500"]:
                return subprocess.CompletedProcess(
                    args=args,
                    returncode=0,
                    stdout=(
                        "3(45) NOTICE: <script>: Contact header: "
                        '<sip:001010000123511@10.20.20.5:5060>;+sip.instance="x"\n'
                    ),
                    stderr="",
                )
            raise AssertionError(f"unexpected command: {args!r}")

        with (
            patch.object(
                resolver, "_lookup_imsi_from_pyhss", return_value="001010000123511"
            ),
            patch(
                "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
                side_effect=fake_run,
            ),
        ):
            resolved = resolver.resolve(target)

        self.assertEqual(resolved.host, "10.20.20.5")
        self.assertEqual(resolved.port, 5060)
        self.assertEqual(resolved.impi, "001010000123511")

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

    def test_prepare_real_ue_direct_payload_rewrites_byte_headers_preserving_binary_body(
        self,
    ) -> None:
        binary_body = b"\x01\x07\x04\x81\x01\x80\xf6\x00"
        original = (
            f"MESSAGE {REALISTIC_REQUEST_URI} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {PCSCF_HOST}:5060;branch=z9hG4bK-1\r\n"
            "Contact: <sip:attacker@203.0.113.10:5090>\r\n"
            f"Content-Length: {len(binary_body)}\r\n\r\n"
        ).encode("ascii") + binary_body

        payload, events = prepare_real_ue_direct_payload(
            SendArtifact.from_packet_bytes(original),
            local_host="127.0.0.1",
            local_port=43210,
        )
        header_part, separator, body = payload.partition(b"\r\n\r\n")
        rendered_headers = header_part.decode("ascii")

        self.assertEqual(separator, b"\r\n\r\n")
        self.assertEqual(body, binary_body)
        self.assertIn(
            "Via: SIP/2.0/UDP 127.0.0.1:43210;branch=z9hG4bK-1;rport",
            rendered_headers,
        )
        self.assertIn("Contact: <sip:attacker@127.0.0.1:43210>", rendered_headers)
        self.assertEqual(
            events,
            (
                "direct-normalization:bytes:via",
                "direct-normalization:bytes:contact",
            ),
        )

    def test_resolve_protected_ports_prefers_matching_msisdn_from_logs(self) -> None:
        """Multi-UE Security-Client logs are filtered by nearby UE IP context.

        Each REGISTER processing block has its UE IP echoed near the
        Security-Client header line; the resolver prefers the block whose
        nearby context matches *requested_ue_ip* over the most-recent global
        match. With both blocks present, asking for 10.20.20.8 must yield
        that UE's pair (8100, 8101) — not 10.20.20.9's (7000, 7001).
        """
        resolver = RealUEDirectResolver()

        # The nearby-UE-IP window is ±20 lines around the Security-Client
        # line, so the two UE blocks must be separated by enough unrelated
        # log lines that 10.20.20.9's block sits outside 10.20.20.8's
        # window (and vice versa). 30 unrelated lines is plenty.
        unrelated_block = "".join(
            f"<script>: unrelated log line {i}\n" for i in range(30)
        )
        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["docker"],
                returncode=0,
                stdout=(
                    "REGISTER from 10.20.20.8 received\n"
                    "<script>: Security-Client=ipsec-3gpp;alg=hmac-md5-96;ealg=null;"
                    "mod=trans;port-c=8100;port-s=8101;prot=esp;spi-c=1;spi-s=2\n"
                    + unrelated_block
                    + "REGISTER from 10.20.20.9 received\n"
                    "<script>: Security-Client=ipsec-3gpp;alg=hmac-md5-96;ealg=null;"
                    "mod=trans;port-c=7000;port-s=7001;prot=esp;spi-c=3;spi-s=4\n"
                ),
                stderr="",
            ),
        ) as mock_run:
            port_pc, port_ps = resolver.resolve_protected_ports(
                "111111",
                ue_ip="10.20.20.8",
            )

        self.assertEqual((port_pc, port_ps), (8100, 8101))
        mock_run.assert_called_once_with(
            ["docker", "logs", "pcscf", "--since", "5m"],
            capture_output=True,
            text=True,
            timeout=15.0,
            check=False,
        )

    def test_resolve_protected_ports_multi_ue_no_nearby_match_falls_through_to_xfrm(
        self,
    ) -> None:
        """Multi-UE Security-Client logs with no nearby UE-IP context must not guess.

        When the requested UE IP appears in no Security-Client line's ±20
        window and the log carries *more than one distinct* port pair, the
        global most-recent fallback is unsafe — it would route to whichever
        UE registered last. Strategy 1 returns None instead, and the
        resolver falls through to the IP-filtered xfrm strategy, which keys
        strictly on 10.20.20.8 and returns its non-adjacent pair
        (63193, 61008) — not the last Security-Client pair (7000, 7001).
        """
        resolver = RealUEDirectResolver(env={"VMF_REAL_UE_PCSCF_IP": "172.22.0.21"})
        # Two distinct Security-Client pairs, neither line carrying the
        # requested UE IP anywhere in its window.
        security_client_log = (
            "<script>: Security-Client=ipsec-3gpp;alg=hmac-md5-96;ealg=null;"
            "mod=trans;port-c=8100;port-s=8101;prot=esp;spi-c=1;spi-s=2\n"
            "<script>: Security-Client=ipsec-3gpp;alg=hmac-md5-96;ealg=null;"
            "mod=trans;port-c=7000;port-s=7001;prot=esp;spi-c=3;spi-s=4\n"
        )
        canonical_xfrm = (
            "src 10.20.20.8 dst 172.22.0.21\n"
            "\tproto esp spi 0x00001000 reqid 4096 mode transport\n"
            "\tsel src 10.20.20.8/32 dst 172.22.0.21/32 sport 61008 dport 5100\n"
            "src 10.20.20.8 dst 172.22.0.21\n"
            "\tproto esp spi 0x00001001 reqid 4097 mode transport\n"
            "\tsel src 10.20.20.8/32 dst 172.22.0.21/32 sport 63193 dport 6100\n"
        )
        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            side_effect=(
                subprocess.CompletedProcess(
                    args=["docker"], returncode=0, stdout=security_client_log, stderr=""
                ),
                subprocess.CompletedProcess(
                    args=["docker"], returncode=0, stdout=canonical_xfrm, stderr=""
                ),
            ),
        ):
            port_pc, port_ps = resolver.resolve_protected_ports(
                "111111",
                ue_ip="10.20.20.8",
            )

        self.assertEqual((port_pc, port_ps), (63193, 61008))

    def test_resolve_protected_ports_single_ue_global_pair_confirmed_by_xfrm(
        self,
    ) -> None:
        """Single-UE global-fallback pair is kept when live xfrm confirms it.

        When every Security-Client line agrees on the same pair (single-UE
        log whose REGISTER block omits the UE IP), the resolver cross-checks
        the pair against live xfrm SAs. Here the UE's installed sports
        contain {8100, 8101}, so the Security-Client pair is trusted and
        returned as-is — xfrm's dport ordering is not used to recompute it.
        """
        resolver = RealUEDirectResolver(env={"VMF_REAL_UE_PCSCF_IP": "172.22.0.21"})
        security_client_log = (
            "<script>: Security-Client=ipsec-3gpp;alg=hmac-md5-96;ealg=null;"
            "mod=trans;port-c=8100;port-s=8101;prot=esp;spi-c=1;spi-s=2\n"
            "<script>: Security-Client=ipsec-3gpp;alg=hmac-md5-96;ealg=null;"
            "mod=trans;port-c=8100;port-s=8101;prot=esp;spi-c=5;spi-s=6\n"
        )
        # UE sports agree with the Security-Client pair (8100, 8101) — but the
        # dport ordering would yield (8101, 8100) if Strategy 2 ran, so a
        # passing assertion proves the Security-Client pair won.
        confirming_xfrm = (
            "src 10.20.20.8 dst 172.22.0.21\n"
            "\tproto esp spi 0x00001000 reqid 4096 mode transport\n"
            "\tsel src 10.20.20.8/32 dst 172.22.0.21/32 sport 8100 dport 5100\n"
            "src 10.20.20.8 dst 172.22.0.21\n"
            "\tproto esp spi 0x00001001 reqid 4097 mode transport\n"
            "\tsel src 10.20.20.8/32 dst 172.22.0.21/32 sport 8101 dport 6100\n"
        )
        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            side_effect=(
                subprocess.CompletedProcess(
                    args=["docker"], returncode=0, stdout=security_client_log, stderr=""
                ),
                subprocess.CompletedProcess(
                    args=["docker"], returncode=0, stdout=confirming_xfrm, stderr=""
                ),
            ),
        ):
            port_pc, port_ps = resolver.resolve_protected_ports(
                "111111",
                ue_ip="10.20.20.8",
            )

        self.assertEqual((port_pc, port_ps), (8100, 8101))

    def test_resolve_protected_ports_stale_global_pair_overridden_by_xfrm(
        self,
    ) -> None:
        """A stale single Security-Client pair loses to the live xfrm SA.

        If the UE rekeyed within the log window, the old Security-Client
        line still parses to a single pair via the global fallback, but the
        kernel's installed sports no longer contain it (zero overlap). The
        cross-check distrusts the stale pair and Strategy 2 resolves the
        live non-adjacent pair (63193, 61008) from xfrm instead.
        """
        resolver = RealUEDirectResolver(env={"VMF_REAL_UE_PCSCF_IP": "172.22.0.21"})
        stale_security_client_log = (
            "<script>: Security-Client=ipsec-3gpp;alg=hmac-md5-96;ealg=null;"
            "mod=trans;port-c=9000;port-s=9001;prot=esp;spi-c=1;spi-s=2\n"
        )
        live_xfrm = (
            "src 10.20.20.8 dst 172.22.0.21\n"
            "\tproto esp spi 0x00001000 reqid 4096 mode transport\n"
            "\tsel src 10.20.20.8/32 dst 172.22.0.21/32 sport 61008 dport 5100\n"
            "src 10.20.20.8 dst 172.22.0.21\n"
            "\tproto esp spi 0x00001001 reqid 4097 mode transport\n"
            "\tsel src 10.20.20.8/32 dst 172.22.0.21/32 sport 63193 dport 6100\n"
        )
        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            side_effect=(
                subprocess.CompletedProcess(
                    args=["docker"],
                    returncode=0,
                    stdout=stale_security_client_log,
                    stderr="",
                ),
                subprocess.CompletedProcess(
                    args=["docker"], returncode=0, stdout=live_xfrm, stderr=""
                ),
            ),
        ):
            port_pc, port_ps = resolver.resolve_protected_ports(
                "111111",
                ue_ip="10.20.20.8",
            )

        self.assertEqual((port_pc, port_ps), (63193, 61008))

    def test_resolve_protected_ports_xfrm_reads_non_adjacent_pair_from_dport(
        self,
    ) -> None:
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
                "111111",
                ue_ip="10.20.20.2",
            )

        self.assertEqual((port_pc, port_ps), (63193, 61008))

    def test_resolve_protected_ports_reads_both_ports_from_security_client_header(
        self,
    ) -> None:
        """Kamailio P-CSCF log lines carry port-c and port-s in Security-Client.

        The header gives the authoritative pair without any +1 estimation:
            Security-Client=ipsec-3gpp;...;port-c=63193;port-s=61008;...

        The single Security-Client pair takes the global fallback (no UE IP
        in the log window), which is cross-checked against live xfrm. The
        mocked xfrm SAs carry the *same* sports (63193, 61008) so the
        cross-check confirms the pair — but their dport ordering would map
        to the swapped tuple (61008, 63193) if Strategy 2 actually ran, so
        any implementation that ignores the Security-Client header and falls
        back to xfrm parsing yields the wrong answer instead of accidentally
        matching.
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

        # Decoy xfrm output — same sports as the Security-Client pair (so the
        # cross-check confirms membership) but dport ordering that Strategy 2
        # would map to the *swapped* tuple (61008, 63193). A fallback-only
        # implementation returns that swap and the assertion fails loudly.
        decoy_xfrm = (
            "src 10.20.20.2 dst 172.22.0.21\n"
            "\tproto esp spi 0x00001000 reqid 4096 mode transport\n"
            "\tsel src 10.20.20.2/32 dst 172.22.0.21/32 sport 63193 dport 5100\n"
            "src 10.20.20.2 dst 172.22.0.21\n"
            "\tproto esp spi 0x00001001 reqid 4097 mode transport\n"
            "\tsel src 10.20.20.2/32 dst 172.22.0.21/32 sport 61008 dport 6100\n"
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
                "111111",
                ue_ip="10.20.20.2",
            )

        self.assertEqual((port_pc, port_ps), (63193, 61008))

    def test_resolve_protected_ports_prefers_matching_msisdn_from_xfrm(self) -> None:
        """Multi-UE xfrm output is filtered by *requested_ue_ip* before mapping.

        Each UE has the full SA pair installed (both directions, two
        distinct PCSCF protected ports). Asking for 10.20.20.8 must
        ignore 10.20.20.9's SAs entirely and apply the dport-ordering
        convention only to UE 8's tuples:

        - dport=5102 (smaller, PCSCF client) → UE sport=8101 = port_ps
        - dport=5103 (larger,  PCSCF server) → UE sport=8100 = port_pc
        """
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
                        "src 172.22.0.21 dst 10.20.20.8\n"
                        "\tproto esp spi 0xeeee reqid 5 mode transport\n"
                        "\tsel src 172.22.0.21/32 dst 10.20.20.8/32 sport 5102 dport 8101\n"
                        "src 10.20.20.8 dst 172.22.0.21\n"
                        "\tproto esp spi 0xffff reqid 6 mode transport\n"
                        "\tsel src 10.20.20.8/32 dst 172.22.0.21/32 sport 8101 dport 5102\n"
                    ),
                    stderr="",
                ),
            ),
        ) as mock_run:
            port_pc, port_ps = resolver.resolve_protected_ports(
                "111111",
                ue_ip="10.20.20.8",
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

    def test_resolve_protected_ports_xfrm_returns_none_with_one_dport(self) -> None:
        """A half-installed SA pair (only one direction) is ambiguous.

        Old behaviour completed it via min+1; new behaviour falls through to
        the next strategy. With logs and xfrm both empty after the partial
        SA, the resolver must raise rather than guess.
        """
        resolver = RealUEDirectResolver(env={"VMF_REAL_UE_PCSCF_IP": "172.22.0.21"})
        partial_xfrm = (
            "src 10.20.20.2 dst 172.22.0.21\n"
            "\tproto esp spi 0x00001000 reqid 4096 mode transport\n"
            "\tsel src 10.20.20.2/32 dst 172.22.0.21/32 sport 61008 dport 5100\n"
        )
        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            side_effect=(
                subprocess.CompletedProcess(
                    args=["docker"], returncode=0, stdout="", stderr=""
                ),
                subprocess.CompletedProcess(
                    args=["docker"], returncode=0, stdout=partial_xfrm, stderr=""
                ),
            ),
        ):
            with self.assertRaises(RealUEDirectResolutionError):
                resolver.resolve_protected_ports("111111", ue_ip="10.20.20.2")

    def test_resolve_protected_ports_xfrm_returns_none_with_three_dports(self) -> None:
        """Rekey overlap can leave 3+ dports installed simultaneously.

        Three-or-more is also ambiguous and must fall through, not pick one.
        """
        resolver = RealUEDirectResolver(env={"VMF_REAL_UE_PCSCF_IP": "172.22.0.21"})
        rekey_overlap_xfrm = (
            "src 10.20.20.2 dst 172.22.0.21\n"
            "\tproto esp spi 0x00001000 reqid 4096 mode transport\n"
            "\tsel src 10.20.20.2/32 dst 172.22.0.21/32 sport 61008 dport 5100\n"
            "src 10.20.20.2 dst 172.22.0.21\n"
            "\tproto esp spi 0x00001001 reqid 4097 mode transport\n"
            "\tsel src 10.20.20.2/32 dst 172.22.0.21/32 sport 63193 dport 6100\n"
            "src 10.20.20.2 dst 172.22.0.21\n"
            "\tproto esp spi 0x00001002 reqid 4098 mode transport\n"
            "\tsel src 10.20.20.2/32 dst 172.22.0.21/32 sport 65000 dport 7100\n"
        )
        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            side_effect=(
                subprocess.CompletedProcess(
                    args=["docker"], returncode=0, stdout="", stderr=""
                ),
                subprocess.CompletedProcess(
                    args=["docker"], returncode=0, stdout=rekey_overlap_xfrm, stderr=""
                ),
            ),
        ):
            with self.assertRaises(RealUEDirectResolutionError):
                resolver.resolve_protected_ports("111111", ue_ip="10.20.20.2")

    def test_resolve_protected_ports_falls_back_to_xfrm_when_security_client_malformed(
        self,
    ) -> None:
        """Malformed Security-Client header (missing port-s) must not poison the chain.

        The regex requires both port-c= and port-s=; if only port-c is present,
        Strategy 1 returns None and the resolver falls through to xfrm. This
        test fixture has Strategy 1 fail by malformation, Strategy 2 succeed
        with the canonical iPhone SA shape, and asserts the answer comes
        from xfrm.
        """
        resolver = RealUEDirectResolver(env={"VMF_REAL_UE_PCSCF_IP": "172.22.0.21"})
        malformed_log = (
            "<script>: Security-Client=ipsec-3gpp;alg=hmac-md5-96;ealg=aes-cbc;mod=trans;"
            "port-c=63193;prot=esp;spi-c=200418294;spi-s=12070439\n"
        )
        canonical_xfrm = (
            "src 10.20.20.2 dst 172.22.0.21\n"
            "\tproto esp spi 0x00001000 reqid 4096 mode transport\n"
            "\tsel src 10.20.20.2/32 dst 172.22.0.21/32 sport 61008 dport 5100\n"
            "src 10.20.20.2 dst 172.22.0.21\n"
            "\tproto esp spi 0x00001001 reqid 4097 mode transport\n"
            "\tsel src 10.20.20.2/32 dst 172.22.0.21/32 sport 63193 dport 6100\n"
        )
        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            side_effect=(
                subprocess.CompletedProcess(
                    args=["docker"], returncode=0, stdout=malformed_log, stderr=""
                ),
                subprocess.CompletedProcess(
                    args=["docker"], returncode=0, stdout=canonical_xfrm, stderr=""
                ),
            ),
        ):
            port_pc, port_ps = resolver.resolve_protected_ports(
                "111111",
                ue_ip="10.20.20.2",
            )
        self.assertEqual((port_pc, port_ps), (63193, 61008))

    def test_resolve_protected_ports_reuses_caller_xfrm_snapshot(self) -> None:
        """A caller-supplied xfrm snapshot skips the in-resolver docker exec.

        With empty logs (Strategy 1 yields nothing) the resolver needs xfrm
        to read ports. When the caller already read the SA table this case
        and threads it in via ``xfrm_state``, the only subprocess call is the
        single ``docker logs`` — the xfrm read is served from the snapshot.
        side_effect has exactly one entry so any second subprocess call
        (a redundant ``docker exec ... ip xfrm state``) raises StopIteration
        and fails the test loudly.
        """
        resolver = RealUEDirectResolver(env={"VMF_REAL_UE_PCSCF_IP": "172.22.0.21"})
        snapshot = (
            "src 10.20.20.8 dst 172.22.0.21\n"
            "\tproto esp spi 0x00001000 reqid 4096 mode transport\n"
            "\tsel src 10.20.20.8/32 dst 172.22.0.21/32 sport 61008 dport 5100\n"
            "src 10.20.20.8 dst 172.22.0.21\n"
            "\tproto esp spi 0x00001001 reqid 4097 mode transport\n"
            "\tsel src 10.20.20.8/32 dst 172.22.0.21/32 sport 63193 dport 6100\n"
        )
        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            side_effect=(
                subprocess.CompletedProcess(
                    args=["docker"], returncode=0, stdout="", stderr=""
                ),
            ),
        ) as mock_run:
            port_pc, port_ps = resolver.resolve_protected_ports(
                "111111",
                ue_ip="10.20.20.8",
                xfrm_state=snapshot,
            )

        self.assertEqual((port_pc, port_ps), (63193, 61008))
        # Only the docker-logs read happened; xfrm came from the snapshot.
        mock_run.assert_called_once()

    def test_resolve_reuses_caller_xfrm_snapshot_for_active_ip_check(self) -> None:
        """resolve() validates the kamctl contact against a threaded snapshot.

        The active-UE-IP sentinel normally issues its own ``docker exec ...
        ip xfrm state``. When the caller threads the snapshot in, that read
        is served from it, so the only subprocess call is the single kamctl
        lookup. A second call (the sentinel's own xfrm exec) would raise
        StopIteration.
        """
        resolver = RealUEDirectResolver(
            env={
                "VMF_REAL_UE_SCSCF_CONTAINER": "scscf",
                "VMF_REAL_UE_PCSCF_CONTAINER": "pcscf",
                "VMF_REAL_UE_PCSCF_IP": "172.22.0.21",
            }
        )
        target = TargetEndpoint(mode="real-ue-direct", msisdn="111111")
        snapshot = (
            "src 10.20.20.8 dst 172.22.0.21\n"
            "\tproto esp spi 0x00001000 reqid 4096 mode transport\n"
            "\tsel src 10.20.20.8/32 dst 172.22.0.21/32 sport 8100 dport 5100\n"
        )
        kamctl_out = "Contact:: <sip:111111@10.20.20.8:8100;...>;q=;expires=..."
        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            side_effect=(
                subprocess.CompletedProcess(
                    args=["docker"], returncode=0, stdout=kamctl_out, stderr=""
                ),
            ),
        ) as mock_run:
            resolved = resolver.resolve(target, xfrm_state=snapshot)

        self.assertEqual(resolved.host, "10.20.20.8")
        mock_run.assert_called_once()

    def test_read_xfrm_state_returns_none_on_failure(self) -> None:
        """read_xfrm_state returns None when docker exec fails (fail-safe)."""
        resolver = RealUEDirectResolver(env={"VMF_REAL_UE_PCSCF_IP": "172.22.0.21"})
        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["docker"], returncode=1, stdout="", stderr="boom"
            ),
        ):
            self.assertIsNone(resolver.read_xfrm_state())


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
                args=["docker"],
                returncode=0,
                stdout=self._XFRM_OUTPUT_WITH_UE_SA,
                stderr="",
            ),
        ):
            status = check_ipsec_sa_alive()
        self.assertTrue(status.alive)
        self.assertGreaterEqual(status.sa_count, 1)

    def test_not_alive_when_no_ue_sa(self) -> None:
        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["docker"],
                returncode=0,
                stdout=self._XFRM_OUTPUT_NO_UE_SA,
                stderr="",
            ),
        ):
            status = check_ipsec_sa_alive()
        self.assertFalse(status.alive)
        self.assertEqual(status.sa_count, 0)

    def test_not_alive_when_empty_output(self) -> None:
        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["docker"],
                returncode=0,
                stdout="",
                stderr="",
            ),
        ):
            status = check_ipsec_sa_alive()
        self.assertFalse(status.alive)

    def test_not_alive_on_command_failure(self) -> None:
        with patch(
            "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["docker"],
                returncode=1,
                stdout="",
                stderr="not found",
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
