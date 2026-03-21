from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from volte_mutation_fuzzer.sender.contracts import SendArtifact, TargetEndpoint
from volte_mutation_fuzzer.sender.real_ue import (
    RealUEDirectResolver,
    RouteCheckResult,
    check_route_to_target,
    prepare_real_ue_direct_payload,
)


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
            "OPTIONS sip:ue@example.com SIP/2.0\r\n"
            "Via: SIP/2.0/UDP proxy.example.com:5060;branch=z9hG4bK-1\r\n"
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
        original = b"INVITE sip:ue@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n"
        payload, events = prepare_real_ue_direct_payload(
            SendArtifact.from_packet_bytes(original),
            local_host="127.0.0.1",
            local_port=43210,
        )

        self.assertEqual(payload, original)
        self.assertEqual(events, ("direct-normalization:bytes-unmodified",))


if __name__ == "__main__":
    unittest.main()
