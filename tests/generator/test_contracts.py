from __future__ import annotations

import unittest

from volte_mutation_fuzzer.generator import (
    DialogContext,
    GeneratorSettings,
    RequestSpec,
    ResponseSpec,
)
from volte_mutation_fuzzer.sip.common import NameAddress, SIPMethod, SIPURI


class GeneratorSettingsTests(unittest.TestCase):
    def test_from_env_uses_defaults_when_env_is_empty(self) -> None:
        settings = GeneratorSettings.from_env({})

        self.assertEqual(settings.target_ue_name, "UE")
        self.assertEqual(settings.via_host, "proxy.example.com")
        self.assertEqual(settings.via_port, 5060)
        self.assertEqual(settings.transport, "UDP")
        self.assertEqual(settings.user_agent, "volte-mutation-fuzzer/0.1.0")
        self.assertEqual(settings.from_user, "remote")
        self.assertEqual(settings.to_user, "ue")
        self.assertEqual(settings.request_uri_user, "ue")

    def test_from_env_reads_prefixed_values_and_normalizes_text(self) -> None:
        settings = GeneratorSettings.from_env(
            {
                "VMF_GENERATOR_TARGET_UE_NAME": " Pixel-9-Pro ",
                "VMF_GENERATOR_VIA_HOST": " ims.example.net ",
                "VMF_GENERATOR_VIA_PORT": " 5080 ",
                "VMF_GENERATOR_TRANSPORT": " tls-sctp ",
                "VMF_GENERATOR_USER_AGENT": " fuzz/0.2 ",
                "VMF_GENERATOR_FROM_DISPLAY_NAME": " P-CSCF ",
                "VMF_GENERATOR_FROM_USER": " scscf ",
                "VMF_GENERATOR_FROM_HOST": " ims.example.net ",
                "VMF_GENERATOR_TO_DISPLAY_NAME": " Victim UE ",
                "VMF_GENERATOR_TO_USER": " ue001 ",
                "VMF_GENERATOR_TO_HOST": " device.example.net ",
                "VMF_GENERATOR_REQUEST_URI_USER": " ue001 ",
                "VMF_GENERATOR_REQUEST_URI_HOST": " device.example.net ",
                "VMF_GENERATOR_CONTACT_DISPLAY_NAME": " ",
                "VMF_GENERATOR_CONTACT_USER": " proxy-contact ",
                "VMF_GENERATOR_CONTACT_HOST": " edge.example.net ",
                "VMF_GENERATOR_CONTACT_PORT": " 5090 ",
            }
        )

        self.assertEqual(settings.target_ue_name, "Pixel-9-Pro")
        self.assertEqual(settings.via_host, "ims.example.net")
        self.assertEqual(settings.via_port, 5080)
        self.assertEqual(settings.transport, "TLS-SCTP")
        self.assertEqual(settings.user_agent, "fuzz/0.2")
        self.assertEqual(settings.from_display_name, "P-CSCF")
        self.assertEqual(settings.to_display_name, "Victim UE")
        self.assertEqual(settings.request_uri_host, "device.example.net")
        self.assertIsNone(settings.contact_display_name)
        self.assertEqual(settings.contact_user, "proxy-contact")
        self.assertEqual(settings.contact_host, "edge.example.net")
        self.assertEqual(settings.contact_port, 5090)

    def test_from_env_rejects_blank_required_string(self) -> None:
        with self.assertRaises(ValueError):
            GeneratorSettings.from_env({"VMF_GENERATOR_VIA_HOST": "   "})


class DialogContextTests(unittest.TestCase):
    def test_defaults_start_without_dialog_state(self) -> None:
        context = DialogContext()

        self.assertIsNone(context.call_id)
        self.assertEqual(context.local_cseq, 0)
        self.assertEqual(context.remote_cseq, 0)
        self.assertEqual(context.route_set, ())
        self.assertFalse(context.has_dialog)
        self.assertFalse(context.is_registered)
        self.assertFalse(context.is_reinvite)

    def test_normalizes_identifiers_and_advances_sequences(self) -> None:
        context = DialogContext(
            call_id=" call-1 ",
            local_tag=" ue-tag ",
            remote_tag=" remote-tag ",
            local_cseq=4,
            remote_cseq=9,
        )

        self.assertEqual(context.call_id, "call-1")
        self.assertEqual(context.local_tag, "ue-tag")
        self.assertEqual(context.remote_tag, "remote-tag")
        self.assertTrue(context.has_dialog)
        self.assertEqual(context.next_local_cseq(), 5)
        self.assertEqual(context.local_cseq, 5)
        self.assertEqual(context.next_remote_cseq(), 10)
        self.assertEqual(context.remote_cseq, 10)

    def test_fork_for_reinvite_preserves_context_state(self) -> None:
        route = NameAddress(uri=SIPURI(scheme="sip", user="proxy", host="ims.example.net"))
        request_uri = SIPURI(scheme="sip", user="ue001", host="device.example.net")
        context = DialogContext(
            call_id="call-2",
            local_tag="ue-tag",
            remote_tag="remote-tag",
            local_cseq=3,
            remote_cseq=7,
            route_set=(route,),
            request_uri=request_uri,
            is_registered=True,
        )

        reinvite_context = context.fork_for_reinvite()

        self.assertIsNot(reinvite_context, context)
        self.assertFalse(context.is_reinvite)
        self.assertTrue(reinvite_context.is_reinvite)
        self.assertEqual(reinvite_context.call_id, "call-2")
        self.assertEqual(reinvite_context.route_set, (route,))
        self.assertEqual(reinvite_context.request_uri, request_uri)
        self.assertTrue(reinvite_context.is_registered)


class RequestSpecTests(unittest.TestCase):
    def test_normalizes_optional_text_and_copies_overrides(self) -> None:
        source_overrides = {"max_forwards": 68}
        spec = RequestSpec.model_validate(
            {
                "method": "INVITE",
                "scenario": " initial inbound call ",
                "body_kind": " sdp_offer ",
                "overrides": source_overrides,
            }
        )

        self.assertEqual(spec.method, SIPMethod.INVITE)
        self.assertEqual(spec.scenario, "initial inbound call")
        self.assertEqual(spec.body_kind, "sdp_offer")
        self.assertEqual(spec.overrides, {"max_forwards": 68})
        self.assertTrue(spec.has_overrides)
        self.assertIsNot(spec.overrides, source_overrides)

    def test_defaults_to_empty_overrides_when_none_is_given(self) -> None:
        spec = RequestSpec.model_validate(
            {
                "method": "OPTIONS",
                "scenario": " ",
                "body_kind": " ",
                "overrides": None,
            }
        )

        self.assertEqual(spec.method, SIPMethod.OPTIONS)
        self.assertIsNone(spec.scenario)
        self.assertIsNone(spec.body_kind)
        self.assertEqual(spec.overrides, {})
        self.assertFalse(spec.has_overrides)

    def test_rejects_unknown_fields(self) -> None:
        with self.assertRaises(ValueError):
            RequestSpec.model_validate({"method": "BYE", "unexpected": True})


class ResponseSpecTests(unittest.TestCase):
    def test_normalizes_scenario_and_copies_overrides(self) -> None:
        source_overrides = {"contact": [{"uri": {"scheme": "sip", "host": "ims.example.net"}}]}
        spec = ResponseSpec.model_validate(
            {
                "status_code": 180,
                "related_method": "INVITE",
                "scenario": " outbound call ringing ",
                "overrides": source_overrides,
            }
        )

        self.assertEqual(spec.status_code, 180)
        self.assertEqual(spec.related_method, SIPMethod.INVITE)
        self.assertEqual(spec.scenario, "outbound call ringing")
        self.assertEqual(spec.overrides, source_overrides)
        self.assertTrue(spec.has_overrides)
        self.assertIsNot(spec.overrides, source_overrides)

    def test_defaults_to_empty_overrides_when_none_is_given(self) -> None:
        spec = ResponseSpec.model_validate(
            {
                "status_code": 200,
                "related_method": "REGISTER",
                "scenario": " ",
                "overrides": None,
            }
        )

        self.assertEqual(spec.status_code, 200)
        self.assertEqual(spec.related_method, SIPMethod.REGISTER)
        self.assertIsNone(spec.scenario)
        self.assertEqual(spec.overrides, {})
        self.assertFalse(spec.has_overrides)

    def test_rejects_status_code_out_of_range(self) -> None:
        with self.assertRaises(ValueError):
            ResponseSpec.model_validate({"status_code": 99, "related_method": "INVITE"})


if __name__ == "__main__":
    unittest.main()
