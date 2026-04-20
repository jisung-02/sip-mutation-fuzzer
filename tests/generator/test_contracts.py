import os
from contextlib import chdir
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from volte_mutation_fuzzer.generator import (
    DialogContext,
    GeneratorSettings,
    RequestSpec,
    ResponseSpec,
)
from volte_mutation_fuzzer.sip.common import NameAddress, SIPMethod, SIPURI

IMS_DOMAIN = "ims.mnc001.mcc001.3gppnetwork.org"
PCSCF_HOST = f"pcscf.{IMS_DOMAIN}"
UE_HOST = f"ue.{IMS_DOMAIN}"
EDGE_HOST = f"edge.{IMS_DOMAIN}"
ALT_IMS_DOMAIN = "ims.mnc999.mcc999.3gppnetwork.org"
REALISTIC_CALL_ID = "a84b4c76e66710@pcscf.ims.mnc001.mcc001.3gppnetwork.org"
REALISTIC_REINVITE_CALL_ID = "b7f2a1d43caa9f1d@pcscf.ims.mnc001.mcc001.3gppnetwork.org"
REALISTIC_LOCAL_TAG = "9fxced76sl"
REALISTIC_REMOTE_TAG = "873294202"


class GeneratorSettingsTests(unittest.TestCase):
    def test_from_env_uses_defaults_when_env_is_empty(self) -> None:
        settings = GeneratorSettings.from_env({})

        self.assertEqual(settings.target_ue_name, "UE")
        self.assertEqual(settings.via_host, PCSCF_HOST)
        self.assertEqual(settings.via_port, 5060)
        self.assertEqual(settings.transport, "UDP")
        self.assertEqual(settings.user_agent, "volte-mutation-fuzzer/0.1.0")
        self.assertEqual(settings.from_user, "remote")
        self.assertEqual(settings.to_user, "111111")
        self.assertEqual(settings.request_uri_user, "111111")

    def test_from_env_reads_prefixed_values_and_normalizes_text(self) -> None:
        settings = GeneratorSettings.from_env(
            {
                "VMF_GENERATOR_TARGET_UE_NAME": " Pixel-9-Pro ",
                "VMF_GENERATOR_VIA_HOST": f" {ALT_IMS_DOMAIN} ",
                "VMF_GENERATOR_VIA_PORT": " 5080 ",
                "VMF_GENERATOR_TRANSPORT": " tls-sctp ",
                "VMF_GENERATOR_USER_AGENT": " fuzz/0.2 ",
                "VMF_GENERATOR_FROM_DISPLAY_NAME": " P-CSCF ",
                "VMF_GENERATOR_FROM_USER": " scscf ",
                "VMF_GENERATOR_FROM_HOST": f" {ALT_IMS_DOMAIN} ",
                "VMF_GENERATOR_TO_DISPLAY_NAME": " Victim UE ",
                "VMF_GENERATOR_TO_USER": " 001010000123511 ",
                "VMF_GENERATOR_TO_HOST": f" {UE_HOST} ",
                "VMF_GENERATOR_REQUEST_URI_USER": " 001010000123511 ",
                "VMF_GENERATOR_REQUEST_URI_HOST": f" {UE_HOST} ",
                "VMF_GENERATOR_CONTACT_DISPLAY_NAME": " ",
                "VMF_GENERATOR_CONTACT_USER": " proxy-contact ",
                "VMF_GENERATOR_CONTACT_HOST": f" {EDGE_HOST} ",
                "VMF_GENERATOR_CONTACT_PORT": " 5090 ",
            }
        )

        self.assertEqual(settings.target_ue_name, "Pixel-9-Pro")
        self.assertEqual(settings.via_host, ALT_IMS_DOMAIN)
        self.assertEqual(settings.via_port, 5080)
        self.assertEqual(settings.transport, "TLS-SCTP")
        self.assertEqual(settings.user_agent, "fuzz/0.2")
        self.assertEqual(settings.from_display_name, "P-CSCF")
        self.assertEqual(settings.to_display_name, "Victim UE")
        self.assertEqual(settings.request_uri_host, UE_HOST)
        self.assertIsNone(settings.contact_display_name)
        self.assertEqual(settings.contact_user, "proxy-contact")
        self.assertEqual(settings.contact_host, EDGE_HOST)
        self.assertEqual(settings.contact_port, 5090)

    def test_from_env_rejects_blank_required_string(self) -> None:
        with self.assertRaises(ValueError):
            GeneratorSettings.from_env({"VMF_GENERATOR_VIA_HOST": "   "})

    def test_from_env_auto_loads_dotenv_when_no_env_mapping_is_given(self) -> None:
        with TemporaryDirectory() as temp_dir, chdir(temp_dir):
            Path(".env").write_text(
                f"VMF_GENERATOR_REQUEST_URI_HOST={ALT_IMS_DOMAIN}\n"
                "VMF_GENERATOR_TRANSPORT=tcp\n",
                encoding="utf-8",
            )

            with patch.dict(os.environ, {}, clear=True):
                settings = GeneratorSettings.from_env()

        self.assertEqual(settings.request_uri_host, ALT_IMS_DOMAIN)
        self.assertEqual(settings.transport, "TCP")

    def test_from_env_prefers_process_env_over_dotenv_values(self) -> None:
        with TemporaryDirectory() as temp_dir, chdir(temp_dir):
            Path(".env").write_text(
                f"VMF_GENERATOR_REQUEST_URI_HOST={ALT_IMS_DOMAIN}\n",
                encoding="utf-8",
            )

            with patch.dict(
                os.environ,
                {"VMF_GENERATOR_REQUEST_URI_HOST": UE_HOST},
                clear=True,
            ):
                settings = GeneratorSettings.from_env()

        self.assertEqual(settings.request_uri_host, UE_HOST)


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
            call_id=f" {REALISTIC_CALL_ID} ",
            local_tag=f" {REALISTIC_LOCAL_TAG} ",
            remote_tag=f" {REALISTIC_REMOTE_TAG} ",
            local_cseq=4,
            remote_cseq=9,
        )

        self.assertEqual(context.call_id, REALISTIC_CALL_ID)
        self.assertEqual(context.local_tag, REALISTIC_LOCAL_TAG)
        self.assertEqual(context.remote_tag, REALISTIC_REMOTE_TAG)
        self.assertTrue(context.has_dialog)
        self.assertEqual(context.next_local_cseq(), 5)
        self.assertEqual(context.local_cseq, 5)
        self.assertEqual(context.next_remote_cseq(), 10)
        self.assertEqual(context.remote_cseq, 10)

    def test_fork_for_reinvite_preserves_context_state(self) -> None:
        route = NameAddress(
            uri=SIPURI(scheme="sip", user="pcscf", host=PCSCF_HOST)
        )
        request_uri = SIPURI(scheme="sip", user="001010000123511", host=UE_HOST)
        context = DialogContext(
            call_id=REALISTIC_REINVITE_CALL_ID,
            local_tag=REALISTIC_LOCAL_TAG,
            remote_tag=REALISTIC_REMOTE_TAG,
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
        self.assertEqual(reinvite_context.call_id, REALISTIC_REINVITE_CALL_ID)
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
        source_overrides = {
            "contact": [{"uri": {"scheme": "sip", "host": PCSCF_HOST}}]
        }
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
