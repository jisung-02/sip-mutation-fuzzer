import unittest

from volte_mutation_fuzzer.generator.optional_defaults import (
    get_request_optional_defaults,
    get_response_optional_defaults,
)
from volte_mutation_fuzzer.sip.body_factory import DEFAULT_INFO_PACKAGE
from volte_mutation_fuzzer.sip.common import SIPMethod

PCSCF_HOST = "pcscf.ims.mnc001.mcc001.3gppnetwork.org"


class OptionalDefaultsTests(unittest.TestCase):
    def test_common_request_optionals_present_for_all_methods(self) -> None:
        for method in SIPMethod:
            with self.subTest(method=method):
                defaults = get_request_optional_defaults(method)

                self.assertEqual(defaults["allow"], tuple(SIPMethod))
                self.assertEqual(
                    defaults["allow_events"],
                    (
                        "presence",
                        "dialog",
                        "conference",
                        "reg",
                        "refer",
                        "message-summary",
                    ),
                )
                self.assertEqual(
                    defaults["accept"],
                    (
                        "application/sdp",
                        "application/pidf+xml",
                        "application/reginfo+xml",
                        "multipart/mixed",
                    ),
                )
                self.assertEqual(defaults["accept_encoding"], ("identity",))
                self.assertEqual(defaults["accept_language"], ("en",))
                self.assertEqual(defaults["organization"], "VoLTE Test Operator")

    def test_invite_request_method_specific_optionals(self) -> None:
        defaults = get_request_optional_defaults(SIPMethod.INVITE)

        self.assertEqual(defaults["session_expires"], 1800)
        self.assertEqual(defaults["min_se"], 90)
        self.assertEqual(defaults["privacy"], ("none",))
        self.assertEqual(defaults["subject"], "VoLTE Call")
        self.assertEqual(defaults["priority"], "normal")
        self.assertIn("histinfo", defaults["supported"])
        self.assertIn("norefersub", defaults["supported"])

    def test_subscribe_request_has_expires(self) -> None:
        defaults = get_request_optional_defaults(SIPMethod.SUBSCRIBE)

        self.assertEqual(defaults["expires"], 3600)

    def test_register_request_has_expires_and_path(self) -> None:
        defaults = get_request_optional_defaults(SIPMethod.REGISTER)

        self.assertEqual(defaults["expires"], 3600)
        self.assertEqual(defaults["path"], (f"sip:{PCSCF_HOST};lr",))

    def test_cancel_request_has_reason_but_not_require_or_proxy_require(self) -> None:
        defaults = get_request_optional_defaults(SIPMethod.CANCEL)

        self.assertEqual(
            defaults["reason"],
            'SIP;cause=location_cancelled;text="Call cancelled"',
        )
        self.assertNotIn("require", defaults)
        self.assertNotIn("proxy_require", defaults)

    def test_info_request_has_info_package(self) -> None:
        defaults = get_request_optional_defaults(SIPMethod.INFO)

        self.assertEqual(defaults["info_package"], DEFAULT_INFO_PACKAGE)

    def test_refer_request_has_refer_sub_enabled(self) -> None:
        defaults = get_request_optional_defaults(SIPMethod.REFER)

        self.assertTrue(defaults["refer_sub"])

    def test_method_specific_defaults_override_common_supported_values(self) -> None:
        invite_defaults = get_request_optional_defaults(SIPMethod.INVITE)
        options_defaults = get_request_optional_defaults(SIPMethod.OPTIONS)

        self.assertIn("histinfo", invite_defaults["supported"])
        self.assertIn("norefersub", invite_defaults["supported"])
        self.assertNotIn("histinfo", options_defaults["supported"])
        self.assertNotIn("norefersub", options_defaults["supported"])

    def test_common_response_optionals_present(self) -> None:
        defaults = get_response_optional_defaults(SIPMethod.OPTIONS, 200)

        self.assertEqual(defaults["allow"], tuple(SIPMethod))
        self.assertEqual(
            defaults["allow_events"],
            (
                "presence",
                "dialog",
                "conference",
                "reg",
                "refer",
                "message-summary",
            ),
        )
        self.assertEqual(
            defaults["accept"],
            ("application/sdp", "application/pidf+xml"),
        )
        self.assertEqual(defaults["accept_encoding"], ("identity",))
        self.assertEqual(defaults["accept_language"], ("en",))

    def test_invite_180_response_defaults_include_reliable_provisional_headers(
        self,
    ) -> None:
        defaults = get_response_optional_defaults(SIPMethod.INVITE, 180)

        self.assertEqual(defaults["rseq"], 1)
        self.assertEqual(defaults["session_expires"], 1800)
        self.assertEqual(defaults["min_se"], 90)

    def test_invite_183_response_defaults_include_rseq(self) -> None:
        defaults = get_response_optional_defaults(SIPMethod.INVITE, 183)

        self.assertEqual(defaults["rseq"], 1)

    def test_invite_200_response_defaults_include_session_expires(self) -> None:
        defaults = get_response_optional_defaults(SIPMethod.INVITE, 200)

        self.assertEqual(defaults["session_expires"], 1800)

    def test_generic_422_response_defaults_include_min_se_for_any_method(
        self,
    ) -> None:
        defaults = get_response_optional_defaults(SIPMethod.MESSAGE, 422)

        self.assertEqual(defaults["min_se"], 1800)

    def test_generic_423_response_defaults_include_min_expires(self) -> None:
        defaults = get_response_optional_defaults(SIPMethod.BYE, 423)

        self.assertEqual(defaults["min_expires"], 300)

    def test_unknown_response_combination_returns_only_common_defaults(self) -> None:
        defaults = get_response_optional_defaults(SIPMethod.OPTIONS, 418)

        self.assertEqual(
            defaults,
            {
                "supported": (
                    "path",
                    "gruu",
                    "outbound",
                    "timer",
                    "100rel",
                    "precondition",
                ),
                "allow": tuple(SIPMethod),
                "allow_events": (
                    "presence",
                    "dialog",
                    "conference",
                    "reg",
                    "refer",
                    "message-summary",
                ),
                "accept": ("application/sdp", "application/pidf+xml"),
                "accept_encoding": ("identity",),
                "accept_language": ("en",),
            },
        )
