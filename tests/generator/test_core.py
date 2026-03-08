from __future__ import annotations

import unittest

from volte_mutation_fuzzer.generator import (
    DialogContext,
    GeneratorSettings,
    RequestSpec,
    ResponseSpec,
    SIPGenerator,
)
from volte_mutation_fuzzer.sip.catalog import SIPCatalog, SIP_CATALOG
from volte_mutation_fuzzer.sip.common import SIPMethod
from volte_mutation_fuzzer.sip.requests import InviteRequest, OptionsRequest


class SIPGeneratorSignatureTests(unittest.TestCase):
    def test_init_sets_settings_and_uses_default_catalog(self) -> None:
        settings = GeneratorSettings()

        generator = SIPGenerator(settings)

        self.assertIs(generator.settings, settings)
        self.assertEqual(generator.catalog.request_count, 14)
        self.assertEqual(generator.catalog.response_count, 75)

    def test_public_methods_are_stubbed_until_implementation_is_added(self) -> None:
        generator = SIPGenerator(GeneratorSettings())

        with self.assertRaises(NotImplementedError):
            generator.generate_request(RequestSpec(method="OPTIONS"))

        with self.assertRaises(NotImplementedError):
            generator.generate_response(
                ResponseSpec(status_code=100, related_method="OPTIONS"),
                DialogContext(),
            )

    def test_resolve_request_model_returns_registered_request_type(self) -> None:
        generator = SIPGenerator(GeneratorSettings())

        self.assertIs(
            generator._resolve_request_model(RequestSpec(method=SIPMethod.OPTIONS)),
            OptionsRequest,
        )
        self.assertIs(
            generator._resolve_request_model(RequestSpec(method=SIPMethod.INVITE)),
            InviteRequest,
        )

    def test_resolve_request_model_rejects_catalog_model_mismatch(self) -> None:
        invite_definition = SIP_CATALOG.get_request(SIPMethod.INVITE)
        mismatched_catalog = SIPCatalog(
            request_definitions=tuple(
                invite_definition.model_copy(update={"model_name": "WrongInviteModel"})
                if definition.method == SIPMethod.INVITE
                else definition
                for definition in SIP_CATALOG.request_definitions
            ),
            response_definitions=SIP_CATALOG.response_definitions,
        )
        generator = SIPGenerator(GeneratorSettings(), catalog=mismatched_catalog)

        with self.assertRaisesRegex(ValueError, "request model mismatch"):
            generator._resolve_request_model(RequestSpec(method=SIPMethod.INVITE))


if __name__ == "__main__":
    unittest.main()
