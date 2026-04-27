import unittest

from volte_mutation_fuzzer.generator import (
    DialogContext,
    GeneratorSettings,
    RequestSpec,
    ResponseSpec,
    SIPGenerator,
)
from volte_mutation_fuzzer.sip.catalog import SIPCatalog, SIP_CATALOG
from volte_mutation_fuzzer.sip.common import NameAddress, SIPMethod, SIPURI
from volte_mutation_fuzzer.sip.requests import (
    REQUEST_MODELS_BY_METHOD,
    ByeRequest,
    CancelRequest,
    InfoRequest,
    InviteRequest,
    NotifyRequest,
    OptionsRequest,
    PrackRequest,
    SubscribeRequest,
)
from volte_mutation_fuzzer.sip.responses import (
    RESPONSE_MODELS_BY_CODE,
)

IMS_DOMAIN = "ims.mnc001.mcc001.3gppnetwork.org"
PCSCF_HOST = f"pcscf.{IMS_DOMAIN}"
EDGE_HOST = f"edge.{IMS_DOMAIN}"
OVERRIDE_HOST = f"override.{IMS_DOMAIN}"
UE_HOST = f"ue.{IMS_DOMAIN}"
REALISTIC_CALL_ID = "a84b4c76e66710@pcscf.ims.mnc001.mcc001.3gppnetwork.org"
REALISTIC_LOCAL_TAG = "9fxced76sl"
REALISTIC_REMOTE_TAG = "873294202"


class SIPGeneratorSignatureTests(unittest.TestCase):
    def test_init_sets_settings_and_uses_default_catalog(self) -> None:
        settings = GeneratorSettings()

        generator = SIPGenerator(settings)

        self.assertIs(generator.settings, settings)
        self.assertEqual(generator.catalog.request_count, 14)
        self.assertEqual(generator.catalog.response_count, 75)

    def test_generate_request_returns_valid_request_instance(self) -> None:
        generator = SIPGenerator(GeneratorSettings())

        packet = generator.generate_request(RequestSpec(method=SIPMethod.OPTIONS))

        self.assertIsInstance(packet, OptionsRequest)
        self.assertEqual(packet.method, SIPMethod.OPTIONS)
        assert isinstance(packet.request_uri, SIPURI)
        self.assertEqual(packet.request_uri.host, UE_HOST)
        self.assertEqual(packet.cseq.sequence, 1)
        self.assertEqual(packet.cseq.method, SIPMethod.OPTIONS)

    def test_generate_request_rejects_missing_transaction_preconditions_before_mutation(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(local_tag=REALISTIC_LOCAL_TAG)

        with self.assertRaisesRegex(ValueError, "Matching INVITE transaction exists."):
            generator.generate_request(RequestSpec(method=SIPMethod.ACK), context)

        self.assertIsNone(context.call_id)
        self.assertIsNone(context.remote_tag)
        self.assertIsNone(context.request_uri)
        self.assertEqual(context.remote_cseq, 0)

    def test_generate_response_returns_valid_response_instance(self) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(
            call_id=REALISTIC_CALL_ID,
            local_tag=REALISTIC_LOCAL_TAG,
            local_cseq=7,
        )

        packet = generator.generate_response(
            ResponseSpec(status_code=200, related_method=SIPMethod.INVITE),
            context,
        )

        self.assertIsInstance(packet, RESPONSE_MODELS_BY_CODE[200])
        self.assertEqual(packet.status_code, 200)
        self.assertEqual(packet.reason_phrase, "OK")
        self.assertEqual(packet.call_id, REALISTIC_CALL_ID)
        self.assertEqual(packet.cseq.sequence, 7)
        self.assertEqual(packet.cseq.method, SIPMethod.INVITE)
        self.assertEqual(packet.to.parameters["tag"], context.remote_tag)

    def test_generate_response_rejects_missing_originating_request_context_before_mutation(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(local_tag=REALISTIC_LOCAL_TAG, local_cseq=1)

        with self.assertRaisesRegex(
            ValueError,
            "UE originated the corresponding request.",
        ):
            generator.generate_response(
                ResponseSpec(status_code=200, related_method=SIPMethod.INVITE),
                context,
            )

        self.assertIsNone(context.call_id)
        self.assertIsNone(context.remote_tag)

    def test_generate_request_surfaces_catalog_model_mismatch(self) -> None:
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
            generator.generate_request(RequestSpec(method=SIPMethod.INVITE))

    def test_generate_response_surfaces_catalog_related_method_failures(self) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(
            call_id=REALISTIC_CALL_ID,
            local_tag=REALISTIC_LOCAL_TAG,
            local_cseq=1,
        )

        with self.assertRaisesRegex(ValueError, "related method"):
            generator.generate_response(
                ResponseSpec(status_code=180, related_method=SIPMethod.OPTIONS),
                context,
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

    def test_resolve_response_model_returns_registered_response_type(self) -> None:
        generator = SIPGenerator(GeneratorSettings())

        self.assertIs(
            generator._resolve_response_model(
                ResponseSpec(status_code=100, related_method=SIPMethod.OPTIONS)
            ),
            RESPONSE_MODELS_BY_CODE[100],
        )
        self.assertIs(
            generator._resolve_response_model(
                ResponseSpec(status_code=180, related_method=SIPMethod.INVITE)
            ),
            RESPONSE_MODELS_BY_CODE[180],
        )
        self.assertIs(
            generator._resolve_response_model(
                ResponseSpec(status_code=200, related_method=SIPMethod.BYE)
            ),
            RESPONSE_MODELS_BY_CODE[200],
        )

    def test_resolve_response_model_rejects_status_code_missing_from_catalog(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings())

        with self.assertRaisesRegex(ValueError, "response status 201"):
            generator._resolve_response_model(
                ResponseSpec(status_code=201, related_method=SIPMethod.INVITE)
            )

    def test_resolve_response_model_rejects_unsupported_related_method(self) -> None:
        generator = SIPGenerator(GeneratorSettings())

        with self.assertRaisesRegex(ValueError, "related method"):
            generator._resolve_response_model(
                ResponseSpec(status_code=180, related_method=SIPMethod.OPTIONS)
            )

    def test_resolve_response_model_rejects_catalog_model_mismatch(self) -> None:
        ok_definition = SIP_CATALOG.get_response(200)
        mismatched_catalog = SIPCatalog(
            request_definitions=SIP_CATALOG.request_definitions,
            response_definitions=tuple(
                ok_definition.model_copy(update={"model_name": "WrongOkResponse"})
                if definition.status_code == 200
                else definition
                for definition in SIP_CATALOG.response_definitions
            ),
        )
        generator = SIPGenerator(GeneratorSettings(), catalog=mismatched_catalog)

        with self.assertRaisesRegex(ValueError, "response model mismatch"):
            generator._resolve_response_model(
                ResponseSpec(status_code=200, related_method=SIPMethod.INVITE)
            )

    def test_build_request_defaults_produces_valid_initial_options_payload(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings())

        defaults = generator._build_request_defaults(
            RequestSpec(method=SIPMethod.OPTIONS)
        )
        packet = OptionsRequest.model_validate(defaults)

        self.assertEqual(packet.method, SIPMethod.OPTIONS)
        assert isinstance(packet.request_uri, SIPURI)
        self.assertEqual(packet.request_uri.host, UE_HOST)
        self.assertEqual(packet.cseq.sequence, 1)
        self.assertEqual(packet.cseq.method, SIPMethod.OPTIONS)
        self.assertEqual(packet.user_agent, "volte-mutation-fuzzer/0.1.0")
        self.assertEqual(packet.via[0].host, PCSCF_HOST)

    def test_build_request_defaults_updates_context_for_stateful_requests(self) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(local_tag=REALISTIC_LOCAL_TAG)

        defaults = generator._build_request_defaults(
            RequestSpec(method=SIPMethod.INVITE),
            context,
        )
        packet = InviteRequest.model_validate(defaults)

        self.assertIsNotNone(context.call_id)
        self.assertIsNotNone(context.remote_tag)
        self.assertEqual(context.remote_cseq, 1)
        self.assertIsInstance(context.request_uri, SIPURI)
        self.assertEqual(packet.call_id, context.call_id)
        self.assertEqual(packet.from_.parameters["tag"], context.remote_tag)
        self.assertEqual(packet.to.parameters["tag"], REALISTIC_LOCAL_TAG)
        self.assertEqual(packet.cseq.sequence, 1)
        self.assertEqual(len(packet.contact), 1)

    def test_build_request_defaults_cover_all_request_models(self) -> None:
        generator = SIPGenerator(GeneratorSettings())

        for method, model in REQUEST_MODELS_BY_METHOD.items():
            with self.subTest(method=method):
                context = DialogContext(
                    call_id=REALISTIC_CALL_ID,
                    local_tag=REALISTIC_LOCAL_TAG,
                    remote_tag=REALISTIC_REMOTE_TAG,
                    local_cseq=3,
                    reliable_invite_rseq=17,
                    reliable_invite_cseq=3,
                    request_uri=SIPURI(
                        scheme="sip",
                        user="001010000123511",
                        host=UE_HOST,
                    ),
                )

                defaults = generator._build_request_defaults(
                    RequestSpec(method=method),
                    context,
                )
                packet = model.model_validate(defaults)

                self.assertEqual(packet.method, method)
                self.assertEqual(packet.cseq.method, method)

    def test_build_request_defaults_populates_initial_publish_body(self) -> None:
        generator = SIPGenerator(GeneratorSettings())

        defaults = generator._build_request_defaults(
            RequestSpec(method=SIPMethod.PUBLISH)
        )
        packet = REQUEST_MODELS_BY_METHOD[SIPMethod.PUBLISH].model_validate(defaults)

        self.assertEqual(packet.method, SIPMethod.PUBLISH)
        self.assertEqual(packet.content_type, "application/pidf+xml")
        self.assertIsNotNone(packet.body)

    def test_generate_request_defaults_info_to_dtmf_body_and_package(self) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(
            call_id=REALISTIC_CALL_ID,
            local_tag=REALISTIC_LOCAL_TAG,
            remote_tag=REALISTIC_REMOTE_TAG,
            local_cseq=2,
            remote_cseq=1,
            request_uri=SIPURI(
                scheme="sip",
                user="001010000123511",
                host=UE_HOST,
            ),
        )

        packet = generator.generate_request(
            RequestSpec(method=SIPMethod.INFO),
            context,
        )

        assert isinstance(packet, InfoRequest)
        self.assertEqual(packet.info_package, "dtmf")
        self.assertEqual(packet.content_type, "application/dtmf-relay")
        assert packet.body is not None
        self.assertIn("Signal=", packet.body)
        self.assertIn("Duration=160", packet.body)

    def test_generate_request_defaults_real_ue_info_to_dtmf_body_and_package(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings(mode="real-ue-direct"))
        context = DialogContext(
            call_id=REALISTIC_CALL_ID,
            local_tag=REALISTIC_LOCAL_TAG,
            remote_tag=REALISTIC_REMOTE_TAG,
            local_cseq=2,
            remote_cseq=1,
            request_uri=SIPURI(
                scheme="sip",
                user="001010000123511",
                host=UE_HOST,
            ),
        )

        packet = generator.generate_request(
            RequestSpec(method=SIPMethod.INFO),
            context,
        )

        assert isinstance(packet, InfoRequest)
        self.assertEqual(packet.info_package, "dtmf")
        self.assertEqual(packet.content_type, "application/dtmf-relay")
        assert packet.body is not None
        self.assertIn("Signal=", packet.body)
        self.assertIn("Duration=160", packet.body)

    def test_generate_request_prack_uses_reliable_provisional_rack_state(self) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(
            call_id=REALISTIC_CALL_ID,
            local_tag=REALISTIC_LOCAL_TAG,
            remote_tag=REALISTIC_REMOTE_TAG,
            local_cseq=2,
            remote_cseq=1,
            request_uri=SIPURI(
                scheme="sip",
                user="001010000123511",
                host=UE_HOST,
            ),
            reliable_invite_rseq=77,
            reliable_invite_cseq=41,
        )

        packet = generator.generate_request(
            RequestSpec(method=SIPMethod.PRACK),
            context,
        )

        assert isinstance(packet, PrackRequest)
        self.assertEqual(packet.rack.response_num, 77)
        self.assertEqual(packet.rack.cseq_num, 41)
        self.assertEqual(packet.rack.method, SIPMethod.INVITE)

    def test_generate_request_honors_explicit_body_kind_before_event_inference(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings())

        packet = generator.generate_request(
            RequestSpec(
                method=SIPMethod.NOTIFY,
                body_kind="sipfrag",
                event_package="presence",
            )
        )

        assert isinstance(packet, NotifyRequest)
        assert packet.event is not None
        self.assertEqual(packet.event.package, "presence")
        self.assertEqual(packet.content_type, "message/sipfrag;version=2.0")
        self.assertEqual(packet.body, "SIP/2.0 200 OK")

    def test_build_response_defaults_populates_subscribe_and_register_success_fields(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(
            call_id=REALISTIC_CALL_ID,
            local_tag=REALISTIC_LOCAL_TAG,
            local_cseq=7,
        )

        subscribe_defaults = generator._build_response_defaults(
            ResponseSpec(status_code=200, related_method=SIPMethod.SUBSCRIBE),
            context,
        )
        subscribe_packet = RESPONSE_MODELS_BY_CODE[200].model_validate(
            subscribe_defaults
        )
        self.assertEqual(subscribe_packet.expires, 3600)

        register_defaults = generator._build_response_defaults(
            ResponseSpec(status_code=200, related_method=SIPMethod.REGISTER),
            context,
        )
        register_packet = RESPONSE_MODELS_BY_CODE[200].model_validate(register_defaults)
        assert register_packet.contact is not None
        self.assertEqual(len(register_packet.contact), 1)

        ringing_defaults = generator._build_response_defaults(
            ResponseSpec(status_code=180, related_method=SIPMethod.INVITE),
            context,
        )
        ringing_packet = RESPONSE_MODELS_BY_CODE[180].model_validate(ringing_defaults)
        assert ringing_packet.contact is not None
        self.assertEqual(len(ringing_packet.contact), 1)

    def test_build_cseq_can_reuse_local_dialog_sequence_without_mutating_context(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(local_cseq=7, remote_cseq=4)

        cseq = generator._build_cseq(
            SIPMethod.INVITE,
            context,
            local_origin=True,
        )

        self.assertEqual(cseq.sequence, 7)
        self.assertEqual(cseq.method, SIPMethod.INVITE)
        self.assertEqual(context.local_cseq, 7)
        self.assertEqual(context.remote_cseq, 4)

    def test_build_response_defaults_produces_valid_ok_payload_from_dialog_context(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(
            call_id=REALISTIC_CALL_ID,
            local_tag=REALISTIC_LOCAL_TAG,
            local_cseq=7,
            route_set=(
                NameAddress(
                    display_name="Edge Proxy",
                    uri=SIPURI(scheme="sip", host=EDGE_HOST),
                ),
            ),
        )

        defaults = generator._build_response_defaults(
            ResponseSpec(status_code=200, related_method=SIPMethod.INVITE),
            context,
        )
        response_model = RESPONSE_MODELS_BY_CODE[200]
        packet = response_model.model_validate(defaults)

        self.assertEqual(packet.status_code, 200)
        self.assertEqual(packet.reason_phrase, "OK")
        self.assertEqual(packet.from_.display_name, "UE")
        self.assertEqual(packet.from_.parameters["tag"], REALISTIC_LOCAL_TAG)
        self.assertEqual(packet.to.display_name, "Remote")
        self.assertEqual(packet.to.parameters["tag"], context.remote_tag)
        self.assertEqual(packet.call_id, REALISTIC_CALL_ID)
        self.assertEqual(packet.cseq.sequence, 7)
        self.assertEqual(packet.cseq.method, SIPMethod.INVITE)
        self.assertEqual(packet.server, "volte-mutation-fuzzer/0.1.0")
        self.assertEqual(packet.record_route, list(context.route_set))
        assert packet.contact is not None
        self.assertEqual(len(packet.contact), 1)

    def test_build_response_defaults_cover_all_response_models(self) -> None:
        generator = SIPGenerator(GeneratorSettings())

        for status_code, model in RESPONSE_MODELS_BY_CODE.items():
            with self.subTest(status_code=status_code, model=model.__name__):
                definition = SIP_CATALOG.get_response(status_code)
                related_method = (
                    definition.related_methods[0]
                    if definition.related_methods
                    else SIPMethod.OPTIONS
                )
                context = DialogContext(
                    call_id=REALISTIC_CALL_ID,
                    local_tag=REALISTIC_LOCAL_TAG,
                    remote_tag=REALISTIC_REMOTE_TAG,
                    local_cseq=3,
                    route_set=(
                        NameAddress(
                            display_name="Edge Proxy",
                            uri=SIPURI(scheme="sip", host=EDGE_HOST),
                        ),
                    ),
                )

                defaults = generator._build_response_defaults(
                    ResponseSpec(
                        status_code=status_code,
                        related_method=related_method,
                    ),
                    context,
                )
                packet = model.model_validate(defaults)

                self.assertEqual(packet.status_code, status_code)
                self.assertEqual(packet.reason_phrase, definition.reason_phrase)
                self.assertEqual(packet.call_id, REALISTIC_CALL_ID)
                self.assertEqual(packet.cseq.sequence, 3)
                self.assertEqual(packet.cseq.method, related_method)

    def test_apply_overrides_returns_new_payload_without_mutating_defaults(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings())
        defaults = {
            "method": SIPMethod.OPTIONS,
            "max_forwards": 70,
            "extension_headers": {"X-Trace": "default"},
        }
        overrides = {
            "max_forwards": 10,
            "extension_headers": {"X-Trace": "override"},
        }

        merged = generator._apply_overrides(defaults, overrides)

        self.assertEqual(merged["max_forwards"], 10)
        self.assertEqual(merged["extension_headers"], {"X-Trace": "override"})
        self.assertEqual(defaults["max_forwards"], 70)
        self.assertEqual(defaults["extension_headers"], {"X-Trace": "default"})

    def test_apply_overrides_normalizes_from_alias(self) -> None:
        generator = SIPGenerator(GeneratorSettings())
        defaults = generator._build_request_defaults(
            RequestSpec(method=SIPMethod.OPTIONS)
        )
        replacement_from = NameAddress(
            display_name="Override Remote",
            uri=SIPURI(scheme="sip", user="override", host=OVERRIDE_HOST),
            parameters={"tag": "override-tag"},
        )

        merged = generator._apply_overrides(defaults, {"from": replacement_from})
        packet = OptionsRequest.model_validate(merged)

        self.assertNotIn("from", merged)
        self.assertEqual(packet.from_.display_name, "Override Remote")
        assert isinstance(packet.from_.uri, SIPURI)
        self.assertEqual(packet.from_.uri.host, OVERRIDE_HOST)
        self.assertEqual(packet.from_.parameters["tag"], "override-tag")

    def test_apply_overrides_normalizes_wire_header_names_case_insensitively(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings())
        defaults = generator._build_request_defaults(
            RequestSpec(method=SIPMethod.OPTIONS)
        )
        replacement_from = NameAddress(
            display_name="Override Remote",
            uri=SIPURI(scheme="sip", user="override", host=OVERRIDE_HOST),
            parameters={"tag": "override-tag"},
        )

        merged = generator._apply_overrides(
            defaults,
            {
                "From": replacement_from,
                "Call-ID": "override-call-id",
                "Max-Forwards": 9,
            },
        )
        packet = OptionsRequest.model_validate(merged)

        self.assertNotIn("From", merged)
        self.assertNotIn("Call-ID", merged)
        self.assertNotIn("Max-Forwards", merged)
        self.assertEqual(packet.from_.display_name, "Override Remote")
        self.assertEqual(packet.call_id, "override-call-id")
        self.assertEqual(packet.max_forwards, 9)

    def test_validate_preconditions_allows_empty_precondition_list(self) -> None:
        generator = SIPGenerator(GeneratorSettings())

        generator._validate_preconditions(context=None, preconditions=())

    def test_validate_preconditions_requires_dialog_context_for_dialog_scoped_rules(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings())
        dialog_preconditions = (
            "Confirmed dialog exists.",
            "Existing dialog exists.",
            "Early or confirmed dialog exists.",
        )

        for precondition in dialog_preconditions:
            with self.subTest(precondition=precondition, context="missing"):
                with self.assertRaisesRegex(ValueError, precondition):
                    generator._validate_preconditions(
                        context=None,
                        preconditions=(precondition,),
                    )

            with self.subTest(precondition=precondition, context="incomplete"):
                with self.assertRaisesRegex(ValueError, precondition):
                    generator._validate_preconditions(
                        context=DialogContext(
                            call_id=REALISTIC_CALL_ID, local_tag=REALISTIC_LOCAL_TAG
                        ),
                        preconditions=(precondition,),
                    )

            with self.subTest(precondition=precondition, context="complete"):
                generator._validate_preconditions(
                    context=DialogContext(
                        call_id=REALISTIC_CALL_ID,
                        local_tag=REALISTIC_LOCAL_TAG,
                        remote_tag=REALISTIC_REMOTE_TAG,
                    ),
                    preconditions=(precondition,),
                )

    def test_validate_preconditions_requires_invite_transaction_context(self) -> None:
        generator = SIPGenerator(GeneratorSettings())
        transaction_preconditions = (
            "Matching INVITE transaction exists.",
            "Matching INVITE server transaction is still proceeding.",
        )

        for precondition in transaction_preconditions:
            with self.subTest(precondition=precondition, context="missing"):
                with self.assertRaisesRegex(ValueError, precondition):
                    generator._validate_preconditions(
                        context=None,
                        preconditions=(precondition,),
                    )

            with self.subTest(precondition=precondition, context="incomplete"):
                with self.assertRaisesRegex(ValueError, precondition):
                    generator._validate_preconditions(
                        context=DialogContext(call_id=REALISTIC_CALL_ID),
                        preconditions=(precondition,),
                    )

            with self.subTest(precondition=precondition, context="complete"):
                generator._validate_preconditions(
                    context=DialogContext(
                        call_id=REALISTIC_CALL_ID,
                        local_tag=REALISTIC_LOCAL_TAG,
                        remote_tag=REALISTIC_REMOTE_TAG,
                        request_uri=SIPURI(
                            scheme="sip",
                            user="001010000123511",
                            host=UE_HOST,
                        ),
                    ),
                    preconditions=(precondition,),
                )

    def test_validate_preconditions_treats_capability_rules_as_advisory(self) -> None:
        generator = SIPGenerator(GeneratorSettings())
        advisory_preconditions = (
            "Active subscription or implicit REFER subscription exists.",
            "UE acts as a publication target/service.",
            "UE acts like a registrar or registration service.",
            "UE supports the targeted event package.",
        )

        for precondition in advisory_preconditions:
            with self.subTest(precondition=precondition):
                generator._validate_preconditions(
                    context=None,
                    preconditions=(precondition,),
                )

    def test_validate_preconditions_requires_reliable_provisional_state_for_prack(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings())
        precondition = "Reliable provisional response was sent."

        with self.assertRaisesRegex(ValueError, precondition):
            generator._validate_preconditions(
                context=None,
                preconditions=(precondition,),
            )

        generator._validate_preconditions(
            context=DialogContext(
                reliable_invite_rseq=73,
                reliable_invite_cseq=41,
            ),
            preconditions=(precondition,),
        )

    def test_validate_preconditions_requires_originating_request_context_for_response_rules(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings())
        response_precondition = "UE originated the corresponding request."

        with self.subTest(context="missing"):
            with self.assertRaisesRegex(ValueError, response_precondition):
                generator._validate_preconditions(
                    context=None,
                    preconditions=(response_precondition,),
                )

        with self.subTest(context="missing-call-id"):
            with self.assertRaisesRegex(ValueError, response_precondition):
                generator._validate_preconditions(
                    context=DialogContext(local_tag=REALISTIC_LOCAL_TAG, local_cseq=1),
                    preconditions=(response_precondition,),
                )

        with self.subTest(context="missing-local-tag"):
            with self.assertRaisesRegex(ValueError, response_precondition):
                generator._validate_preconditions(
                    context=DialogContext(call_id=REALISTIC_CALL_ID, local_cseq=1),
                    preconditions=(response_precondition,),
                )

        with self.subTest(context="missing-local-cseq"):
            with self.assertRaisesRegex(ValueError, response_precondition):
                generator._validate_preconditions(
                    context=DialogContext(
                        call_id=REALISTIC_CALL_ID, local_tag=REALISTIC_LOCAL_TAG
                    ),
                    preconditions=(response_precondition,),
                )

        with self.subTest(context="complete"):
            generator._validate_preconditions(
                context=DialogContext(
                    call_id=REALISTIC_CALL_ID,
                    local_tag=REALISTIC_LOCAL_TAG,
                    local_cseq=1,
                ),
                preconditions=(response_precondition,),
            )

    def test_validate_preconditions_rejects_unknown_rule_strings(self) -> None:
        generator = SIPGenerator(GeneratorSettings())

        with self.assertRaisesRegex(ValueError, "unsupported request precondition"):
            generator._validate_preconditions(
                context=None,
                preconditions=("Unexpected request precondition.",),
            )

    def test_request_defaults_populate_optional_headers_for_invite(self) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(local_tag=REALISTIC_LOCAL_TAG)

        defaults = generator._build_request_defaults(
            RequestSpec(method=SIPMethod.INVITE),
            context,
        )
        packet = InviteRequest.model_validate(defaults)

        self.assertEqual(packet.session_expires, 1800)
        self.assertEqual(packet.min_se, 90)
        self.assertEqual(packet.privacy, ("none",))
        self.assertEqual(packet.subject, "VoLTE Call")
        self.assertEqual(packet.priority, "normal")
        assert packet.supported is not None
        self.assertIn("histinfo", packet.supported)
        self.assertIn("norefersub", packet.supported)
        assert packet.p_asserted_identity is not None
        self.assertEqual(len(packet.p_asserted_identity), 1)
        self.assertEqual(packet.p_asserted_identity[0].display_name, "Remote")
        self.assertEqual(packet.content_disposition, "session")
        self.assertIsNotNone(packet.content_language)

    def test_request_defaults_populate_optional_headers_for_subscribe(self) -> None:
        generator = SIPGenerator(GeneratorSettings())

        defaults = generator._build_request_defaults(
            RequestSpec(method=SIPMethod.SUBSCRIBE)
        )
        packet = SubscribeRequest.model_validate(defaults)

        self.assertEqual(packet.expires, 3600)
        self.assertEqual(packet.organization, "VoLTE Test Operator")
        assert packet.allow is not None
        self.assertIn(SIPMethod.INVITE, packet.allow)

    def test_request_defaults_populate_optional_headers_for_cancel(self) -> None:
        generator = SIPGenerator(GeneratorSettings())

        defaults = generator._build_request_defaults(
            RequestSpec(method=SIPMethod.CANCEL)
        )
        packet = CancelRequest.model_validate(defaults)

        self.assertEqual(
            packet.reason,
            'SIP;cause=location_cancelled;text="Call cancelled"',
        )
        self.assertIsNone(packet.require)
        self.assertIsNone(packet.proxy_require)

    def test_response_defaults_populate_optional_headers_for_invite_180(self) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(
            call_id=REALISTIC_CALL_ID,
            local_tag=REALISTIC_LOCAL_TAG,
            local_cseq=7,
        )

        defaults = generator._build_response_defaults(
            ResponseSpec(status_code=180, related_method=SIPMethod.INVITE),
            context,
        )
        packet = RESPONSE_MODELS_BY_CODE[180].model_validate(defaults)

        self.assertEqual(packet.rseq, 1)
        self.assertEqual(packet.session_expires, 1800)
        self.assertEqual(packet.min_se, 90)
        assert packet.recv_info is not None
        self.assertEqual(packet.recv_info, ("g.3gpp.iari-ref",))
        assert packet.supported is not None
        self.assertIn("100rel", packet.supported)
        self.assertIsNone(packet.body)
        self.assertIsNone(packet.content_type)
        self.assertEqual(packet.content_length, 0)
        self.assertIsNotNone(packet.timestamp)
        assert packet.timestamp is not None
        self.assertGreater(packet.timestamp, 0)

    def test_response_defaults_only_autogenerate_bodies_for_selected_success_cases(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(
            call_id=REALISTIC_CALL_ID,
            local_tag=REALISTIC_LOCAL_TAG,
            local_cseq=7,
        )

        options_defaults = generator._build_response_defaults(
            ResponseSpec(status_code=200, related_method=SIPMethod.OPTIONS),
            context,
        )
        options_packet = RESPONSE_MODELS_BY_CODE[200].model_validate(options_defaults)
        self.assertIsNone(options_packet.body)
        self.assertIsNone(options_packet.content_type)
        self.assertEqual(options_packet.content_length, 0)

        notify_defaults = generator._build_response_defaults(
            ResponseSpec(
                status_code=200,
                related_method=SIPMethod.NOTIFY,
                event_package="presence",
            ),
            context,
        )
        notify_packet = RESPONSE_MODELS_BY_CODE[200].model_validate(notify_defaults)
        self.assertIsNone(notify_packet.body)
        self.assertIsNone(notify_packet.content_type)
        self.assertEqual(notify_packet.content_length, 0)

        invite_progress_defaults = generator._build_response_defaults(
            ResponseSpec(status_code=183, related_method=SIPMethod.INVITE),
            context,
        )
        invite_progress_packet = RESPONSE_MODELS_BY_CODE[183].model_validate(
            invite_progress_defaults
        )
        self.assertEqual(invite_progress_packet.content_type, "application/sdp")
        self.assertIsNotNone(invite_progress_packet.body)

        invite_ok_defaults = generator._build_response_defaults(
            ResponseSpec(status_code=200, related_method=SIPMethod.INVITE),
            context,
        )
        invite_ok_packet = RESPONSE_MODELS_BY_CODE[200].model_validate(
            invite_ok_defaults
        )
        self.assertEqual(invite_ok_packet.content_type, "application/sdp")
        self.assertIsNotNone(invite_ok_packet.body)

        update_ok_defaults = generator._build_response_defaults(
            ResponseSpec(status_code=200, related_method=SIPMethod.UPDATE),
            context,
        )
        update_ok_packet = RESPONSE_MODELS_BY_CODE[200].model_validate(
            update_ok_defaults
        )
        self.assertEqual(update_ok_packet.content_type, "application/sdp")
        self.assertIsNotNone(update_ok_packet.body)

        alternative_service_defaults = generator._build_response_defaults(
            ResponseSpec(status_code=380, related_method=SIPMethod.INVITE),
            context,
        )
        alternative_service_packet = RESPONSE_MODELS_BY_CODE[380].model_validate(
            alternative_service_defaults
        )
        self.assertEqual(
            alternative_service_packet.content_type,
            "application/3gpp-ims+xml",
        )
        self.assertIsNotNone(alternative_service_packet.body)

    def test_response_generation_rejects_missing_required_body(self) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(
            call_id=REALISTIC_CALL_ID,
            local_tag=REALISTIC_LOCAL_TAG,
            local_cseq=7,
        )

        for body in (None, ""):
            with self.subTest(body=body):
                with self.assertRaisesRegex(
                    ValueError,
                    "response policy requires a body",
                ):
                    generator.generate_response(
                        ResponseSpec(
                            status_code=183,
                            related_method=SIPMethod.INVITE,
                            overrides={"body": body, "content_type": "text/plain"},
                        ),
                        context,
                    )

    def test_response_generation_rejects_override_body_for_forbidden_response(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(
            call_id=REALISTIC_CALL_ID,
            local_tag=REALISTIC_LOCAL_TAG,
            local_cseq=7,
        )

        for body in ("unexpected notify payload", ""):
            with self.subTest(body=body):
                with self.assertRaisesRegex(
                    ValueError,
                    "response policy forbids a body",
                ):
                    generator.generate_response(
                        ResponseSpec(
                            status_code=200,
                            related_method=SIPMethod.NOTIFY,
                            overrides={
                                "body": body,
                                "content_type": "text/plain",
                            },
                        ),
                        context,
                    )

    def test_request_defaults_populate_contact_for_bye(self) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(
            call_id=REALISTIC_CALL_ID,
            local_tag=REALISTIC_LOCAL_TAG,
            remote_tag=REALISTIC_REMOTE_TAG,
            local_cseq=1,
            remote_cseq=1,
        )

        defaults = generator._build_request_defaults(
            RequestSpec(method=SIPMethod.BYE), context
        )
        packet = ByeRequest.model_validate(defaults)

        self.assertIsNotNone(packet.contact)
        assert packet.contact is not None
        self.assertEqual(len(packet.contact), 1)

    def test_overrides_take_precedence_over_optional_defaults(self) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(local_tag=REALISTIC_LOCAL_TAG)

        packet = generator.generate_request(
            RequestSpec(
                method=SIPMethod.INVITE,
                overrides={
                    "session_expires": 900,
                    "supported": ("custom",),
                    "subject": "Overridden Subject",
                },
            ),
            context,
        )

        assert isinstance(packet, InviteRequest)
        self.assertEqual(packet.session_expires, 900)
        self.assertEqual(packet.supported, ("custom",))
        self.assertEqual(packet.subject, "Overridden Subject")

    def test_response_defaults_do_not_populate_message_success_forbidden_headers(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(
            call_id=REALISTIC_CALL_ID,
            local_tag=REALISTIC_LOCAL_TAG,
            local_cseq=7,
        )

        defaults = generator._build_response_defaults(
            ResponseSpec(status_code=200, related_method=SIPMethod.MESSAGE),
            context,
        )
        packet = RESPONSE_MODELS_BY_CODE[200].model_validate(defaults)

        self.assertIsNone(packet.contact)
        self.assertIsNone(packet.body)
        self.assertIsNone(packet.content_type)
        self.assertEqual(packet.content_length, 0)


class SIPGeneratorSeedDeterminismTests(unittest.TestCase):
    """Verify the same ``seed`` produces byte-identical baselines.

    Without seed control, transaction-unique IDs (Call-ID, Via branch,
    From tag, nonce, sip_etag, ICID) come from ``uuid4()`` and break
    reproduction of fuzz cases. With ``seed`` forwarded to the generator,
    ``mutate request --seed N`` two runs back-to-back must yield the
    exact same wire — not just the same mutation pattern.
    """

    def setUp(self) -> None:
        self.generator = SIPGenerator(GeneratorSettings())

    def test_same_seed_yields_identical_call_id_and_branch(self) -> None:
        first = self.generator.generate_request(
            RequestSpec(method=SIPMethod.OPTIONS), seed=42
        )
        second = self.generator.generate_request(
            RequestSpec(method=SIPMethod.OPTIONS), seed=42
        )

        self.assertEqual(first.call_id, second.call_id)
        self.assertEqual(first.via[0].branch, second.via[0].branch)
        self.assertEqual(
            first.from_.parameters.get("tag"),
            second.from_.parameters.get("tag"),
        )

    def test_different_seed_yields_different_ids(self) -> None:
        first = self.generator.generate_request(
            RequestSpec(method=SIPMethod.OPTIONS), seed=1
        )
        second = self.generator.generate_request(
            RequestSpec(method=SIPMethod.OPTIONS), seed=2
        )

        # At least one of the per-call IDs must differ.
        self.assertTrue(
            first.call_id != second.call_id
            or first.via[0].branch != second.via[0].branch
        )

    def test_no_seed_uses_uuid4_each_call(self) -> None:
        # Without ``seed``, behaviour falls back to the standard
        # ``uuid4`` path so transaction IDs stay unique per call. Pinning
        # this preserves the spec-compliant default for ad-hoc invocations
        # outside the campaign loop.
        first = self.generator.generate_request(
            RequestSpec(method=SIPMethod.OPTIONS)
        )
        second = self.generator.generate_request(
            RequestSpec(method=SIPMethod.OPTIONS)
        )
        self.assertNotEqual(first.call_id, second.call_id)

    def test_seed_is_per_call_no_state_leak(self) -> None:
        # A seeded call must not leave a deterministic stream behind for
        # the next unseeded call — otherwise unrelated invocations on the
        # same generator instance start producing repeating IDs.
        seeded = self.generator.generate_request(
            RequestSpec(method=SIPMethod.OPTIONS), seed=99
        )
        unseeded_a = self.generator.generate_request(
            RequestSpec(method=SIPMethod.OPTIONS)
        )
        unseeded_b = self.generator.generate_request(
            RequestSpec(method=SIPMethod.OPTIONS)
        )
        self.assertNotEqual(unseeded_a.call_id, unseeded_b.call_id)
        self.assertNotEqual(seeded.call_id, unseeded_a.call_id)

    def test_response_seed_also_deterministic(self) -> None:
        context = DialogContext(call_id="abc@host", local_tag="t1", local_cseq=1)
        first = self.generator.generate_response(
            ResponseSpec(status_code=200, related_method=SIPMethod.INVITE),
            context,
            seed=7,
        )
        second = self.generator.generate_response(
            ResponseSpec(status_code=200, related_method=SIPMethod.INVITE),
            context,
            seed=7,
        )
        self.assertEqual(first.via[0].branch, second.via[0].branch)

    def test_response_seed_makes_timestamp_deterministic(self) -> None:
        # Catches the regression where ``timestamp`` was wall-clock-derived
        # and silently broke seeded response equality even after the rest
        # of the IDs were locked down.
        context = DialogContext(call_id="abc@host", local_tag="t1", local_cseq=1)
        first = self.generator.generate_response(
            ResponseSpec(status_code=200, related_method=SIPMethod.INVITE),
            context,
            seed=11,
        )
        second = self.generator.generate_response(
            ResponseSpec(status_code=200, related_method=SIPMethod.INVITE),
            context,
            seed=11,
        )
        self.assertEqual(first.timestamp, second.timestamp)
        # Whole packets must be identical, not just one field.
        self.assertEqual(first.model_dump(mode="json"), second.model_dump(mode="json"))


if __name__ == "__main__":
    unittest.main()
