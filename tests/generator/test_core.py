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
    InviteRequest,
    OptionsRequest,
    SubscribeRequest,
)
from volte_mutation_fuzzer.sip.responses import (
    RESPONSE_MODELS_BY_CODE,
)


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
        self.assertEqual(packet.request_uri.host, "example.com")
        self.assertEqual(packet.cseq.sequence, 1)
        self.assertEqual(packet.cseq.method, SIPMethod.OPTIONS)

    def test_generate_request_rejects_missing_transaction_preconditions_before_mutation(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(local_tag="ue-tag")

        with self.assertRaisesRegex(ValueError, "Matching INVITE transaction exists."):
            generator.generate_request(RequestSpec(method=SIPMethod.ACK), context)

        self.assertIsNone(context.call_id)
        self.assertIsNone(context.remote_tag)
        self.assertIsNone(context.request_uri)
        self.assertEqual(context.remote_cseq, 0)

    def test_generate_response_returns_valid_response_instance(self) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(
            call_id="call-1",
            local_tag="ue-tag",
            local_cseq=7,
        )

        packet = generator.generate_response(
            ResponseSpec(status_code=200, related_method=SIPMethod.INVITE),
            context,
        )

        self.assertIsInstance(packet, RESPONSE_MODELS_BY_CODE[200])
        self.assertEqual(packet.status_code, 200)
        self.assertEqual(packet.reason_phrase, "OK")
        self.assertEqual(packet.call_id, "call-1")
        self.assertEqual(packet.cseq.sequence, 7)
        self.assertEqual(packet.cseq.method, SIPMethod.INVITE)
        self.assertEqual(packet.to.parameters["tag"], context.remote_tag)

    def test_generate_response_rejects_missing_originating_request_context_before_mutation(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(local_tag="ue-tag", local_cseq=1)

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
            call_id="call-1",
            local_tag="ue-tag",
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
        self.assertEqual(packet.request_uri.host, "example.com")
        self.assertEqual(packet.cseq.sequence, 1)
        self.assertEqual(packet.cseq.method, SIPMethod.OPTIONS)
        self.assertEqual(packet.user_agent, "volte-mutation-fuzzer/0.1.0")
        self.assertEqual(packet.via[0].host, "proxy.example.com")

    def test_build_request_defaults_updates_context_for_stateful_requests(self) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(local_tag="ue-tag")

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
        self.assertEqual(packet.to.parameters["tag"], "ue-tag")
        self.assertEqual(packet.cseq.sequence, 1)
        self.assertEqual(len(packet.contact), 1)

    def test_build_request_defaults_cover_all_request_models(self) -> None:
        generator = SIPGenerator(GeneratorSettings())

        for method, model in REQUEST_MODELS_BY_METHOD.items():
            with self.subTest(method=method):
                context = DialogContext(
                    call_id="call-1",
                    local_tag="ue-tag",
                    remote_tag="remote-tag",
                    local_cseq=3,
                    request_uri=SIPURI(
                        scheme="sip",
                        user="ue001",
                        host="device.example.net",
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

    def test_build_response_defaults_populates_subscribe_and_register_success_fields(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(
            call_id="call-1",
            local_tag="ue-tag",
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
            call_id="call-1",
            local_tag="ue-tag",
            local_cseq=7,
            route_set=(
                NameAddress(
                    display_name="Edge Proxy",
                    uri=SIPURI(scheme="sip", host="proxy.example.net"),
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
        self.assertEqual(packet.from_.parameters["tag"], "ue-tag")
        self.assertEqual(packet.to.display_name, "Remote")
        self.assertEqual(packet.to.parameters["tag"], context.remote_tag)
        self.assertEqual(packet.call_id, "call-1")
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
                    call_id="call-1",
                    local_tag="ue-tag",
                    remote_tag="remote-tag",
                    local_cseq=3,
                    route_set=(
                        NameAddress(
                            display_name="Edge Proxy",
                            uri=SIPURI(scheme="sip", host="proxy.example.net"),
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
                self.assertEqual(packet.call_id, "call-1")
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
            uri=SIPURI(scheme="sip", user="override", host="override.example.net"),
            parameters={"tag": "override-tag"},
        )

        merged = generator._apply_overrides(defaults, {"from": replacement_from})
        packet = OptionsRequest.model_validate(merged)

        self.assertNotIn("from", merged)
        self.assertEqual(packet.from_.display_name, "Override Remote")
        assert isinstance(packet.from_.uri, SIPURI)
        self.assertEqual(packet.from_.uri.host, "override.example.net")
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
            uri=SIPURI(scheme="sip", user="override", host="override.example.net"),
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
                        context=DialogContext(call_id="call-1", local_tag="ue-tag"),
                        preconditions=(precondition,),
                    )

            with self.subTest(precondition=precondition, context="complete"):
                generator._validate_preconditions(
                    context=DialogContext(
                        call_id="call-1",
                        local_tag="ue-tag",
                        remote_tag="remote-tag",
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
                        context=DialogContext(call_id="call-1"),
                        preconditions=(precondition,),
                    )

            with self.subTest(precondition=precondition, context="complete"):
                generator._validate_preconditions(
                    context=DialogContext(
                        call_id="call-1",
                        local_tag="ue-tag",
                        remote_tag="remote-tag",
                        request_uri=SIPURI(
                            scheme="sip",
                            user="ue001",
                            host="device.example.net",
                        ),
                    ),
                    preconditions=(precondition,),
                )

    def test_validate_preconditions_treats_capability_rules_as_advisory(self) -> None:
        generator = SIPGenerator(GeneratorSettings())
        advisory_preconditions = (
            "Active subscription or implicit REFER subscription exists.",
            "Reliable provisional response was sent.",
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
                    context=DialogContext(local_tag="ue-tag", local_cseq=1),
                    preconditions=(response_precondition,),
                )

        with self.subTest(context="missing-local-tag"):
            with self.assertRaisesRegex(ValueError, response_precondition):
                generator._validate_preconditions(
                    context=DialogContext(call_id="call-1", local_cseq=1),
                    preconditions=(response_precondition,),
                )

        with self.subTest(context="missing-local-cseq"):
            with self.assertRaisesRegex(ValueError, response_precondition):
                generator._validate_preconditions(
                    context=DialogContext(call_id="call-1", local_tag="ue-tag"),
                    preconditions=(response_precondition,),
                )

        with self.subTest(context="complete"):
            generator._validate_preconditions(
                context=DialogContext(
                    call_id="call-1",
                    local_tag="ue-tag",
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
        context = DialogContext(local_tag="ue-tag")

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
            call_id="call-1",
            local_tag="ue-tag",
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
        self.assertIsNotNone(packet.timestamp)
        self.assertGreater(packet.timestamp, 0)

    def test_request_defaults_populate_contact_for_bye(self) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(
            call_id="call-1",
            local_tag="ue-tag",
            remote_tag="remote-tag",
            local_cseq=1,
            remote_cseq=1,
        )

        defaults = generator._build_request_defaults(
            RequestSpec(method=SIPMethod.BYE), context
        )
        packet = ByeRequest.model_validate(defaults)

        self.assertIsNotNone(packet.contact)
        self.assertEqual(len(packet.contact), 1)

    def test_overrides_take_precedence_over_optional_defaults(self) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(local_tag="ue-tag")

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

        self.assertEqual(packet.session_expires, 900)
        self.assertEqual(packet.supported, ("custom",))
        self.assertEqual(packet.subject, "Overridden Subject")

    def test_response_defaults_do_not_populate_message_success_forbidden_headers(
        self,
    ) -> None:
        generator = SIPGenerator(GeneratorSettings())
        context = DialogContext(
            call_id="call-1",
            local_tag="ue-tag",
            local_cseq=7,
        )

        defaults = generator._build_response_defaults(
            ResponseSpec(status_code=200, related_method=SIPMethod.MESSAGE),
            context,
        )
        packet = RESPONSE_MODELS_BY_CODE[200].model_validate(defaults)

        self.assertIsNone(packet.contact)
        self.assertIsNone(packet.body)


if __name__ == "__main__":
    unittest.main()
