import unittest

from volte_mutation_fuzzer.sip import SIPMethod
from volte_mutation_fuzzer.sip.catalog import SIP_CATALOG, validate_catalog_counts
from volte_mutation_fuzzer.sip.common import (
    AbsoluteURI,
    AuthChallenge,
    CSeqHeader,
    NameAddress,
    SIPURI,
    SubscriptionStateHeader,
    ViaHeader,
)
from volte_mutation_fuzzer.sip.requests import REQUEST_MODELS_BY_METHOD
from volte_mutation_fuzzer.sip.responses import RESPONSE_MODELS_BY_CODE
from volte_mutation_fuzzer.packet_docs import (
    render_request_docs,
    render_response_docs,
)

IMS_DOMAIN = "ims.mnc001.mcc001.3gppnetwork.org"
UE_HOST = f"ue.{IMS_DOMAIN}"
PCSCF_HOST = f"pcscf.{IMS_DOMAIN}"
REALISTIC_CALL_ID_1 = "a84b4c76e66710@pcscf.ims.mnc001.mcc001.3gppnetwork.org"
REALISTIC_CALL_ID_2 = "b7f2a1d43caa9f1d@pcscf.ims.mnc001.mcc001.3gppnetwork.org"
REALISTIC_CALL_ID_3 = "d93f7c440f8b11ef@pcscf.ims.mnc001.mcc001.3gppnetwork.org"
REALISTIC_CALL_ID_4 = "e5c17d43caa9f1d2@pcscf.ims.mnc001.mcc001.3gppnetwork.org"


class SIPCatalogTests(unittest.TestCase):
    def test_catalog_counts(self) -> None:
        validate_catalog_counts()
        self.assertEqual(SIP_CATALOG.request_count, 14)
        self.assertEqual(SIP_CATALOG.response_count, 75)

    def test_uri_scheme_validation(self) -> None:
        with self.assertRaises(ValueError):
            SIPURI(scheme="sip", user="alice")
        tel = SIPURI(scheme="tel", user="01012345678")
        self.assertIsNone(tel.host)
        absolute = AbsoluteURI(uri=f"mailto:sip-ops@{IMS_DOMAIN}")
        self.assertEqual(absolute.uri, f"mailto:sip-ops@{IMS_DOMAIN}")

    def test_invite_requires_contact(self) -> None:
        invite_model = REQUEST_MODELS_BY_METHOD[SIPMethod.INVITE]
        with self.assertRaises(Exception):
            invite_model.model_validate(
                {
                    "request_uri": SIPURI(scheme="sip", host=UE_HOST),
                    "via": [ViaHeader(host=PCSCF_HOST, branch="z9hG4bK-1")],
                    "max_forwards": 70,
                    "from_": NameAddress(
                        uri=SIPURI(scheme="sip", user="caller", host=IMS_DOMAIN),
                        parameters={"tag": "a"},
                    ),
                    "to": NameAddress(
                        uri=SIPURI(scheme="sip", user="111111", host=IMS_DOMAIN)
                    ),
                    "call_id": REALISTIC_CALL_ID_1,
                    "cseq": CSeqHeader(sequence=1, method=SIPMethod.INVITE),
                }
            )

    def test_message_body_is_optional_but_contact_is_forbidden(self) -> None:
        message_model = REQUEST_MODELS_BY_METHOD[SIPMethod.MESSAGE]
        packet = message_model.model_validate(
            {
                "request_uri": SIPURI(scheme="sip", host=UE_HOST),
                "via": [ViaHeader(host=PCSCF_HOST, branch="z9hG4bK-2")],
                "max_forwards": 70,
                "from_": NameAddress(
                    uri=SIPURI(scheme="sip", user="sender", host=IMS_DOMAIN),
                    parameters={"tag": "a"},
                ),
                "to": NameAddress(
                    uri=SIPURI(scheme="sip", user="111111", host=IMS_DOMAIN)
                ),
                "call_id": REALISTIC_CALL_ID_2,
                "cseq": CSeqHeader(sequence=2, method=SIPMethod.MESSAGE),
            }
        )
        self.assertIsNone(packet.body)

        with self.assertRaises(Exception):
            message_model.model_validate(
                {
                    "request_uri": SIPURI(scheme="sip", host=UE_HOST),
                    "via": [ViaHeader(host=PCSCF_HOST, branch="z9hG4bK-2")],
                    "max_forwards": 70,
                    "from_": NameAddress(
                        uri=SIPURI(scheme="sip", user="sender", host=IMS_DOMAIN),
                        parameters={"tag": "a"},
                    ),
                    "to": NameAddress(
                        uri=SIPURI(scheme="sip", user="111111", host=IMS_DOMAIN)
                    ),
                    "call_id": REALISTIC_CALL_ID_2,
                    "cseq": CSeqHeader(sequence=2, method=SIPMethod.MESSAGE),
                    "contact": [
                        NameAddress(
                            uri=SIPURI(scheme="sip", user="sender", host=IMS_DOMAIN)
                        )
                    ],
                }
            )

        with self.assertRaises(Exception):
            message_model.model_validate(
                {
                    "request_uri": SIPURI(scheme="sip", host=UE_HOST),
                    "via": [ViaHeader(host=PCSCF_HOST, branch="z9hG4bK-2")],
                    "max_forwards": 70,
                    "from_": NameAddress(
                        uri=SIPURI(scheme="sip", user="sender", host=IMS_DOMAIN),
                        parameters={"tag": "a"},
                    ),
                    "to": NameAddress(
                        uri=SIPURI(scheme="sip", user="111111", host=IMS_DOMAIN)
                    ),
                    "call_id": REALISTIC_CALL_ID_2,
                    "cseq": CSeqHeader(sequence=2, method=SIPMethod.MESSAGE),
                    "body": "hello",
                }
            )

    def test_info_request_rejects_recv_info(self) -> None:
        info_model = REQUEST_MODELS_BY_METHOD[SIPMethod.INFO]
        with self.assertRaises(Exception):
            info_model.model_validate(
                {
                    "request_uri": SIPURI(scheme="sip", host=UE_HOST),
                    "via": [ViaHeader(host=PCSCF_HOST, branch="z9hG4bK-2")],
                    "max_forwards": 70,
                    "from_": NameAddress(
                        uri=SIPURI(scheme="sip", user="sender", host=IMS_DOMAIN),
                        parameters={"tag": "a"},
                    ),
                    "to": NameAddress(
                        uri=SIPURI(scheme="sip", user="111111", host=IMS_DOMAIN)
                    ),
                    "call_id": REALISTIC_CALL_ID_2,
                    "cseq": CSeqHeader(sequence=2, method=SIPMethod.INFO),
                    "recv_info": ("dtmf",),
                }
            )

    def test_publish_initial_request_requires_body(self) -> None:
        publish_model = REQUEST_MODELS_BY_METHOD[SIPMethod.PUBLISH]
        with self.assertRaises(Exception):
            publish_model.model_validate(
                {
                    "request_uri": SIPURI(scheme="sip", host=UE_HOST),
                    "via": [ViaHeader(host=PCSCF_HOST, branch="z9hG4bK-pub")],
                    "max_forwards": 70,
                    "from_": NameAddress(
                        uri=SIPURI(scheme="sip", user="sender", host=IMS_DOMAIN),
                        parameters={"tag": "a"},
                    ),
                    "to": NameAddress(
                        uri=SIPURI(scheme="sip", user="111111", host=IMS_DOMAIN)
                    ),
                    "call_id": REALISTIC_CALL_ID_2,
                    "cseq": CSeqHeader(sequence=2, method=SIPMethod.PUBLISH),
                    "event": {"package": "presence"},
                }
            )

    def test_2xx_to_message_forbids_contact_and_body(self) -> None:
        ok_model = RESPONSE_MODELS_BY_CODE[200]

        with self.assertRaises(Exception):
            ok_model.model_validate(
                {
                    "via": [ViaHeader(host=PCSCF_HOST, branch="z9hG4bK-msg1")],
                    "from_": NameAddress(
                        uri=SIPURI(scheme="sip", user="remote", host=IMS_DOMAIN),
                        parameters={"tag": "remote"},
                    ),
                    "to": NameAddress(
                        uri=SIPURI(scheme="sip", user="111111", host=IMS_DOMAIN),
                        parameters={"tag": "ue"},
                    ),
                    "call_id": REALISTIC_CALL_ID_2,
                    "cseq": CSeqHeader(sequence=5, method=SIPMethod.MESSAGE),
                    "contact": [
                        NameAddress(
                            uri=SIPURI(scheme="sip", user="remote", host=IMS_DOMAIN)
                        )
                    ],
                }
            )

        with self.assertRaises(Exception):
            ok_model.model_validate(
                {
                    "via": [ViaHeader(host=PCSCF_HOST, branch="z9hG4bK-msg2")],
                    "from_": NameAddress(
                        uri=SIPURI(scheme="sip", user="remote", host=IMS_DOMAIN),
                        parameters={"tag": "remote"},
                    ),
                    "to": NameAddress(
                        uri=SIPURI(scheme="sip", user="111111", host=IMS_DOMAIN),
                        parameters={"tag": "ue"},
                    ),
                    "call_id": REALISTIC_CALL_ID_2,
                    "cseq": CSeqHeader(sequence=5, method=SIPMethod.MESSAGE),
                    "content_type": "text/plain",
                    "body": "delivered",
                }
            )

    def test_401_requires_www_authenticate(self) -> None:
        unauthorized_model = RESPONSE_MODELS_BY_CODE[401]
        with self.assertRaises(Exception):
            unauthorized_model.model_validate(
                {
                    "via": [ViaHeader(host=PCSCF_HOST, branch="z9hG4bK-3")],
                    "from_": NameAddress(
                        uri=SIPURI(scheme="sip", user="registrar", host=IMS_DOMAIN),
                        parameters={"tag": "reg"},
                    ),
                    "to": NameAddress(
                        uri=SIPURI(scheme="sip", user="111111", host=IMS_DOMAIN),
                        parameters={"tag": "ue"},
                    ),
                    "call_id": REALISTIC_CALL_ID_3,
                    "cseq": CSeqHeader(sequence=3, method=SIPMethod.REGISTER),
                }
            )

        packet = unauthorized_model.model_validate(
            {
                "via": [ViaHeader(host=PCSCF_HOST, branch="z9hG4bK-3")],
                "from_": NameAddress(
                    uri=SIPURI(scheme="sip", user="registrar", host=IMS_DOMAIN),
                    parameters={"tag": "reg"},
                ),
                "to": NameAddress(
                    uri=SIPURI(scheme="sip", user="111111", host=IMS_DOMAIN),
                    parameters={"tag": "ue"},
                ),
                "call_id": REALISTIC_CALL_ID_3,
                "cseq": CSeqHeader(sequence=3, method=SIPMethod.REGISTER),
                "www_authenticate": (
                    AuthChallenge(realm=IMS_DOMAIN, nonce="nonce-1"),
                ),
            }
        )
        self.assertEqual(packet.status_code, 401)

    def test_469_requires_recv_info(self) -> None:
        bad_info_model = RESPONSE_MODELS_BY_CODE[469]
        with self.assertRaises(Exception):
            bad_info_model.model_validate(
                {
                    "via": [ViaHeader(host=PCSCF_HOST, branch="z9hG4bK-4")],
                    "from_": NameAddress(
                        uri=SIPURI(scheme="sip", user="remote", host=IMS_DOMAIN),
                        parameters={"tag": "remote"},
                    ),
                    "to": NameAddress(
                        uri=SIPURI(scheme="sip", user="111111", host=IMS_DOMAIN),
                        parameters={"tag": "ue"},
                    ),
                    "call_id": REALISTIC_CALL_ID_4,
                    "cseq": CSeqHeader(sequence=4, method=SIPMethod.INFO),
                }
            )

    def test_424_requires_geolocation_error(self) -> None:
        bad_location_model = RESPONSE_MODELS_BY_CODE[424]
        with self.assertRaises(Exception):
            bad_location_model.model_validate(
                {
                    "via": [ViaHeader(host=PCSCF_HOST, branch="z9hG4bK-geo")],
                    "from_": NameAddress(
                        uri=SIPURI(scheme="sip", user="remote", host=IMS_DOMAIN),
                        parameters={"tag": "remote"},
                    ),
                    "to": NameAddress(
                        uri=SIPURI(scheme="sip", user="111111", host=IMS_DOMAIN),
                        parameters={"tag": "ue"},
                    ),
                    "call_id": REALISTIC_CALL_ID_4,
                    "cseq": CSeqHeader(sequence=4, method=SIPMethod.INVITE),
                }
            )

    def test_425_requires_alert_msg_error(self) -> None:
        bad_alert_model = RESPONSE_MODELS_BY_CODE[425]
        with self.assertRaises(Exception):
            bad_alert_model.model_validate(
                {
                    "via": [
                        ViaHeader(host=PCSCF_HOST, branch="z9hG4bK-alert")
                    ],
                    "from_": NameAddress(
                        uri=SIPURI(scheme="sip", user="remote", host=IMS_DOMAIN),
                        parameters={"tag": "remote"},
                    ),
                    "to": NameAddress(
                        uri=SIPURI(scheme="sip", user="111111", host=IMS_DOMAIN),
                        parameters={"tag": "ue"},
                    ),
                    "call_id": REALISTIC_CALL_ID_4,
                    "cseq": CSeqHeader(sequence=4, method=SIPMethod.INVITE),
                }
            )

    def test_non_100_responses_require_to_tag(self) -> None:
        ok_model = RESPONSE_MODELS_BY_CODE[200]
        with self.assertRaises(Exception):
            ok_model.model_validate(
                {
                    "via": [ViaHeader(host=PCSCF_HOST, branch="z9hG4bK-tag")],
                    "from_": NameAddress(
                        uri=SIPURI(scheme="sip", user="remote", host=IMS_DOMAIN),
                        parameters={"tag": "remote"},
                    ),
                    "to": NameAddress(uri=SIPURI(scheme="sip", user="111111", host=IMS_DOMAIN)),
                    "call_id": REALISTIC_CALL_ID_4,
                    "cseq": CSeqHeader(sequence=5, method=SIPMethod.OPTIONS),
                }
            )

    def test_2xx_to_subscribe_requires_expires(self) -> None:
        ok_model = RESPONSE_MODELS_BY_CODE[200]
        with self.assertRaises(Exception):
            ok_model.model_validate(
                {
                    "via": [ViaHeader(host=PCSCF_HOST, branch="z9hG4bK-sub")],
                    "from_": NameAddress(
                        uri=SIPURI(scheme="sip", user="remote", host=IMS_DOMAIN),
                        parameters={"tag": "remote"},
                    ),
                    "to": NameAddress(
                        uri=SIPURI(scheme="sip", user="111111", host=IMS_DOMAIN),
                        parameters={"tag": "ue"},
                    ),
                    "call_id": REALISTIC_CALL_ID_4,
                    "cseq": CSeqHeader(sequence=5, method=SIPMethod.SUBSCRIBE),
                }
            )

    def test_2xx_to_register_requires_contact(self) -> None:
        ok_model = RESPONSE_MODELS_BY_CODE[200]
        with self.assertRaises(Exception):
            ok_model.model_validate(
                {
                    "via": [ViaHeader(host=PCSCF_HOST, branch="z9hG4bK-reg")],
                    "from_": NameAddress(
                        uri=SIPURI(scheme="sip", user="registrar", host=IMS_DOMAIN),
                        parameters={"tag": "remote"},
                    ),
                    "to": NameAddress(
                        uri=SIPURI(scheme="sip", user="111111", host=IMS_DOMAIN),
                        parameters={"tag": "ue"},
                    ),
                    "call_id": REALISTIC_CALL_ID_3,
                    "cseq": CSeqHeader(sequence=5, method=SIPMethod.REGISTER),
                    "expires": 3600,
                }
            )

    def test_non_100_invite_responses_require_contact(self) -> None:
        ringing_model = RESPONSE_MODELS_BY_CODE[180]
        with self.assertRaises(Exception):
            ringing_model.model_validate(
                {
                    "via": [ViaHeader(host=PCSCF_HOST, branch="z9hG4bK-180")],
                    "from_": NameAddress(
                        uri=SIPURI(scheme="sip", user="remote", host=IMS_DOMAIN),
                        parameters={"tag": "remote"},
                    ),
                    "to": NameAddress(
                        uri=SIPURI(scheme="sip", user="111111", host=IMS_DOMAIN),
                        parameters={"tag": "ue"},
                    ),
                    "call_id": REALISTIC_CALL_ID_1,
                    "cseq": CSeqHeader(sequence=5, method=SIPMethod.INVITE),
                }
            )

    def test_199_invite_response_allows_no_contact_when_reason_present(self) -> None:
        terminated_model = RESPONSE_MODELS_BY_CODE[199]
        packet = terminated_model.model_validate(
            {
                "via": [ViaHeader(host=PCSCF_HOST, branch="z9hG4bK-199")],
                "from_": NameAddress(
                    uri=SIPURI(scheme="sip", user="remote", host=IMS_DOMAIN),
                    parameters={"tag": "remote"},
                ),
                "to": NameAddress(
                    uri=SIPURI(scheme="sip", user="111111", host=IMS_DOMAIN),
                    parameters={"tag": "ue"},
                ),
                "call_id": REALISTIC_CALL_ID_1,
                "cseq": CSeqHeader(sequence=5, method=SIPMethod.INVITE),
                "reason": 'SIP;cause=487;text="Request Terminated"',
            }
        )
        self.assertEqual(packet.status_code, 199)
        self.assertIsNone(packet.contact)

    def test_subscription_state_requires_expires_for_active_and_pending(self) -> None:
        with self.assertRaises(Exception):
            SubscriptionStateHeader(state="active")

        with self.assertRaises(Exception):
            SubscriptionStateHeader(state="pending")

        with self.assertRaises(Exception):
            SubscriptionStateHeader(state="terminated", expires=10)

    def test_reason_phrase_is_overridable(self) -> None:
        ok_model = RESPONSE_MODELS_BY_CODE[200]
        packet = ok_model.model_validate(
            {
                "via": [ViaHeader(host=PCSCF_HOST, branch="z9hG4bK-200")],
                "from_": NameAddress(
                    uri=SIPURI(scheme="sip", user="remote", host=IMS_DOMAIN),
                    parameters={"tag": "remote"},
                ),
                "to": NameAddress(
                    uri=SIPURI(scheme="sip", user="111111", host=IMS_DOMAIN),
                    parameters={"tag": "ue"},
                ),
                "call_id": REALISTIC_CALL_ID_4,
                "cseq": CSeqHeader(sequence=5, method=SIPMethod.OPTIONS),
                "reason_phrase": "Okay",
            }
        )
        self.assertEqual(packet.reason_phrase, "Okay")

    def test_via_ttl_zero_and_cseq_upper_bound(self) -> None:
        via = ViaHeader(
            host=PCSCF_HOST, branch="z9hG4bK-ttl", ttl=0, transport="TLS-SCTP"
        )
        self.assertEqual(via.ttl, 0)
        self.assertEqual(via.transport, "TLS-SCTP")

        CSeqHeader(sequence=(2**31) - 1, method=SIPMethod.INVITE)
        with self.assertRaises(Exception):
            CSeqHeader(sequence=2**31, method=SIPMethod.INVITE)

    def test_json_schema_exports_cover_all_packets(self) -> None:
        self.assertEqual(len(SIP_CATALOG.request_json_schemas()), 14)
        self.assertEqual(len(SIP_CATALOG.response_json_schemas()), 75)

    def test_document_generators_cover_key_specs(self) -> None:
        request_doc = render_request_docs()
        response_doc = render_response_docs()

        self.assertIn("MESSAGE sip:", request_doc)
        self.assertIn("### 금지 헤더", request_doc)
        self.assertIn("SIP/2.0 424 Bad Location Information", response_doc)
        self.assertIn("## 참고 RFC", response_doc)


if __name__ == "__main__":
    unittest.main()
