"""RFC 4028 Session-Expires structure and adjacent header bound tests."""

import unittest

from pydantic import ValidationError

from volte_mutation_fuzzer.sip.common import (
    CSeqHeader,
    NameAddress,
    RAckHeader,
    SessionExpiresHeader,
    SIPMethod,
    SIPURI,
    ViaHeader,
)
from volte_mutation_fuzzer.sip.render import render_packet
from volte_mutation_fuzzer.sip.requests import InviteRequest
from volte_mutation_fuzzer.sip.responses import SIPResponse


def _response(**overrides) -> SIPResponse:
    payload = {
        "status_code": 200,
        "reason_phrase": "OK",
        "via": [ViaHeader(host="pcscf.example", branch="z9hG4bK-test")],
        "from_": NameAddress(
            uri=SIPURI(user="111111", host="ue.example"),
            parameters={"tag": "ue-tag"},
        ),
        "to": NameAddress(
            uri=SIPURI(user="222222", host="ims.example"),
            parameters={"tag": "net-tag"},
        ),
        "call_id": "test@pcscf.example",
        "cseq": CSeqHeader(sequence=1, method=SIPMethod.INVITE),
        "contact": [NameAddress(uri=SIPURI(user="222222", host="ims.example"))],
    }
    payload.update(overrides)
    return SIPResponse.model_validate(payload)


class SessionExpiresHeaderTests(unittest.TestCase):
    def test_plain_seconds_render_without_refresher(self) -> None:
        self.assertEqual(str(SessionExpiresHeader(seconds=1800)), "1800")

    def test_refresher_parameter_is_rendered(self) -> None:
        header = SessionExpiresHeader(seconds=1800, refresher="uas")
        self.assertEqual(str(header), "1800;refresher=uas")

    def test_refresher_rejects_unknown_values(self) -> None:
        with self.assertRaises(ValidationError):
            SessionExpiresHeader.model_validate({"seconds": 1800, "refresher": "proxy"})

    def test_seconds_rejects_negative_values(self) -> None:
        with self.assertRaises(ValidationError):
            SessionExpiresHeader(seconds=-1)


class SessionExpiresWireRenderingTests(unittest.TestCase):
    def test_response_renders_refresher_on_the_wire(self) -> None:
        response = _response(
            session_expires=SessionExpiresHeader(seconds=1800, refresher="uas")
        )

        wire = render_packet(response)

        self.assertIn("Session-Expires: 1800;refresher=uas", wire)

    def test_response_accepts_plain_integer_backwards_compatible(self) -> None:
        response = _response(session_expires=1800)

        self.assertEqual(response.session_expires, 1800)
        self.assertIn("Session-Expires: 1800", render_packet(response))


class RfcBoundTests(unittest.TestCase):
    def test_rseq_accepts_upper_bound(self) -> None:
        response = _response(status_code=180, reason_phrase="Ringing", rseq=2**31 - 1)

        self.assertEqual(response.rseq, 2**31 - 1)

    def test_rseq_rejects_values_above_2_pow_31_minus_1(self) -> None:
        with self.assertRaises(ValidationError):
            _response(status_code=180, reason_phrase="Ringing", rseq=2**31)

    def test_rack_response_num_must_be_at_least_one(self) -> None:
        with self.assertRaises(ValidationError):
            RAckHeader(response_num=0, cseq_num=1, method=SIPMethod.INVITE)

        header = RAckHeader(response_num=1, cseq_num=1, method=SIPMethod.INVITE)
        self.assertEqual(header.response_num, 1)

    def test_p_asserted_identity_allows_at_most_two_values(self) -> None:
        def _invite(values: int) -> InviteRequest:
            identities = tuple(
                NameAddress(uri=SIPURI(user=str(user), host="ims.example"))
                for user in range(values)
            )
            return InviteRequest.model_validate(
                {
                    "request_uri": SIPURI(user="111111", host="ue.example"),
                    "via": [ViaHeader(host="pcscf.example", branch="z9hG4bK-test")],
                    "max_forwards": 70,
                    "from_": NameAddress(
                        uri=SIPURI(user="222222", host="ims.example"),
                        parameters={"tag": "from-tag"},
                    ),
                    "to": NameAddress(uri=SIPURI(user="111111", host="ue.example")),
                    "call_id": "test@pcscf.example",
                    "cseq": CSeqHeader(sequence=1, method=SIPMethod.INVITE),
                    "contact": [
                        NameAddress(uri=SIPURI(user="222222", host="ims.example"))
                    ],
                    "p_asserted_identity": identities,
                }
            )

        self.assertEqual(len(_invite(2).p_asserted_identity or ()), 2)
        with self.assertRaises(ValidationError):
            _invite(3)


if __name__ == "__main__":
    unittest.main()
