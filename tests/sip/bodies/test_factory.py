import unittest

from volte_mutation_fuzzer.sip.bodies.conference_info import ConferenceInfoBody
from volte_mutation_fuzzer.sip.bodies.dialog_info import DialogInfoBody
from volte_mutation_fuzzer.sip.bodies.dtmf import DtmfRelayBody
from volte_mutation_fuzzer.sip.bodies.ims_service import ImsServiceBody
from volte_mutation_fuzzer.sip.bodies.message_summary import MessageSummaryBody
from volte_mutation_fuzzer.sip.bodies.pidf import PIdfBody
from volte_mutation_fuzzer.sip.bodies.plain_text import PlainTextBody
from volte_mutation_fuzzer.sip.bodies.reginfo import ReginfoBody
from volte_mutation_fuzzer.sip.bodies.sdp import SDPBody
from volte_mutation_fuzzer.sip.bodies.sipfrag import SipfragBody
from volte_mutation_fuzzer.sip.bodies.sms import SmsBody
from volte_mutation_fuzzer.sip.body_factory import (
    DEFAULT_INFO_PACKAGE,
    BodyContext,
    BodyFactory,
)
from volte_mutation_fuzzer.sip.common import SIPMethod


class BodyFactoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.factory = BodyFactory()

    def test_select_request_body_types(self) -> None:
        self.assertIs(
            self.factory.select(
                BodyContext(method=SIPMethod.NOTIFY, event_package="presence")
            ),
            PIdfBody,
        )
        self.assertIs(
            self.factory.select(
                BodyContext(method=SIPMethod.NOTIFY, event_package="refer")
            ),
            SipfragBody,
        )
        self.assertIs(
            self.factory.select(
                BodyContext(method=SIPMethod.NOTIFY, event_package="reg")
            ),
            ReginfoBody,
        )
        self.assertIs(
            self.factory.select(
                BodyContext(method=SIPMethod.NOTIFY, event_package="dialog")
            ),
            DialogInfoBody,
        )
        self.assertIs(
            self.factory.select(
                BodyContext(method=SIPMethod.NOTIFY, event_package="conference")
            ),
            ConferenceInfoBody,
        )
        self.assertIs(
            self.factory.select(
                BodyContext(method=SIPMethod.NOTIFY, event_package="message-summary")
            ),
            MessageSummaryBody,
        )
        self.assertIs(
            self.factory.select(
                BodyContext(method=SIPMethod.INFO, info_package="dtmf")
            ),
            DtmfRelayBody,
        )
        self.assertIs(
            self.factory.select(
                BodyContext(method=SIPMethod.MESSAGE, sms_over_ip=True)
            ),
            SmsBody,
        )
        self.assertIs(
            self.factory.select(BodyContext(method=SIPMethod.MESSAGE)),
            PlainTextBody,
        )
        self.assertIs(
            self.factory.select(BodyContext(method=SIPMethod.PUBLISH)),
            PIdfBody,
        )
        self.assertIs(
            self.factory.select(BodyContext(method=SIPMethod.INVITE)),
            SDPBody,
        )
        self.assertIs(
            self.factory.select(BodyContext(method=SIPMethod.UPDATE)),
            SDPBody,
        )
        self.assertIs(
            self.factory.select(BodyContext(method=SIPMethod.PRACK)),
            SDPBody,
        )

    def test_explicit_body_kind_takes_precedence_over_method_inference(self) -> None:
        self.assertIs(
            self.factory.select(
                BodyContext(
                    method=SIPMethod.NOTIFY,
                    body_kind=" sdp_offer ",
                    event_package="presence",
                )
            ),
            SDPBody,
        )
        self.assertIs(
            self.factory.select(
                BodyContext(
                    method=SIPMethod.INFO,
                    body_kind=" plain_text ",
                    info_package=DEFAULT_INFO_PACKAGE,
                )
            ),
            PlainTextBody,
        )

    def test_unknown_explicit_body_kind_raises_instead_of_falling_back(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported body_kind"):
            self.factory.select(
                BodyContext(
                    method=SIPMethod.NOTIFY,
                    body_kind="unknown-kind",
                    event_package="presence",
                )
            )

    def test_select_response_body_types(self) -> None:
        self.assertIs(
            self.factory.select(BodyContext(method=SIPMethod.INVITE, status_code=180)),
            SDPBody,
        )
        self.assertIs(
            self.factory.select(BodyContext(method=SIPMethod.UPDATE, status_code=200)),
            SDPBody,
        )
        self.assertIs(
            self.factory.select(BodyContext(method=SIPMethod.PRACK, status_code=204)),
            SDPBody,
        )
        self.assertIs(
            self.factory.select(BodyContext(method=SIPMethod.OPTIONS, status_code=200)),
            SDPBody,
        )
        self.assertIs(
            self.factory.select(BodyContext(method=SIPMethod.INVITE, status_code=380)),
            ImsServiceBody,
        )
        self.assertIsNone(
            self.factory.select(BodyContext(method=SIPMethod.MESSAGE, status_code=200))
        )

    def test_create_returns_default_instances(self) -> None:
        body = self.factory.create(
            BodyContext(method=SIPMethod.NOTIFY, event_package="presence")
        )

        self.assertIsInstance(body, PIdfBody)
        self.assertIsNone(
            self.factory.create(BodyContext(method=SIPMethod.BYE, status_code=200))
        )
