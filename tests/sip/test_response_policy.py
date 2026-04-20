import unittest

from volte_mutation_fuzzer.sip.common import SIPMethod
from volte_mutation_fuzzer.sip.response_policy import (
    _DEFAULT_POLICY,
    _ERROR_DEFAULT_POLICY,
    get_response_policy,
)


class ResponsePolicyTests(unittest.TestCase):
    def test_exact_and_generic_status_policies(self) -> None:
        cases = (
            (
                SIPMethod.INVITE,
                180,
                frozenset({"contact"}),
                frozenset(),
                False,
                False,
            ),
            (
                SIPMethod.INVITE,
                200,
                frozenset({"contact"}),
                frozenset(),
                True,
                False,
            ),
            (
                SIPMethod.REGISTER,
                200,
                frozenset({"contact", "expires"}),
                frozenset(),
                False,
                True,
            ),
            (
                SIPMethod.MESSAGE,
                200,
                frozenset(),
                frozenset({"contact"}),
                False,
                True,
            ),
            (
                SIPMethod.SUBSCRIBE,
                200,
                frozenset({"expires"}),
                frozenset(),
                False,
                True,
            ),
            (
                SIPMethod.INVITE,
                183,
                frozenset({"contact"}),
                frozenset(),
                True,
                False,
            ),
            (
                SIPMethod.UPDATE,
                200,
                frozenset(),
                frozenset(),
                True,
                False,
            ),
            (
                SIPMethod.NOTIFY,
                200,
                frozenset(),
                frozenset(),
                False,
                True,
            ),
            (
                SIPMethod.INVITE,
                380,
                frozenset(),
                frozenset(),
                True,
                False,
            ),
            (
                SIPMethod.INVITE,
                301,
                frozenset({"contact"}),
                frozenset(),
                False,
                False,
            ),
        )

        for (
            method,
            status_code,
            required_headers,
            forbidden_headers,
            body_required,
            body_forbidden,
        ) in cases:
            with self.subTest(method=method, status_code=status_code):
                policy = get_response_policy(method, status_code)

                self.assertEqual(policy.required_headers, required_headers)
                self.assertEqual(policy.forbidden_headers, forbidden_headers)
                self.assertEqual(policy.body_required, body_required)
                self.assertEqual(policy.body_forbidden, body_forbidden)

    def test_invite_100_uses_empty_default_policy(self) -> None:
        policy = get_response_policy(SIPMethod.INVITE, 100)

        self.assertEqual(policy, _DEFAULT_POLICY)

    def test_error_responses_use_error_default_policy(self) -> None:
        for method in (SIPMethod.BYE, SIPMethod.PUBLISH):
            with self.subTest(method=method):
                policy = get_response_policy(method, 404)

                self.assertEqual(policy, _ERROR_DEFAULT_POLICY)
