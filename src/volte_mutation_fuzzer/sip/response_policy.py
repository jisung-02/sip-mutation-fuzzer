from dataclasses import dataclass

from volte_mutation_fuzzer.sip.common import SIPMethod


@dataclass(frozen=True)
class ResponseHeaderPolicy:
    required_headers: frozenset[str] = frozenset()
    forbidden_headers: frozenset[str] = frozenset()
    body_required: bool = False
    body_forbidden: bool = False

    def __post_init__(self) -> None:
        overlap = self.required_headers & self.forbidden_headers
        if overlap:
            raise ValueError(
                f"response policy cannot require and forbid the same headers: {overlap}"
            )
        if self.body_required and self.body_forbidden:
            raise ValueError(
                "response policy body cannot be both required and forbidden"
            )


_DEFAULT_POLICY = ResponseHeaderPolicy()
_ERROR_DEFAULT_POLICY = ResponseHeaderPolicy(body_forbidden=True)

RESPONSE_HEADER_POLICIES: dict[
    tuple[SIPMethod | None, int | None], ResponseHeaderPolicy
] = {
    (SIPMethod.INVITE, 180): ResponseHeaderPolicy(
        required_headers=frozenset({"contact"})
    ),
    (SIPMethod.INVITE, 183): ResponseHeaderPolicy(
        required_headers=frozenset({"contact"}),
        body_required=True,
    ),
    (SIPMethod.INVITE, 200): ResponseHeaderPolicy(
        required_headers=frozenset({"contact"}),
        body_required=True,
    ),
    (SIPMethod.UPDATE, 200): ResponseHeaderPolicy(body_required=True),
    (SIPMethod.PRACK, 200): _DEFAULT_POLICY,
    (SIPMethod.REGISTER, 200): ResponseHeaderPolicy(
        required_headers=frozenset({"contact", "expires"}),
        body_forbidden=True,
    ),
    (SIPMethod.NOTIFY, 200): ResponseHeaderPolicy(body_forbidden=True),
    (SIPMethod.SUBSCRIBE, 200): ResponseHeaderPolicy(
        required_headers=frozenset({"expires"}),
        body_forbidden=True,
    ),
    (SIPMethod.MESSAGE, 200): ResponseHeaderPolicy(
        forbidden_headers=frozenset({"contact"}),
        body_forbidden=True,
    ),
    (SIPMethod.INVITE, 380): ResponseHeaderPolicy(body_required=True),
    (None, 300): ResponseHeaderPolicy(required_headers=frozenset({"contact"})),
    (None, 301): ResponseHeaderPolicy(required_headers=frozenset({"contact"})),
    (None, 302): ResponseHeaderPolicy(required_headers=frozenset({"contact"})),
    (None, 305): ResponseHeaderPolicy(required_headers=frozenset({"contact"})),
}


def get_response_policy(method: SIPMethod, status_code: int) -> ResponseHeaderPolicy:
    exact_policy = RESPONSE_HEADER_POLICIES.get((method, status_code))
    if exact_policy is not None:
        return exact_policy

    generic_status_policy = RESPONSE_HEADER_POLICIES.get((None, status_code))
    if generic_status_policy is not None:
        return generic_status_policy

    method_wide_policy = RESPONSE_HEADER_POLICIES.get((method, None))
    if method_wide_policy is not None:
        return method_wide_policy

    if 400 <= status_code < 700:
        return _ERROR_DEFAULT_POLICY

    return _DEFAULT_POLICY


__all__ = [
    "RESPONSE_HEADER_POLICIES",
    "ResponseHeaderPolicy",
    "_DEFAULT_POLICY",
    "_ERROR_DEFAULT_POLICY",
    "get_response_policy",
]
