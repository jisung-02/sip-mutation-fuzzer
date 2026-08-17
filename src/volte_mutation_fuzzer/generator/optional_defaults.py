from __future__ import annotations

from typing import Any

from volte_mutation_fuzzer.sip.common import SIPMethod, SessionExpiresHeader
from volte_mutation_fuzzer.sip.body_factory import DEFAULT_INFO_PACKAGE

_COMMON_REQUEST_OPTIONALS: dict[str, Any] = {
    "supported": (
        "path",
        "gruu",
        "outbound",
        "timer",
        "100rel",
        "precondition",
        "replaces",
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
    "accept": (
        "application/sdp",
        "application/pidf+xml",
        "application/reginfo+xml",
        "multipart/mixed",
    ),
    "accept_encoding": ("identity",),
    "accept_language": ("en",),
    "organization": "VoLTE Test Operator",
}

_METHOD_REQUEST_OPTIONALS: dict[SIPMethod, dict[str, Any]] = {
    SIPMethod.INVITE: {
        "supported": (
            "path",
            "gruu",
            "outbound",
            "timer",
            "100rel",
            "precondition",
            "replaces",
            "histinfo",
            "norefersub",
        ),
        "session_expires": 1800,
        "min_se": 90,
        "recv_info": ("infoDtmf",),
        "privacy": ("none",),
        "subject": "VoLTE Call",
        "priority": "normal",
        "alert_info": ("urn:alert:service:call-waiting",),
    },
    SIPMethod.UPDATE: {
        "session_expires": 1800,
        "min_se": 90,
        "recv_info": ("infoDtmf",),
    },
    SIPMethod.SUBSCRIBE: {
        "expires": 3600,
    },
    SIPMethod.REGISTER: {
        "expires": 3600,
        "path": ("sip:pcscf.ims.mnc001.mcc001.3gppnetwork.org;lr",),
        "recv_info": ("infoDtmf",),
    },
    SIPMethod.PUBLISH: {
        "expires": 3600,
    },
    SIPMethod.REFER: {
        "refer_sub": True,
    },
    SIPMethod.CANCEL: {
        # RFC 3326: cause must be 1*DIGIT mirroring a SIP response code.
        "reason": 'SIP;cause=487;text="Request Terminated"',
    },
    SIPMethod.PRACK: {
        "recv_info": ("infoDtmf",),
    },
    SIPMethod.INFO: {
        "info_package": DEFAULT_INFO_PACKAGE,
    },
}

_COMMON_RESPONSE_OPTIONALS: dict[str, Any] = {
    "supported": ("path", "gruu", "outbound", "timer", "100rel", "precondition"),
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
}

_RESPONSE_OPTIONALS: dict[tuple[SIPMethod | None, int | None], dict[str, Any]] = {
    (SIPMethod.INVITE, 180): {
        "rseq": 1,
        "recv_info": ("infoDtmf",),
    },
    (SIPMethod.INVITE, 183): {
        "rseq": 1,
        "recv_info": ("infoDtmf",),
    },
    (SIPMethod.INVITE, 199): {
        "reason": 'SIP;cause=487;text="Request Terminated"',
    },
    (SIPMethod.INVITE, 200): {
        # RFC 4028 §9: the 2xx Session-Expires MUST carry a refresher
        # parameter. "uas" keeps the refresh responsibility on the network
        # side (choosing "uac" would additionally require Require: timer).
        "session_expires": SessionExpiresHeader(seconds=1800, refresher="uas"),
        "recv_info": ("infoDtmf",),
    },
    (SIPMethod.UPDATE, 200): {
        "session_expires": SessionExpiresHeader(seconds=1800, refresher="uas"),
    },
    (None, 422): {
        "min_se": 1800,
    },
    (None, 423): {
        "min_expires": 300,
    },
}


def get_request_optional_defaults(method: SIPMethod) -> dict[str, Any]:
    """Return merged common + method-specific optional defaults for a request."""
    result = dict(_COMMON_REQUEST_OPTIONALS)
    method_specific = _METHOD_REQUEST_OPTIONALS.get(method)
    if method_specific is not None:
        result.update(method_specific)
    return result


def get_response_optional_defaults(
    method: SIPMethod, status_code: int
) -> dict[str, Any]:
    """Return merged common + (method, status)-specific optional defaults."""
    result = dict(_COMMON_RESPONSE_OPTIONALS)

    exact = _RESPONSE_OPTIONALS.get((method, status_code))
    if exact is not None:
        result.update(exact)
        return result

    generic = _RESPONSE_OPTIONALS.get((None, status_code))
    if generic is not None:
        result.update(generic)
        return result

    method_wide = _RESPONSE_OPTIONALS.get((method, None))
    if method_wide is not None:
        result.update(method_wide)

    return result


__all__ = ["get_request_optional_defaults", "get_response_optional_defaults"]
