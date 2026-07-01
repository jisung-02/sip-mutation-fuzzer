"""Extract SIP dialog state from server responses."""

import re
from typing import Final, Literal
from collections.abc import Sequence

from volte_mutation_fuzzer.generator.contracts import DialogContext
from volte_mutation_fuzzer.sender.contracts import SocketObservation
from volte_mutation_fuzzer.sip.common import SIPURI

# `;tag=<value>` — value ends at whitespace, semicolon, or angle-bracket
_TAG_PATTERN: Final[re.Pattern[str]] = re.compile(r";tag=([^\s;>,]+)", re.IGNORECASE)

# `<sip:...>` or `<sips:...>` or `<tel:...>` — grab the URI inside angle brackets
_ANGLE_URI_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"<((?:sip|sips|tel):[^>]+)>", re.IGNORECASE
)

# Record-Route header: may appear as a single comma-separated line
_COMMA_SPLIT_PATTERN: Final[re.Pattern[str]] = re.compile(r",\s*(?=<)")
_DIALOG_STATE_CLASSIFICATIONS: Final[frozenset[str]] = frozenset(
    {"provisional", "success"}
)


def _extract_tag(header_value: str) -> str | None:
    """Extract the tag parameter from a SIP From/To header value."""
    match = _TAG_PATTERN.search(header_value)
    return match.group(1) if match else None


def _extract_angle_uri(header_value: str) -> str | None:
    """Extract the URI inside angle brackets from a Contact or Route value."""
    match = _ANGLE_URI_PATTERN.search(header_value)
    return match.group(1) if match else None


def _parse_cseq(header_value: str) -> tuple[int, str] | None:
    parts = header_value.strip().split()
    if len(parts) != 2:
        return None
    try:
        return int(parts[0]), parts[1].upper()
    except ValueError:
        return None


def _contains_option_tag(header_value: str, option_tag: str) -> bool:
    tokens = [token.strip().lower() for token in header_value.split(",")]
    return option_tag.lower() in tokens


def _parse_sip_uri(uri_str: str) -> SIPURI | None:
    """Parse a SIP URI string into a SIPURI model, returning None on failure."""
    # Minimal parser: sip:user@host:port;param or sip:host:port;param
    uri_str = uri_str.strip()
    try:
        uri_part, _, raw_headers = uri_str.partition("?")
        scheme, rest = uri_part.split(":", 1)
        scheme_lower = scheme.lower()
        if scheme_lower == "sip":
            parsed_scheme: Literal["sip", "sips", "tel"] = "sip"
        elif scheme_lower == "sips":
            parsed_scheme = "sips"
        else:
            return None

        parameters: dict[str, str | None] = {}
        if ";" in rest:
            authority, *parameter_tokens = rest.split(";")
        else:
            authority, parameter_tokens = rest, []
        for token in parameter_tokens:
            token = token.strip()
            if not token:
                continue
            key, separator, value = token.partition("=")
            parameters[key] = value if separator else None

        headers: dict[str, str] = {}
        if raw_headers:
            for token in raw_headers.split("&"):
                token = token.strip()
                if not token:
                    continue
                key, separator, value = token.partition("=")
                headers[key] = value if separator else ""

        # rest is user@host:port or host:port
        port: int | None = None
        if "@" in authority:
            user, hostpart = authority.split("@", 1)
        else:
            user = None
            hostpart = authority
        if ":" in hostpart:
            host, port_str = hostpart.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                host = hostpart
        else:
            host = hostpart
        return SIPURI(
            scheme=parsed_scheme,
            user=user,
            host=host,
            port=port,
            parameters=parameters,
            headers=headers,
        )
    except Exception:
        return None


def extract_dialog_state(
    observation: SocketObservation,
    context: DialogContext,
) -> DialogContext:
    """Update DialogContext from a SIP response (typically a 200 OK to INVITE).

    Extracts:
    - To-tag → context.local_tag (the UAS/target's tag)
    - Contact URI → context.request_uri (for subsequent in-dialog requests)
    - Record-Route → context.route_set (reversed, as required by RFC 3261)

    The context is mutated in-place and also returned for convenience.
    """
    headers = observation.headers  # already case-folded

    # Extract To-tag → local_tag
    to_header = headers.get("to") or headers.get("t")
    if to_header:
        tag = _extract_tag(to_header)
        if tag:
            context.local_tag = tag

    # Extract Contact URI → request_uri
    contact_header = headers.get("contact") or headers.get("m")
    if contact_header and contact_header.strip() != "*":
        uri_str = _extract_angle_uri(contact_header)
        if uri_str:
            parsed = _parse_sip_uri(uri_str)
            if parsed is not None:
                context.request_uri = parsed

    # Extract Record-Route → route_set (reversed per RFC 3261 §12.1.2)
    record_route = headers.get("record-route")
    if record_route:
        # May be a single comma-separated line
        entries = _COMMA_SPLIT_PATTERN.split(record_route)
        routes = []
        for entry in entries:
            uri_str = _extract_angle_uri(entry.strip())
            if uri_str:
                parsed_rr = _parse_sip_uri(uri_str)
                if parsed_rr is not None:
                    routes.append(parsed_rr)
        if routes:
            context.route_set = tuple(reversed(routes))

    require_header = headers.get("require")
    rseq_header = headers.get("rseq")
    cseq_header = headers.get("cseq")
    if (
        observation.classification == "provisional"
        and require_header is not None
        and _contains_option_tag(require_header, "100rel")
        and rseq_header is not None
        and cseq_header is not None
    ):
        cseq = _parse_cseq(cseq_header)
        if cseq is not None and cseq[1] == "INVITE":
            try:
                context.reliable_invite_rseq = int(rseq_header.strip())
            except ValueError:
                pass
            else:
                context.reliable_invite_cseq = cseq[0]

    return context


def _observation_has_dialog_state(observation: SocketObservation) -> bool:
    headers = observation.headers

    to_header = headers.get("to") or headers.get("t")
    if to_header and _extract_tag(to_header):
        return True

    contact_header = headers.get("contact") or headers.get("m")
    if (
        contact_header
        and contact_header.strip() != "*"
        and _extract_angle_uri(contact_header) is not None
    ):
        return True

    record_route = headers.get("record-route")
    if record_route:
        entries = _COMMA_SPLIT_PATTERN.split(record_route)
        for entry in entries:
            if _extract_angle_uri(entry.strip()) is not None:
                return True

    return False


def extract_dialog_state_from_responses(
    responses: Sequence[SocketObservation],
    context: DialogContext,
) -> DialogContext:
    """Populate dialog state from the best INVITE response seen so far.

    Merge dialog-establishing headers from provisional/success responses in
    arrival order so later responses can refine the dialog without discarding
    richer Contact or Record-Route data learned from earlier provisionals.
    """

    for observation in responses:
        if observation.classification not in _DIALOG_STATE_CLASSIFICATIONS:
            continue
        if not _observation_has_dialog_state(observation):
            continue
        extract_dialog_state(observation, context)

    return context


__all__ = ["extract_dialog_state", "extract_dialog_state_from_responses"]
