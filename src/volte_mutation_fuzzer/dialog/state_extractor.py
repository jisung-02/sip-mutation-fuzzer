"""Extract SIP dialog state from server responses."""

import re
from typing import Final, Literal

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


def _extract_tag(header_value: str) -> str | None:
    """Extract the tag parameter from a SIP From/To header value."""
    match = _TAG_PATTERN.search(header_value)
    return match.group(1) if match else None


def _extract_angle_uri(header_value: str) -> str | None:
    """Extract the URI inside angle brackets from a Contact or Route value."""
    match = _ANGLE_URI_PATTERN.search(header_value)
    return match.group(1) if match else None


def _parse_sip_uri(uri_str: str) -> SIPURI | None:
    """Parse a SIP URI string into a SIPURI model, returning None on failure."""
    # Minimal parser: sip:user@host:port or sip:host:port
    uri_str = uri_str.split(";")[0].strip()  # drop parameters
    try:
        scheme, rest = uri_str.split(":", 1)
        scheme_lower = scheme.lower()
        if scheme_lower == "sip":
            parsed_scheme: Literal["sip", "sips", "tel"] = "sip"
        elif scheme_lower == "sips":
            parsed_scheme = "sips"
        else:
            return None
        # rest is user@host:port or host:port
        port: int | None = None
        if "@" in rest:
            user, hostpart = rest.split("@", 1)
        else:
            user = None
            hostpart = rest
        if ":" in hostpart:
            host, port_str = hostpart.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                host = hostpart
        else:
            host = hostpart
        return SIPURI(scheme=parsed_scheme, user=user, host=host, port=port)
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

    return context


__all__ = ["extract_dialog_state"]
