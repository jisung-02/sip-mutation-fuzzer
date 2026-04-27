"""SDP (RFC 4566) grammar-aware mutator helpers.

Used by ``_apply_sdp_boundary_only`` in ``mutator.core`` to surgically
mutate specific tokens inside an SDP body — port numbers on ``m=``
lines, IP addresses on ``c=`` lines, codec names on ``a=rtpmap:`` lines,
codec params on ``a=fmtp:`` lines, and bandwidth values on ``b=`` lines.

The generic wire-layer mutator only sees SIP headers; the byte-layer
mutator hits the SDP region only by accident. This module provides the
intent-driven SDP fuzz coverage that real CVE classes (CVE-2018-9489,
CVE-2019-2017, …) historically required.

Parsing is intentionally lenient — RFC 4566 has multi-line continuations
and optional fields we never emit, so we treat the body as an ordered
list of ``(type_letter, value)`` pairs. Round-trip is byte-exact for
the baseline SDP shapes our generator produces (``_INVITE_SDP_TEMPLATE``
and ``SDPBody.render()``).
"""

from __future__ import annotations

import random
from typing import Final


# Each tuple element is (type_letter, value_text). type_letter is the
# single character before ``=``; value_text is everything after ``=``,
# without the trailing CRLF. Lines that don't fit ``X=...`` are kept
# verbatim under type_letter ``"?"`` so re-render preserves them.
SDPLine = tuple[str, str]


_BOUNDARY_PORTS: Final[tuple[int, ...]] = (
    0,
    1,
    65535,
    65536,
    32767,
    32768,
    -1,
)
_BOUNDARY_TRANSPORTS: Final[tuple[str, ...]] = (
    "RTP/SAVP",
    "RTP/SAVPF",
    "UDP",
    "TCP",
    "GARBAGE",
)
_BOUNDARY_ADDRESSES: Final[tuple[str, ...]] = (
    "0.0.0.0",
    "255.255.255.255",
    "127.0.0.1",
    "::1",
    "::ffff:10.0.0.1",
    "999.999.999.999",
)
_BOUNDARY_CODECS: Final[tuple[str, ...]] = (
    "GARBAGE",
    "X",
    "A" * 100,
    "AMR-WTF",
    "telephone-event-fuzz",
)
_BOUNDARY_CLOCKS: Final[tuple[int, ...]] = (
    0,
    1,
    -1,
    2147483647,
    2147483648,
)
_BOUNDARY_BANDWIDTHS: Final[tuple[int, ...]] = (
    0,
    -1,
    2147483647,
    2147483648,
    9999999999,
)

VARIANTS: Final[tuple[str, ...]] = (
    "media_port",
    "media_transport",
    "connection_addr",
    "rtpmap_codec",
    "bandwidth",
)

STRUCT_VARIANTS: Final[tuple[str, ...]] = (
    "extra_media",
    "extra_attribute",
    "missing_session_name",
    "missing_origin",
    "version_corrupt",
    "direction_conflict",
)

_DIRECTION_ATTRS: Final[tuple[str, ...]] = (
    "sendrecv",
    "sendonly",
    "recvonly",
    "inactive",
)

_VERSION_CORRUPT_VALUES: Final[tuple[str, ...]] = (
    "99",
    "",
    "A",
)

_EXTRA_ATTRS: Final[tuple[str, ...]] = (
    "garbage:42 random_value",
    "fuzz-attr",
    "x-fuzz:1",
    "unknown-attr:bogus",
)


def parse_sdp_body(text: str) -> list[SDPLine]:
    """Split an SDP body into ``[(type_letter, value), ...]`` pairs.

    CRLF or LF line endings are both accepted; trailing blank lines are
    preserved as ``("", "")`` so round-trip emits the same byte length.
    """
    if not text:
        return []
    # Normalise to LF, then split. Re-render emits CRLF.
    normalised = text.replace("\r\n", "\n")
    out: list[SDPLine] = []
    for line in normalised.split("\n"):
        if not line:
            out.append(("", ""))
            continue
        if len(line) >= 2 and line[1] == "=":
            out.append((line[0], line[2:]))
        else:
            # Lines that don't match ``X=...`` are passthrough — generators
            # we control don't emit them, but be lenient.
            out.append(("?", line))
    return out


def render_sdp_body(lines: list[SDPLine]) -> str:
    """Inverse of ``parse_sdp_body``. Emits CRLF-separated SDP."""
    parts: list[str] = []
    for type_letter, value in lines:
        if type_letter == "":
            parts.append("")
        elif type_letter == "?":
            parts.append(value)
        else:
            parts.append(f"{type_letter}={value}")
    return "\r\n".join(parts)


def _line_indices(lines: list[SDPLine], type_letter: str) -> list[int]:
    return [i for i, (k, _v) in enumerate(lines) if k == type_letter]


def _attr_indices_with_prefix(lines: list[SDPLine], prefix: str) -> list[int]:
    """Return indices of ``a=<prefix>:...`` lines."""
    return [
        i
        for i, (k, v) in enumerate(lines)
        if k == "a" and v.startswith(f"{prefix}:")
    ]


class SDPMutationResult:
    """Lightweight record describing a single SDP variant application.

    Lives outside ``MutationRecord`` so the caller can decide how to map
    the SDP-specific path/before/after into the broader record schema.
    """

    __slots__ = ("path", "operator", "before", "after", "note")

    def __init__(
        self,
        *,
        path: str,
        operator: str,
        before: str,
        after: str,
        note: str,
    ) -> None:
        self.path = path
        self.operator = operator
        self.before = before
        self.after = after
        self.note = note


def apply_sdp_boundary(
    lines: list[SDPLine],
    rng: random.Random,
    *,
    variant: str | None = None,
) -> SDPMutationResult:
    """Apply one ``sdp_boundary_only`` variant in place on ``lines``.

    If ``variant`` is None we pick from the variants whose target line
    actually exists in this SDP body — ``bandwidth`` is skipped on
    generic INVITE baselines that have no ``b=`` line, etc. Raises
    ``ValueError`` when no fuzzable line exists at all (or when an
    explicit ``variant`` argument is given but its line is absent),
    so the multi-mutation loop in core.py can break gracefully.
    """
    if variant is None:
        viable: list[str] = []
        if _line_indices(lines, "m"):
            viable.append("media_port")
            viable.append("media_transport")
        if _line_indices(lines, "c"):
            viable.append("connection_addr")
        if _attr_indices_with_prefix(lines, "rtpmap"):
            viable.append("rtpmap_codec")
        if _line_indices(lines, "b"):
            viable.append("bandwidth")
        if not viable:
            raise ValueError(
                "sdp body has no fuzzable line for sdp_boundary_only "
                "(missing m=/c=/a=rtpmap/b=)"
            )
        variant = viable[rng.randrange(len(viable))]

    if variant == "media_port":
        return _mutate_media_port(lines, rng)
    if variant == "media_transport":
        return _mutate_media_transport(lines, rng)
    if variant == "connection_addr":
        return _mutate_connection_addr(lines, rng)
    if variant == "rtpmap_codec":
        return _mutate_rtpmap_codec(lines, rng)
    if variant == "bandwidth":
        return _mutate_bandwidth(lines, rng)
    raise ValueError(f"unknown sdp boundary variant: {variant!r}")


def _mutate_media_port(
    lines: list[SDPLine], rng: random.Random
) -> SDPMutationResult:
    indices = _line_indices(lines, "m")
    if not indices:
        raise ValueError("sdp body has no m= line for media_port variant")
    idx = indices[rng.randrange(len(indices))]
    before_value = lines[idx][1]
    parts = before_value.split()
    if len(parts) < 2:
        raise ValueError(f"malformed m-line at index {idx}: {before_value!r}")
    new_port = _BOUNDARY_PORTS[rng.randrange(len(_BOUNDARY_PORTS))]
    parts[1] = str(new_port)
    after_value = " ".join(parts)
    lines[idx] = ("m", after_value)
    return SDPMutationResult(
        path=f"body:sdp:m_line[{idx}].port",
        operator="sdp_boundary_only",
        before=f"m={before_value}",
        after=f"m={after_value}",
        note="variant=media_port",
    )


def _mutate_media_transport(
    lines: list[SDPLine], rng: random.Random
) -> SDPMutationResult:
    indices = _line_indices(lines, "m")
    if not indices:
        raise ValueError("sdp body has no m= line for media_transport variant")
    idx = indices[rng.randrange(len(indices))]
    before_value = lines[idx][1]
    parts = before_value.split()
    if len(parts) < 3:
        raise ValueError(f"malformed m-line at index {idx}: {before_value!r}")
    new_transport = _BOUNDARY_TRANSPORTS[rng.randrange(len(_BOUNDARY_TRANSPORTS))]
    parts[2] = new_transport
    after_value = " ".join(parts)
    lines[idx] = ("m", after_value)
    return SDPMutationResult(
        path=f"body:sdp:m_line[{idx}].transport",
        operator="sdp_boundary_only",
        before=f"m={before_value}",
        after=f"m={after_value}",
        note="variant=media_transport",
    )


def _mutate_connection_addr(
    lines: list[SDPLine], rng: random.Random
) -> SDPMutationResult:
    indices = _line_indices(lines, "c")
    if not indices:
        raise ValueError("sdp body has no c= line for connection_addr variant")
    idx = indices[rng.randrange(len(indices))]
    before_value = lines[idx][1]
    parts = before_value.split()
    if len(parts) < 3:
        raise ValueError(f"malformed c-line at index {idx}: {before_value!r}")
    new_addr = _BOUNDARY_ADDRESSES[rng.randrange(len(_BOUNDARY_ADDRESSES))]
    parts[2] = new_addr
    after_value = " ".join(parts)
    lines[idx] = ("c", after_value)
    return SDPMutationResult(
        path=f"body:sdp:c_line[{idx}].address",
        operator="sdp_boundary_only",
        before=f"c={before_value}",
        after=f"c={after_value}",
        note="variant=connection_addr",
    )


def _mutate_rtpmap_codec(
    lines: list[SDPLine], rng: random.Random
) -> SDPMutationResult:
    indices = _attr_indices_with_prefix(lines, "rtpmap")
    if not indices:
        raise ValueError("sdp body has no a=rtpmap line for rtpmap_codec variant")
    idx = indices[rng.randrange(len(indices))]
    before_value = lines[idx][1]
    # ``rtpmap:<pt> <codec>/<clock>[/<channels>]``
    head, _, rest = before_value.partition(":")
    pt_part, _, codec_clock = rest.partition(" ")
    if not codec_clock:
        raise ValueError(f"malformed rtpmap at index {idx}: {before_value!r}")
    codec_clock_parts = codec_clock.split("/")
    if rng.random() < 0.5 or len(codec_clock_parts) < 2:
        # Mutate the codec name.
        codec_clock_parts[0] = _BOUNDARY_CODECS[rng.randrange(len(_BOUNDARY_CODECS))]
        sub_target = "codec_name"
    else:
        # Mutate the clock rate.
        codec_clock_parts[1] = str(
            _BOUNDARY_CLOCKS[rng.randrange(len(_BOUNDARY_CLOCKS))]
        )
        sub_target = "clock_rate"
    new_codec_clock = "/".join(codec_clock_parts)
    after_value = f"{head}:{pt_part} {new_codec_clock}"
    lines[idx] = ("a", after_value)
    return SDPMutationResult(
        path=f"body:sdp:rtpmap[{idx}].{sub_target}",
        operator="sdp_boundary_only",
        before=f"a={before_value}",
        after=f"a={after_value}",
        note=f"variant=rtpmap_codec.{sub_target}",
    )


def _mutate_bandwidth(
    lines: list[SDPLine], rng: random.Random
) -> SDPMutationResult:
    indices = _line_indices(lines, "b")
    if not indices:
        raise ValueError("sdp body has no b= line for bandwidth variant")
    idx = indices[rng.randrange(len(indices))]
    before_value = lines[idx][1]
    bw_type, _, _bw_value = before_value.partition(":")
    if not bw_type:
        raise ValueError(f"malformed b-line at index {idx}: {before_value!r}")
    new_bw = _BOUNDARY_BANDWIDTHS[rng.randrange(len(_BOUNDARY_BANDWIDTHS))]
    after_value = f"{bw_type}:{new_bw}"
    lines[idx] = ("b", after_value)
    return SDPMutationResult(
        path=f"body:sdp:b_line[{idx}].value",
        operator="sdp_boundary_only",
        before=f"b={before_value}",
        after=f"b={after_value}",
        note="variant=bandwidth",
    )


def apply_sdp_struct(
    lines: list[SDPLine],
    rng: random.Random,
    *,
    variant: str | None = None,
) -> SDPMutationResult:
    """Apply one ``sdp_struct_only`` variant in place on ``lines``.

    Where ``apply_sdp_boundary`` mutates *tokens within* SDP lines, this
    helper mutates the *line set itself* — adds/removes/reorders whole
    lines, exercising the SDP parser's state machine and line-ordering
    assumptions.

    If ``variant`` is None, pick from variants whose target line(s)
    actually exist in the body. Variants without a hard target prereq
    (``extra_attribute``, ``direction_conflict``) are always viable.
    Raises ``ValueError`` when no fuzzable opportunity exists, or when
    an explicit ``variant`` is given but its target line is absent — the
    multi-mutation loop in core.py treats that as a graceful break.
    """
    if variant is None:
        viable: list[str] = []
        if _line_indices(lines, "m"):
            viable.append("extra_media")
        # extra_attribute is always viable — we just append a new a= line.
        viable.append("extra_attribute")
        if _line_indices(lines, "s"):
            viable.append("missing_session_name")
        if _line_indices(lines, "o"):
            viable.append("missing_origin")
        if _line_indices(lines, "v"):
            viable.append("version_corrupt")
        # direction_conflict is always viable — we either inject a second
        # direction next to an existing one, or add two direction attrs.
        viable.append("direction_conflict")
        if not viable:
            raise ValueError(
                "sdp body has no fuzzable structure for sdp_struct_only"
            )
        variant = viable[rng.randrange(len(viable))]

    if variant == "extra_media":
        return _struct_extra_media(lines, rng)
    if variant == "extra_attribute":
        return _struct_extra_attribute(lines, rng)
    if variant == "missing_session_name":
        return _struct_missing_session_name(lines, rng)
    if variant == "missing_origin":
        return _struct_missing_origin(lines, rng)
    if variant == "version_corrupt":
        return _struct_version_corrupt(lines, rng)
    if variant == "direction_conflict":
        return _struct_direction_conflict(lines, rng)
    raise ValueError(f"unknown sdp struct variant: {variant!r}")


def _struct_extra_media(
    lines: list[SDPLine], rng: random.Random
) -> SDPMutationResult:
    """Insert a second ``m=audio <port> RTP/AVP 0`` line after the c= line
    (or after the existing m= line if no c= follows it), exercising
    SDP parsers that assume only one media stream.
    """
    m_indices = _line_indices(lines, "m")
    if not m_indices:
        raise ValueError("sdp body has no m= line for extra_media variant")
    base_idx = m_indices[0]
    base_value = lines[base_idx][1]
    base_parts = base_value.split()
    if len(base_parts) < 2:
        raise ValueError(
            f"malformed m-line at index {base_idx}: {base_value!r}"
        )
    try:
        base_port = int(base_parts[1])
    except ValueError:
        base_port = 49170
    new_port = (base_port + 10) if 0 <= base_port <= 65000 else 49180
    new_line_value = f"audio {new_port} RTP/AVP 0"

    # Prefer to insert after the c= line that follows base m=, otherwise
    # right after the m= line itself.
    insert_idx = base_idx + 1
    for i in range(base_idx + 1, len(lines)):
        k, _v = lines[i]
        if k == "c":
            insert_idx = i + 1
            break
        if k == "m":
            # Reached another media section — stop scanning.
            break

    lines.insert(insert_idx, ("m", new_line_value))
    return SDPMutationResult(
        path=f"body:sdp:struct.extra_media[{insert_idx}]",
        operator="sdp_struct_only",
        before="<no second m-line>",
        after=f"m={new_line_value}",
        note="variant=extra_media",
    )


def _struct_extra_attribute(
    lines: list[SDPLine], rng: random.Random
) -> SDPMutationResult:
    """Insert an unknown ``a=...`` attribute at a random position.

    If a-lines already exist, we splice between them; otherwise we
    append at the end (just before the trailing blank line if present).
    """
    attr_value = _EXTRA_ATTRS[rng.randrange(len(_EXTRA_ATTRS))]
    a_indices = _line_indices(lines, "a")
    if a_indices:
        # Insert at one of the boundary positions inside (or just after)
        # the a-line block, to maximise placement diversity.
        insert_choices = a_indices + [a_indices[-1] + 1]
        insert_idx = insert_choices[rng.randrange(len(insert_choices))]
    else:
        # No a-lines — append, but keep trailing blank ("", "") last.
        insert_idx = len(lines)
        if lines and lines[-1] == ("", ""):
            insert_idx = len(lines) - 1
    lines.insert(insert_idx, ("a", attr_value))
    return SDPMutationResult(
        path=f"body:sdp:struct.extra_attribute[{insert_idx}]",
        operator="sdp_struct_only",
        before="<no extra attribute>",
        after=f"a={attr_value}",
        note="variant=extra_attribute",
    )


def _struct_missing_session_name(
    lines: list[SDPLine], rng: random.Random
) -> SDPMutationResult:
    """Remove the (mandatory) ``s=`` line."""
    indices = _line_indices(lines, "s")
    if not indices:
        raise ValueError(
            "sdp body has no s= line for missing_session_name variant"
        )
    idx = indices[rng.randrange(len(indices))]
    before_value = lines[idx][1]
    del lines[idx]
    return SDPMutationResult(
        path=f"body:sdp:struct.missing_session_name[{idx}]",
        operator="sdp_struct_only",
        before=f"s={before_value}",
        after="<s= line removed>",
        note="variant=missing_session_name",
    )


def _struct_missing_origin(
    lines: list[SDPLine], rng: random.Random
) -> SDPMutationResult:
    """Remove the (mandatory) ``o=`` line."""
    indices = _line_indices(lines, "o")
    if not indices:
        raise ValueError(
            "sdp body has no o= line for missing_origin variant"
        )
    idx = indices[rng.randrange(len(indices))]
    before_value = lines[idx][1]
    del lines[idx]
    return SDPMutationResult(
        path=f"body:sdp:struct.missing_origin[{idx}]",
        operator="sdp_struct_only",
        before=f"o={before_value}",
        after="<o= line removed>",
        note="variant=missing_origin",
    )


def _struct_version_corrupt(
    lines: list[SDPLine], rng: random.Random
) -> SDPMutationResult:
    """Replace ``v=0`` with ``v=99`` / ``v=`` / ``v=A``."""
    indices = _line_indices(lines, "v")
    if not indices:
        raise ValueError(
            "sdp body has no v= line for version_corrupt variant"
        )
    idx = indices[rng.randrange(len(indices))]
    before_value = lines[idx][1]
    new_value = _VERSION_CORRUPT_VALUES[
        rng.randrange(len(_VERSION_CORRUPT_VALUES))
    ]
    lines[idx] = ("v", new_value)
    return SDPMutationResult(
        path=f"body:sdp:struct.version_corrupt[{idx}]",
        operator="sdp_struct_only",
        before=f"v={before_value}",
        after=f"v={new_value}",
        note=f"variant=version_corrupt.value={new_value!r}",
    )


def _struct_direction_conflict(
    lines: list[SDPLine], rng: random.Random
) -> SDPMutationResult:
    """Inject conflicting direction attributes.

    If a direction attribute already exists, append a *different*
    direction immediately after it. If none exists, add both
    ``a=sendrecv`` and ``a=sendonly`` at the end of the a-line block.
    """
    existing_dir_idx: int | None = None
    existing_dir_value: str | None = None
    for i, (k, v) in enumerate(lines):
        if k == "a" and v in _DIRECTION_ATTRS:
            existing_dir_idx = i
            existing_dir_value = v
            break

    if existing_dir_idx is not None and existing_dir_value is not None:
        # Pick a different direction.
        candidates = [d for d in _DIRECTION_ATTRS if d != existing_dir_value]
        new_dir = candidates[rng.randrange(len(candidates))]
        insert_idx = existing_dir_idx + 1
        lines.insert(insert_idx, ("a", new_dir))
        return SDPMutationResult(
            path=f"body:sdp:struct.direction_conflict[{insert_idx}]",
            operator="sdp_struct_only",
            before=f"a={existing_dir_value}",
            after=f"a={existing_dir_value} + a={new_dir}",
            note=f"variant=direction_conflict.added={new_dir}",
        )

    # No existing direction attribute — add two conflicting ones.
    a_indices = _line_indices(lines, "a")
    if a_indices:
        insert_idx = a_indices[-1] + 1
    else:
        insert_idx = len(lines)
        if lines and lines[-1] == ("", ""):
            insert_idx = len(lines) - 1
    lines.insert(insert_idx, ("a", "sendrecv"))
    lines.insert(insert_idx + 1, ("a", "sendonly"))
    return SDPMutationResult(
        path=f"body:sdp:struct.direction_conflict[{insert_idx}]",
        operator="sdp_struct_only",
        before="<no direction attr>",
        after="a=sendrecv + a=sendonly",
        note="variant=direction_conflict.added=sendrecv+sendonly",
    )
