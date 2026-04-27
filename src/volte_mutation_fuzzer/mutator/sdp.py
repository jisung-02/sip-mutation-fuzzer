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
