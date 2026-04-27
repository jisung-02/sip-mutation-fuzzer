from __future__ import annotations

import random
from typing import Literal, get_args

MutationProfile = Literal[
    "legacy",
    "delivery_preserving",
    "ims_specific",
    "parser_breaker",
]

SUPPORTED_MUTATION_PROFILES: tuple[str, ...] = get_args(MutationProfile)

SUPPORTED_STRATEGIES_BY_LAYER: dict[str, frozenset[str]] = {
    "model": frozenset({"default", "state_breaker"}),
    "wire": frozenset(
        {
            "default",
            "identity",
            "safe",
            "header_whitespace_noise",
            "final_crlf_loss",
            "duplicate_content_length_conflict",
            "alias_port_desync",
            "null_byte_only",
            "boundary_only",
            "byte_edit_only",
            "sdp_boundary_only",
            "sdp_struct_only",
        }
    ),
    "byte": frozenset(
        {
            "default",
            "identity",
            "safe",
            "header_targeted",
            "tail_chop_1",
            "tail_garbage",
        }
    ),
}

PROFILE_ALLOWED_STRATEGIES: dict[str, dict[str, frozenset[str]]] = {
    "legacy": {
        "model": SUPPORTED_STRATEGIES_BY_LAYER["model"],
        "wire": SUPPORTED_STRATEGIES_BY_LAYER["wire"],
        "byte": SUPPORTED_STRATEGIES_BY_LAYER["byte"],
    },
    "delivery_preserving": {
        "model": frozenset({"default"}),
        "wire": frozenset({"default", "identity", "safe", "header_whitespace_noise", "null_byte_only", "boundary_only", "byte_edit_only", "sdp_boundary_only", "sdp_struct_only"}),
        "byte": frozenset({"default", "identity", "safe", "header_targeted"}),
    },
    "ims_specific": {
        "model": frozenset(),
        "wire": frozenset(
            {"default", "identity", "safe", "alias_port_desync", "sdp_boundary_only", "sdp_struct_only"}
        ),
        "byte": frozenset({"default", "identity", "header_targeted"}),
    },
    "parser_breaker": {
        "model": frozenset(),
        "wire": frozenset(
            {"default", "identity", "final_crlf_loss", "duplicate_content_length_conflict"}
        ),
        "byte": frozenset({"default", "identity", "tail_chop_1", "tail_garbage"}),
    },
}

PROFILE_DEFAULT_STRATEGY_POOLS: dict[str, dict[str, tuple[str, ...]]] = {
    "legacy": {
        "model": ("default",),
        "wire": ("default",),
        "byte": ("default",),
    },
    "delivery_preserving": {
        "model": ("default",),
        "wire": ("safe", "header_whitespace_noise"),
        "byte": ("safe", "header_targeted"),
    },
    "ims_specific": {
        "wire": ("safe", "alias_port_desync"),
        "byte": ("header_targeted",),
    },
    "parser_breaker": {
        "wire": ("final_crlf_loss", "duplicate_content_length_conflict"),
        "byte": ("tail_chop_1", "tail_garbage"),
    },
}

IMS_PROFILE_HEADER_NAMES: frozenset[str] = frozenset(
    {
        "contact",
        "record-route",
        "route",
        "path",
        "service-route",
        "p-asserted-identity",
        "p-preferred-identity",
        "p-access-network-info",
        "p-visited-network-id",
        "p-charging-vector",
        "p-charging-function-addresses",
        "session-expires",
        "min-se",
    }
)


def normalize_profile_name(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise ValueError("profile must not be blank")
    if stripped not in SUPPORTED_MUTATION_PROFILES:
        raise ValueError(f"unsupported mutation profile: {stripped}")
    return stripped


def profile_supports_strategy(profile: str, layer: str, strategy: str) -> bool:
    normalized_profile = normalize_profile_name(profile)
    return strategy in PROFILE_ALLOWED_STRATEGIES.get(normalized_profile, {}).get(
        layer, frozenset()
    )


def validate_profile_strategy(profile: str, layer: str, strategy: str) -> None:
    normalized_profile = normalize_profile_name(profile)
    supported = SUPPORTED_STRATEGIES_BY_LAYER.get(layer)
    if supported is None:
        raise ValueError(f"unsupported mutation layer: {layer}")
    if strategy not in supported:
        raise ValueError(f"unsupported mutation strategy for {layer}: {strategy}")
    if not profile_supports_strategy(normalized_profile, layer, strategy):
        raise ValueError(f"profile '{normalized_profile}' does not support {layer}/{strategy}")


def resolve_effective_strategy(
    profile: str,
    layer: str,
    strategy: str,
    seed: int | None,
) -> str:
    normalized_profile = normalize_profile_name(profile)
    if strategy != "default":
        validate_profile_strategy(normalized_profile, layer, strategy)
        return strategy

    if normalized_profile == "legacy":
        validate_profile_strategy("legacy", layer, "default")
        return "default"

    pool = PROFILE_DEFAULT_STRATEGY_POOLS.get(normalized_profile, {}).get(layer, ())
    if not pool:
        raise ValueError(
            f"profile '{normalized_profile}' does not define a default strategy for {layer}"
        )
    rng = random.Random(seed)
    chosen = pool[rng.randrange(len(pool))]
    validate_profile_strategy(normalized_profile, layer, chosen)
    return chosen


__all__ = [
    "IMS_PROFILE_HEADER_NAMES",
    "MutationProfile",
    "PROFILE_ALLOWED_STRATEGIES",
    "PROFILE_DEFAULT_STRATEGY_POOLS",
    "SUPPORTED_MUTATION_PROFILES",
    "SUPPORTED_STRATEGIES_BY_LAYER",
    "normalize_profile_name",
    "profile_supports_strategy",
    "resolve_effective_strategy",
    "validate_profile_strategy",
]
