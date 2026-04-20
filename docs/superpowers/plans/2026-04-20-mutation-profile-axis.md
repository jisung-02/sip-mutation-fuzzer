# Mutation Profile Axis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an explicit mutation `profile` axis that selects realistic fuzzing families independently from sender `mode`, keeps seed-based reproduction deterministic, and records the chosen family from mutator entry points through campaign results and reports.

**Architecture:** Centralize profile/layer/strategy compatibility in one shared catalog so `SIPMutator` and `CaseGenerator` stop carrying divergent allowlists. Treat `profile` as the "bug family" selector and keep `strategy` as either an explicit concrete mutation or the requested `default`, which resolves deterministically inside the chosen profile from `seed`. Thread the resolved profile and effective strategy through contracts, CLI, campaign execution, replay, evidence, and HTML/report surfaces without changing existing sender `mode` semantics such as `softphone` or `real-ue-direct`.

**Tech Stack:** Python 3.12, Pydantic, Typer, existing `SIPMutator`, `CaseGenerator`, `CampaignExecutor`, `pytest`

---

## File Structure

- Create: `src/volte_mutation_fuzzer/mutator/profile_catalog.py`
  One source of truth for supported profiles, layer/strategy compatibility, profile-default resolution, and IMS-focused header allowlists.
- Modify: `src/volte_mutation_fuzzer/mutator/contracts.py`
  Add `profile` to mutator config/output contracts.
- Modify: `src/volte_mutation_fuzzer/campaign/contracts.py`
  Add `profiles` to campaign config and `profile` to case spec/result contracts.
- Modify: `src/volte_mutation_fuzzer/mutator/core.py`
  Resolve profile-aware effective strategies, reject ambiguous targeted profile mutations in v1, and bias IMS-specific selection to realistic IMS headers.
- Modify: `src/volte_mutation_fuzzer/mutator/cli.py`
  Expose `--profile` on mutate commands and surface resolved profile/strategy in JSON output.
- Modify: `src/volte_mutation_fuzzer/campaign/core.py`
  Generate cases across the new profile axis and persist resolved profile/strategy in results and reproduction commands.
- Modify: `src/volte_mutation_fuzzer/campaign/cli.py`
  Expose `--profile` on campaign runs, preserve backward-compatible defaults, and include `profile` in report/replay payloads.
- Modify: `src/volte_mutation_fuzzer/campaign/dashboard.py`
  Show `profile` in live progress output.
- Modify: `src/volte_mutation_fuzzer/campaign/report.py`
  Group and render results by `profile/layer/strategy` instead of `layer/strategy` only.
- Modify: `src/volte_mutation_fuzzer/campaign/evidence.py`
  Persist `profile` in `summary.json` for interesting cases.
- Modify: `tests/mutator/test_contracts.py`
  Lock in new mutator contract fields and normalization.
- Modify: `tests/campaign/test_contracts.py`
  Lock in new campaign contract fields and defaults.
- Modify: `tests/mutator/test_cli.py`
  Lock in `--profile` help and resolved strategy behavior.
- Modify: `tests/campaign/test_cli.py`
  Lock in campaign CLI parsing and report/replay profile plumbing.
- Modify: `tests/mutator/test_core.py`
  Lock in deterministic profile-default resolution and IMS-specific target narrowing.
- Modify: `tests/campaign/test_core.py`
  Lock in case generation across profiles and profile-aware result persistence.
- Modify: `docs/USAGE.md`
  Document `--profile` and realistic examples.
- Modify: `docs/ARCHITECTURE.md`
  Update the scheduling/execution model to `method × profile × layer × strategy`.
- Modify: `docs/Fuzzer.md`
  Update the reproducibility contract to include `profile`.

---

### Task 1: Create The Shared Profile Catalog And Contract Fields

**Files:**
- Create: `src/volte_mutation_fuzzer/mutator/profile_catalog.py`
- Modify: `src/volte_mutation_fuzzer/mutator/contracts.py`
- Modify: `src/volte_mutation_fuzzer/campaign/contracts.py`
- Test: `tests/mutator/test_contracts.py`
- Test: `tests/campaign/test_contracts.py`

- [ ] **Step 1: Write the failing contract tests**

```python
class MutationConfigTests(MutatorContractTestCase):
    def test_defaults_include_legacy_profile(self) -> None:
        config = MutationConfig()
        payload = config.model_dump(mode="json")

        self.assertEqual(config.profile, "legacy")
        self.assertIn("profile", payload)

    def test_rejects_blank_or_unknown_profile(self) -> None:
        with self.assertRaises(ValueError):
            MutationConfig(profile="   ")

        with self.assertRaises(ValueError):
            MutationConfig(profile="not-a-real-profile")


class MutatedCaseTests(MutatorContractTestCase):
    def test_model_layer_serializes_profile(self) -> None:
        original_packet = self.build_request()
        mutated_packet = original_packet.model_copy(
            update={"call_id": REALISTIC_MUTATED_CALL_ID}
        )

        case = MutatedCase(
            original_packet=original_packet,
            mutated_packet=mutated_packet,
            profile="delivery_preserving",
            strategy="default",
            final_layer="model",
        )

        payload = case.model_dump(mode="json", by_alias=True, exclude_none=True)
        self.assertEqual(payload["profile"], "delivery_preserving")
```

```python
class CampaignConfigTests(unittest.TestCase):
    def test_defaults_include_legacy_profile_axis(self) -> None:
        cfg = CampaignConfig(target_host="127.0.0.1")
        self.assertEqual(cfg.profiles, ("legacy",))

    def test_profiles_normalize_and_validate(self) -> None:
        cfg = CampaignConfig(target_host="127.0.0.1", profiles=(" parser_breaker ",))
        self.assertEqual(cfg.profiles, ("parser_breaker",))

        with self.assertRaises(ValidationError):
            CampaignConfig(target_host="127.0.0.1", profiles=("unknown",))


class CaseResultTests(unittest.TestCase):
    def test_profile_is_serialized(self) -> None:
        result = CaseResult(
            case_id=0,
            seed=0,
            method="OPTIONS",
            profile="parser_breaker",
            layer="byte",
            strategy="tail_chop_1",
            verdict="normal",
            reason="ok",
            elapsed_ms=50.0,
            reproduction_cmd="uv run fuzzer ...",
            timestamp=1.0,
        )
        self.assertEqual(result.model_dump(mode="json")["profile"], "parser_breaker")
```

- [ ] **Step 2: Run the focused contract tests and verify they fail**

Run: `uv run pytest tests/mutator/test_contracts.py tests/campaign/test_contracts.py -k "profile" -q`

Expected:
- FAIL because `MutationConfig`, `MutatedCase`, `CampaignConfig`, and `CaseResult` do not define `profile`/`profiles`
- FAIL because no validation exists for supported profile names

- [ ] **Step 3: Implement the shared profile catalog and contract plumbing**

```python
# src/volte_mutation_fuzzer/mutator/profile_catalog.py
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
        "wire": frozenset({"default", "identity", "safe", "header_whitespace_noise"}),
        "byte": frozenset({"default", "identity", "safe", "header_targeted"}),
    },
    "ims_specific": {
        "model": frozenset(),
        "wire": frozenset({"default", "identity", "safe", "alias_port_desync"}),
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
        raise ValueError(
            f"profile '{normalized_profile}' does not support {layer}/{strategy}"
        )


def resolve_effective_strategy(
    *,
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
```

```python
# src/volte_mutation_fuzzer/mutator/contracts.py
from volte_mutation_fuzzer.mutator.profile_catalog import normalize_profile_name


class MutationConfig(BaseModel):
    seed: int | None = Field(default=None, ge=0)
    profile: str = Field(default="legacy", min_length=1)
    strategy: str = Field(default="default", min_length=1)
    layer: Literal["model", "wire", "byte", "auto"] = "auto"
    max_operations: int = Field(default=1, ge=1)
    preserve_valid_model: bool = True

    @field_validator("profile", mode="before")
    @classmethod
    def _normalize_profile(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        return normalize_profile_name(value)


class MutatedCase(BaseModel):
    original_packet: PacketModel
    mutated_packet: PacketModel | None = None
    wire_text: str | None = None
    packet_bytes: bytes | None = None
    records: tuple[MutationRecord, ...] = Field(default_factory=tuple)
    seed: int | None = Field(default=None, ge=0)
    profile: str = Field(default="legacy", min_length=1)
    strategy: str = Field(default="default", min_length=1)
    final_layer: Literal["model", "wire", "byte"]


class MutatedWireCase(BaseModel):
    wire_text: str | None = None
    packet_bytes: bytes | None = None
    records: tuple[MutationRecord, ...] = Field(default_factory=tuple)
    seed: int | None = Field(default=None, ge=0)
    profile: str = Field(default="legacy", min_length=1)
    strategy: str = Field(default="default", min_length=1)
    final_layer: Literal["wire", "byte"]
```

```python
# src/volte_mutation_fuzzer/campaign/contracts.py
from volte_mutation_fuzzer.mutator.profile_catalog import normalize_profile_name


class CampaignConfig(BaseModel):
    target_host: str | None = Field(default=None, min_length=1)
    target_port: int = Field(default=5060, ge=1, le=65535)
    transport: str = "UDP"
    mode: str = "softphone"
    methods: tuple[str, ...] = Field(default_factory=tuple)
    response_codes: tuple[int, ...] = Field(default_factory=tuple)
    with_dialog: bool = False
    profiles: tuple[str, ...] = ("legacy",)
    strategies: tuple[str, ...] = ("default", "state_breaker")
    layers: tuple[str, ...] = ("model", "wire", "byte")

    @field_validator("profiles", mode="before")
    @classmethod
    def _normalize_profiles(cls, value: Any) -> Any:
        if value is None:
            return ("legacy",)
        if isinstance(value, str):
            value = value.split(",")
        normalized: list[str] = []
        for item in value:
            stripped = str(item).strip()
            if not stripped:
                continue
            normalized_name = normalize_profile_name(stripped)
            if normalized_name not in normalized:
                normalized.append(normalized_name)
        return tuple(normalized or ("legacy",))


class CaseSpec(BaseModel):
    case_id: int = Field(ge=0)
    seed: int = Field(ge=0)
    method: str = Field(min_length=1)
    profile: str = Field(default="legacy", min_length=1)
    layer: str = Field(min_length=1)
    strategy: str = Field(min_length=1)
    response_code: int | None = Field(default=None, ge=100, le=699)
    related_method: str | None = None


class CaseResult(BaseModel):
    case_id: int = Field(ge=0)
    seed: int = Field(ge=0)
    method: str
    profile: str = Field(default="legacy", min_length=1)
    layer: str
    strategy: str
    mutation_ops: tuple[str, ...] = Field(default_factory=tuple)
    verdict: str
    reason: str
    response_code: int | None = None
    elapsed_ms: float
    process_alive: bool | None = None
    raw_response: str | None = None
    reproduction_cmd: str
    error: str | None = None
    details: dict[str, object] = Field(default_factory=dict)
    timestamp: float
    fuzz_response_code: int | None = None
    fuzz_related_method: str | None = None
    pcap_path: str | None = None
    case_wall_ms: float | None = None
```

- [ ] **Step 4: Re-run the contract tests and verify they pass**

Run: `uv run pytest tests/mutator/test_contracts.py tests/campaign/test_contracts.py -q`

Expected:
- PASS

- [ ] **Step 5: Commit**

```bash
git add src/volte_mutation_fuzzer/mutator/profile_catalog.py \
  src/volte_mutation_fuzzer/mutator/contracts.py \
  src/volte_mutation_fuzzer/campaign/contracts.py \
  tests/mutator/test_contracts.py \
  tests/campaign/test_contracts.py
git commit -m "feat: add mutation profile contracts and catalog"
```

---

### Task 2: Expose Profiles In CLI And Case Scheduling

**Files:**
- Modify: `src/volte_mutation_fuzzer/mutator/cli.py`
- Modify: `src/volte_mutation_fuzzer/campaign/cli.py`
- Modify: `src/volte_mutation_fuzzer/campaign/core.py`
- Test: `tests/mutator/test_cli.py`
- Test: `tests/campaign/test_cli.py`
- Test: `tests/campaign/test_core.py`

- [ ] **Step 1: Write the failing CLI and case-generation tests**

```python
class SIPMutatorCLITests(unittest.TestCase):
    def test_help_exposes_profile_option(self) -> None:
        for command in ("packet", "request", "response"):
            with self.subTest(command=command):
                result = self.runner.invoke(self.app, [command, "--help"])
                self.assertEqual(result.exit_code, 0, msg=result.output)
                self.assertIn("--profile", result.output)

    def test_packet_command_accepts_profile_and_reports_it(self) -> None:
        baseline_json = self.generate_request_baseline_json("OPTIONS")

        result = self.runner.invoke(
            self.app,
            [
                "packet",
                "--layer",
                "byte",
                "--profile",
                "parser_breaker",
                "--strategy",
                "default",
                "--seed",
                "17",
            ],
            input=baseline_json,
        )

        payload = self.parse_output(result)
        self.assertEqual(payload["profile"], "parser_breaker")
        self.assertIn(payload["strategy"], {"tail_chop_1", "tail_garbage"})
```

```python
class CampaignRunCLITests(unittest.TestCase):
    def test_run_command_profile_without_strategy_uses_requested_default(self) -> None:
        captured: dict[str, CampaignConfig] = {}

        def _build_executor(config: CampaignConfig) -> Mock:
            captured["config"] = config
            executor = Mock()
            executor.campaign_dir = Path("results") / "test_run"
            executor.run.return_value = CampaignResult(
                campaign_id="cli-profile-default",
                started_at="2026-01-01T00:00:00Z",
                completed_at="2026-01-01T00:00:01Z",
                status="completed",
                config=config,
                summary=CampaignSummary(total=1),
            )
            return executor

        with patch(
            "volte_mutation_fuzzer.campaign.cli.CampaignExecutor",
            side_effect=_build_executor,
        ):
            result = self.runner.invoke(
                app,
                [
                    "campaign",
                    "run",
                    "--target-host",
                    "127.0.0.1",
                    "--methods",
                    "OPTIONS",
                    "--layer",
                    "wire,byte",
                    "--profile",
                    "parser_breaker",
                    "--max-cases",
                    "1",
                    "--timeout",
                    "0.1",
                    "--cooldown",
                    "0",
                    "--no-process-check",
                    "--output",
                    "test_run",
                ],
            )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(captured["config"].profiles, ("parser_breaker",))
        self.assertEqual(captured["config"].strategies, ("default",))
```

```python
class CaseGeneratorTests(unittest.TestCase):
    def test_case_generator_tracks_profiles(self) -> None:
        cfg = self._config(
            methods=("OPTIONS",),
            profiles=("parser_breaker",),
            layers=("wire", "byte"),
            strategies=("default",),
            max_cases=8,
        )

        cases = list(CaseGenerator(cfg).generate())
        self.assertTrue(cases)
        self.assertTrue(all(case.profile == "parser_breaker" for case in cases))

    def test_case_generator_skips_profile_layer_strategy_mismatches(self) -> None:
        cfg = self._config(
            methods=("OPTIONS",),
            profiles=("parser_breaker",),
            layers=("model", "wire"),
            strategies=("default", "state_breaker"),
            max_cases=32,
        )

        cases = list(CaseGenerator(cfg).generate())
        self.assertTrue(all(case.layer != "model" for case in cases))
        self.assertTrue(all(case.strategy == "default" for case in cases))
```

- [ ] **Step 2: Run the focused CLI and scheduler tests and verify they fail**

Run: `uv run pytest tests/mutator/test_cli.py tests/campaign/test_cli.py tests/campaign/test_core.py -k "profile" -q`

Expected:
- FAIL because mutator commands do not expose `--profile`
- FAIL because campaign CLI does not parse/store profile selections
- FAIL because `CaseSpec` does not carry `profile` and `CaseGenerator` does not iterate it

- [ ] **Step 3: Add `--profile` to both CLIs and make `CaseGenerator` iterate the new axis**

```python
# src/volte_mutation_fuzzer/mutator/cli.py
from volte_mutation_fuzzer.mutator.profile_catalog import SUPPORTED_MUTATION_PROFILES

_PROFILE_HELP = (
    "Mutation profile name. Choices: "
    + ", ".join(SUPPORTED_MUTATION_PROFILES)
    + ". 'legacy' preserves existing behavior."
)


def _build_config(
    strategy: str,
    layer: str,
    seed: int | None,
    profile: str,
) -> MutationConfig:
    return MutationConfig(
        strategy=strategy,
        layer=layer,
        seed=seed,
        profile=profile,
    )


@app.command("packet")
def packet_command(
    profile: Annotated[
        str, typer.Option("--profile", help=_PROFILE_HELP)
    ] = "legacy",
    strategy: Annotated[
        str, typer.Option("--strategy", help=_STRATEGY_HELP)
    ] = "default",
    layer: Annotated[
        str, typer.Option("--layer", help="Mutation layer: model, wire, byte, or auto.")
    ] = "auto",
    seed: Annotated[
        int | None, typer.Option("--seed", help="Random seed for reproducibility.")
    ] = None,
    target: Annotated[
        str | None, typer.Option("--target", help="Explicit mutation target path.")
    ] = None,
) -> None:
    raw = sys.stdin.read()
    packet = _parse_packet_json(raw)
    config = _build_config(strategy, layer, seed, profile)
    mutation_target = _build_target(target, layer)
    mutator = SIPMutator()
    case = _execute_mutation(mutator, packet, config, mutation_target)
    typer.echo(_render_result(case))
```

```python
# src/volte_mutation_fuzzer/campaign/cli.py
def _parse_csv(raw: str | None) -> tuple[str, ...] | None:
    if raw is None:
        return None
    return tuple(item.strip() for item in raw.split(",") if item.strip())


@app.command("run")
def run_command(
    profile: Annotated[
        str | None,
        typer.Option(
            "--profile",
            help="Mutation profile (legacy, delivery_preserving, ims_specific, parser_breaker). Comma-separated for multiple.",
        ),
    ] = None,
    strategy: Annotated[
        str | None,
        typer.Option(
            "--strategy",
            help="Mutation strategy. Comma-separated for multiple. If omitted with a non-legacy profile, 'default' is resolved inside that profile.",
        ),
    ] = None,
    layer: Annotated[
        str | None,
        typer.Option(
            "--layer",
            help="Mutation layer (model/wire/byte). Comma-separated for multiple.",
        ),
    ] = None,
) -> None:
    profiles = _parse_csv(profile) or ("legacy",)
    layers = _parse_csv(layer) or ("model", "wire", "byte")
    strategies = (
        _parse_csv(strategy)
        if strategy is not None
        else (("default", "state_breaker") if profiles == ("legacy",) else ("default",))
    )

    config = CampaignConfig(
        target_host=target_host,
        target_port=target_port,
        transport=transport,
        mode=mode,
        methods=_parse_methods(methods) or (),
        response_codes=_parse_response_codes(response_codes) or (),
        with_dialog=bool(with_dialog) if with_dialog is not None else False,
        profiles=profiles,
        strategies=strategies or ("default",),
        layers=layers,
        max_cases=max_cases,
        timeout_seconds=timeout,
        cooldown_seconds=cooldown,
        seed_start=seed_start,
        output_name=output,
        crash_analysis=crash_analysis,
        process_name=process_name,
        check_process=None if no_process_check is None else not no_process_check,
        log_path=log_path,
        adb_enabled=adb,
        adb_serial=adb_serial,
        ios_enabled=ios,
        ios_udid=ios_udid,
        ios_run_diagnostics=ios_diagnostics,
        pcap_enabled=pcap,
        pcap_interface=pcap_interface,
        target_msisdn=target_msisdn,
        impi=impi,
        mt=mt,
        mt_invite_template=mt_invite_template,
        ipsec_mode=ipsec_mode_value,
        preserve_via=preserve_via,
        preserve_contact=preserve_contact,
        mo_contact_host=mo_contact_host,
        mo_contact_port_pc=mo_contact_port_pc,
        mo_contact_port_ps=mo_contact_port_ps,
        from_msisdn=from_msisdn,
        mt_local_port=mt_local_port,
        resume=resume,
        circuit_breaker_threshold=circuit_breaker,
        adb_buffers=adb_buffers_value,
        ios_filter_processes=ios_filter_processes_value,
    )
```

```python
# src/volte_mutation_fuzzer/campaign/core.py
from volte_mutation_fuzzer.mutator.profile_catalog import profile_supports_strategy


class CaseGenerator:
    def generate(self, skip_before: int = -1) -> Iterator[CaseSpec]:
        config = self._config
        seen: set[tuple[str, int | None, str | None, str, str, str]] = set()
        combos: list[tuple[str, int | None, str | None, str, str, str]] = []

        template_active = config.mt_invite_template is not None
        effective_layers = (
            tuple(lyr for lyr in config.layers if lyr != "model")
            if template_active
            else config.layers
        )

        for method in config.methods:
            for profile in config.profiles:
                for layer in effective_layers:
                    for strategy in config.strategies:
                        if not profile_supports_strategy(profile, layer, strategy):
                            continue
                        key = (method, None, None, profile, layer, strategy)
                        if key not in seen:
                            seen.add(key)
                            combos.append(key)

        for response_code in config.response_codes:
            response_definition = SIP_CATALOG.get_response(response_code)
            related_methods = tuple(
                method.value for method in response_definition.related_methods
            ) or ("INVITE",)
            for related_method in related_methods:
                for profile in config.profiles:
                    for layer in config.layers:
                        for strategy in config.strategies:
                            if not profile_supports_strategy(profile, layer, strategy):
                                continue
                            key = (
                                related_method,
                                response_code,
                                related_method,
                                profile,
                                layer,
                                strategy,
                            )
                            if key not in seen:
                                seen.add(key)
                                combos.append(key)

        recurring_combos = [
            combo
            for combo in combos
            if not (
                combo[0] == "INVITE"
                and combo[1] is None
                and combo[4] == "wire"
                and combo[5] == "identity"
            )
        ]

        unlimited = config.max_cases == 0
        case_id = 0
        round_num = 0
        while True:
            round_combos = combos if round_num == 0 else recurring_combos
            for method, response_code, related_method, profile, layer, strategy in round_combos:
                if not unlimited and case_id >= config.max_cases:
                    return
                if case_id <= skip_before:
                    case_id += 1
                    continue
                yield CaseSpec(
                    case_id=case_id,
                    seed=config.seed_start + case_id,
                    method=method,
                    profile=profile,
                    layer=layer,
                    strategy=strategy,
                    response_code=response_code,
                    related_method=related_method,
                )
                case_id += 1
            round_num += 1
            if not recurring_combos:
                return
```

- [ ] **Step 4: Re-run the CLI and scheduler tests and verify they pass**

Run: `uv run pytest tests/mutator/test_cli.py tests/campaign/test_cli.py tests/campaign/test_core.py -k "profile" -q`

Expected:
- PASS

- [ ] **Step 5: Commit**

```bash
git add src/volte_mutation_fuzzer/mutator/cli.py \
  src/volte_mutation_fuzzer/campaign/cli.py \
  src/volte_mutation_fuzzer/campaign/core.py \
  tests/mutator/test_cli.py \
  tests/campaign/test_cli.py \
  tests/campaign/test_core.py
git commit -m "feat: expose mutation profiles in cli and case scheduling"
```

---

### Task 3: Resolve Effective Strategies Inside The Chosen Profile

**Files:**
- Modify: `src/volte_mutation_fuzzer/mutator/core.py`
- Test: `tests/mutator/test_core.py`

- [ ] **Step 1: Write the failing profile-resolution tests**

```python
class SIPMutatorProfileResolutionTests(SIPMutatorTestCase):
    def test_parser_breaker_default_strategy_resolves_to_wire_breaker(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()

        case = mutator.mutate(
            packet,
            MutationConfig(
                seed=101,
                layer="wire",
                profile="parser_breaker",
                strategy="default",
            ),
        )

        self.assertEqual(case.profile, "parser_breaker")
        self.assertIn(
            case.strategy,
            {"final_crlf_loss", "duplicate_content_length_conflict"},
        )
        self.assertEqual(case.records[0].operator, case.strategy)

    def test_same_seed_and_profile_resolve_same_concrete_byte_strategy(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()
        config = MutationConfig(
            seed=202,
            layer="byte",
            profile="parser_breaker",
            strategy="default",
        )

        first = mutator.mutate(packet, config)
        second = mutator.mutate(packet, config)

        self.assertEqual(first.profile, "parser_breaker")
        self.assertEqual(first.strategy, second.strategy)
        self.assertEqual(first.packet_bytes, second.packet_bytes)

    def test_ims_specific_safe_prefers_ims_headers(self) -> None:
        mutator = SIPMutator()
        message = EditableSIPMessage(
            start_line=EditableStartLine(text="INVITE sip:111111@10.20.20.8 SIP/2.0"),
            headers=(
                EditableHeader(
                    name="Via",
                    value="SIP/2.0/UDP 172.22.0.21:5060;branch=z9hG4bK-1",
                ),
                EditableHeader(
                    name="P-Asserted-Identity",
                    value="<sip:222222@ims.mnc001.mcc001.3gppnetwork.org>",
                ),
                EditableHeader(
                    name="Record-Route",
                    value="<sip:pcscf.ims.mnc001.mcc001.3gppnetwork.org;lr>",
                ),
            ),
        )

        case = mutator.mutate_editable(
            message,
            MutationConfig(
                seed=7,
                layer="wire",
                profile="ims_specific",
                strategy="safe",
            ),
        )

        self.assertEqual(case.profile, "ims_specific")
        self.assertRegex(case.records[0].target.path, r"^header(:|\\[)")
        self.assertNotIn("Via", case.records[0].target.path)

    def test_profile_scoped_targeted_mutation_is_rejected_in_v1(self) -> None:
        mutator = SIPMutator()
        packet = self.build_request()

        with self.assertRaisesRegex(
            ValueError,
            "profile-scoped mutation does not support explicit targets",
        ):
            mutator.mutate_field(
                packet,
                MutationTarget(layer="model", path="call_id"),
                MutationConfig(
                    seed=1,
                    layer="model",
                    profile="delivery_preserving",
                    strategy="default",
                ),
            )
```

- [ ] **Step 2: Run the focused mutator-core tests and verify they fail**

Run: `uv run pytest tests/mutator/test_core.py -k "parser_breaker or ims_specific or profile_scoped" -q`

Expected:
- FAIL because `SIPMutator` ignores `profile`
- FAIL because `default` is never resolved to profile-specific concrete strategies
- FAIL because IMS-specific target narrowing does not exist

- [ ] **Step 3: Make the mutator resolve `default` inside the chosen profile and bias IMS-specific target selection**

```python
# src/volte_mutation_fuzzer/mutator/core.py
from volte_mutation_fuzzer.mutator.profile_catalog import (
    IMS_PROFILE_HEADER_NAMES,
    resolve_effective_strategy,
    validate_profile_strategy,
)


def mutate_editable(
    self,
    message: EditableSIPMessage,
    config: MutationConfig,
) -> MutatedWireCase:
    effective_layer = config.layer if config.layer != "auto" else "wire"
    effective_strategy = resolve_effective_strategy(
        profile=config.profile,
        layer=effective_layer,
        strategy=config.strategy,
        seed=config.seed,
    )

    if effective_strategy == "identity":
        if effective_layer == "wire":
            return MutatedWireCase(
                wire_text=self._finalize_wire_message(message),
                records=(),
                seed=config.seed,
                profile=config.profile,
                strategy="identity",
                final_layer="wire",
            )
        editable_bytes = self._to_packet_bytes(message)
        return MutatedWireCase(
            packet_bytes=self._finalize_packet_bytes(editable_bytes),
            records=(),
            seed=config.seed,
            profile=config.profile,
            strategy="identity",
            final_layer="byte",
        )
```

```python
def _mutate_packet(
    self,
    *,
    packet: PacketModel,
    definition: PacketDefinition,
    config: MutationConfig,
    context: DialogContext | None,
    target: MutationTarget | None,
) -> MutatedCase:
    effective_layer = config.layer if target is None else target.layer
    if effective_layer == "auto":
        effective_layer = "model"

    if target is not None and config.profile != "legacy":
        raise ValueError("profile-scoped mutation does not support explicit targets")

    effective_strategy = resolve_effective_strategy(
        profile=config.profile,
        layer=effective_layer,
        strategy=config.strategy,
        seed=config.seed,
    )
    validate_profile_strategy(config.profile, effective_layer, effective_strategy)

    if effective_layer == "model":
        return self._mutate_model(
            packet=packet,
            definition=definition,
            config=config,
            context=context,
            target=target if target is None or target.layer == "model" else None,
            effective_strategy=effective_strategy,
        )

    if effective_layer == "wire":
        return self._mutate_wire(
            packet=packet,
            definition=definition,
            editable_message=self._to_editable_message(packet),
            config=config,
            context=context,
            target=target if target is None or target.layer == "wire" else None,
            effective_strategy=effective_strategy,
        )

    if effective_layer == "byte":
        return self._mutate_bytes(
            packet=packet,
            editable_bytes=self._to_packet_bytes(self._to_editable_message(packet)),
            config=config,
            context=context,
            target=target if target is None or target.layer == "byte" else None,
            effective_strategy=effective_strategy,
        )

    raise ValueError(f"unsupported mutation layer: {effective_layer}")
```

```python
def _filter_wire_targets_for_profile(
    self,
    targets: tuple[MutationTarget, ...],
    editable_message: EditableSIPMessage,
    profile: str,
) -> tuple[MutationTarget, ...]:
    if profile != "ims_specific":
        return targets

    filtered: list[MutationTarget] = []
    for target in targets:
        if target.path.startswith("header:"):
            header_name = target.path.split(":", 1)[1]
            if self._header_name_key(header_name) in IMS_PROFILE_HEADER_NAMES:
                filtered.append(target)
            continue

        if target.path.startswith("header["):
            header_index = int(target.path[7:-1])
            if header_index < len(editable_message.headers):
                header_name = editable_message.headers[header_index].name
                if self._header_name_key(header_name) in IMS_PROFILE_HEADER_NAMES:
                    filtered.append(target)

    return tuple(filtered) or targets


def _profile_header_value_ranges(
    self,
    data: bytes,
    profile: str,
) -> list[tuple[str, int, int]]:
    ranges = self._collect_header_byte_ranges(data)
    if profile != "ims_specific":
        return ranges
    filtered = [
        item
        for item in ranges
        if self._header_name_key(item[0]) in IMS_PROFILE_HEADER_NAMES
    ]
    return filtered or ranges
```

```python
def _mutate_wire(
    self,
    *,
    packet: PacketModel,
    definition: PacketDefinition,
    editable_message: EditableSIPMessage,
    config: MutationConfig,
    context: DialogContext | None,
    target: MutationTarget | None,
    effective_strategy: str,
) -> MutatedCase:
    del definition
    self._snapshot_context(context)
    rng = self._rng_from_seed(config.seed)
    current_message = editable_message
    records: list[MutationRecord] = []

    deterministic_wire_mutation = None
    if target is None:
        deterministic_wire_mutation = self._apply_deterministic_wire_strategy(
            current_message,
            effective_strategy,
            rng,
        )

    if deterministic_wire_mutation is not None:
        current_message, record = deterministic_wire_mutation
        records.append(record)
    elif target is None:
        used_paths: set[str] = set()
        is_safe = effective_strategy == "safe"
        for _ in range(config.max_operations):
            available_targets = tuple(
                candidate
                for candidate in self._filter_wire_targets_for_profile(
                    self._collect_wire_targets(current_message, self._resolve_packet_definition(packet)),
                    current_message,
                    config.profile,
                )
                if candidate.path not in used_paths
                and (not is_safe or not self._is_wire_target_protected(candidate))
            )
            if not available_targets:
                break
            selected_target = available_targets[rng.randrange(len(available_targets))]
            operator = self._resolve_wire_operator(selected_target, current_message, rng)
            current_message, record = self._apply_wire_operator(
                current_message,
                selected_target,
                operator,
                rng,
            )
            used_paths.add(selected_target.path)
            records.append(record)

    return MutatedCase(
        original_packet=packet,
        wire_text=self._finalize_wire_message(current_message),
        records=tuple(records),
        seed=config.seed,
        profile=config.profile,
        strategy=effective_strategy,
        final_layer="wire",
    )
```

```python
def _mutate_bytes(
    self,
    *,
    packet: PacketModel,
    editable_bytes: EditablePacketBytes,
    config: MutationConfig,
    context: DialogContext | None,
    target: MutationTarget | None,
    effective_strategy: str,
) -> MutatedCase:
    self._snapshot_context(context)
    rng = self._rng_from_seed(config.seed)
    current_bytes = editable_bytes
    records: list[MutationRecord] = []

    if target is None and effective_strategy == "header_targeted":
        header_ranges = self._profile_header_value_ranges(
            current_bytes.data,
            config.profile,
        )
        if header_ranges:
            _header_name, start, end = header_ranges[rng.randrange(len(header_ranges))]
            if start < end:
                byte_idx = rng.randrange(start, end)
                byte_target = MutationTarget(layer="byte", path=f"byte[{byte_idx}]")
                current_bytes, record = self._apply_byte_operator(
                    current_bytes,
                    byte_target,
                    "flip_byte",
                    rng,
                )
                records.append(record)

    if not records and target is None:
        deterministic_byte_mutation = self._apply_deterministic_byte_strategy(
            current_bytes,
            effective_strategy,
            rng,
        )
        if deterministic_byte_mutation is not None:
            current_bytes, record = deterministic_byte_mutation
            records.append(record)

    return MutatedCase(
        original_packet=packet,
        packet_bytes=self._finalize_packet_bytes(current_bytes),
        records=tuple(records),
        seed=config.seed,
        profile=config.profile,
        strategy=effective_strategy,
        final_layer="byte",
    )
```

- [ ] **Step 4: Re-run the focused mutator-core tests and verify they pass**

Run: `uv run pytest tests/mutator/test_core.py -k "parser_breaker or ims_specific or profile_scoped" -q`

Expected:
- PASS

- [ ] **Step 5: Commit**

```bash
git add src/volte_mutation_fuzzer/mutator/core.py tests/mutator/test_core.py
git commit -m "feat: resolve profile-driven mutation strategies"
```

---

### Task 4: Persist Profile And Effective Strategy Through Campaign Results

**Files:**
- Modify: `src/volte_mutation_fuzzer/campaign/core.py`
- Modify: `src/volte_mutation_fuzzer/campaign/cli.py`
- Modify: `src/volte_mutation_fuzzer/campaign/dashboard.py`
- Modify: `src/volte_mutation_fuzzer/campaign/report.py`
- Modify: `src/volte_mutation_fuzzer/campaign/evidence.py`
- Test: `tests/campaign/test_core.py`
- Test: `tests/campaign/test_cli.py`

- [ ] **Step 1: Write the failing campaign result and replay/report tests**

```python
class CampaignExecutorProfileTests(unittest.TestCase):
    def test_execute_case_records_profile_and_effective_strategy(self) -> None:
        cfg = CampaignConfig(
            target_host="127.0.0.1",
            methods=("OPTIONS",),
            profiles=("parser_breaker",),
            layers=("byte",),
            strategies=("default",),
            max_cases=1,
            timeout_seconds=0.1,
            cooldown_seconds=0.0,
            check_process=False,
        )
        executor = CampaignExecutor(cfg)
        spec = CaseSpec(
            case_id=0,
            seed=0,
            method="OPTIONS",
            profile="parser_breaker",
            layer="byte",
            strategy="default",
        )

        result = executor._execute_case(spec)

        self.assertEqual(result.profile, "parser_breaker")
        self.assertIn(result.strategy, {"tail_chop_1", "tail_garbage"})
        self.assertIn("--profile parser_breaker", result.reproduction_cmd)
```

```python
class CampaignReportCLITests(unittest.TestCase):
    def test_report_includes_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            cases = [
                _make_case_result(0, "normal").model_copy(
                    update={"profile": "parser_breaker", "strategy": "tail_chop_1"}
                )
            ]
            _write_sample_jsonl(path, cases)

            result = self.runner.invoke(app, ["campaign", "report", str(path)])
            self.assertEqual(result.exit_code, 0, msg=result.output)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["cases"][0]["profile"], "parser_breaker")

    def test_replay_uses_case_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "campaign.jsonl"
            _write_sample_jsonl(
                path,
                [
                    _make_case_result(0).model_copy(
                        update={"profile": "ims_specific", "strategy": "alias_port_desync"}
                    )
                ],
            )

            with patch("volte_mutation_fuzzer.campaign.cli.CampaignExecutor") as executor_cls:
                executor = executor_cls.return_value
                executor._execute_case.return_value = _make_case_result(0).model_copy(
                    update={"profile": "ims_specific", "strategy": "alias_port_desync"}
                )

                result = self.runner.invoke(
                    app,
                    ["campaign", "replay", str(path), "--case-id", "0"],
                )

            self.assertEqual(result.exit_code, 0, msg=result.output)
            replay_spec = executor._execute_case.call_args.args[0]
            self.assertEqual(replay_spec.profile, "ims_specific")
```

- [ ] **Step 2: Run the focused campaign tests and verify they fail**

Run: `uv run pytest tests/campaign/test_core.py tests/campaign/test_cli.py -k "profile" -q`

Expected:
- FAIL because `CaseResult` creation paths still copy `spec.strategy` only
- FAIL because reproduction commands do not include `--profile`
- FAIL because report/replay payloads do not serialize profile data

- [ ] **Step 3: Centralize case-result construction and propagate profile through replay, evidence, dashboard, and reports**

```python
# src/volte_mutation_fuzzer/campaign/core.py
def _build_case_result(
    self,
    spec: CaseSpec,
    *,
    profile: str | None = None,
    strategy: str | None = None,
    mutation_ops: tuple[str, ...] = (),
    verdict: str,
    reason: str,
    elapsed_ms: float,
    timestamp: float,
    response_code: int | None = None,
    process_alive: bool | None = None,
    raw_response: str | None = None,
    error: str | None = None,
    details: dict[str, object] | None = None,
    pcap_path: str | None = None,
    case_wall_ms: float | None = None,
    fuzz_response_code: int | None = None,
    fuzz_related_method: str | None = None,
) -> CaseResult:
    actual_profile = profile or spec.profile
    actual_strategy = strategy or spec.strategy
    return CaseResult(
        case_id=spec.case_id,
        seed=spec.seed,
        method=spec.method,
        profile=actual_profile,
        layer=spec.layer,
        strategy=actual_strategy,
        mutation_ops=mutation_ops,
        verdict=verdict,
        reason=reason,
        response_code=response_code,
        elapsed_ms=elapsed_ms,
        process_alive=process_alive,
        raw_response=raw_response,
        reproduction_cmd=self._build_reproduction_cmd(
            spec,
            profile=actual_profile,
            strategy=actual_strategy,
        ),
        error=error,
        details=details or {},
        timestamp=timestamp,
        fuzz_response_code=fuzz_response_code,
        fuzz_related_method=fuzz_related_method,
        pcap_path=pcap_path,
        case_wall_ms=case_wall_ms,
    )
```

```python
def _build_reproduction_cmd(
    self,
    spec: CaseSpec,
    *,
    profile: str | None = None,
    strategy: str | None = None,
) -> str:
    cfg = self._config
    actual_profile = profile or spec.profile
    actual_strategy = strategy or spec.strategy
    target_args = self._build_replay_target_args()
    transport_arg = (
        f" --transport {cfg.transport}" if cfg.transport.upper() != "UDP" else ""
    )
    ipsec_arg = f" --ipsec-mode {cfg.ipsec_mode}" if cfg.ipsec_mode else ""

    if spec.response_code is not None:
        context = json.dumps(
            self._synthetic_dialog_context().model_dump(mode="json"),
            ensure_ascii=False,
        )
        related_method = spec.related_method or spec.method
        return (
            f"uv run fuzzer mutate response {spec.response_code} {related_method}"
            f" --context '{context}'"
            f" --profile {actual_profile}"
            f" --strategy {actual_strategy}"
            f" --layer {spec.layer}"
            f" --seed {spec.seed}"
            f" | uv run fuzzer send packet"
            f" --mode {cfg.mode}"
            f"{target_args}"
            f" --target-port {cfg.target_port}"
            f"{transport_arg}"
            f"{ipsec_arg}"
        )

    return (
        f"uv run fuzzer mutate request {spec.method}"
        f" --profile {actual_profile}"
        f" --strategy {actual_strategy}"
        f" --layer {spec.layer}"
        f" --seed {spec.seed}"
        f" | uv run fuzzer send packet"
        f" --mode {cfg.mode}"
        f"{target_args}"
        f" --target-port {cfg.target_port}"
        f"{transport_arg}"
        f"{ipsec_arg}"
    )
```

```python
def _execute_case(self, spec: CaseSpec) -> CaseResult:
    packet = self._build_packet(spec)
    mutation_config = MutationConfig(
        seed=spec.seed,
        profile=spec.profile,
        strategy=spec.strategy,
        layer=cast(Literal["model", "wire", "byte", "auto"], spec.layer),
    )
    mutated = self._mutator.mutate(packet, mutation_config)

    return self._build_case_result(
        spec,
        profile=mutated.profile,
        strategy=mutated.strategy,
        mutation_ops=tuple(record.operator for record in mutated.records),
        verdict=verdict.verdict,
        reason=verdict.reason,
        elapsed_ms=verdict.elapsed_ms,
        response_code=verdict.response_code,
        process_alive=verdict.process_alive,
        raw_response=raw_response,
        details=getattr(verdict, "details", {}) or {},
        timestamp=timestamp,
        pcap_path=pcap_path_saved,
        case_wall_ms=0.0,
    )
```

```python
# src/volte_mutation_fuzzer/campaign/cli.py
report = {
    "campaign_id": header.campaign_id,
    "status": header.status,
    "started_at": header.started_at,
    "completed_at": header.completed_at,
    "config": header.config.model_dump(mode="json"),
    "summary": header.summary.model_dump(mode="json"),
    "cases": [
        {
            "case_id": c.case_id,
            "method": c.method,
            "profile": c.profile,
            "layer": c.layer,
            "strategy": c.strategy,
            "seed": c.seed,
            "verdict": c.verdict,
            "reason": c.reason,
            "response_code": c.response_code,
            "elapsed_ms": c.elapsed_ms,
            "reproduction_cmd": c.reproduction_cmd,
        }
        for c in filtered
    ],
}

spec = CaseSpec(
    case_id=case.case_id,
    seed=case.seed,
    method=case.method,
    profile=case.profile,
    layer=case.layer,
    strategy=case.strategy,
    response_code=case.fuzz_response_code,
    related_method=case.fuzz_related_method,
)
```

```python
# src/volte_mutation_fuzzer/campaign/dashboard.py
return (
    f"  [{spec.case_id + 1}/{total_str}] "
    f"{target_label} {result.profile}:{result.layer}/{result.strategy} seed={spec.seed} "
    f"-> {result.verdict} ({code_str}{result.elapsed_ms:.0f}ms)"
)
```

```python
# src/volte_mutation_fuzzer/campaign/report.py
for c in cases:
    key = f"{c.profile}/{c.layer}/{c.strategy}"
    if key not in groups:
        groups[key] = {v: 0 for v in _VERDICT_ORDER}
    if c.verdict in groups[key]:
        groups[key][c.verdict] += 1
```

```python
# src/volte_mutation_fuzzer/campaign/evidence.py
summary = {
    "case_id": case_result.case_id,
    "seed": case_result.seed,
    "method": case_result.method,
    "profile": case_result.profile,
    "layer": case_result.layer,
    "strategy": case_result.strategy,
    "verdict": case_result.verdict,
    "reason": case_result.reason,
    "response_code": case_result.response_code,
    "elapsed_ms": case_result.elapsed_ms,
    "mutation_ops": list(case_result.mutation_ops),
    "reproduction_cmd": case_result.reproduction_cmd,
    "timestamp": case_result.timestamp,
    "error": case_result.error,
    "details": case_result.details,
}
```

- [ ] **Step 4: Re-run the focused campaign tests and verify they pass**

Run: `uv run pytest tests/campaign/test_core.py tests/campaign/test_cli.py -k "profile" -q`

Expected:
- PASS

- [ ] **Step 5: Commit**

```bash
git add src/volte_mutation_fuzzer/campaign/core.py \
  src/volte_mutation_fuzzer/campaign/cli.py \
  src/volte_mutation_fuzzer/campaign/dashboard.py \
  src/volte_mutation_fuzzer/campaign/report.py \
  src/volte_mutation_fuzzer/campaign/evidence.py \
  tests/campaign/test_core.py \
  tests/campaign/test_cli.py
git commit -m "feat: persist mutation profiles in campaign results"
```

---

### Task 5: Document The New Axis And Verify End-To-End

**Files:**
- Modify: `docs/USAGE.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/Fuzzer.md`

- [ ] **Step 1: Update the usage guide with realistic profile examples**

```md
<!-- docs/USAGE.md -->
## Mutation Profile Axis

- `legacy`: current behavior; preserves today's strategy semantics.
- `delivery_preserving`: prefer mutations that still arrive and get parsed far enough to exercise dialog/state logic.
- `ims_specific`: bias to MT/IMS-sensitive headers such as `Contact`, `Record-Route`, `P-Asserted-Identity`, `P-Access-Network-Info`, and `Session-Expires`.
- `parser_breaker`: target framing, delimiter, truncation, and tail-corruption failures.
```

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --impi 001010000123511 \
  --methods INVITE \
  --profile ims_specific \
  --layer wire,byte \
  --max-cases 100
```

```bash
uv run fuzzer campaign run \
  --target-host 127.0.0.1 \
  --profile parser_breaker \
  --layer wire,byte \
  --max-cases 50
```

- [ ] **Step 2: Update architecture and reproducibility docs**

```md
<!-- docs/ARCHITECTURE.md -->
- **역할**: 테스트 케이스 조합 생성 (`method × profile × layer × strategy`)
- `profile`는 "어떤 실패 패밀리를 노릴지"를 뜻하고, sender `mode`와는 독립이다.
- `strategy=default`는 `legacy`에서는 기존 동작을 유지하고, 다른 profile에서는 seed 기반으로 concrete strategy 하나를 결정한다.
```

```md
<!-- docs/Fuzzer.md -->
- **케이스 명세(Spec)**: 각 케이스는 `method/profile/layer/strategy/seed`의 조합으로 정의된다.
- **재현성**: 같은 baseline, 같은 `profile`, 같은 `layer`, 같은 요청 strategy, 같은 `seed`면 동일한 concrete strategy와 동일한 변조 결과가 나온다.
- **결과 기록**: 결과 JSONL에는 `profile`, resolved `strategy`, `mutation_ops`, `before/after` 정보가 함께 남는다.
```

- [ ] **Step 3: Run the targeted verification suite**

Run: `uv run pytest tests/mutator/test_contracts.py tests/mutator/test_core.py tests/mutator/test_cli.py tests/campaign/test_contracts.py tests/campaign/test_core.py tests/campaign/test_cli.py -q`

Expected:
- PASS

- [ ] **Step 4: Run the full test suite**

Run: `uv run pytest tests -q`

Expected:
- PASS

- [ ] **Step 5: Commit**

```bash
git add docs/USAGE.md docs/ARCHITECTURE.md docs/Fuzzer.md
git commit -m "docs: add mutation profile guidance"
```

---

## Scope Notes

- This plan keeps sender `mode` untouched. `profile` is a fuzzing intent axis, not a transport/runtime mode selector.
- This plan deliberately rejects non-legacy explicit `--target` mutations in v1 so campaign fuzzing semantics stay clear and deterministic. If targeted profile mutations are needed later, add them as a follow-up with explicit behavior for "requested target + profile default resolution".
- `CaseSpec.strategy` remains the requested strategy from scheduling, while `CaseResult.strategy` and mutator output surfaces the resolved effective concrete strategy. That gives replay and reports the exact mutation name that actually ran.
