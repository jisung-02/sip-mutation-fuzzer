# Pixel IMS Mutation Profile Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Pixel-focused SIP mutation profile and concrete strategies for more effective Pixel real-UE MT-INVITE fuzzing.

**Architecture:** Extend the existing profile catalog with `pixel_ims`, add deterministic wire strategies inside `SIPMutator`, and reuse existing default-resolution/applicability hooks so seed-based reproduction stays intact. Keep sender Pixel delivery behavior in `--pixel`; this change only affects mutation policy and target narrowing.

**Tech Stack:** Python 3.12, Pydantic contracts, Typer CLI, pytest/unittest, existing `EditableSIPMessage` and SDP helper APIs.

---

## File Structure

- Modify `src/volte_mutation_fuzzer/mutator/profile_catalog.py`: add the profile, strategies, default pools, and Pixel header allowlist.
- Modify `src/volte_mutation_fuzzer/mutator/core.py`: add strategy validation, applicability checks, deterministic wire strategy handlers, shared Content-Length update helper, and `pixel_ims` byte target narrowing.
- Modify `src/volte_mutation_fuzzer/mutator/cli.py`: include `pixel_ims` in help text examples.
- Modify `tests/mutator/test_core.py`: cover strategy behavior and target narrowing.
- Modify `tests/mutator/test_cli.py` and `tests/campaign/test_cli.py`: cover CLI/profile acceptance where existing profile tests are located.
- Modify `docs/AI_AGENT_GUIDE.md` and `docs/USAGE.md`: document Pixel usage.

## Task 1: Catalog And Strategy Validation

**Files:**
- Modify: `src/volte_mutation_fuzzer/mutator/profile_catalog.py`
- Modify: `src/volte_mutation_fuzzer/mutator/core.py`
- Test: `tests/mutator/test_core.py`

- [ ] **Step 1: Write failing tests**

Add tests that assert:

```python
from volte_mutation_fuzzer.mutator.profile_catalog import (
    PIXEL_IMS_HEADER_NAMES,
    profile_supports_strategy,
    resolve_effective_strategy,
)

def test_pixel_ims_profile_advertises_pixel_wire_strategies(self):
    for strategy in (
        "pixel_sdp_media_negotiation",
        "pixel_session_timer_skew",
        "pixel_p_header_pressure",
    ):
        self.assertTrue(profile_supports_strategy("pixel_ims", "wire", strategy))
    self.assertTrue(profile_supports_strategy("pixel_ims", "byte", "header_targeted"))
    self.assertFalse(profile_supports_strategy("pixel_ims", "model", "default"))
    self.assertIn("p-access-network-info", PIXEL_IMS_HEADER_NAMES)

def test_pixel_ims_default_strategy_is_seed_deterministic(self):
    first = resolve_effective_strategy("pixel_ims", "wire", "default", 7)
    second = resolve_effective_strategy("pixel_ims", "wire", "default", 7)
    self.assertEqual(first, second)
    self.assertIn(
        first,
        {
            "pixel_sdp_media_negotiation",
            "pixel_session_timer_skew",
            "pixel_p_header_pressure",
            "sdp_struct_only",
            "sdp_byte_edit",
            "alias_port_desync",
        },
    )
```

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/mutator/test_core.py -k "pixel_ims_profile or pixel_ims_default" -q`

Expected: FAIL because `pixel_ims` and `PIXEL_IMS_HEADER_NAMES` do not exist.

- [ ] **Step 3: Implement catalog and validation**

Update `MutationProfile`, `SUPPORTED_STRATEGIES_BY_LAYER["wire"]`, `PROFILE_ALLOWED_STRATEGIES`, `PROFILE_DEFAULT_STRATEGY_POOLS`, and `__all__`. Add `PIXEL_IMS_HEADER_NAMES`.

Update `SIPMutator._validate_supported_strategy()` to allow the three new wire strategy names.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/mutator/test_core.py -k "pixel_ims_profile or pixel_ims_default" -q`

Expected: PASS.

## Task 2: Pixel Wire Strategies

**Files:**
- Modify: `src/volte_mutation_fuzzer/mutator/core.py`
- Test: `tests/mutator/test_core.py`

- [ ] **Step 1: Write failing tests**

Add tests using `parse_editable_from_wire()` that cover:

```python
def test_pixel_sdp_media_negotiation_mutates_sdp_and_updates_content_length(self):
    case = SIPMutator().mutate_editable(
        self.build_pixel_invite_message(),
        MutationConfig(profile="pixel_ims", layer="wire", strategy="pixel_sdp_media_negotiation", seed=11),
    )
    self.assertEqual(case.strategy, "pixel_sdp_media_negotiation")
    self.assertEqual(case.records[0].operator, "pixel_sdp_media_negotiation")
    self.assertRegex(case.records[0].target.path, r"^body:sdp:")
    self.assert_content_length_matches_body(case.wire_text)

def test_pixel_session_timer_skew_mutates_timer_headers(self):
    case = SIPMutator().mutate_editable(
        self.build_pixel_invite_message(),
        MutationConfig(profile="pixel_ims", layer="wire", strategy="pixel_session_timer_skew", seed=12),
    )
    self.assertEqual(case.records[0].operator, "pixel_session_timer_skew")
    self.assertRegex(case.records[0].target.path, r"^header")

def test_pixel_p_header_pressure_mutates_p_headers(self):
    case = SIPMutator().mutate_editable(
        self.build_pixel_invite_message(),
        MutationConfig(profile="pixel_ims", layer="wire", strategy="pixel_p_header_pressure", seed=13),
    )
    self.assertEqual(case.records[0].operator, "pixel_p_header_pressure")
    self.assertIn(case.records[0].before[0].casefold(), PIXEL_IMS_HEADER_NAMES)
```

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/mutator/test_core.py -k "pixel_sdp_media or pixel_session_timer or pixel_p_header" -q`

Expected: FAIL because strategy handlers do not exist.

- [ ] **Step 3: Implement strategy handlers**

Add `_apply_pixel_sdp_media_negotiation()`, `_apply_pixel_session_timer_skew()`, and `_apply_pixel_p_header_pressure()` in `SIPMutator`. Wire them into `_apply_deterministic_wire_strategy()`.

Implementation rules:

- `pixel_sdp_media_negotiation` requires SDP content and updates `Content-Length`.
- `pixel_session_timer_skew` mutates existing `Session-Expires`, `Min-SE`, `Supported`, or `Require` headers; raises if no timer-relevant header exists.
- `pixel_p_header_pressure` mutates headers in `PIXEL_IMS_HEADER_NAMES` whose names start with `p-`; raises if absent.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/mutator/test_core.py -k "pixel_sdp_media or pixel_session_timer or pixel_p_header" -q`

Expected: PASS.

## Task 3: Default Applicability And Byte Target Narrowing

**Files:**
- Modify: `src/volte_mutation_fuzzer/mutator/core.py`
- Test: `tests/mutator/test_core.py`

- [ ] **Step 1: Write failing tests**

Add tests that assert:

```python
def test_pixel_ims_default_wire_skips_missing_prerequisites(self):
    message = parse_editable_from_wire(
        "OPTIONS sip:001010000123511@10.20.20.8 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.20.20.1:5060;branch=z9hG4bK-1\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )
    case = SIPMutator().mutate_editable(
        message,
        MutationConfig(profile="pixel_ims", layer="wire", strategy="default", seed=1),
    )
    self.assertEqual(case.profile, "pixel_ims")
    self.assertIn(case.strategy, {"safe", "header_whitespace_noise"})

def test_pixel_ims_byte_targeting_prefers_pixel_headers(self):
    mutator = SIPMutator()
    message = self.build_pixel_invite_message()
    ranges = mutator._collect_profile_header_byte_ranges(
        message.render().encode("utf-8"),
        "pixel_ims",
    )
    self.assertTrue(ranges)
    self.assertTrue(all(name.casefold() in PIXEL_IMS_HEADER_NAMES for name, _, _ in ranges))
```

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/mutator/test_core.py -k "pixel_ims_default_wire or pixel_ims_byte_targeting" -q`

Expected: FAIL because applicability and byte narrowing do not know `pixel_ims`.

- [ ] **Step 3: Implement applicability and byte narrowing**

Update `_is_strategy_applicable()` for the three Pixel strategies. Update `_collect_profile_wire_targets()` and `_collect_profile_header_byte_ranges()` so `pixel_ims` narrows to `PIXEL_IMS_HEADER_NAMES`.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/mutator/test_core.py -k "pixel_ims_default_wire or pixel_ims_byte_targeting" -q`

Expected: PASS.

## Task 4: CLI, Campaign, And Docs

**Files:**
- Modify: `src/volte_mutation_fuzzer/mutator/cli.py`
- Modify: `docs/AI_AGENT_GUIDE.md`
- Modify: `docs/USAGE.md`
- Test: `tests/mutator/test_cli.py`
- Test: `tests/campaign/test_cli.py`

- [ ] **Step 1: Write failing CLI tests**

Add assertions that help text includes `pixel_ims`, and that mutation/campaign commands accept `--profile pixel_ims` without unknown-profile validation errors.

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/mutator/test_cli.py tests/campaign/test_cli.py -k "pixel_ims or profile" -q`

Expected: FAIL until help text/catalog updates are complete.

- [ ] **Step 3: Update help/docs**

Add `pixel_ims` to mutate CLI help text and usage docs. Include this real-UE example:

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --methods INVITE \
  --pixel \
  --profile pixel_ims \
  --layer wire,byte \
  --strategy default \
  --ipsec-mode native \
  --max-cases 50
```

- [ ] **Step 4: Run full relevant verification**

Run:

```bash
uv run pytest \
  tests/mutator/test_core.py \
  tests/mutator/test_cli.py \
  tests/mutator/test_sdp.py \
  tests/campaign/test_cli.py \
  tests/campaign/test_core.py \
  -q
```

Expected: PASS.
