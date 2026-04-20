# SIP Packet Completeness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> Historical note: this plan predates the final shipped completeness semantics. For commit-worthy truth, read `src/volte_mutation_fuzzer/sip/completeness.py` and `docs/프로토콜/SIP-메시지-완성도-매트릭스.md` first; examples below may retain older planning language.

**Goal:** Bring every SIP request method in this repo to an explicit completion tier, make all 14 request methods at least generator-complete, and make the practical UE-facing methods runtime-complete with honest state setup instead of pretending every message is equally runnable.

**Architecture:** Keep the existing SIP catalog as the source of truth for method/status coverage, then add an explicit packet-completeness layer that distinguishes `runtime_complete` from `generator_complete`. Complete request generation by threading `body_kind`, `event_package`, and `info_package` from contracts through `BodyFactory`, `SIPGenerator`, dialog orchestration, and the `real-ue-direct` MT builder. Tighten response/body defaults so generated packets match realistic SIP/IMS expectations, and extend dialog setup/state extraction so INVITE-family stateful methods receive valid context before fuzzing.

**Tech Stack:** Python 3.12, Pydantic, Typer, existing `SIPGenerator`, `BodyFactory`, `DialogOrchestrator`, `CampaignExecutor`, `real-ue-direct` MT builder, `pytest`

---

## File Structure

- Create: `src/volte_mutation_fuzzer/sip/completeness.py`
  Explicit completion-tier registry for each SIP request method.
- Create: `tests/sip/test_packet_completeness.py`
  Locks down completion tiers and prevents silent regressions in method accounting.
- Create: `docs/프로토콜/SIP-메시지-완성도-매트릭스.md`
  Human-readable matrix of runtime/generator completeness, runtime path, and verification scope.
- Modify: `src/volte_mutation_fuzzer/sip/__init__.py`
  Export the completeness helpers.
- Modify: `src/volte_mutation_fuzzer/sip/body_factory.py`
  Honor explicit `body_kind` and stop auto-selecting unrealistic response bodies.
- Modify: `src/volte_mutation_fuzzer/generator/contracts.py`
  Tighten request/body selection inputs and normalization.
- Modify: `src/volte_mutation_fuzzer/generator/optional_defaults.py`
  Align default `INFO`/event defaults with supported body implementations.
- Modify: `src/volte_mutation_fuzzer/generator/core.py`
  Thread `body_kind`, infer default info/event packages consistently, and generate realistic defaults.
- Modify: `src/volte_mutation_fuzzer/generator/mt_packet.py`
  Keep `real-ue-direct` wire generation in sync with the softphone generator for non-INVITE methods.
- Modify: `src/volte_mutation_fuzzer/sip/response_policy.py`
  Make response header/body rules explicit for realistic success/error cases.
- Modify: `src/volte_mutation_fuzzer/dialog/contracts.py`
  Allow dialog steps to carry body/event/info hints instead of method-only sending.
- Modify: `src/volte_mutation_fuzzer/dialog/scenarios.py`
  Keep runtime-complete methods routed through honest setup flows and make unsupported runtime methods explicit.
- Modify: `src/volte_mutation_fuzzer/dialog/core.py`
  Build `RequestSpec` from scenario step metadata and extract early-dialog state for PRACK-class flows.
- Modify: `src/volte_mutation_fuzzer/dialog/state_extractor.py`
  Extract tags/routes/contact from provisional INVITE responses as well as final responses.
- Modify: `src/volte_mutation_fuzzer/campaign/core.py`
  Route only runtime-complete methods through dialog orchestration and preserve honest reproduction metadata.
- Modify: `tests/generator/test_contracts.py`
  Lock down normalized body/event/info inputs.
- Modify: `tests/generator/test_core.py`
  Lock down realistic default packet generation and response defaults.
- Modify: `tests/generator/test_mt_packet.py`
  Lock down `real-ue-direct` non-INVITE body/header parity.
- Modify: `tests/sip/bodies/test_factory.py`
  Lock down explicit body-kind selection and realistic response-body rules.
- Modify: `tests/sip/test_response_policy.py`
  Lock down tightened header/body requirements.
- Modify: `tests/dialog/test_contracts.py`
  Lock down richer dialog step metadata.
- Modify: `tests/dialog/test_scenarios.py`
  Lock down runtime-complete method routing.
- Modify: `tests/campaign/test_dialog_integration.py`
  Lock down dialog orchestration for runtime-complete methods.
- Modify: `tests/campaign/test_core.py`
  Lock down campaign routing and resolved reproduction metadata.
- Modify: `docs/USAGE.md`
  Document which methods are runtime-complete vs generator-complete and how to smoke-test them.
- Modify: `docs/ARCHITECTURE.md`
  Document the new completeness tier and runtime routing rules.
- Modify: `docs/구현-문서.md`
  Replace ambiguous “implemented” language with tiered completeness language.
- Modify: `docs/README.md`
  Index the new completeness matrix.

---

### Task 1: Add An Explicit Packet Completion Registry And Matrix

**Files:**
- Create: `src/volte_mutation_fuzzer/sip/completeness.py`
- Create: `tests/sip/test_packet_completeness.py`
- Create: `docs/프로토콜/SIP-메시지-완성도-매트릭스.md`
- Modify: `src/volte_mutation_fuzzer/sip/__init__.py`
- Modify: `docs/README.md`

- [ ] **Step 1: Write the failing completeness tests**

```python
from volte_mutation_fuzzer.dialog.scenarios import scenario_for_method
from volte_mutation_fuzzer.generator import GeneratorSettings, RequestSpec, SIPGenerator
from volte_mutation_fuzzer.sip.common import SIPMethod
from volte_mutation_fuzzer.sip.completeness import (
    PacketCompletionTier,
    RUNTIME_COMPLETE_METHODS,
    GENERATOR_COMPLETE_METHODS,
    get_packet_completion,
)
from volte_mutation_fuzzer.sip.requests import REQUEST_MODELS_BY_METHOD


def test_every_request_method_has_a_completion_entry() -> None:
    accounted_for = {method for method in RUNTIME_COMPLETE_METHODS | GENERATOR_COMPLETE_METHODS}
    assert accounted_for == set(REQUEST_MODELS_BY_METHOD)


def test_runtime_complete_methods_have_a_real_runtime_path() -> None:
    assert get_packet_completion(SIPMethod.BYE).tier == PacketCompletionTier.runtime_complete
    assert scenario_for_method("BYE") is not None
    assert get_packet_completion(SIPMethod.PRACK).runtime_path == "invite_prack"


def test_generator_complete_methods_still_render_without_overrides() -> None:
    generator = SIPGenerator(GeneratorSettings())
    for method in GENERATOR_COMPLETE_METHODS:
        packet = generator.generate_request(RequestSpec(method=method))
        assert packet.cseq.method == method
```

- [ ] **Step 2: Run the focused completeness tests and verify they fail**

Run: `uv run pytest tests/sip/test_packet_completeness.py -q`

Expected:
- FAIL because `volte_mutation_fuzzer.sip.completeness` does not exist yet
- FAIL because no explicit completion-tier registry exists

- [ ] **Step 3: Implement the completion registry and write the human matrix**

```python
# src/volte_mutation_fuzzer/sip/completeness.py
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from volte_mutation_fuzzer.sip.common import SIPMethod


class PacketCompletionTier(StrEnum):
    runtime_complete = "runtime_complete"
    generator_complete = "generator_complete"


@dataclass(frozen=True)
class PacketCompletion:
    tier: PacketCompletionTier
    runtime_path: str
    baseline_scope: str
    note: str


PACKET_COMPLETENESS: dict[SIPMethod, PacketCompletion] = {
    SIPMethod.INVITE: PacketCompletion(PacketCompletionTier.runtime_complete, "stateless", "real-ue baseline", "Primary real-UE path."),
    SIPMethod.ACK: PacketCompletion(PacketCompletionTier.runtime_complete, "invite_ack", "softphone dialog smoke", "Requires a successful 2xx INVITE setup."),
    SIPMethod.BYE: PacketCompletion(PacketCompletionTier.runtime_complete, "invite_dialog", "softphone dialog smoke", "Requires a confirmed dialog."),
    SIPMethod.CANCEL: PacketCompletion(PacketCompletionTier.runtime_complete, "invite_cancel", "softphone provisional dialog smoke", "Requires a pending INVITE transaction."),
    SIPMethod.INFO: PacketCompletion(PacketCompletionTier.runtime_complete, "invite_dialog", "softphone dialog smoke", "Defaults to DTMF INFO package."),
    SIPMethod.MESSAGE: PacketCompletion(PacketCompletionTier.runtime_complete, "stateless", "softphone/request smoke", "Pager-mode request path."),
    SIPMethod.NOTIFY: PacketCompletion(PacketCompletionTier.generator_complete, "unsupported", "generator/render only", "Incoming NOTIFY requires an existing UE-originated subscription."),
    SIPMethod.OPTIONS: PacketCompletion(PacketCompletionTier.runtime_complete, "stateless", "softphone/request smoke", "No dialog setup required."),
    SIPMethod.PRACK: PacketCompletion(PacketCompletionTier.runtime_complete, "invite_prack", "softphone provisional dialog smoke", "Requires early-dialog extraction from 18x."),
    SIPMethod.PUBLISH: PacketCompletion(PacketCompletionTier.generator_complete, "unsupported", "generator/render only", "Publication-target role is not part of the current runtime path."),
    SIPMethod.REFER: PacketCompletion(PacketCompletionTier.runtime_complete, "invite_dialog", "softphone dialog smoke", "Requires a confirmed dialog."),
    SIPMethod.REGISTER: PacketCompletion(PacketCompletionTier.generator_complete, "unsupported", "generator/render only", "UE-as-registrar is not a current runtime target."),
    SIPMethod.SUBSCRIBE: PacketCompletion(PacketCompletionTier.generator_complete, "unsupported", "generator/render only", "Generator coverage exists, but the honest runtime prerequisite subscription/service state is not modeled yet."),
    SIPMethod.UPDATE: PacketCompletion(PacketCompletionTier.runtime_complete, "invite_dialog", "softphone dialog smoke", "Confirmed-dialog mid-call request."),
}

RUNTIME_COMPLETE_METHODS = frozenset(
    method for method, meta in PACKET_COMPLETENESS.items() if meta.tier == PacketCompletionTier.runtime_complete
)
GENERATOR_COMPLETE_METHODS = frozenset(
    method for method, meta in PACKET_COMPLETENESS.items() if meta.tier == PacketCompletionTier.generator_complete
)


def get_packet_completion(method: SIPMethod) -> PacketCompletion:
    return PACKET_COMPLETENESS[method]
```

```markdown
| Method | Tier | Runtime Path | Baseline Scope | Note |
| --- | --- | --- | --- | --- |
| `INVITE` | `runtime_complete` | `stateless` | real-UE baseline | Proven A31 MT path |
| `ACK` | `runtime_complete` | `invite_ack` | softphone dialog smoke | Requires 2xx INVITE setup |
| `NOTIFY` | `generator_complete` | `unsupported` | generator/render only | Needs UE-originated subscription first |
```

- [ ] **Step 4: Run the completeness tests and verify they pass**

Run: `uv run pytest tests/sip/test_packet_completeness.py -q`

Expected:
- PASS with all request methods assigned to an explicit tier
- PASS with runtime-complete methods mapped to honest runtime paths

- [ ] **Step 5: Commit**

```bash
git add src/volte_mutation_fuzzer/sip/completeness.py src/volte_mutation_fuzzer/sip/__init__.py tests/sip/test_packet_completeness.py docs/프로토콜/SIP-메시지-완성도-매트릭스.md docs/README.md
git commit -m "feat: add SIP packet completeness tiers"
```

---

### Task 2: Thread Body Selection Hints Through Generator And MT Paths

**Files:**
- Modify: `src/volte_mutation_fuzzer/sip/body_factory.py`
- Modify: `src/volte_mutation_fuzzer/generator/contracts.py`
- Modify: `src/volte_mutation_fuzzer/generator/optional_defaults.py`
- Modify: `src/volte_mutation_fuzzer/generator/core.py`
- Modify: `src/volte_mutation_fuzzer/generator/mt_packet.py`
- Modify: `src/volte_mutation_fuzzer/dialog/contracts.py`
- Modify: `src/volte_mutation_fuzzer/dialog/core.py`
- Modify: `tests/generator/test_contracts.py`
- Modify: `tests/sip/bodies/test_factory.py`
- Modify: `tests/generator/test_core.py`
- Modify: `tests/generator/test_mt_packet.py`
- Modify: `tests/dialog/test_contracts.py`

- [ ] **Step 1: Write the failing body-selection tests**

```python
def test_info_request_populates_default_dtmf_body() -> None:
    generator = SIPGenerator(GeneratorSettings())
    defaults = generator._build_request_defaults(RequestSpec(method=SIPMethod.INFO))

    assert defaults["info_package"] == "dtmf"
    assert defaults["content_type"] == "application/dtmf-relay"
    assert "Signal=" in defaults["body"]


def test_explicit_body_kind_overrides_notify_event_default() -> None:
    factory = BodyFactory()

    body_cls = factory.select(
        BodyContext(
            method=SIPMethod.NOTIFY,
            event_package="dialog",
            body_kind="dialog_info",
        )
    )

    assert body_cls is DialogInfoBody


def test_mt_packet_info_defaults_match_softphone_generator() -> None:
    packet = build_mt_packet(
        method="INFO",
        impi="001010000123511",
        msisdn="111111",
        ue_ip="10.20.20.8",
        port_pc=31800,
        port_ps=31100,
        seed=4,
        env={},
    )

    headers, body = _split_packet(packet)
    assert "Info-Package: dtmf" in headers
    assert "Content-Type: application/dtmf-relay" in headers
    assert "Signal=4" in body
```

- [ ] **Step 2: Run the focused generator/body tests and verify they fail**

Run: `uv run pytest tests/generator/test_contracts.py tests/sip/bodies/test_factory.py tests/generator/test_core.py tests/generator/test_mt_packet.py -k "body_kind or info or notify" -q`

Expected:
- FAIL because `body_kind` is normalized but not used by `BodyFactory`
- FAIL because `INFO` defaults do not currently infer a body-producing package
- FAIL because dialog steps cannot carry `body_kind`/package hints yet

- [ ] **Step 3: Implement end-to-end body hint threading**

```python
# src/volte_mutation_fuzzer/sip/body_factory.py
@dataclass(frozen=True)
class BodyContext:
    method: SIPMethod
    status_code: int | None = None
    body_kind: str | None = None
    event_package: str | None = None
    info_package: str | None = None
    sms_over_ip: bool = False


class BodyFactory:
    _BODY_KIND_MAP: dict[str, type[SIPBody]] = {
        "conference_info": ConferenceInfoBody,
        "dialog_info": DialogInfoBody,
        "dtmf": DtmfRelayBody,
        "ims_service": ImsServiceBody,
        "message_summary": MessageSummaryBody,
        "pidf": PIdfBody,
        "plain_text": PlainTextBody,
        "reginfo": ReginfoBody,
        "sdp": SDPBody,
        "sipfrag": SipfragBody,
        "sms": SmsBody,
    }

    def select(self, ctx: BodyContext) -> type[SIPBody] | None:
        explicit = self._BODY_KIND_MAP.get(self._normalize(ctx.body_kind))
        if explicit is not None:
            return explicit
        if ctx.status_code is None:
            return self._select_request_body(ctx)
        return self._select_response_body(ctx)
```

```python
# src/volte_mutation_fuzzer/generator/core.py
def _infer_info_package(self, defaults: dict[str, Any]) -> str | None:
    info_package = defaults.get("info_package")
    if isinstance(info_package, str):
        stripped = info_package.strip()
        return stripped or None
    return None


body_ctx = BodyContext(
    method=spec.method,
    body_kind=spec.body_kind,
    event_package=event_pkg,
    info_package=spec.info_package or self._infer_info_package(defaults),
    sms_over_ip=spec.sms_over_ip,
)
```

```python
# src/volte_mutation_fuzzer/dialog/contracts.py
class DialogStep(BaseModel):
    method: str
    role: Literal["send", "expect"]
    is_fuzz_target: bool = False
    expect_status_min: int | None = None
    expect_status_max: int | None = None
    body_kind: str | None = None
    event_package: str | None = None
    info_package: str | None = None
```

- [ ] **Step 4: Run the focused generator/body tests and verify they pass**

Run: `uv run pytest tests/generator/test_contracts.py tests/sip/bodies/test_factory.py tests/generator/test_core.py tests/generator/test_mt_packet.py tests/dialog/test_contracts.py -q`

Expected:
- PASS with explicit body kinds honored
- PASS with default `INFO` packets producing a realistic DTMF body
- PASS with `real-ue-direct` MT packets matching softphone defaults for the same method

- [ ] **Step 5: Commit**

```bash
git add src/volte_mutation_fuzzer/sip/body_factory.py src/volte_mutation_fuzzer/generator/contracts.py src/volte_mutation_fuzzer/generator/optional_defaults.py src/volte_mutation_fuzzer/generator/core.py src/volte_mutation_fuzzer/generator/mt_packet.py src/volte_mutation_fuzzer/dialog/contracts.py src/volte_mutation_fuzzer/dialog/core.py tests/generator/test_contracts.py tests/sip/bodies/test_factory.py tests/generator/test_core.py tests/generator/test_mt_packet.py tests/dialog/test_contracts.py
git commit -m "feat: thread SIP body selection through generators"
```

---

### Task 3: Align Response Defaults With Realistic SIP Body Policy

**Files:**
- Modify: `src/volte_mutation_fuzzer/sip/body_factory.py`
- Modify: `src/volte_mutation_fuzzer/sip/response_policy.py`
- Modify: `src/volte_mutation_fuzzer/generator/optional_defaults.py`
- Modify: `src/volte_mutation_fuzzer/generator/core.py`
- Modify: `tests/sip/test_response_policy.py`
- Modify: `tests/sip/bodies/test_factory.py`
- Modify: `tests/generator/test_core.py`
- Modify: `tests/test_sip_catalog.py`

- [ ] **Step 1: Write the failing response-policy tests**

```python
def test_invite_180_does_not_auto_generate_an_sdp_body() -> None:
    generator = SIPGenerator(GeneratorSettings())
    context = DialogContext(call_id=REALISTIC_CALL_ID, local_tag=REALISTIC_LOCAL_TAG, local_cseq=1)

    defaults = generator._build_response_defaults(
        ResponseSpec(status_code=180, related_method=SIPMethod.INVITE),
        context,
    )

    assert defaults.get("body") is None
    assert defaults.get("content_type") is None


def test_prack_204_does_not_select_sdp_body() -> None:
    factory = BodyFactory()
    assert factory.select(BodyContext(method=SIPMethod.PRACK, status_code=204)) is None


def test_notify_200_response_forbids_body() -> None:
    policy = get_response_policy(SIPMethod.NOTIFY, 200)
    assert policy.body_forbidden is True
```

- [ ] **Step 2: Run the focused response-policy tests and verify they fail**

Run: `uv run pytest tests/sip/test_response_policy.py tests/sip/bodies/test_factory.py tests/generator/test_core.py tests/test_sip_catalog.py -k "notify or prack or 180" -q`

Expected:
- FAIL because `INVITE 180` currently auto-picks an SDP body
- FAIL because response body selection still treats `PRACK 204` as SDP-bearing
- FAIL because `NOTIFY 200` has no explicit body-forbidden policy

- [ ] **Step 3: Implement realistic response-body rules**

```python
# src/volte_mutation_fuzzer/sip/response_policy.py
RESPONSE_HEADER_POLICIES.update(
    {
        (SIPMethod.NOTIFY, 200): ResponseHeaderPolicy(body_forbidden=True),
        (SIPMethod.INFO, 200): ResponseHeaderPolicy(body_forbidden=True),
        (SIPMethod.PUBLISH, 200): ResponseHeaderPolicy(body_forbidden=True),
        (SIPMethod.OPTIONS, 200): ResponseHeaderPolicy(),
    }
)
```

```python
# src/volte_mutation_fuzzer/sip/body_factory.py
def _select_response_body(self, ctx: BodyContext) -> type[SIPBody] | None:
    status_code = ctx.status_code
    if status_code is None:
        return None
    if ctx.method == SIPMethod.INVITE and status_code in {183, 200}:
        return SDPBody
    if ctx.method == SIPMethod.INVITE and status_code == 380:
        return ImsServiceBody
    if ctx.method == SIPMethod.UPDATE and status_code == 200:
        return SDPBody
    if ctx.method == SIPMethod.OPTIONS and status_code == 200 and self._normalize(ctx.body_kind) == "sdp":
        return SDPBody
    return None
```

- [ ] **Step 4: Run the focused response-policy tests and verify they pass**

Run: `uv run pytest tests/sip/test_response_policy.py tests/sip/bodies/test_factory.py tests/generator/test_core.py tests/test_sip_catalog.py -q`

Expected:
- PASS with no unrealistic auto-generated response bodies
- PASS with response-policy tests aligned with generator defaults

- [ ] **Step 5: Commit**

```bash
git add src/volte_mutation_fuzzer/sip/body_factory.py src/volte_mutation_fuzzer/sip/response_policy.py src/volte_mutation_fuzzer/generator/optional_defaults.py src/volte_mutation_fuzzer/generator/core.py tests/sip/test_response_policy.py tests/sip/bodies/test_factory.py tests/generator/test_core.py tests/test_sip_catalog.py
git commit -m "feat: align SIP response defaults with policy"
```

---

### Task 4: Complete Runtime Dialog Flows For Stateful INVITE-Family Packets

**Files:**
- Modify: `src/volte_mutation_fuzzer/dialog/contracts.py`
- Modify: `src/volte_mutation_fuzzer/dialog/scenarios.py`
- Modify: `src/volte_mutation_fuzzer/dialog/core.py`
- Modify: `src/volte_mutation_fuzzer/dialog/state_extractor.py`
- Modify: `src/volte_mutation_fuzzer/campaign/core.py`
- Modify: `tests/dialog/test_scenarios.py`
- Modify: `tests/campaign/test_dialog_integration.py`
- Modify: `tests/campaign/test_core.py`

- [ ] **Step 1: Write the failing stateful-runtime tests**

```python
def test_prack_setup_extracts_early_dialog_state_from_183() -> None:
    observation = SocketObservation(
        status_code=183,
        reason_phrase="Session Progress",
        classification="provisional",
        raw_text=(
            "SIP/2.0 183 Session Progress\r\n"
            "To: <sip:111111@ims.mnc001.mcc001.3gppnetwork.org>;tag=early-tag\r\n"
            "Contact: <sip:remote@10.20.20.9:31800>\r\n"
            "Record-Route: <sip:edge1@172.22.0.21;lr>,<sip:edge2@172.22.0.20;lr>\r\n\r\n"
        ),
        headers={
            "to": "<sip:111111@ims.mnc001.mcc001.3gppnetwork.org>;tag=early-tag",
            "contact": "<sip:remote@10.20.20.9:31800>",
            "record-route": "<sip:edge1@172.22.0.21;lr>,<sip:edge2@172.22.0.20;lr>",
        },
    )
    context = DialogContext()

    extract_dialog_state(observation, context)

    assert context.local_tag == "early-tag"
    assert context.request_uri is not None
    assert context.route_set


def test_info_dialog_step_can_carry_info_package() -> None:
    scenario = scenario_for_method("INFO")
    assert scenario is not None
    assert scenario.fuzz_step.info_package == "dtmf"
```

- [ ] **Step 2: Run the focused dialog tests and verify they fail**

Run: `uv run pytest tests/dialog/test_scenarios.py tests/campaign/test_dialog_integration.py tests/campaign/test_core.py -k "prack or info or dialog" -q`

Expected:
- FAIL because early provisional responses are not used to seed dialog state for PRACK
- FAIL because `DialogStep` does not yet carry `info_package`/`body_kind` hints through scenario execution

- [ ] **Step 3: Implement richer dialog-step metadata and early-dialog extraction**

```python
# src/volte_mutation_fuzzer/dialog/scenarios.py
def _build_invite_dialog(method: str) -> DialogScenario:
    fuzz_step = DialogStep(method=method, role="send", is_fuzz_target=True)
    if method == "INFO":
        fuzz_step = fuzz_step.model_copy(update={"info_package": "dtmf"})
    if method == "REFER":
        fuzz_step = fuzz_step.model_copy(update={"body_kind": "sipfrag"})
    return DialogScenario(
        scenario_type=DialogScenarioType.invite_dialog,
        fuzz_method=method,
        setup_steps=(
            DialogStep(method="INVITE", role="send", expect_status_min=200, expect_status_max=299),
            DialogStep(method="ACK", role="send"),
        ),
        fuzz_step=fuzz_step,
        teardown_steps=(() if method == "BYE" else (DialogStep(method="BYE", role="send"),)),
    )
```

```python
# src/volte_mutation_fuzzer/dialog/core.py
packet = self._generator.generate_request(
    RequestSpec(
        method=SIPMethod(step.method),
        body_kind=step.body_kind,
        event_package=step.event_package,
        info_package=step.info_package,
    ),
    context,
)

if (
    step.method == "INVITE"
    and result.send_result is not None
):
    final_or_provisional = (
        result.send_result.final_response
        or next((obs for obs in reversed(result.send_result.responses) if obs.status_code and obs.status_code >= 180), None)
    )
    if final_or_provisional is not None:
        extract_dialog_state(final_or_provisional, context)
```

- [ ] **Step 4: Run the focused dialog tests and verify they pass**

Run: `uv run pytest tests/dialog/test_scenarios.py tests/campaign/test_dialog_integration.py tests/campaign/test_core.py -q`

Expected:
- PASS with `BYE`, `ACK`, `CANCEL`, `PRACK`, `UPDATE`, `INFO`, and `REFER` routed through honest setup flows
- PASS with PRACK using early-dialog state instead of a half-populated context

- [ ] **Step 5: Commit**

```bash
git add src/volte_mutation_fuzzer/dialog/contracts.py src/volte_mutation_fuzzer/dialog/scenarios.py src/volte_mutation_fuzzer/dialog/core.py src/volte_mutation_fuzzer/dialog/state_extractor.py src/volte_mutation_fuzzer/campaign/core.py tests/dialog/test_scenarios.py tests/campaign/test_dialog_integration.py tests/campaign/test_core.py
git commit -m "feat: complete runtime dialog paths for SIP packets"
```

---

### Task 5: Document Method Tiers And Run Final Verification

**Files:**
- Modify: `docs/USAGE.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/구현-문서.md`
- Modify: `docs/README.md`
- Modify: `docs/프로토콜/SIP-메시지-완성도-매트릭스.md`

- [ ] **Step 1: Write the documentation updates**

```markdown
## SIP Packet Completeness

- `runtime_complete`
  - `INVITE`, `ACK`, `BYE`, `CANCEL`, `INFO`, `MESSAGE`, `OPTIONS`, `PRACK`, `REFER`, `UPDATE`
- `generator_complete`
  - `REGISTER`, `PUBLISH`, `SUBSCRIBE`, `NOTIFY`

`generator_complete` does not mean “missing”; it means the repo can generate and mutate the packet coherently, but the current runtime path does not honestly satisfy the required remote state.
```

- [ ] **Step 2: Run the full packet-completeness verification suite**

Run: `uv run pytest tests/test_sip_catalog.py tests/sip/test_packet_completeness.py tests/sip/bodies/test_factory.py tests/sip/test_response_policy.py tests/generator/test_contracts.py tests/generator/test_core.py tests/generator/test_mt_packet.py tests/dialog/test_contracts.py tests/dialog/test_scenarios.py tests/campaign/test_dialog_integration.py tests/campaign/test_core.py -q`

Expected:
- PASS with all packet completeness, generator, dialog, and campaign routing checks green

- [ ] **Step 3: Run whitespace and patch hygiene checks**

Run: `git diff --check`

Expected:
- PASS with no trailing whitespace, malformed patches, or merge markers

- [ ] **Step 4: Record manual lab smoke commands in the docs**

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --methods INVITE \
  --profile legacy \
  --layer wire \
  --strategy identity \
  --max-cases 1 \
  --mt-invite-template a31 \
  --ipsec-mode null

uv run fuzzer campaign run \
  --mode softphone \
  --target-host 127.0.0.1 \
  --target-port 5060 \
  --methods BYE,INFO,UPDATE,REFER,PRACK \
  --profile legacy \
  --layer model \
  --strategy identity \
  --max-cases 1
```

- [ ] **Step 5: Commit**

```bash
git add docs/USAGE.md docs/ARCHITECTURE.md docs/구현-문서.md docs/README.md docs/프로토콜/SIP-메시지-완성도-매트릭스.md
git commit -m "docs: document SIP packet completeness"
```

---

## Notes For Execution

- `runtime_complete` is the bar for packets the repo can honestly send with required setup.
- `generator_complete` is still a success state for methods whose real runtime prerequisites are not currently under fuzzer control.
- Do not “upgrade” `NOTIFY`, `REGISTER`, or `PUBLISH` to runtime-complete by documentation alone. Only change their tier after a real state-creation path exists in code and tests.
- Keep `real-ue-direct` and softphone generation semantics aligned where the same method is supported in both paths.
- Do not re-introduce `--impi` into copy-paste campaign examples unless the command is explicitly meant to be self-contained across environments.
