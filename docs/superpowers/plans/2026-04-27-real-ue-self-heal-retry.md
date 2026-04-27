# Real-UE Self-Heal Retry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one-case real-UE self-healing that detects stale registration hints, re-resolves the live UE endpoint, and retries at most once without splitting the result into a second case.

**Architecture:** Keep self-heal ownership in the real-UE delivery layer, but split the work by payload semantics, not by MT labels. Endpoint-independent `real-ue-direct` sends self-heal inside `SIPSenderReactor` because a fresh live bundle can be applied without rebuilding the payload. Endpoint-baked flows must rebuild wire text from a fresh UE snapshot before retry because Request-URI, alias parameters, template slots, or body fields may embed UE host/port directly. MT template flows (`campaign` and sender CLI `--mt`) are the always-baked subset. Every retry stays inside the same logical send/case and is exposed as structured attempt metadata plus observer events.

**Tech Stack:** Python 3.12, Pydantic models, Typer CLI, unittest/pytest-style test suite, existing real-UE resolver and campaign reporter.

---

## File Map

- Modify: `src/volte_mutation_fuzzer/sender/contracts.py`
  - Add structured per-attempt metadata for self-heal aware sends.
- Modify: `src/volte_mutation_fuzzer/sender/real_ue.py`
  - Add coherent live-resolution bundle APIs so host and protected ports come from the same snapshot.
- Modify: `src/volte_mutation_fuzzer/sender/core.py`
  - Add payload classification plus one-shot stale self-heal for endpoint-independent `real-ue-direct` sends.
- Modify: `src/volte_mutation_fuzzer/sender/cli.py`
  - Route endpoint-baked single-shot sends, including MT `--mt`, through a rebuildable self-heal loop.
- Modify: `src/volte_mutation_fuzzer/campaign/core.py`
  - Rebuild endpoint-baked payloads on retry, merge retry metadata into one `CaseResult`, and preserve one case ID.
- Modify: `src/volte_mutation_fuzzer/campaign/report.py`
  - Surface self-heal summary in HTML context lines.
- Modify: `docs/TROUBLESHOOTING.md`
  - Document new self-heal behavior and how to read retry metadata.
- Modify: `docs/A31_REAL_UE_GUIDE.md`
  - Document that stale re-registration now produces one case with attempt history instead of a silent timeout.

- Test: `tests/sender/test_real_ue.py`
  - Resolver bundle coherence and stale-hint detection.
- Test: `tests/sender/test_core.py`
  - Endpoint-independent sender self-heal behavior and merged attempt traces.
- Test: `tests/sender/test_cli.py`
  - Endpoint-baked CLI path rebuilds and retries in one printed result.
- Test: `tests/campaign/test_core.py`
  - Endpoint-baked campaign path retries without creating a second case.
- Test: `tests/campaign/test_report.py`
  - Report surfaces self-heal summary text.

## Non-Goals

- No new user-facing retry-count flag in this change.
- No multi-retry backoff ladder. Max attempts remain `2` total: initial send plus at most one self-heal retry.
- No verdict split such as "timeout_then_success". Final verdict remains the final attempt outcome; attempt history carries the earlier timeout.

### Task 1: Add Attempt Trace Contracts

**Files:**
- Modify: `src/volte_mutation_fuzzer/sender/contracts.py`
- Test: `tests/sender/test_core.py`

- [ ] **Step 1: Write the failing test for structured attempt traces**

```python
def test_send_result_keeps_attempt_traces_for_real_ue_self_heal(self) -> None:
    result = SendReceiveResult(
        target=TargetEndpoint(mode="real-ue-direct", msisdn="111111"),
        artifact_kind="wire",
        bytes_sent=100,
        outcome="success",
        responses=(),
        send_started_at=1.0,
        send_completed_at=1.2,
        attempt_traces=(
            DeliveryAttemptTrace(
                attempt_index=1,
                phase="initial",
                trigger="stale_hint",
                requested_host="10.20.20.8",
                requested_port=8100,
                resolved_host="10.20.20.2",
                resolved_port=8102,
                resolver_source="pcscf-log",
                outcome="timeout",
            ),
            DeliveryAttemptTrace(
                attempt_index=2,
                phase="self_heal_retry",
                trigger="timeout",
                requested_host="10.20.20.2",
                requested_port=8102,
                resolved_host="10.20.20.2",
                resolved_port=8102,
                resolver_source="xfrm-state",
                outcome="success",
            ),
        ),
    )

    self.assertEqual(len(result.attempt_traces), 2)
    self.assertEqual(result.attempt_traces[0].phase, "initial")
    self.assertEqual(result.attempt_traces[1].phase, "self_heal_retry")
```

- [ ] **Step 2: Run the focused test and confirm the field is missing**

Run: `uv run pytest tests/sender/test_core.py -k attempt_traces -q`

Expected: FAIL with `NameError` or Pydantic validation error because `DeliveryAttemptTrace` / `attempt_traces` does not exist yet.

- [ ] **Step 3: Add the minimal contract types**

```python
class DeliveryAttemptTrace(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    attempt_index: int = Field(ge=1)
    phase: Literal["initial", "self_heal_retry"]
    trigger: Literal["initial", "stale_hint", "timeout"]
    requested_host: str | None = None
    requested_port: int | None = Field(default=None, ge=1, le=65535)
    resolved_host: str | None = None
    resolved_port: int | None = Field(default=None, ge=1, le=65535)
    port_role: Literal["contact", "port_pc", "port_ps"] | None = None
    resolver_source: str | None = None
    outcome: DeliveryOutcome
    note: str | None = None


class SendReceiveResult(BaseModel):
    ...
    attempt_traces: tuple[DeliveryAttemptTrace, ...] = Field(default_factory=tuple)
```

- [ ] **Step 4: Re-run the focused test**

Run: `uv run pytest tests/sender/test_core.py -k attempt_traces -q`

Expected: PASS.

- [ ] **Step 5: Commit the contract groundwork**

```bash
git add src/volte_mutation_fuzzer/sender/contracts.py tests/sender/test_core.py
git commit -m "feat: add real-ue delivery attempt trace model"
```

### Task 2: Build Coherent Real-UE Resolution Bundles

**Files:**
- Modify: `src/volte_mutation_fuzzer/sender/real_ue.py`
- Test: `tests/sender/test_real_ue.py`

- [ ] **Step 1: Write failing resolver-bundle tests**

```python
def test_resolve_live_delivery_bundle_uses_one_generation_for_host_and_ports(self) -> None:
    resolver = RealUEDirectResolver()
    target = TargetEndpoint(mode="real-ue-direct", msisdn="111111", ipsec_mode="native")

    with (
        patch.object(
            resolver,
            "_lookup_ue_contact",
            return_value=UEContact(
                msisdn="111111",
                host="10.20.20.2",
                port=5072,
                source="pcscf-log",
            ),
        ),
        patch.object(
            resolver,
            "resolve_protected_ports",
            return_value=(8102, 8103),
        ) as mock_ports,
    ):
        bundle = resolver.resolve_live_delivery_bundle(target, impi="001010000123511")

    self.assertEqual(bundle.host, "10.20.20.2")
    self.assertEqual(bundle.port_pc, 8102)
    self.assertEqual(bundle.port_ps, 8103)
    self.assertEqual(bundle.delivery_port, 8103)
    mock_ports.assert_called_once_with("111111", ue_ip="10.20.20.2")


def test_resolve_live_delivery_bundle_marks_stale_hint_when_requested_target_differs(self) -> None:
    resolver = RealUEDirectResolver()
    target = TargetEndpoint(
        mode="real-ue-direct",
        host="10.20.20.8",
        port=8100,
        msisdn="111111",
        ipsec_mode="null",
    )

    with (
        patch.object(
            resolver,
            "_lookup_ue_contact",
            return_value=UEContact(
                msisdn="111111",
                host="10.20.20.2",
                port=5072,
                source="pcscf-log",
            ),
        ),
        patch.object(
            resolver,
            "resolve_protected_ports",
            return_value=(8102, 8103),
        ),
    ):
        bundle = resolver.resolve_live_delivery_bundle(target)

    self.assertEqual(bundle.stale_markers, ("host_changed", "port_changed"))
    self.assertEqual(bundle.delivery_port, 8102)
```

- [ ] **Step 2: Run the resolver bundle tests**

Run: `uv run pytest tests/sender/test_real_ue.py -k live_delivery_bundle -q`

Expected: FAIL because `resolve_live_delivery_bundle()` and bundle objects do not exist.

- [ ] **Step 3: Implement coherent bundle types and APIs**

```python
@dataclass(frozen=True)
class RealUEDeliveryBundle:
    msisdn: str | None
    impi: str | None
    host: str
    contact_port: int
    port_pc: int | None
    port_ps: int | None
    delivery_port: int
    port_role: Literal["contact", "port_pc", "port_ps"]
    source: str
    stale_markers: tuple[str, ...]
    observer_events: tuple[str, ...]


def resolve_live_delivery_bundle(
    self,
    target: TargetEndpoint,
    *,
    impi: str | None = None,
    port_role: Literal["contact", "port_pc", "port_ps"] | None = None,
) -> RealUEDeliveryBundle:
    if target.msisdn is None:
        ...
    contact = self._lookup_ue_contact(target.msisdn, impi=impi)
    ...
    return RealUEDeliveryBundle(...)
```

Implementation rules:

- If `target.msisdn` is present, do **not** short-circuit on `target.host`; treat `host`/`port` as caller hints and compare them against the fresh live bundle.
- Default `port_role` to:
  - `"port_ps"` for native IPsec
  - `"contact"` for generic msisdn sends with no pre-materialized port
  - explicit caller-provided role for MT paths
- Populate `stale_markers` from exact mismatches such as `host_changed`, `port_changed`, and `source_upgraded`.

- [ ] **Step 4: Re-run the resolver tests**

Run: `uv run pytest tests/sender/test_real_ue.py -k live_delivery_bundle -q`

Expected: PASS.

- [ ] **Step 5: Commit the bundle refactor**

```bash
git add src/volte_mutation_fuzzer/sender/real_ue.py tests/sender/test_real_ue.py
git commit -m "refactor: add coherent real-ue delivery bundles"
```

### Task 3: Add Sender Self-Heal for Endpoint-Independent Real-UE Sends

**Files:**
- Modify: `src/volte_mutation_fuzzer/sender/core.py`
- Test: `tests/sender/test_core.py`

- [ ] **Step 1: Write failing sender self-heal tests**

```python
def test_send_real_ue_direct_timeout_retries_once_after_live_bundle_change_for_endpoint_independent_artifact(self) -> None:
    artifact = SendArtifact.from_wire_text("OPTIONS sip:test SIP/2.0\r\n\r\n")
    target = TargetEndpoint(mode="real-ue-direct", msisdn="111111", timeout_seconds=0.2)

    bundle_a = SimpleNamespace(
        host="10.20.20.8",
        delivery_port=8100,
        contact_port=5072,
        port_pc=None,
        port_ps=None,
        port_role="contact",
        source="pcscf-log",
        stale_markers=(),
        observer_events=("resolver:bundle:10.20.20.8:8100",),
    )
    bundle_b = SimpleNamespace(
        host="10.20.20.2",
        delivery_port=8102,
        contact_port=5072,
        port_pc=None,
        port_ps=None,
        port_role="contact",
        source="xfrm-state",
        stale_markers=("host_changed", "port_changed"),
        observer_events=("resolver:bundle:10.20.20.2:8102",),
    )

    with (
        patch(
            "volte_mutation_fuzzer.sender.core.RealUEDirectResolver.resolve_live_delivery_bundle",
            side_effect=[bundle_a, bundle_b],
        ),
        patch.object(
            SIPSenderReactor,
            "_send_udp",
            side_effect=[[], [SocketObservation(status_code=200, raw_text="SIP/2.0 200 OK", classification="success")]],
        ),
    ):
        result = self.reactor.send_artifact(artifact, target)

    self.assertEqual(result.outcome, "success")
    self.assertEqual(len(result.attempt_traces), 2)
    self.assertEqual(result.attempt_traces[0].outcome, "timeout")
    self.assertEqual(result.attempt_traces[1].phase, "self_heal_retry")


def test_send_real_ue_direct_stale_hint_rewrites_first_attempt_without_extra_case(self) -> None:
    ...
```

- [ ] **Step 2: Run the focused sender tests**

Run: `uv run pytest tests/sender/test_core.py -k "timeout_retries_once or stale_hint_rewrites" -q`

Expected: FAIL because `send_artifact()` does not retry or record attempts.

- [ ] **Step 3: Implement sender-level self-heal orchestration**

```python
def _send_real_ue_direct_with_self_heal(
    self,
    artifact: SendArtifact,
    target: TargetEndpoint,
    *,
    collect_all_responses: bool,
) -> SendReceiveResult:
    if _artifact_is_endpoint_baked_for_real_ue(artifact, target):
        return self._send_real_ue_direct_once(
            artifact,
            target,
            collect_all_responses=collect_all_responses,
        )

    first = self._send_real_ue_direct_once(
        artifact,
        target,
        collect_all_responses=collect_all_responses,
    )
    if (
        target.msisdn is None
        or first.outcome != "timeout"
        or len(first.attempt_traces) != 1
    ):
        return first

    retry_bundle = RealUEDirectResolver(env=self._env).resolve_live_delivery_bundle(target)
    if not retry_bundle.stale_markers:
        return first

    second = self._send_real_ue_direct_once(
        artifact,
        target.model_copy(
            update={"host": retry_bundle.host, "port": retry_bundle.delivery_port},
            deep=True,
        ),
        collect_all_responses=collect_all_responses,
        attempt_index=2,
        trigger="timeout",
    )
    return _merge_attempt_results(first, second)
```

Implementation rules:

- Refactor the current `_send_real_ue_direct()` into `_send_real_ue_direct_once()` plus a wrapper that decides whether to self-heal.
- Add explicit payload classification for real-UE sends:
  - endpoint-independent: destination can change without rebuilding the artifact
  - endpoint-baked: Request-URI host/port, alias data, or body fields embed the UE endpoint and therefore must be rebuilt by the caller
- Sender-owned self-heal in this task applies only to endpoint-independent artifacts.
- Before the first actual socket send, if a fresh live bundle has stale markers, overwrite the hinted target with the fresh bundle and record `trigger="stale_hint"` on attempt 1.
- Re-send the same `SendArtifact`, not previously rendered raw bytes, so normal Via/Contact rewriting still runs on the fresh target.
- Retry at most once.
- Final `SendReceiveResult` keeps:
  - one `target` equal to the final attempt target
  - final `outcome`
  - concatenated `observer_events`
  - structured `attempt_traces`
- Do **not** create a second campaign case or second CLI result object.

- [ ] **Step 4: Run the sender test slice**

Run: `uv run pytest tests/sender/test_core.py -k "real_ue_direct and self_heal" -q`

Expected: PASS.

- [ ] **Step 5: Commit the endpoint-independent sender self-heal**

```bash
git add src/volte_mutation_fuzzer/sender/core.py tests/sender/test_core.py
git commit -m "feat: add real-ue self-heal retry to sender"
```

### Task 4: Rebuild Endpoint-Baked Payloads on Self-Heal in Campaign and CLI

**Files:**
- Modify: `src/volte_mutation_fuzzer/campaign/core.py`
- Modify: `src/volte_mutation_fuzzer/sender/cli.py`
- Test: `tests/campaign/test_core.py`
- Test: `tests/sender/test_cli.py`

- [ ] **Step 1: Write failing endpoint-baked retry tests**

```python
def test_mt_template_timeout_self_heal_rebuilds_payload_and_keeps_one_case(self) -> None:
    cfg = self._make_config(
        "10.20.20.8",
        5060,
        mode="real-ue-direct",
        methods=("INVITE",),
        target_msisdn="111111",
        impi="001010000123511",
        mt_invite_template="a31",
        ipsec_mode="native",
        max_cases=1,
        layers=("wire",),
        strategies=("identity",),
    )
    executor = CampaignExecutor(cfg)
    spec = CaseSpec(case_id=0, seed=7, method="INVITE", layer="wire", strategy="identity")

    with (
        patch.object(
            executor,
            "_resolve_mt_delivery_bundle",
            side_effect=[
                SimpleNamespace(host="10.20.20.8", port_pc=8100, port_ps=8101, impi="001010000123511", stale_markers=()),
                SimpleNamespace(host="10.20.20.2", port_pc=8102, port_ps=8103, impi="001010000123511", stale_markers=("host_changed", "port_changed")),
            ],
        ),
        patch.object(
            executor._sender,
            "send_artifact",
            side_effect=[
                SendReceiveResult(..., outcome="timeout", responses=(), attempt_traces=()),
                SendReceiveResult(..., outcome="success", responses=(SocketObservation(status_code=180, raw_text="SIP/2.0 180 Ringing", classification="provisional"),), attempt_traces=()),
            ],
        ),
    ):
        result = executor._execute_mt_template_case(spec, timestamp=1234.5, case_started_monotonic=1234.0)

    self.assertEqual(result.case_id, 0)
    self.assertEqual(result.verdict, "normal")
    self.assertEqual(result.details["self_heal"]["attempt_count"], 2)
```

```python
def test_packet_command_mt_prints_one_result_with_attempt_traces(self) -> None:
    ...
```

- [ ] **Step 2: Run the MT-focused tests**

Run: `uv run pytest tests/campaign/test_core.py -k self_heal -q`

Run: `uv run pytest tests/sender/test_cli.py -k self_heal -q`

Expected: FAIL because endpoint-baked paths do not rebuild wire text after a stale timeout.

- [ ] **Step 3: Implement endpoint-baked self-heal with payload rebuild**

```python
def _build_mt_attempt(
    self,
    spec: CaseSpec,
    bundle: RealUEDeliveryBundle,
) -> tuple[SendArtifact, TargetEndpoint, str | bytes]:
    wire_text = self._render_mt_wire_text_from_bundle(spec, bundle)
    mutated_wire = self._mutate_mt_wire_text(spec, wire_text)
    artifact = self._artifact_from_mutated_mt(mutated_wire)
    target = self._target.model_copy(
        update={
            "host": bundle.host,
            "port": bundle.port_ps if self._config.ipsec_mode == "native" else bundle.port_pc,
            "msisdn": self._config.target_msisdn,
        },
        deep=True,
    )
    return artifact, target, artifact.wire_text or artifact.packet_bytes
```

Campaign rules:

- Resolve a coherent MT bundle once per attempt.
- Build and mutate the payload from that bundle on every attempt.
- Treat MT as the concrete endpoint-baked case in campaign code; do not assume MT/non-MT is the architectural boundary.
- Fix the current MT campaign mismatch locus by resolving `ue_ip`, `port_pc`, and `port_ps` from the same bundle per attempt instead of independent lookups.
- If the first attempt times out and the retry bundle changed, rebuild with the same `case_id`, `seed`, `profile`, and `strategy`.
- Merge retry metadata into `CaseResult.details["self_heal"]`.
- Keep final `raw_request` / `raw_response` from the final attempt only.

CLI rules:

- Reuse the same endpoint-baked bundle builder used by campaign.
- Print one JSON result with `attempt_traces`, not two prints and not two process exits.

- [ ] **Step 4: Re-run the MT-focused tests**

Run: `uv run pytest tests/campaign/test_core.py -k self_heal -q`

Run: `uv run pytest tests/sender/test_cli.py -k self_heal -q`

Expected: PASS.

- [ ] **Step 5: Commit the endpoint-baked rebuild flow**

```bash
git add src/volte_mutation_fuzzer/campaign/core.py src/volte_mutation_fuzzer/sender/cli.py tests/campaign/test_core.py tests/sender/test_cli.py
git commit -m "feat: rebuild mt payloads during real-ue self-heal"
```

### Task 5: Surface Self-Heal Metadata in Case Results and Reports

**Files:**
- Modify: `src/volte_mutation_fuzzer/campaign/core.py`
- Modify: `src/volte_mutation_fuzzer/campaign/report.py`
- Modify: `docs/TROUBLESHOOTING.md`
- Modify: `docs/A31_REAL_UE_GUIDE.md`
- Test: `tests/campaign/test_report.py`

- [ ] **Step 1: Write the report regression test**

```python
def test_context_lines_show_self_heal_summary(self) -> None:
    case = _make_case(
        7,
        "normal",
        details={
            "self_heal": {
                "attempt_count": 2,
                "retry_trigger": "timeout",
                "final_target": "10.20.20.2:8103",
            }
        },
    )

    lines = _context_lines(case)

    self.assertIn(
        "Self-heal: 2 attempts (retry=timeout) final=10.20.20.2:8103",
        lines,
    )
```

- [ ] **Step 2: Run the report test**

Run: `uv run pytest tests/campaign/test_report.py -k self_heal -q`

Expected: FAIL because the report does not know about `details["self_heal"]`.

- [ ] **Step 3: Add case-detail shaping and report rendering**

```python
def _self_heal_details_from_send_result(send_result: SendReceiveResult) -> dict[str, object]:
    if not send_result.attempt_traces:
        return {}
    return {
        "attempt_count": len(send_result.attempt_traces),
        "retried": len(send_result.attempt_traces) > 1,
        "retry_trigger": send_result.attempt_traces[-1].trigger if len(send_result.attempt_traces) > 1 else None,
        "final_target": f"{send_result.target.host}:{send_result.target.port}",
        "attempts": [trace.model_dump(mode="json", exclude_none=True) for trace in send_result.attempt_traces],
    }
```

```python
def _context_lines(case: CaseResult) -> list[str]:
    ...
    self_heal = case.details.get("self_heal")
    if isinstance(self_heal, dict) and self_heal.get("attempt_count"):
        lines.append(
            f"Self-heal: {self_heal['attempt_count']} attempts "
            f"(retry={self_heal.get('retry_trigger') or 'none'}) "
            f"final={self_heal.get('final_target') or 'unknown'}"
        )
    return lines
```

Docs must explicitly say:

- one campaign case remains one case after self-heal
- earlier timeout is preserved in `details["self_heal"]["attempts"]`
- `observer_events` keep low-level retry evidence for sender CLI / raw JSON

- [ ] **Step 4: Run the report and docs verification slice**

Run: `uv run pytest tests/campaign/test_report.py -k self_heal -q`

Run: `uv run pytest tests/campaign/test_core.py -k self_heal -q`

Expected: PASS.

- [ ] **Step 5: Commit metadata/report/docs updates**

```bash
git add src/volte_mutation_fuzzer/campaign/core.py src/volte_mutation_fuzzer/campaign/report.py docs/TROUBLESHOOTING.md docs/A31_REAL_UE_GUIDE.md tests/campaign/test_report.py tests/campaign/test_core.py
git commit -m "docs: surface real-ue self-heal attempt history"
```

## Verification Checklist

- Run: `uv run pytest tests/sender/test_real_ue.py tests/sender/test_core.py tests/sender/test_cli.py tests/campaign/test_core.py tests/campaign/test_report.py -q`
- Run: `uv run pytest tests/sender/test_core.py -k real_ue_direct -q`
- Run: `uv run pytest tests/campaign/test_core.py -k "native_mt_template or self_heal" -q`

Expected verification outcomes:

- Endpoint-independent `real-ue-direct` timeout with stale endpoint yields one `SendReceiveResult` with `attempt_traces == 2`.
- Endpoint-baked retry rebuilds payload from a fresh bundle and still yields one logical result or case.
- MT campaign retry yields one `CaseResult` with unchanged `case_id` and `details["self_heal"]["attempt_count"] == 2`.
- HTML report shows a self-heal summary line instead of hiding the retry.
- No path performs more than one retry.

## Self-Review

- Spec coverage: payload classification, endpoint-independent sender retry, endpoint-baked rebuild flow, one-case semantics, retry trace visibility, and report visibility are each covered by a dedicated task.
- Placeholder scan: no `TODO`/`TBD` markers remain.
- Type consistency: the plan uses `DeliveryAttemptTrace`, `RealUEDeliveryBundle`, `attempt_traces`, and `details["self_heal"]` consistently across sender, campaign, CLI, and report work.
