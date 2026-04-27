# Real-UE Self-Heal Phasing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the small `_resolve_ports_live` uncoupled-lookup fix first (Phase 0), measure how much of the observed `real-ue-direct` timeout volume is actually stale-endpoint mismatch, then use that measurement to gate the larger endpoint-baked / endpoint-independent self-heal infrastructure (Phase 1).

**Architecture:** Phase 0 is a 1-method, ~3-line behavior fix in `CampaignExecutor._resolve_ports_live`: thread the already-resolved `ue_ip` into `resolve_protected_ports` so host and protected ports come from the same generation. Phase 1 (the existing `2026-04-27-real-ue-self-heal-retry.md` plan) is a multi-task self-heal retry framework whose ROI is unknown until Phase 0 ships and a measurement campaign quantifies the residual stale rate.

**Tech Stack:** Python 3.12, pytest/unittest, existing `RealUEDirectResolver` and `CampaignExecutor` codepaths, jsonl campaign output, real Samsung A31 / A16 / Pixel UEs against the IMS testbed at `163.180.185.51`.

---

## File Map

- Modify: `src/volte_mutation_fuzzer/campaign/core.py`
  - `_resolve_ports_live` accepts an optional `ue_ip` and forwards it to `resolve_protected_ports`.
  - The call site at line 1018 passes the `ue_ip` resolved at line 1007.

- Test: `tests/campaign/test_core.py`
  - One new unit test that proves `_resolve_ports_live` forwards `ue_ip` to the resolver. Existing `patch.object(..., "_resolve_ports_live", return_value=(8100, 8101))` mocks accept any signature, so they keep passing.

- Create (in Task 3, not yet present): `docs/이슈/2026-04-28-real-ue-stale-baseline.md`
  - Measurement worklog with before/after timeout counts plus the Phase 1 go/no-go decision and reasoning. The file does not exist until Task 3 runs the campaign and records the numbers.

- Reference (no edits in this plan): `docs/superpowers/plans/2026-04-27-real-ue-self-heal-retry.md`
  - Phase 1 plan. Phase 0's measurement gate decides whether Phase 1 stays at its current scope, shrinks, or is deferred.

## Non-Goals

- No new attempt-trace contracts, payload classifier, or retry loop in this plan. Those are Phase 1 and only execute if Phase 0 measurement justifies them.
- No changes to `RealUEDirectResolver`, `sender/core.py`, `sender/cli.py`, or `campaign/report.py`.
- No new CLI flags or user-facing options. The fix is internal.
- No retroactive change to existing test mocks of `_resolve_ports_live`. The new keyword-only parameter is optional and backward-compatible.

---

## Phase 0 — Uncoupled-lookup fix

### Task 1: Add a failing test for `_resolve_ports_live(ue_ip=...)` forwarding

**Files:**
- Test: `tests/campaign/test_core.py`

- [ ] **Step 1: Locate the existing `CampaignExecutor` test fixture style**

Run: `grep -n "class .*TestCase\|def test_.*resolve" tests/campaign/test_core.py | head`

The new test goes inside the same `unittest.TestCase` class that already exercises `_resolve_ports_live` mocks (around line 478 and 827). Pick the first such class; do not introduce a new test file.

- [ ] **Step 2: Write the failing test**

Append the test inside the existing `CampaignExecutor` test class (the same class that contains the current `patch.object(executor, "_resolve_ports_live", return_value=(8100, 8101))` blocks):

```python
def test_resolve_ports_live_forwards_ue_ip_to_resolver(self) -> None:
    """The MT campaign path resolves ue_ip and ports separately. The fix
    threads the already-resolved ue_ip into resolve_protected_ports so
    a re-registration between the two lookups cannot land us on a
    different generation of port_pc/port_ps."""
    executor = self._build_executor_with_minimal_config()
    captured: dict[str, object] = {}

    def fake_resolve_protected_ports(msisdn: str, *, ue_ip: str | None = None):
        captured["msisdn"] = msisdn
        captured["ue_ip"] = ue_ip
        return (8100, 8101)

    with unittest.mock.patch.object(
        executor._ue_resolver,
        "resolve_protected_ports",
        side_effect=fake_resolve_protected_ports,
    ):
        port_pc, port_ps = executor._resolve_ports_live(
            "111111", ue_ip="10.20.20.8"
        )

    self.assertEqual((port_pc, port_ps), (8100, 8101))
    self.assertEqual(captured["msisdn"], "111111")
    self.assertEqual(captured["ue_ip"], "10.20.20.8")
```

If a `_build_executor_with_minimal_config` helper does not exist in the file, copy the executor construction pattern used by the nearest existing test (search for `executor = CampaignExecutor(` in `tests/campaign/test_core.py`). Inline the construction; do **not** add a new helper for one test.

- [ ] **Step 3: Run the test to confirm it fails**

Run: `uv run pytest tests/campaign/test_core.py -k test_resolve_ports_live_forwards_ue_ip_to_resolver -v`

Expected: FAIL with `TypeError: _resolve_ports_live() got an unexpected keyword argument 'ue_ip'`. This proves the test exercises the missing parameter rather than passing trivially.

- [ ] **Step 4: Commit the failing test alone**

```bash
git add tests/campaign/test_core.py
git commit -m "test(campaign): cover _resolve_ports_live forwarding ue_ip"
```

The failing-test-first commit lets the next reviewer (or `git bisect`) see the regression boundary clearly.

### Task 2: Thread `ue_ip` through `_resolve_ports_live`

**Files:**
- Modify: `src/volte_mutation_fuzzer/campaign/core.py:880-890`
- Modify: `src/volte_mutation_fuzzer/campaign/core.py:1018`

- [ ] **Step 1: Update `_resolve_ports_live` to accept and forward `ue_ip`**

Replace lines 880-890:

```python
def _resolve_ports_live(
    self, msisdn: str, *, ue_ip: str | None = None,
) -> tuple[int, int]:
    """Resolve (port_pc, port_ps) fresh on every call.

    Caching was previously used to avoid docker-logs overhead per case,
    but UEs re-register frequently (especially Samsung A16 / Pixel-class
    spec-strict stacks during long campaigns). A stale cache silently
    sends to the old protected ports for the rest of the run, which
    masquerades as "all timeout" — indistinguishable from a real
    non-responsive UE. The ~150 ms per case is worth the correctness.

    ``ue_ip`` is forwarded so the resolver filters protected-port
    candidates by the same generation of UE IP that the caller already
    resolved. Without it, a re-registration between the caller's
    ``resolve()`` and this call could land us on a port pair from a
    newer or older generation than the host we are about to send to.
    """
    return self._ue_resolver.resolve_protected_ports(msisdn, ue_ip=ue_ip)
```

- [ ] **Step 2: Update the call site at line 1018**

The MT template flow at lines 1006-1018 already resolves `ue_ip` via `self._ue_resolver.resolve(self._target, impi=impi)` and stores it in the `ue_ip` local. Pass that value through:

```python
# 2. Resolve live port_pc / port_ps (no caching — UE re-registration
#    invalidates ports and stale values silently masquerade as timeouts).
#    Pass ue_ip so the protected-port lookup is filtered against the
#    same generation as the host we just resolved on the line above.
port_pc, port_ps = self._resolve_ports_live(
    config.target_msisdn, ue_ip=ue_ip,
)
```

`ue_ip` here is the `str` value that lines 1003-1007 already populate (either `config.target_host` or `resolved.host`). It is always non-None at this point because lines 1006-1009 unconditionally assign it before the early `raise ValueError` for missing IMPI.

- [ ] **Step 3: Run the new test to confirm it passes**

Run: `uv run pytest tests/campaign/test_core.py -k test_resolve_ports_live_forwards_ue_ip_to_resolver -v`

Expected: PASS.

- [ ] **Step 4: Run the full campaign test module to confirm no regression**

Run: `uv run pytest tests/campaign/test_core.py -q`

Expected: All tests in the file pass. Existing `patch.object(executor, "_resolve_ports_live", return_value=(8100, 8101))` mocks ignore the new keyword argument (`patch.object` does not enforce signature compatibility), so legacy tests remain green.

If any unrelated test fails because it now receives a `ue_ip` keyword it did not expect, do **not** edit that test in this task — re-read the failure carefully. The expected outcome is no test changes needed.

- [ ] **Step 5: Run the broader regression**

Run: `uv run pytest --ignore=tests/adb --ignore=tests/sender -q`

Expected: 720+ passed (the previous green baseline was 719; the new test adds one). The pre-existing 5 failures in `tests/adb` and `tests/sender` are documented as unrelated and may be skipped.

- [ ] **Step 6: Commit the fix**

```bash
git add src/volte_mutation_fuzzer/campaign/core.py
git commit -m "$(cat <<'EOF'
fix(campaign): pass ue_ip through _resolve_ports_live to avoid stale port pair

The MT template path resolves ue_ip and (port_pc, port_ps) via two
independent lookups. If the UE re-registers between them, the fuzzer
sends to a host from one generation and ports from another — wire
arrives at the right machine but the wrong protected-port pair, the
UE silently drops the datagram, and the case logs as "timeout" with
no indication that the cause was uncoupled resolution rather than a
non-responsive UE.

Thread the already-resolved ue_ip into resolve_protected_ports so
both halves of the live bundle are filtered by the same generation.

This is Phase 0 of the real-ue self-heal plan. The measurement that
follows decides whether the broader Phase 1 (attempt-trace + payload
classifier + same-case retry) is still warranted.
EOF
)"
```

### Task 3: Measurement campaign + Phase 1 go/no-go decision

**Files:**
- Create: `docs/이슈/2026-04-28-real-ue-stale-baseline.md`

This task records empirical data, not code. It exists in the plan because the next plan (Phase 1) depends on its outcome.

- [ ] **Step 1: Capture the pre-fix baseline if available**

Look at the most recent `real-ue-direct` campaign jsonl files prior to the Phase 0 commit:

Run: `ls -t results/ | head -5`

Pick the most recent `--mode real-ue-direct --methods INVITE` campaign with `--strategy default --profile delivery_preserving` of at least 30 cases. Note its directory path. If no such campaign exists in `results/`, skip this step and rely only on the post-fix measurement (the comparison will be against zero baseline).

Extract the timeout count:

```bash
# Replace <campaign-dir> with the actual directory.
jq -r 'select(.verdict == "timeout") | .case_id' \
    results/<campaign-dir>/campaign.jsonl | wc -l
```

Record the absolute count and the total case count.

- [ ] **Step 2: Run a fresh post-fix measurement campaign**

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --methods INVITE \
  --layer wire \
  --strategy default \
  --profile delivery_preserving \
  --mt-invite-template a31 \
  --ipsec-mode null \
  --preserve-contact --preserve-via \
  --max-cases 50 \
  --output-name phase0-stale-baseline
```

Wait for completion. Capture the resulting `results/<timestamp>_<id>/` path.

- [ ] **Step 3: Extract post-fix timeout count from the new run**

```bash
jq -r 'select(.verdict == "timeout") | .case_id' \
    results/<post-fix-dir>/campaign.jsonl | wc -l
```

Also capture the verdict distribution for context:

```bash
jq -r '.verdict' results/<post-fix-dir>/campaign.jsonl | sort | uniq -c
```

- [ ] **Step 4: Write the measurement worklog**

Create `docs/이슈/2026-04-28-real-ue-stale-baseline.md` with this exact structure:

```markdown
# 2026-04-28 real-ue-direct stale-endpoint baseline

Phase 0 (`_resolve_ports_live` 가 `ue_ip` 결합) 가 timeout 분포에 미친 영향 측정.

## 측정 조건

- 캠페인 옵션: `--mode real-ue-direct --target-msisdn 111111 --methods INVITE --layer wire --strategy default --profile delivery_preserving --mt-invite-template a31 --ipsec-mode null --max-cases 50`
- 단말: <Samsung A31 / A16 / Pixel — 실제 사용한 모델>
- 서버: 163.180.185.51 (`fuzzer-pcscf` netns 의 P-CSCF)

## 결과

| 시점 | 캠페인 dir | 총 케이스 | timeout | timeout 비율 |
|---|---|---|---|---|
| 사전 (Phase 0 전) | `results/<pre-fix-dir>` | <N> | <T_pre> | <T_pre/N %> |
| 사후 (Phase 0 후) | `results/<post-fix-dir>` | 50 | <T_post> | <T_post/50 %> |

verdict 분포 (사후):

```
<jq output 붙여넣기>
```

## 해석

- 절대 감소: <T_pre/N - T_post/50>%p
- 상대 감소: <(T_pre/N - T_post/50) / (T_pre/N) * 100>%

## Phase 1 결정

기준:

- 잔여 timeout 비율 < 10% → Phase 1 보류 (현재 risk 가 ROI 에 비해 낮음)
- 잔여 timeout 비율 10~30% → Phase 1 축소 진행 (sender 트랙은 보류, MT 트랙만 진행)
- 잔여 timeout 비율 > 30% → Phase 1 전체 진행 (`docs/superpowers/plans/2026-04-27-real-ue-self-heal-retry.md`)

본 측정 결과 잔여 비율 = <T_post/50 %>.

따라서 결정: <보류 / 축소 진행 / 전체 진행> 중 하나.

근거: <한 줄로 의사결정 이유 — 예: "10% 미만이라 stale 이슈는 Phase 0 만으로 실용적 해결됨; Phase 1 의 attempt_trace 가시화는 별도 가치가 있어 분리 plan 으로 follow-up">.

## 주의

- 잔여 timeout 의 일부는 stale 이 아니라 실제 UE 무응답 (예: 단말 ringing 중 ESP 거부, 단말 SIP stack 의 정상 4xx 응답이 oracle 에서 timeout 으로 분류) 일 수 있다. timeout=stale 등식이 아님을 인지.
- 측정 표본 50 케이스는 통계적 유의미성보다 운영 의사결정용 단일 데이터 포인트. 결과가 경계에 걸리면 200 케이스로 확장.
```

Replace every `<...>` placeholder with the measured number. Do not commit until every placeholder is filled — placeholders defeat the purpose of this task.

- [ ] **Step 5: Commit the measurement worklog**

```bash
git add "docs/이슈/2026-04-28-real-ue-stale-baseline.md"
git commit -m "docs(이슈): real-ue-direct Phase 0 stale-endpoint baseline 측정"
```

- [ ] **Step 6: Update the Phase 1 plan with the gating result**

Open `docs/superpowers/plans/2026-04-27-real-ue-self-heal-retry.md` and add a `## Status` block immediately under the existing header (above `## File Map`):

```markdown
## Status

- 2026-04-28: Phase 0 (`_resolve_ports_live` ue_ip 결합) shipped in commit `<phase-0-commit-sha>`. Post-fix stale-endpoint timeout 비율 = `<T_post/50 %>` (`docs/이슈/2026-04-28-real-ue-stale-baseline.md`).
- 결정: `<보류 / 축소 진행 / 전체 진행>` — 사유는 measurement worklog 참조.
```

Replace `<phase-0-commit-sha>` with the SHA from Task 2 Step 6 (`git log -1 --format=%h`) and the `<...>` fields with the same values you used in the worklog.

- [ ] **Step 7: Commit the status update**

```bash
git add docs/superpowers/plans/2026-04-27-real-ue-self-heal-retry.md
git commit -m "docs(plan): record Phase 0 outcome in self-heal-retry plan status"
```

---

## Self-Review

**Spec coverage:**
- Phase 0 fix (uncoupled-lookup) → Task 2 (implementation) plus Task 1 (failing test).
- Phase 0 verification → Task 2 Steps 3-5 (unit + module + broad regression).
- Measurement step → Task 3 Steps 1-3.
- Decision gate for Phase 1 → Task 3 Step 4 ("Phase 1 결정" section in worklog) and Task 3 Step 6 (Status block in Phase 1 plan).
- Reference to existing Phase 1 plan → File Map ("Reference"). No content duplication.

**Placeholder scan:** The only `<...>` placeholders left are inside the Step 4 worklog template, where they are explicitly populated from measured data in the same step. No "TBD" or "implement later" markers in any executable step.

**Type consistency:** `_resolve_ports_live(self, msisdn, *, ue_ip=None) -> tuple[int, int]` is used identically in Task 1 (test), Task 2 Step 1 (definition), and Task 2 Step 2 (call site). `ue_ip` keyword-only matches `RealUEDirectResolver.resolve_protected_ports`'s existing signature at `src/volte_mutation_fuzzer/sender/real_ue.py:507-509`. The `T_pre`, `T_post`, `N` placeholders in Task 3 Step 4 are reused consistently in the "해석" section of the same step.

---

**Plan complete and saved to `docs/superpowers/plans/2026-04-27-real-ue-self-heal-phasing.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**
