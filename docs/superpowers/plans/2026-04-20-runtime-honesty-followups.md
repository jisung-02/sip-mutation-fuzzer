# Runtime Honesty Follow-Ups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tighten the remaining SIP completeness claims so stateless/event methods, real-UE dialog routing, and runnable docs match what the repo can honestly execute today.

**Architecture:** Re-audit the remaining non-INVITE methods through the current completeness registry instead of widening support by prose alone. Promote only the methods whose runtime path is already owned by the repo, fix `real-ue-direct` routing so dialog-dependent methods do not silently fall back to standalone packet sends, and then clean runtime-adjacent docs/examples to reflect the updated truth.

**Tech Stack:** Python 3.12, pytest, pydantic SIP models, campaign/dialog runtime, Markdown docs

---

### Task 1: Re-audit prerequisite-state methods

**Files:**
- Modify: `src/volte_mutation_fuzzer/sip/completeness.py`
- Modify: `tests/sip/test_packet_completeness.py`
- Modify: `docs/프로토콜/SIP-메시지-완성도-매트릭스.md`

- [ ] Write a failing completeness test for any method whose runtime claim is currently too weak or too strong.
- [ ] Update the registry only for methods whose runtime path is already owned by the repo.
- [ ] Re-run the packet completeness tests and keep the matrix/docs aligned with the registry.

### Task 2: Fix real-UE dialog routing honesty

**Files:**
- Modify: `src/volte_mutation_fuzzer/campaign/core.py`
- Modify: `tests/campaign/test_core.py`
- Modify: `docs/USAGE.md`
- Modify: `docs/ARCHITECTURE.md`

- [ ] Write a failing campaign test that proves dialog-dependent methods in `real-ue-direct` should not be captured by the MT standalone path when a dialog runtime path exists.
- [ ] Reorder or narrow execution routing so dialog methods keep their honest setup path while standalone INVITE/MT cases still use the MT builder.
- [ ] Document the actual real-UE validation boundary after the routing fix.

### Task 3: Clean runtime-adjacent examples and AI guidance

**Files:**
- Modify: `README.md`
- Modify: `docs/AI_AGENT_GUIDE.md`
- Modify: `docs/구현-문서.md`
- Modify: `src/volte_mutation_fuzzer/packet_docs.py`

- [ ] Replace or qualify misleading placeholder examples in runnable or guidance-heavy surfaces.
- [ ] Keep research/archive documents out of scope unless they are directly used as runnable instructions.
- [ ] Reconcile AI guidance with the updated completeness and real-UE routing rules.

### Task 4: Verify and review

**Files:**
- Test: `tests/sip/test_packet_completeness.py`
- Test: `tests/campaign/test_core.py`
- Test: `tests/campaign/test_dialog_integration.py`
- Test: `tests/dialog/test_core.py`
- Test: `tests/dialog/test_scenarios.py`

- [ ] Run focused pytest suites for completeness and campaign/dialog routing.
- [ ] Run `git diff --check`.
- [ ] Perform a final clean review pass and report any remaining work that still depends on external lab validation.
