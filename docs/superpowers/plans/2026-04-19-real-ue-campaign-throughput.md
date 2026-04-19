# Real-UE Campaign Throughput Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce `real-ue-direct` per-case wall-clock time from the current ~10-14 s range for non-INVITE cases to roughly ~3-5 s without regressing delayed crash detection for `INVITE`.

**Architecture:** Keep `INVITE` conservative, but cut fixed overhead for the rest of the campaign. Measure true case wall time separately from socket elapsed time, make oracle grace adaptive by SIP method while preserving explicit user overrides, split ADB snapshots into light/full profiles so every case keeps log evidence but only interesting cases pay the heavy shell cost, and then parallelize the remaining full-snapshot shell commands.

**Tech Stack:** Python 3.12, Pydantic models, `subprocess`, `ThreadPoolExecutor`, pytest, existing `AdbLogCollector` history slicing.

---

## File Structure

- Modify: `src/volte_mutation_fuzzer/campaign/contracts.py`
  - Add a `case_wall_ms` field to `CaseResult`.
  - Add a method-aware grace helper on `CampaignConfig` that preserves explicit `oracle_log_grace_seconds` overrides.
- Modify: `src/volte_mutation_fuzzer/campaign/core.py`
  - Measure real wall-clock per case.
  - Route oracle grace through the new helper.
  - Centralize ADB snapshot capture and choose `light` vs `full` profile by verdict.
- Modify: `src/volte_mutation_fuzzer/adb/core.py`
  - Add `profile="light" | "full"` to `take_snapshot`.
  - Keep collector-sliced logcat in both profiles.
  - Parallelize full-profile shell dumps.
- Modify: `src/volte_mutation_fuzzer/campaign/report.py`
  - Surface `case_wall_ms` in HTML so throughput tuning is visible without opening JSONL.
- Modify: `tests/campaign/test_contracts.py`
  - Lock in adaptive grace policy and explicit-override behavior.
- Modify: `tests/campaign/test_core.py`
  - Lock in `case_wall_ms` recording and snapshot profile selection.
- Modify: `tests/adb/test_core.py`
  - Lock in light/full snapshot behavior and full-profile concurrency.
- Modify: `tests/campaign/test_report.py`
  - Lock in rendering of wall-clock metrics.
- Modify: `docs/A31_REAL_UE_GUIDE.md`
  - Document adaptive grace defaults, snapshot policy, and expected throughput trade-offs.
- Modify: `docs/TROUBLESHOOTING.md`
  - Document how to reason about `elapsed_ms` vs `case_wall_ms`.

## Non-Goals

- Do not change `INVITE` delayed-crash sensitivity in this plan. `INVITE` keeps the current long grace window.
- Do not add background ADB snapshot workers in this plan. Heavy snapshots remain synchronous but should become rare.
- Do not change iOS collection logic in this plan.
- Do not change pcap capture semantics beyond what already shipped.

### Task 1: Add True Case Wall-Clock Telemetry

**Files:**
- Modify: `src/volte_mutation_fuzzer/campaign/contracts.py`
- Modify: `src/volte_mutation_fuzzer/campaign/core.py`
- Modify: `src/volte_mutation_fuzzer/campaign/report.py`
- Test: `tests/campaign/test_core.py`
- Test: `tests/campaign/test_report.py`

- [ ] **Step 1: Write the failing tests for `case_wall_ms`**

```python
def test_execute_case_records_case_wall_ms(self) -> None:
    cfg = self._make_config(
        "127.0.0.1",
        5060,
        methods=("OPTIONS",),
        max_cases=1,
    )
    executor = CampaignExecutor(cfg)
    spec = CaseSpec(
        case_id=0,
        seed=0,
        method="OPTIONS",
        layer="model",
        strategy="default",
    )
    send_result = SendReceiveResult(
        target=TargetEndpoint(host="127.0.0.1", port=5060),
        artifact_kind="packet",
        bytes_sent=120,
        outcome="success",
        responses=(
            SocketObservation(
                status_code=200,
                reason_phrase="OK",
                raw_text="SIP/2.0 200 OK\r\n\r\n",
                classification="success",
            ),
        ),
        send_started_at=100.1,
        send_completed_at=100.2,
    )

    with unittest.mock.patch.object(
        executor._sender,
        "send_artifact",
        return_value=send_result,
    ), unittest.mock.patch.object(
        executor._oracle,
        "evaluate",
        return_value=SimpleNamespace(
            verdict="normal",
            reason="ok",
            response_code=200,
            elapsed_ms=100.0,
            process_alive=True,
            details={},
        ),
    ), unittest.mock.patch(
        "volte_mutation_fuzzer.campaign.core.time.monotonic",
        side_effect=[10.0, 10.9],
    ):
        result = executor._execute_case(spec)

    self.assertEqual(result.case_wall_ms, 900.0)


def test_cases_table_renders_wall_ms(self) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        jsonl_path = Path(tmpdir) / "campaign.jsonl"
        store = ResultStore(jsonl_path)
        header = CampaignResult(
            campaign_id="abc123",
            started_at="2026-04-19T00:00:00+00:00",
            status="running",
            config=CampaignConfig(
                target_host="127.0.0.1",
                target_port=5060,
                methods=("OPTIONS",),
            ),
            summary=CampaignSummary(total=1, normal=1),
        )
        store.write_header(header)
        store.append(
            CaseResult(
                case_id=0,
                seed=0,
                method="OPTIONS",
                layer="model",
                strategy="default",
                verdict="normal",
                reason="ok",
                elapsed_ms=42.0,
                case_wall_ms=913.0,
                reproduction_cmd="uv run fuzzer campaign run --target-host 127.0.0.1 --target-port 5060 --methods OPTIONS --max-cases 1",
                timestamp=1.0,
            )
        )
        store.write_footer(header.model_copy(update={"status": "completed"}))

        content = HtmlReportGenerator(jsonl_path).generate().read_text()

    self.assertIn("Wall", content)
    self.assertIn("913", content)
```

- [ ] **Step 2: Run the targeted tests and verify they fail**

Run: `uv run pytest tests/campaign/test_core.py -k case_wall_ms -q`
Expected: FAIL because `CaseResult` has no `case_wall_ms` field yet.

Run: `uv run pytest tests/campaign/test_report.py -k wall_ms -q`
Expected: FAIL because the report does not render the field yet.

- [ ] **Step 3: Add `case_wall_ms` to `CaseResult` and measure it in the executors**

```python
class CaseResult(BaseModel):
    """Result of executing a single test case, including oracle verdict."""

    model_config = ConfigDict(extra="forbid")

    case_id: int = Field(ge=0)
    seed: int = Field(ge=0)
    method: str
    layer: str
    strategy: str
    mutation_ops: tuple[str, ...] = Field(default_factory=tuple)
    verdict: str
    reason: str
    response_code: int | None = None
    elapsed_ms: float
    case_wall_ms: float | None = None
    process_alive: bool | None = None
    raw_response: str | None = None
    reproduction_cmd: str
    error: str | None = None
    details: dict[str, object] = Field(default_factory=dict)
    timestamp: float
    fuzz_response_code: int | None = None
    fuzz_related_method: str | None = None
    pcap_path: str | None = None
```

```python
def _build_case_result(
    self,
    *,
    case_started_monotonic: float,
    **kwargs: object,
) -> CaseResult:
    return CaseResult(
        **kwargs,
        case_wall_ms=round(
            (time.monotonic() - case_started_monotonic) * 1000,
            3,
        ),
    )
```

```python
case_started_monotonic = time.monotonic()

case_result = self._build_case_result(
        case_started_monotonic=case_started_monotonic,
        case_id=spec.case_id,
        seed=spec.seed,
        method=spec.method,
        layer=spec.layer,
        strategy=spec.strategy,
        mutation_ops=mutation_ops,
        verdict=verdict.verdict,
        reason=verdict.reason,
        response_code=verdict.response_code,
        elapsed_ms=verdict.elapsed_ms,
        process_alive=verdict.process_alive,
        raw_response=raw_response,
        reproduction_cmd=self._build_reproduction_cmd(spec),
        error=error,
        details=getattr(verdict, "details", {}) or {},
        timestamp=timestamp,
        fuzz_response_code=spec.response_code,
        fuzz_related_method=spec.related_method,
        pcap_path=pcap_path_saved,
    )

return case_result
```

```python
headers = [
    "ID",
    "Method",
    "Layer",
    "Strategy",
    "Seed",
    "Verdict",
    "Code",
    "Elapsed",
    "Wall",
    "Context",
]
```

```python
wall_ms = "-" if c.case_wall_ms is None else f"{c.case_wall_ms:.0f}"
parts.append(
    "<tr>"
    f"<td>{c.case_id}</td>"
    f"<td>{_esc(c.method)}</td>"
    f"<td>{_esc(c.layer)}</td>"
    f"<td>{_esc(c.strategy)}</td>"
    f"<td>{c.seed}</td>"
    f"<td>{_esc(c.verdict)}</td>"
    f"<td>{c.response_code or ''}</td>"
    f"<td>{c.elapsed_ms:.0f}</td>"
    f"<td>{wall_ms}</td>"
    f"<td>{_esc(_context_lines(c.details))}</td>"
    "</tr>"
)
```

- [ ] **Step 4: Run the targeted tests and verify they pass**

Run: `uv run pytest tests/campaign/test_core.py -k case_wall_ms -q`
Expected: PASS

Run: `uv run pytest tests/campaign/test_report.py -k wall_ms -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add \
  src/volte_mutation_fuzzer/campaign/contracts.py \
  src/volte_mutation_fuzzer/campaign/core.py \
  src/volte_mutation_fuzzer/campaign/report.py \
  tests/campaign/test_core.py \
  tests/campaign/test_report.py
git commit -m "feat: record campaign case wall-clock metrics"
```

### Task 2: Make Oracle Grace Adaptive by SIP Method

**Files:**
- Modify: `src/volte_mutation_fuzzer/campaign/contracts.py`
- Modify: `src/volte_mutation_fuzzer/campaign/core.py`
- Test: `tests/campaign/test_contracts.py`
- Test: `tests/campaign/test_core.py`

- [ ] **Step 1: Write the failing tests for adaptive grace**

```python
def test_real_ue_adaptive_grace_defaults_by_method(self) -> None:
    cfg = CampaignConfig(
        mode="real-ue-direct",
        target_msisdn="111111",
        target_port=5060,
        methods=("OPTIONS",),
    )

    self.assertEqual(cfg.oracle_log_grace_seconds_for_method("INVITE"), 8.0)
    self.assertEqual(cfg.oracle_log_grace_seconds_for_method("OPTIONS"), 1.0)
    self.assertEqual(cfg.oracle_log_grace_seconds_for_method("BYE"), 2.0)


def test_explicit_oracle_grace_override_is_preserved(self) -> None:
    cfg = CampaignConfig(
        mode="real-ue-direct",
        target_msisdn="111111",
        target_port=5060,
        methods=("OPTIONS",),
        oracle_log_grace_seconds=6.5,
    )

    self.assertEqual(cfg.oracle_log_grace_seconds_for_method("INVITE"), 6.5)
    self.assertEqual(cfg.oracle_log_grace_seconds_for_method("OPTIONS"), 6.5)
```

```python
def test_execute_case_uses_method_specific_oracle_grace(self) -> None:
    cfg = self._make_config(
        "127.0.0.1",
        5060,
        mode="real-ue-direct",
        target_msisdn="111111",
        methods=("OPTIONS",),
        max_cases=1,
    )
    executor = CampaignExecutor(cfg)
    spec = CaseSpec(
        case_id=0,
        seed=0,
        method="OPTIONS",
        layer="model",
        strategy="default",
    )
    send_result = SendReceiveResult(
        target=TargetEndpoint(host="127.0.0.1", port=5060),
        artifact_kind="packet",
        bytes_sent=120,
        outcome="success",
        responses=(),
        send_started_at=100.1,
        send_completed_at=100.2,
    )

    with unittest.mock.patch.object(
        executor._sender,
        "send_artifact",
        return_value=send_result,
    ), unittest.mock.patch.object(
        executor._oracle,
        "evaluate",
        return_value=SimpleNamespace(
            verdict="normal",
            reason="ok",
            response_code=200,
            elapsed_ms=12.5,
            process_alive=True,
            details={},
        ),
    ) as evaluate_mock:
        executor._execute_case(spec)

    context = evaluate_mock.call_args.args[1]
    self.assertEqual(context.log_grace_seconds, 1.0)
```

- [ ] **Step 2: Run the targeted tests and verify they fail**

Run: `uv run pytest tests/campaign/test_contracts.py -k grace -q`
Expected: FAIL because `CampaignConfig` has no method-specific helper.

Run: `uv run pytest tests/campaign/test_core.py -k method_specific_oracle_grace -q`
Expected: FAIL because `_execute_case()` still passes a fixed grace value.

- [ ] **Step 3: Implement the helper and use it in all executor paths**

```python
def oracle_log_grace_seconds_for_method(self, method: str) -> float:
    if (
        "oracle_log_grace_seconds" in self.model_fields_set
        and self.oracle_log_grace_seconds is not None
    ):
        return self.oracle_log_grace_seconds

    if self.mode != "real-ue-direct":
        return 0.0

    normalized = method.upper()
    if normalized == "INVITE":
        return 8.0
    if normalized in {"ACK", "CANCEL", "PRACK", "BYE", "UPDATE", "REFER", "INFO"}:
        return 2.0
    return 1.0
```

```python
context = OracleContext(
    method=spec.related_method or spec.method,
    timeout_threshold_ms=config.timeout_seconds * 1000,
    log_grace_seconds=config.oracle_log_grace_seconds_for_method(
        spec.related_method or spec.method
    ),
)
```

```python
context = OracleContext(
    method=spec.method,
    timeout_threshold_ms=config.timeout_seconds * 1000,
    log_grace_seconds=config.oracle_log_grace_seconds_for_method(spec.method),
)
```

- [ ] **Step 4: Run the targeted tests and verify they pass**

Run: `uv run pytest tests/campaign/test_contracts.py -k grace -q`
Expected: PASS

Run: `uv run pytest tests/campaign/test_core.py -k method_specific_oracle_grace -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add \
  src/volte_mutation_fuzzer/campaign/contracts.py \
  src/volte_mutation_fuzzer/campaign/core.py \
  tests/campaign/test_contracts.py \
  tests/campaign/test_core.py
git commit -m "perf: make oracle grace adaptive by sip method"
```

### Task 3: Split ADB Snapshots into Light and Full Profiles

**Files:**
- Modify: `src/volte_mutation_fuzzer/adb/core.py`
- Test: `tests/adb/test_core.py`

- [ ] **Step 1: Write the failing tests for light/full snapshot behavior**

```python
def test_take_snapshot_light_profile_omits_heavy_shell_outputs(tmp_path: Path) -> None:
    output_dir = tmp_path / "snapshots"
    connector = AdbConnector(serial="SERIAL")
    collector = AdbLogCollector()
    collector.push_for_test("main", "04-19 10:00:00.000 first", timestamp=1.1)
    collector.push_for_test("radio", "04-19 10:00:00.500 second", timestamp=1.5)

    with patch.object(
        connector,
        "run_shell",
        return_value=_DummyCompletedProcess(stdout="  mCallState=0\n"),
    ) as shell_mock:
        snapshot = connector.take_snapshot(
            str(output_dir),
            collector=collector,
            log_since=1.0,
            log_until=2.0,
            profile="light",
        )

    assert snapshot.telephony_path is not None
    assert snapshot.ims_path is None
    assert snapshot.netstat_path is None
    assert snapshot.meminfo_path is None
    assert snapshot.dmesg_path is None
    assert (output_dir / "logcat_all.txt").exists()
    shell_mock.assert_called_once_with("dumpsys", "telephony.registry", timeout=30)
```

```python
def test_take_snapshot_full_profile_preserves_existing_outputs(tmp_path: Path) -> None:
    output_dir = tmp_path / "snapshots"
    connector = AdbConnector(serial="SERIAL")

    with patch.object(
        connector,
        "run_shell",
        side_effect=[
            _DummyCompletedProcess(stdout="telephony output\n"),
            _DummyCompletedProcess(stdout="ims output\n"),
            _DummyCompletedProcess(stdout="netstat output\n"),
            _DummyCompletedProcess(stdout="meminfo output\n"),
            _DummyCompletedProcess(stdout="dmesg output\n"),
        ],
    ):
        snapshot = connector.take_snapshot(str(output_dir), profile="full")

    assert snapshot.telephony_path is not None
    assert snapshot.ims_path is not None
    assert snapshot.netstat_path is not None
    assert snapshot.meminfo_path is not None
    assert snapshot.dmesg_path is not None
```

- [ ] **Step 2: Run the targeted tests and verify they fail**

Run: `uv run pytest tests/adb/test_core.py -k "light_profile or full_profile" -q`
Expected: FAIL because `take_snapshot()` has no `profile` argument yet.

- [ ] **Step 3: Add `profile` support while preserving collector-sliced logcat**

```python
SnapshotProfile = Literal["light", "full"]


def _write_logcat_outputs(
    self,
    base_dir: Path,
    *,
    collector: "AdbLogCollector | None",
    log_since: float | None,
    log_until: float | None,
    errors: list[str],
) -> str | None:
    logcat_path: str | None = None
    logcat_buffers = ("main", "system", "radio", "crash")

    if collector is not None and log_since is not None and log_until is not None:
        log_lines = collector.slice(log_since, log_until)
        combined_lines = [line for buffer_name, line in log_lines if buffer_name in logcat_buffers]
        for buf in logcat_buffers:
            matched = [line for buffer_name, line in log_lines if buffer_name == buf]
            if not matched:
                continue
            buf_file = base_dir / f"logcat_{buf}.txt"
            buf_file.write_text("\n".join(matched) + "\n", encoding="utf-8")
        if combined_lines:
            logcat_file = base_dir / "logcat_all.txt"
            logcat_file.write_text("\n".join(combined_lines) + "\n", encoding="utf-8")
            logcat_path = str(logcat_file)
        return logcat_path

    for buf in logcat_buffers:
        try:
            buf_file = base_dir / f"logcat_{buf}.txt"
            result = subprocess.run(
                self._adb_cmd("logcat", "-d", "-b", buf),
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0 and result.stdout:
                buf_file.write_text(result.stdout, encoding="utf-8")
        except Exception as exc:
            errors.append(f"logcat -b {buf} failed: {exc}")

    try:
        logcat_file = base_dir / "logcat_all.txt"
        result = subprocess.run(
            self._adb_cmd("logcat", "-d", "-b", ",".join(logcat_buffers)),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout:
            logcat_file.write_text(result.stdout, encoding="utf-8")
            logcat_path = str(logcat_file)
    except Exception as exc:
        errors.append(f"logcat dump failed: {exc}")

    return logcat_path


def take_snapshot(
    self,
    output_dir: str,
    *,
    bugreport: bool = False,
    collector: "AdbLogCollector | None" = None,
    log_since: float | None = None,
    log_until: float | None = None,
    profile: SnapshotProfile = "full",
) -> AdbSnapshotResult:
    base_dir = Path(output_dir)
    base_dir.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []
    bugreport_path: str | None = None

    telephony_path = _write_shell_output(
        "telephony.txt", "dumpsys", "telephony.registry", timeout=30
    )
    logcat_path = _write_logcat_outputs(
        base_dir,
        collector=collector,
        log_since=log_since,
        log_until=log_until,
        errors=errors,
    )

    ims_path: str | None = None
    netstat_path: str | None = None
    meminfo_path: str | None = None
    dmesg_path: str | None = None

    if profile == "full":
        ims_path = _write_shell_output("ims.txt", "dumpsys", "ims", timeout=30)
        netstat_path = _write_shell_output("netstat.txt", "netstat", "-tlnup", timeout=10)
        meminfo_path = _write_shell_output("meminfo.txt", "dumpsys", "meminfo", timeout=60)
        dmesg_path = _write_shell_output("dmesg.txt", "dmesg", timeout=60)

    return AdbSnapshotResult(
        meminfo_path=meminfo_path,
        dmesg_path=dmesg_path,
        bugreport_path=bugreport_path,
        logcat_path=logcat_path,
        telephony_path=telephony_path,
        ims_path=ims_path,
        netstat_path=netstat_path,
        errors=tuple(errors),
    )
```

- [ ] **Step 4: Run the targeted tests and verify they pass**

Run: `uv run pytest tests/adb/test_core.py -k "light_profile or full_profile" -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/volte_mutation_fuzzer/adb/core.py tests/adb/test_core.py
git commit -m "perf: add light and full adb snapshot profiles"
```

### Task 4: Use Light Snapshots for Every Case and Full Snapshots for Interesting Verdicts

**Files:**
- Modify: `src/volte_mutation_fuzzer/campaign/core.py`
- Test: `tests/campaign/test_core.py`

- [ ] **Step 1: Write the failing tests for snapshot profile selection**

```python
def test_execute_case_uses_light_snapshot_for_normal_verdict(self) -> None:
    cfg = self._make_config(
        "127.0.0.1",
        5060,
        methods=("OPTIONS",),
        max_cases=1,
        adb_enabled=True,
    )
    executor = CampaignExecutor(cfg)
    spec = CaseSpec(case_id=0, seed=0, method="OPTIONS", layer="model", strategy="default")
    send_result = SendReceiveResult(
        target=TargetEndpoint(host="127.0.0.1", port=5060),
        artifact_kind="packet",
        bytes_sent=120,
        outcome="success",
        responses=(),
        send_started_at=100.1,
        send_completed_at=100.2,
    )

    with unittest.mock.patch.object(
        executor._sender,
        "send_artifact",
        return_value=send_result,
    ), unittest.mock.patch.object(
        executor._oracle,
        "evaluate",
        return_value=SimpleNamespace(
            verdict="normal",
            reason="ok",
            response_code=200,
            elapsed_ms=12.5,
            process_alive=True,
            details={},
        ),
    ), unittest.mock.patch(
        "volte_mutation_fuzzer.adb.core.AdbConnector.take_snapshot",
        return_value=SimpleNamespace(),
    ) as snapshot_mock:
        executor._execute_case(spec)

    self.assertEqual(snapshot_mock.call_args.kwargs["profile"], "light")
```

```python
def test_execute_case_uses_full_snapshot_for_stack_failure(self) -> None:
    cfg = self._make_config(
        "127.0.0.1",
        5060,
        methods=("OPTIONS",),
        max_cases=1,
        adb_enabled=True,
    )
    executor = CampaignExecutor(cfg)
    spec = CaseSpec(case_id=0, seed=0, method="OPTIONS", layer="model", strategy="default")
    send_result = SendReceiveResult(
        target=TargetEndpoint(host="127.0.0.1", port=5060),
        artifact_kind="packet",
        bytes_sent=120,
        outcome="success",
        responses=(),
        send_started_at=100.1,
        send_completed_at=100.2,
    )

    with unittest.mock.patch.object(
        executor._sender,
        "send_artifact",
        return_value=send_result,
    ), unittest.mock.patch.object(
        executor._oracle,
        "evaluate",
        return_value=SimpleNamespace(
            verdict="stack_failure",
            reason="adb anomaly",
            response_code=None,
            elapsed_ms=12.5,
            process_alive=True,
            details={},
        ),
    ), unittest.mock.patch(
        "volte_mutation_fuzzer.adb.core.AdbConnector.take_snapshot",
        return_value=SimpleNamespace(),
    ) as snapshot_mock:
        executor._execute_case(spec)

    self.assertEqual(snapshot_mock.call_args.kwargs["profile"], "full")
```

- [ ] **Step 2: Run the targeted tests and verify they fail**

Run: `uv run pytest tests/campaign/test_core.py -k "light_snapshot or full_snapshot" -q`
Expected: FAIL because campaign code never chooses a snapshot profile.

- [ ] **Step 3: Centralize snapshot capture and select profile by verdict**

```python
def _adb_snapshot_profile_for_verdict(self, verdict: str) -> str:
    if verdict in {"suspicious", "crash", "stack_failure"}:
        return "full"
    return "light"


def _capture_adb_snapshot(
    self,
    *,
    case_id: int,
    verdict: str,
    log_since: float,
    log_until: float,
) -> str | None:
    if not self._config.adb_enabled:
        return None

    from volte_mutation_fuzzer.adb.core import AdbConnector

    adb_snapshot_dir = str(self._campaign_dir / "adb_snapshots" / f"case_{case_id}")
    profile = self._adb_snapshot_profile_for_verdict(verdict)
    AdbConnector(serial=self._config.adb_serial).take_snapshot(
        adb_snapshot_dir,
        collector=self._adb_collector,
        log_since=log_since,
        log_until=log_until,
        profile=profile,
    )
    return adb_snapshot_dir
```

```python
snapshot_until = time.time()
adb_snapshot_dir = self._capture_adb_snapshot(
    case_id=spec.case_id,
    verdict=verdict.verdict,
    log_since=timestamp,
    log_until=snapshot_until,
)
```

- [ ] **Step 4: Run the targeted tests and verify they pass**

Run: `uv run pytest tests/campaign/test_core.py -k "light_snapshot or full_snapshot" -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/volte_mutation_fuzzer/campaign/core.py tests/campaign/test_core.py
git commit -m "perf: use light adb snapshots for non-interesting cases"
```

### Task 5: Parallelize the Remaining Full ADB Snapshot Shell Work

**Files:**
- Modify: `src/volte_mutation_fuzzer/adb/core.py`
- Test: `tests/adb/test_core.py`

- [ ] **Step 1: Write the failing tests for full-snapshot concurrency**

```python
def test_take_snapshot_full_profile_runs_shell_dumps_concurrently(tmp_path: Path) -> None:
    output_dir = tmp_path / "snapshots"
    connector = AdbConnector(serial="SERIAL")
    current = 0
    peak = 0
    lock = threading.Lock()

    def _run_shell(*args: str, timeout: int) -> subprocess.CompletedProcess[str]:
        nonlocal current, peak
        with lock:
            current += 1
            peak = max(peak, current)
        try:
            time.sleep(0.05)
            return _DummyCompletedProcess(stdout="ok\n")
        finally:
            with lock:
                current -= 1

    with patch.object(connector, "run_shell", side_effect=_run_shell):
        snapshot = connector.take_snapshot(str(output_dir), profile="full")

    assert snapshot.telephony_path is not None
    assert snapshot.ims_path is not None
    assert peak >= 2
```

```python
def test_take_snapshot_full_profile_partial_failure_keeps_other_outputs(tmp_path: Path) -> None:
    output_dir = tmp_path / "snapshots"
    connector = AdbConnector(serial="SERIAL")

    def _run_shell(*args: str, timeout: int) -> subprocess.CompletedProcess[str]:
        if args == ("dumpsys", "ims"):
            raise RuntimeError("ims boom")
        return _DummyCompletedProcess(stdout="ok\n")

    with patch.object(connector, "run_shell", side_effect=_run_shell):
        snapshot = connector.take_snapshot(str(output_dir), profile="full")

    assert snapshot.telephony_path is not None
    assert snapshot.ims_path is None
    assert snapshot.meminfo_path is not None
    assert any("dumpsys ims failed" in err for err in snapshot.errors)
```

- [ ] **Step 2: Run the targeted tests and verify they fail**

Run: `uv run pytest tests/adb/test_core.py -k "concurrently or partial_failure" -q`
Expected: FAIL because full snapshots still run shell commands serially.

- [ ] **Step 3: Parallelize only the full-profile shell commands**

```python
_FULL_SNAPSHOT_TASKS: tuple[tuple[str, tuple[str, ...], int], ...] = (
    ("telephony.txt", ("dumpsys", "telephony.registry"), 30),
    ("ims.txt", ("dumpsys", "ims"), 30),
    ("netstat.txt", ("netstat", "-tlnup"), 10),
    ("meminfo.txt", ("dumpsys", "meminfo"), 60),
    ("dmesg.txt", ("dmesg",), 60),
)
```

```python
def _run_full_snapshot_tasks(
    self,
    base_dir: Path,
    errors: list[str],
) -> dict[str, str | None]:
    paths: dict[str, str | None] = {name: None for name, _, _ in _FULL_SNAPSHOT_TASKS}
    error_lock = threading.Lock()

    def _worker(filename: str, args: tuple[str, ...], timeout: int) -> tuple[str, str | None]:
        path = base_dir / filename
        try:
            result = self.run_shell(*args, timeout=timeout)
        except Exception as exc:
            with error_lock:
                errors.append(f"{' '.join(args)} failed: {exc}")
            return filename, None

        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip() or "unknown error"
            with error_lock:
                errors.append(f"{' '.join(args)} failed: {message}")
            return filename, None

        path.write_text(result.stdout, encoding="utf-8")
        return filename, str(path)

    with ThreadPoolExecutor(max_workers=len(_FULL_SNAPSHOT_TASKS)) as executor:
        futures = [
            executor.submit(_worker, filename, args, timeout)
            for filename, args, timeout in _FULL_SNAPSHOT_TASKS
        ]
        for future in futures:
            filename, path = future.result()
            paths[filename] = path

    return paths
```

```python
if profile == "full":
    full_paths = self._run_full_snapshot_tasks(base_dir, errors)
    telephony_path = full_paths["telephony.txt"]
    ims_path = full_paths["ims.txt"]
    netstat_path = full_paths["netstat.txt"]
    meminfo_path = full_paths["meminfo.txt"]
    dmesg_path = full_paths["dmesg.txt"]
else:
    telephony_path = _write_shell_output(
        "telephony.txt", "dumpsys", "telephony.registry", timeout=30
    )
```

- [ ] **Step 4: Run the targeted tests and the focused regressions**

Run: `uv run pytest tests/adb/test_core.py -k "concurrently or partial_failure or light_profile or full_profile" -q`
Expected: PASS

Run: `uv run pytest tests/campaign/test_core.py tests/campaign/test_report.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/volte_mutation_fuzzer/adb/core.py tests/adb/test_core.py
git commit -m "perf: parallelize full adb snapshot shell dumps"
```

### Task 6: Update Docs and Run Full Verification

**Files:**
- Modify: `docs/A31_REAL_UE_GUIDE.md`
- Modify: `docs/TROUBLESHOOTING.md`

- [ ] **Step 1: Document the new defaults and operator expectations**

```markdown
## Throughput Notes

- `INVITE` keeps the long oracle grace window because delayed IMS crashes have been observed several seconds after the transport response.
- Non-`INVITE` methods use shorter default grace windows in `real-ue-direct` mode to improve campaign throughput.
- ADB snapshots now run in two profiles:
  - `light`: every case, collector-sliced logcat plus lightweight telephony state
  - `full`: only `suspicious`, `crash`, and `stack_failure` cases
- `campaign.jsonl` and `report.html` now show both transport `elapsed_ms` and end-to-end `case_wall_ms`.
```

- [ ] **Step 2: Run full verification**

Run: `uv run pytest -q`
Expected: PASS with zero failures

Run: `uv run ruff check src/volte_mutation_fuzzer/adb/core.py src/volte_mutation_fuzzer/campaign/contracts.py src/volte_mutation_fuzzer/campaign/core.py src/volte_mutation_fuzzer/campaign/report.py tests/adb/test_core.py tests/campaign/test_contracts.py tests/campaign/test_core.py tests/campaign/test_report.py`
Expected: `All checks passed!`

- [ ] **Step 3: Commit**

```bash
git add docs/A31_REAL_UE_GUIDE.md docs/TROUBLESHOOTING.md
git commit -m "docs: document real-ue throughput tuning behavior"
```

## Expected Outcome

- Non-`INVITE` `real-ue-direct` cases should stop paying the unconditional 8-second grace penalty.
- Normal cases should stop paying for full `ims/netstat/meminfo/dmesg` collection.
- `INVITE` delayed-crash detection should remain conservative.
- Reports and JSONL should finally expose true wall-clock time, making further tuning evidence-based instead of guess-based.

## Rollout Notes

- Implement Tasks 1 and 2 first and run a small `--methods OPTIONS,MESSAGE,REGISTER --max-cases 10` campaign to capture before/after `case_wall_ms`.
- Do not start Task 5 before Tasks 3 and 4 are green, because snapshot parallelization should optimize the new `full` path only.
- If post-change sampling shows `stack_failure` coverage regression on non-`INVITE`, raise the adaptive defaults to `OPTIONS/MESSAGE/REGISTER = 2.0` before reverting the whole feature.
