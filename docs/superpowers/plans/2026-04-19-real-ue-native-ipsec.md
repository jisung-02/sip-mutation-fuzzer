# Real-UE Native IPsec Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--ipsec-mode native` real-UE mode that uses the live negotiated IMS IPsec/xfrm path, still supports malformed payload injection, and reports responses through observer-backed results that fit the current oracle flow.

**Architecture:** Thread `ipsec_mode` all the way into `TargetEndpoint`, resolve a live UE/P-CSCF protected-port mapping from `ip xfrm state`, preflight the native path before the first case, derive best-effort correlation keys from `packet`, `wire_text`, or `packet_bytes`, send native packets from the `pcscf` netns with an `AF_INET` raw IPv4/UDP injector so Kamailio-owned protected ports are not bound by the fuzzer, and poll P-CSCF logs until a bounded timeout so observer-backed `SocketObservation` objects can still feed the current `SendReceiveResult` and oracle flow.

**Tech Stack:** Python 3.12, Typer, Pydantic, `subprocess` + `docker exec`, Linux raw sockets, existing `RealUEDirectResolver`, existing oracle/campaign pipeline, `pytest`

---

### Task 1: Native Mode Contract And CLI Wiring

**Files:**
- Modify: `src/volte_mutation_fuzzer/campaign/contracts.py:53-78`
- Modify: `src/volte_mutation_fuzzer/campaign/contracts.py:140-178`
- Modify: `src/volte_mutation_fuzzer/campaign/cli.py:153-175`
- Modify: `src/volte_mutation_fuzzer/campaign/cli.py:235-272`
- Modify: `src/volte_mutation_fuzzer/sender/contracts.py:46-60`
- Modify: `src/volte_mutation_fuzzer/sender/cli.py:121-145`
- Modify: `src/volte_mutation_fuzzer/sender/cli.py:154-359`
- Test: `tests/campaign/test_contracts.py`
- Test: `tests/sender/test_cli.py`

- [ ] **Step 1: Write the failing contract and CLI tests**

```python
# tests/campaign/test_contracts.py
def test_mt_template_accepts_native_ipsec_mode(self) -> None:
    cfg = CampaignConfig(
        target_host="10.20.20.8",
        mode="real-ue-direct",
        target_msisdn="111111",
        impi="001010000123511",
        mt_invite_template="a31",
        ipsec_mode="native",
    )
    self.assertEqual(cfg.ipsec_mode, "native")
    self.assertEqual(cfg.bind_container, "pcscf")

def test_ipsec_alias_normalizes_to_native(self) -> None:
    cfg = CampaignConfig(
        target_host="10.20.20.8",
        mode="real-ue-direct",
        target_msisdn="111111",
        impi="001010000123511",
        mt_invite_template="a31",
        ipsec_mode="ipsec",
    )
    self.assertEqual(cfg.ipsec_mode, "native")

# tests/sender/test_cli.py
@patch(
    "volte_mutation_fuzzer.sender.core.check_route_to_target",
    return_value=RouteCheckResult(True, "loopback"),
)
def test_send_packet_command_accepts_native_ipsec_mode(
    self, _mock_route: object
) -> None:
    result = self.runner.invoke(
        app,
        [
            "send",
            "packet",
            "--mode",
            "real-ue-direct",
            "--target-host",
            "10.20.20.8",
            "--target-port",
            "8100",
            "--ipsec-mode",
            "native",
        ],
        input="OPTIONS sip:ue@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n",
    )
    self.assertEqual(result.exit_code, 0, msg=result.output)
```

- [ ] **Step 2: Run the focused tests and confirm they fail for the expected reasons**

Run: `pytest tests/campaign/test_contracts.py tests/sender/test_cli.py -k "native or alias or ipsec_mode" -v`

Expected:
- `ValidationError` because `ipsec_mode="native"` / `"ipsec"` is not accepted yet
- Typer rejects `send packet --ipsec-mode native` because the option is not defined yet

- [ ] **Step 3: Implement the config and CLI plumbing**

```python
# src/volte_mutation_fuzzer/campaign/contracts.py
IPsecMode = Literal["null", "bypass", "native"]

ipsec_mode: IPsecMode | None = None

@field_validator("ipsec_mode", mode="before")
@classmethod
def _normalize_ipsec_mode(cls, value: Any) -> Any:
    if not isinstance(value, str):
        return value
    normalized = value.strip().lower()
    if normalized == "ipsec":
        return "native"
    return normalized

@model_validator(mode="after")
def _validate_mt_invite_template(self) -> Self:
    if self.mode == "real-ue-direct":
        if self.target_host is None and self.target_msisdn is None:
            raise ValueError("real-ue-direct mode requires either target_host or target_msisdn")

    if self.impi is None:
        env_impi = os.environ.get("VMF_IMPI")
        if env_impi:
            object.__setattr__(self, "impi", env_impi)

    if self.mt and self.mt_invite_template is None:
        object.__setattr__(self, "mt_invite_template", "3gpp")
    if self.mt:
        object.__setattr__(self, "preserve_via", True)
        object.__setattr__(self, "preserve_contact", True)

    if self.mt_invite_template is not None:
        if self.mode != "real-ue-direct":
            raise ValueError("mt_invite_template requires mode='real-ue-direct'")
        if self.target_msisdn is None:
            raise ValueError("mt_invite_template requires target_msisdn")
        if self.ipsec_mode is None:
            object.__setattr__(self, "ipsec_mode", "null")

    if self.ipsec_mode == "null":
        object.__setattr__(self, "source_ip", None)
        object.__setattr__(self, "bind_container", "pcscf")
    elif self.ipsec_mode == "bypass":
        object.__setattr__(self, "source_ip", None)
        object.__setattr__(self, "bind_container", "pcscf")
    elif self.ipsec_mode == "native":
        if self.transport.upper() != "UDP":
            raise ValueError("ipsec_mode='native' only supports UDP")
        object.__setattr__(self, "source_ip", None)
        object.__setattr__(self, "bind_container", "pcscf")

    return self
```

```python
# src/volte_mutation_fuzzer/campaign/cli.py
ipsec_mode: Annotated[
    str | None,
    typer.Option(
        "--ipsec-mode",
        help="IPsec mode: 'null', 'bypass', 'native' (alias: 'ipsec').",
    ),
] = None
```

```python
# src/volte_mutation_fuzzer/sender/contracts.py
IPsecMode = Literal["null", "bypass", "native"]

ipsec_mode: IPsecMode | None = None

@field_validator("ipsec_mode", mode="before")
@classmethod
def _normalize_ipsec_mode(cls, value: object) -> object:
    if not isinstance(value, str):
        return value
    normalized = value.strip().lower()
    if normalized == "ipsec":
        return "native"
    return normalized

# insert inside TargetEndpoint._validate_target_shape(), within the real-ue-direct branch
if self.ipsec_mode == "native" and self.transport != "UDP":
    raise ValueError("real-ue-direct native IPsec supports UDP only")
```

```python
# src/volte_mutation_fuzzer/sender/cli.py
ipsec_mode: Annotated[
    str | None,
    typer.Option("--ipsec-mode", help="IPsec mode: 'null', 'bypass', 'native' (alias: 'ipsec')."),
] = None

def _build_target(
    *,
    host: str | None,
    port: int | None,
    msisdn: str | None,
    transport: str,
    mode: str,
    timeout_seconds: float,
    label: str | None,
    ipsec_mode: str | None = None,
) -> TargetEndpoint:
    return TargetEndpoint(
        host=host,
        port=port,
        msisdn=msisdn,
        transport=cast(TransportProtocol, transport),
        mode=cast(TargetMode, mode),
        timeout_seconds=timeout_seconds,
        label=label,
        ipsec_mode=cast(str | None, ipsec_mode),
    )
```

```python
# src/volte_mutation_fuzzer/sender/cli.py
@app.command("packet")
def packet_command(
    target_host: Annotated[str | None, typer.Option("--target-host")] = None,
    target_port: Annotated[int | None, typer.Option("--target-port")] = None,
    target_msisdn: Annotated[str | None, typer.Option("--target-msisdn")] = None,
    transport: Annotated[str, typer.Option("--transport")] = "UDP",
    mode: Annotated[str, typer.Option("--mode")] = "softphone",
    timeout: Annotated[float, typer.Option("--timeout")] = 2.0,
    label: Annotated[str | None, typer.Option("--label")] = None,
    ipsec_mode: Annotated[
        str | None,
        typer.Option("--ipsec-mode", help="IPsec mode: 'null', 'bypass', 'native' (alias: 'ipsec')."),
    ] = None,
) -> None:
    target = _build_target(
        host=target_host,
        port=target_port,
        msisdn=target_msisdn,
        transport=transport,
        mode=mode,
        timeout_seconds=timeout,
        label=label,
        ipsec_mode=ipsec_mode,
    )
```

- [ ] **Step 4: Re-run the focused tests**

Run: `pytest tests/campaign/test_contracts.py tests/sender/test_cli.py -k "native or alias or ipsec_mode" -v`

Expected:
- All newly added tests pass
- No regressions in existing `null` / `bypass` tests

- [ ] **Step 5: Commit the contract/CLI slice**

```bash
git add tests/campaign/test_contracts.py tests/sender/test_cli.py src/volte_mutation_fuzzer/campaign/contracts.py src/volte_mutation_fuzzer/campaign/cli.py src/volte_mutation_fuzzer/sender/contracts.py src/volte_mutation_fuzzer/sender/cli.py
git commit -m "feat: add native ipsec mode plumbing"
```

### Task 2: Resolve Live Native IPsec Session Port Bindings

**Files:**
- Modify: `src/volte_mutation_fuzzer/sender/real_ue.py:366-593`
- Test: `tests/sender/test_real_ue.py`

- [ ] **Step 1: Write the failing xfrm parser and session mapping tests**

```python
# tests/sender/test_real_ue.py
def test_resolve_native_ipsec_session_builds_ue_to_pcscf_port_map(self) -> None:
    xfrm_output = (
        "src 10.20.20.8 dst 172.22.0.21\n"
        "\tproto esp spi 0x01 reqid 1 mode transport\n"
        "\tsel src 10.20.20.8/32 dst 172.22.0.21/32 sport 8100 dport 5103\n"
        "src 10.20.20.8 dst 172.22.0.21\n"
        "\tproto esp spi 0x02 reqid 2 mode transport\n"
        "\tsel src 10.20.20.8/32 dst 172.22.0.21/32 sport 8101 dport 6103\n"
        "src 172.22.0.21 dst 10.20.20.8\n"
        "\tproto esp spi 0x03 reqid 3 mode transport\n"
        "\tsel src 172.22.0.21/32 dst 10.20.20.8/32 sport 5103 dport 8100\n"
        "src 172.22.0.21 dst 10.20.20.8\n"
        "\tproto esp spi 0x04 reqid 4 mode transport\n"
        "\tsel src 172.22.0.21/32 dst 10.20.20.8/32 sport 6103 dport 8101\n"
    )
    with patch(
        "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
        return_value=subprocess.CompletedProcess(
            args=["docker"], returncode=0, stdout=xfrm_output, stderr=""
        ),
    ):
        session = resolve_native_ipsec_session(ue_ip="10.20.20.8")
    self.assertEqual(session.port_map[8100], 5103)
    self.assertEqual(session.port_map[8101], 6103)

def test_resolve_native_ipsec_session_raises_when_no_matching_tuple(self) -> None:
    with patch(
        "volte_mutation_fuzzer.sender.real_ue.subprocess.run",
        return_value=subprocess.CompletedProcess(
            args=["docker"], returncode=0, stdout="", stderr=""
        ),
    ):
        with self.assertRaises(RealUEDirectResolutionError):
            resolve_native_ipsec_session(ue_ip="10.20.20.8")
```

- [ ] **Step 2: Run the focused resolver tests and confirm they fail**

Run: `pytest tests/sender/test_real_ue.py -k "native_ipsec_session or port_map" -v`

Expected:
- Import failure or `NameError` for `resolve_native_ipsec_session`
- No parser exists yet for `ue_port -> pcscf_port`

- [ ] **Step 3: Implement the live session resolver**

```python
# src/volte_mutation_fuzzer/sender/real_ue.py
@dataclass(frozen=True)
class ResolvedNativeIPsecSession:
    ue_ip: str
    pcscf_ip: str
    port_map: dict[int, int]
    observer_events: tuple[str, ...]

    def pcscf_port_for(self, ue_port: int) -> int:
        try:
            return self.port_map[ue_port]
        except KeyError as exc:
            raise RealUEDirectResolutionError(
                f"no native IPsec source port matched UE protected port {ue_port}"
            ) from exc

def resolve_native_ipsec_session(
    *,
    ue_ip: str,
    pcscf_container: str = _DEFAULT_PCSCF_CONTAINER,
    env: dict[str, str] | None = None,
) -> ResolvedNativeIPsecSession:
    source = os.environ if env is None else env
    pcscf_ip = source.get("VMF_REAL_UE_PCSCF_IP", "172.22.0.21")
    result = subprocess.run(
        ["docker", "exec", pcscf_container, "ip", "xfrm", "state"],
        capture_output=True,
        text=True,
        timeout=10.0,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise RealUEDirectResolutionError("native IPsec session lookup failed: xfrm state unavailable")

    port_map: dict[int, int] = {}
    current_src: str | None = None
    current_dst: str | None = None
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("src ") and " dst " in line:
            parts = line.split()
            if len(parts) >= 4:
                current_src = parts[1]
                current_dst = parts[3]
            continue
        if not line.startswith("sel "):
            continue
        parts = line.split()
        sport: int | None = None
        dport: int | None = None
        for index, token in enumerate(parts):
            if token == "sport" and index + 1 < len(parts):
                sport = int(parts[index + 1])
            if token == "dport" and index + 1 < len(parts):
                dport = int(parts[index + 1])
        if (
            current_src == pcscf_ip
            and current_dst == ue_ip
            and sport is not None
            and dport is not None
        ):
            port_map[dport] = sport

    if not port_map:
        raise RealUEDirectResolutionError(
            f"no native IPsec xfrm tuple matched UE {ue_ip}"
        )

    return ResolvedNativeIPsecSession(
        ue_ip=ue_ip,
        pcscf_ip=pcscf_ip,
        port_map=port_map,
        observer_events=tuple(
            f"native-ipsec:port-map:{ue_port}->{pcscf_port}"
            for ue_port, pcscf_port in sorted(port_map.items())
        ),
    )
```

- [ ] **Step 4: Re-run the resolver tests**

Run: `pytest tests/sender/test_real_ue.py -k "native_ipsec_session or port_map" -v`

Expected:
- The new session tests pass
- Existing route and payload-rewrite tests still pass

- [ ] **Step 5: Commit the resolver slice**

```bash
git add tests/sender/test_real_ue.py src/volte_mutation_fuzzer/sender/real_ue.py
git commit -m "feat: resolve native ipsec port mappings from xfrm"
```

### Task 3: Add Native Preflight, Correlation, Injector, And Log Observer

**Files:**
- Create: `src/volte_mutation_fuzzer/sender/ipsec_native.py`
- Modify: `src/volte_mutation_fuzzer/sender/contracts.py:193-246`
- Modify: `src/volte_mutation_fuzzer/sender/core.py:143-209`
- Modify: `src/volte_mutation_fuzzer/sender/core.py:269-526`
- Modify: `src/volte_mutation_fuzzer/sender/real_ue.py:548-593`
- Test: `tests/sender/test_ipsec_native.py`
- Test: `tests/sender/test_core.py`

- [ ] **Step 1: Write the failing native sender and observer tests**

```python
# tests/sender/test_ipsec_native.py
def test_extract_correlation_from_wire_text_returns_call_id_and_cseq() -> None:
    artifact = SendArtifact.from_wire_text(
        "INVITE sip:ue@example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 172.22.0.21:5103;branch=z9hG4bK-native-1\r\n"
        "Call-ID: native-abc@example.com\r\n"
        "CSeq: 7 INVITE\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    correlation = extract_correlation_from_artifact(artifact)
    assert correlation.call_id == "native-abc@example.com"
    assert correlation.cseq_method == "INVITE"
    assert correlation.cseq_sequence == 7
    assert correlation.via_branch == "z9hG4bK-native-1"

def test_observe_pcscf_log_responses_returns_socket_observations() -> None:
    log_text = (
        "INFO: reply SIP/2.0 100 Trying Call-ID: abc@example.com CSeq: 1 INVITE\n"
        "INFO: reply SIP/2.0 180 Ringing Call-ID: abc@example.com CSeq: 1 INVITE\n"
    )
    with patch(
        "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
        return_value=subprocess.CompletedProcess(
            args=["docker"], returncode=0, stdout=log_text, stderr=""
        ),
    ):
        observations = observe_pcscf_log_responses(
            container="pcscf",
            since="2026-04-19T00:00:00",
            ue_ip="10.20.20.8",
            ue_port=8100,
            correlation=ArtifactCorrelation(
                call_id="abc@example.com",
                cseq_method="INVITE",
                cseq_sequence=1,
                via_branch=None,
                confidence="high",
            ),
            timeout_seconds=1.0,
            poll_interval_seconds=0.2,
            collect_all_responses=True,
        )
    assert [item.status_code for item in observations] == [100, 180]
    assert observations[-1].source == "pcscf-log"

def test_observe_pcscf_log_responses_polls_until_final_response() -> None:
    responses = [
        subprocess.CompletedProcess(args=["docker"], returncode=0, stdout="", stderr=""),
        subprocess.CompletedProcess(
            args=["docker"],
            returncode=0,
            stdout="INFO: reply SIP/2.0 100 Trying Call-ID: abc@example.com CSeq: 1 INVITE\n",
            stderr="",
        ),
        subprocess.CompletedProcess(
            args=["docker"],
            returncode=0,
            stdout=(
                "INFO: reply SIP/2.0 100 Trying Call-ID: abc@example.com CSeq: 1 INVITE\n"
                "INFO: reply SIP/2.0 486 Busy Here Call-ID: abc@example.com CSeq: 1 INVITE\n"
            ),
            stderr="",
        ),
    ]
    with patch(
        "volte_mutation_fuzzer.sender.ipsec_native.subprocess.run",
        side_effect=responses,
    ):
        observations = observe_pcscf_log_responses(
            container="pcscf",
            since="2026-04-19T00:00:00",
            ue_ip="10.20.20.8",
            ue_port=8100,
            correlation=ArtifactCorrelation(
                call_id="abc@example.com",
                cseq_method="INVITE",
                cseq_sequence=1,
                via_branch=None,
                confidence="high",
            ),
            timeout_seconds=1.0,
            poll_interval_seconds=0.2,
            collect_all_responses=True,
        )
    assert [item.status_code for item in observations] == [100, 486]

def test_preflight_native_ipsec_target_rejects_unknown_ue_port() -> None:
    session = ResolvedNativeIPsecSession(
        ue_ip="10.20.20.8",
        pcscf_ip="172.22.0.21",
        port_map={8100: 5103},
        observer_events=("native-ipsec:port-map:8100->5103",),
    )
    with pytest.raises(RealUEDirectResolutionError):
        preflight_native_ipsec_target(
            session=session,
            ue_ip="10.20.20.8",
            ue_port=8101,
            container="pcscf",
        )

# tests/sender/test_core.py
@patch(
    "volte_mutation_fuzzer.sender.core.resolve_native_ipsec_session",
    return_value=ResolvedNativeIPsecSession(
        ue_ip="10.20.20.8",
        pcscf_ip="172.22.0.21",
        port_map={8100: 5103},
        observer_events=("native-ipsec:port-map:8100->5103",),
    ),
)
@patch(
    "volte_mutation_fuzzer.sender.core.send_via_native_ipsec",
    return_value=NativeIPsecSendResult(
        payload_size=128,
        observer_events=("native-ipsec:send:ok",),
    ),
)
@patch(
    "volte_mutation_fuzzer.sender.core.observe_pcscf_log_responses",
    return_value=(
        SocketObservation(
            source="pcscf-log",
            status_code=180,
            reason_phrase="Ringing",
            classification="provisional",
            raw_text="SIP/2.0 180 Ringing",
        ),
    ),
)
def test_send_real_ue_direct_native_returns_observer_response(
    self,
    _mock_observer: object,
    _mock_send: object,
    _mock_session: object,
) -> None:
    result = self.reactor.send_artifact(
        SendArtifact.from_wire_text(
            "INVITE sip:ue@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n"
        ),
        TargetEndpoint(
            mode="real-ue-direct",
            host="10.20.20.8",
            port=8100,
            timeout_seconds=0.5,
            ipsec_mode="native",
            bind_container="pcscf",
        ),
        collect_all_responses=True,
    )
    self.assertEqual(result.outcome, "provisional")
    self.assertEqual(result.final_response.status_code, 180)
    self.assertIn("native-ipsec:send:ok", result.observer_events)

@patch(
    "volte_mutation_fuzzer.sender.core.resolve_native_ipsec_session",
    return_value=ResolvedNativeIPsecSession(
        ue_ip="10.20.20.8",
        pcscf_ip="172.22.0.21",
        port_map={8100: 5103},
        observer_events=("native-ipsec:port-map:8100->5103",),
    ),
)
@patch(
    "volte_mutation_fuzzer.sender.core.send_via_native_ipsec",
    return_value=NativeIPsecSendResult(
        payload_size=128,
        observer_events=("native-ipsec:send:ok",),
    ),
)
@patch(
    "volte_mutation_fuzzer.sender.core.observe_pcscf_log_responses",
    return_value=(),
)
def test_send_real_ue_direct_native_marks_tuple_only_fallback_when_no_correlation(
    self,
    _mock_observer: object,
    _mock_send: object,
    _mock_session: object,
) -> None:
    result = self.reactor.send_artifact(
        SendArtifact.from_packet_bytes(b"\x00\x01malformed-sip"),
        TargetEndpoint(
            mode="real-ue-direct",
            host="10.20.20.8",
            port=8100,
            timeout_seconds=0.5,
            ipsec_mode="native",
            bind_container="pcscf",
        ),
    )
    self.assertIn("correlation:fallback:tuple-only", result.observer_events)
    self.assertIn("correlation:low-confidence", result.observer_events)
```

- [ ] **Step 2: Run the focused sender tests and confirm they fail**

Run: `pytest tests/sender/test_ipsec_native.py tests/sender/test_core.py -k "native or pcscf_log" -v`

Expected:
- New module imports fail because `ipsec_native.py` does not exist yet
- `SocketObservation.source == "pcscf-log"` is invalid because the field is still fixed to `"socket"`
- No best-effort correlation extractor exists for `wire_text` / `packet_bytes`
- The observer does not poll, deduplicate, or enforce a native preflight yet

- [ ] **Step 3: Implement the native injector, preflight, observer, and sender branch**

```python
# src/volte_mutation_fuzzer/sender/contracts.py
ObservationSource = Literal["socket", "pcscf-log"]

# replace the existing fixed source field with this declaration
source: ObservationSource = "socket"
```

```python
# src/volte_mutation_fuzzer/sender/ipsec_native.py
@dataclass(frozen=True)
class ArtifactCorrelation:
    call_id: str | None
    cseq_method: str | None
    cseq_sequence: int | None
    via_branch: str | None
    confidence: Literal["high", "low"]

@dataclass(frozen=True)
class NativeIPsecSendResult:
    payload_size: int
    observer_events: tuple[str, ...]

@dataclass(frozen=True)
class NativeIPsecPreflight:
    pcscf_port: int
    observer_events: tuple[str, ...]

def extract_correlation_from_artifact(artifact: SendArtifact) -> ArtifactCorrelation:
    if artifact.packet is not None:
        cseq = getattr(artifact.packet, "cseq", None)
        via = getattr(artifact.packet, "via", ())
        top_via = via[0] if via else None
        return ArtifactCorrelation(
            call_id=getattr(artifact.packet, "call_id", None),
            cseq_method=str(getattr(cseq, "method", None)) if cseq is not None else None,
            cseq_sequence=getattr(cseq, "sequence", None),
            via_branch=getattr(top_via, "branch", None),
            confidence="high",
        )

    raw_text = artifact.wire_text
    if raw_text is None and artifact.packet_bytes is not None:
        raw_text = artifact.packet_bytes.decode("utf-8", errors="replace")

    if raw_text is None:
        return ArtifactCorrelation(None, None, None, None, "low")

    call_id_match = re.search(r"^Call-ID:\s*(.+?)\s*$", raw_text, re.MULTILINE | re.IGNORECASE)
    cseq_match = re.search(r"^CSeq:\s*(\d+)\s+([A-Z]+)\s*$", raw_text, re.MULTILINE | re.IGNORECASE)
    via_match = re.search(r"^Via:\s.*?branch=([^;\\s]+)", raw_text, re.MULTILINE | re.IGNORECASE)
    return ArtifactCorrelation(
        call_id=call_id_match.group(1).strip() if call_id_match else None,
        cseq_method=cseq_match.group(2).upper() if cseq_match else None,
        cseq_sequence=int(cseq_match.group(1)) if cseq_match else None,
        via_branch=via_match.group(1).strip() if via_match else None,
        confidence="high" if call_id_match or cseq_match or via_match else "low",
    )

def preflight_native_ipsec_target(
    *,
    session: ResolvedNativeIPsecSession,
    ue_ip: str,
    ue_port: int,
    container: str,
) -> NativeIPsecPreflight:
    if ue_ip != session.ue_ip:
        raise RealUEDirectResolutionError(
            f"native IPsec preflight UE mismatch: expected {session.ue_ip}, got {ue_ip}"
        )
    if ue_port not in session.port_map:
        raise RealUEDirectResolutionError(
            f"native IPsec preflight could not map UE protected port {ue_port}"
        )
    probe = subprocess.run(
        [
            "docker",
            "exec",
            container,
            "python3",
            "-c",
            "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP); s.close(); print('ok')",
        ],
        capture_output=True,
        text=True,
        timeout=5.0,
        check=False,
    )
    if probe.returncode != 0:
        stderr_text = (probe.stderr or probe.stdout).strip()[:200]
        raise RealUEDirectResolutionError(
            f"native IPsec preflight failed: raw socket unavailable in {container}: {stderr_text}"
        )
    pcscf_port = session.pcscf_port_for(ue_port)
    return NativeIPsecPreflight(
        pcscf_port=pcscf_port,
        observer_events=(
            f"native-ipsec:preflight:ok:{container}",
            f"native-ipsec:tuple:{session.pcscf_ip}:{pcscf_port}->{ue_ip}:{ue_port}",
        ),
    )

def send_via_native_ipsec(
    *,
    container: str,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    payload: bytes,
    timeout_seconds: float,
) -> NativeIPsecSendResult:
    # The driver must use AF_INET/SOCK_RAW/IPPROTO_UDP with IP_HDRINCL=1.
    # Build a full IPv4 header plus UDP header in userspace, compute the IPv4
    # header checksum and UDP checksum, then send via sendto(). Do not use
    # AF_PACKET here because the packet must still traverse the kernel IP/xfrm
    # path to become ESP on the wire.
    driver = [
        "docker",
        "exec",
        "-i",
        container,
        "python3",
        "-c",
        _DRIVER_SCRIPT,
        src_ip,
        str(src_port),
        dst_ip,
        str(dst_port),
        str(timeout_seconds),
    ]
    stdin_data = len(payload).to_bytes(4, "big") + payload
    proc = subprocess.run(driver, input=stdin_data, capture_output=True, timeout=timeout_seconds + 5.0)
    if proc.returncode != 0:
        stderr_text = proc.stderr.decode("utf-8", errors="replace")[:200]
        raise RuntimeError(f"native IPsec injector failed: {stderr_text}")
    return NativeIPsecSendResult(
        payload_size=len(payload),
        observer_events=("native-ipsec:send:ok", f"native-ipsec:tuple:{src_ip}:{src_port}->{dst_ip}:{dst_port}"),
    )

def observe_pcscf_log_responses(
    *,
    container: str,
    since: str,
    ue_ip: str,
    ue_port: int,
    correlation: ArtifactCorrelation,
    timeout_seconds: float,
    poll_interval_seconds: float,
    collect_all_responses: bool,
) -> tuple[SocketObservation, ...]:
    status_pattern = re.compile(r"SIP/2\.0\s+(\d{3})\s+([A-Za-z][^\r\n]*)")
    observations: list[SocketObservation] = []
    seen_lines: set[str] = set()
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["docker", "logs", container, "--since", since],
            capture_output=True,
            text=True,
            timeout=max(poll_interval_seconds, 0.2) + 5.0,
            check=False,
        )
        for line in (result.stdout + result.stderr).splitlines():
            if line in seen_lines:
                continue
            seen_lines.add(line)
            if correlation.call_id and correlation.call_id not in line:
                continue
            if correlation.cseq_method and correlation.cseq_method not in line:
                continue
            match = status_pattern.search(line)
            if match is None:
                continue
            code = int(match.group(1))
            reason = match.group(2).strip()
            observations.append(
                SocketObservation(
                    source="pcscf-log",
                    remote_host=ue_ip,
                    remote_port=ue_port,
                    status_code=code,
                    reason_phrase=reason,
                    raw_text=line,
                    raw_size=len(line.encode("utf-8")),
                    classification=classify_status_code(code),
                )
            )
            if not collect_all_responses and code >= 200:
                return tuple(observations)
        time.sleep(poll_interval_seconds)
    return tuple(observations)
```

```python
# src/volte_mutation_fuzzer/sender/core.py
from datetime import datetime, timezone
from volte_mutation_fuzzer.sender.ipsec_native import (
    NativeIPsecSendResult,
    observe_pcscf_log_responses,
    send_via_native_ipsec,
)
from volte_mutation_fuzzer.sender.real_ue import resolve_native_ipsec_session

if target.ipsec_mode == "native":
    return self._send_via_native_ipsec(
        artifact=artifact,
        target=target,
        resolved_target=resolved_target,
        resolved_host=resolved.host,
        resolved_port=resolved.port,
        observer_events=observer_events,
        collect_all_responses=collect_all_responses,
    )

if target.bind_container is not None and target.source_ip is None:
    return self._send_via_container(
        artifact=artifact,
        target=target,
        resolved_target=resolved_target,
        resolved_host=resolved.host,
        resolved_port=resolved.port,
        observer_events=observer_events,
        collect_all_responses=collect_all_responses,
    )

def _send_via_native_ipsec(
    self,
    *,
    artifact: SendArtifact,
    target: TargetEndpoint,
    resolved_target: TargetEndpoint,
    resolved_host: str,
    resolved_port: int,
    observer_events: list[str],
    collect_all_responses: bool,
) -> tuple[TargetEndpoint, bytes, list[SocketObservation], tuple[str, ...]]:
    assert target.bind_container is not None
    session = resolve_native_ipsec_session(ue_ip=resolved_host)
    observer_events.extend(session.observer_events)
    preflight = preflight_native_ipsec_target(
        session=session,
        ue_ip=resolved_host,
        ue_port=resolved_port,
        container=target.bind_container,
    )
    observer_events.extend(preflight.observer_events)
    pcscf_port = preflight.pcscf_port
    payload, normalization_events = prepare_real_ue_direct_payload(
        artifact,
        local_host=session.pcscf_ip,
        local_port=pcscf_port,
        rewrite_via=not artifact.preserve_via,
        rewrite_contact=not artifact.preserve_contact,
    )
    observer_events.extend(normalization_events)
    correlation = extract_correlation_from_artifact(artifact)
    if correlation.confidence == "low":
        observer_events.append("correlation:fallback:tuple-only")
        observer_events.append("correlation:low-confidence")
    else:
        observer_events.append("correlation:best-effort:artifact")
    started_iso = datetime.now(timezone.utc).isoformat()
    native_result = send_via_native_ipsec(
        container=target.bind_container,
        src_ip=session.pcscf_ip,
        src_port=pcscf_port,
        dst_ip=resolved_host,
        dst_port=resolved_port,
        payload=payload,
        timeout_seconds=target.timeout_seconds,
    )
    observer_events.extend(native_result.observer_events)
    observations = list(
        observe_pcscf_log_responses(
            container=target.bind_container,
            since=started_iso,
            ue_ip=resolved_host,
            ue_port=resolved_port,
            correlation=correlation,
            timeout_seconds=target.timeout_seconds,
            poll_interval_seconds=0.25,
            collect_all_responses=collect_all_responses,
        )
    )
    return resolved_target, payload, observations, tuple(observer_events)
```

- [ ] **Step 4: Re-run the sender tests**

Run: `pytest tests/sender/test_ipsec_native.py tests/sender/test_core.py -k "native or pcscf_log" -v`

Expected:
- Native sender tests pass
- Existing non-native sender tests still pass
- Native observer uses bounded polling instead of one-shot log capture
- Malformed raw-byte sends emit fallback correlation events instead of pretending to have a strong match

- [ ] **Step 5: Commit the native sender slice**

```bash
git add tests/sender/test_ipsec_native.py tests/sender/test_core.py src/volte_mutation_fuzzer/sender/contracts.py src/volte_mutation_fuzzer/sender/core.py src/volte_mutation_fuzzer/sender/ipsec_native.py src/volte_mutation_fuzzer/sender/real_ue.py
git commit -m "feat: add native ipsec sender and observer"
```

### Task 4: Integrate Native Mode Into Campaign And All Real-UE Send Paths

**Files:**
- Modify: `src/volte_mutation_fuzzer/campaign/core.py:349-358`
- Modify: `src/volte_mutation_fuzzer/campaign/core.py:473-497`
- Modify: `src/volte_mutation_fuzzer/campaign/core.py:890-1064`
- Modify: `src/volte_mutation_fuzzer/campaign/core.py:1103-1300`
- Modify: `src/volte_mutation_fuzzer/sender/cli.py:240-359`
- Test: `tests/campaign/test_core.py`
- Test: `tests/sender/test_cli.py`

- [ ] **Step 1: Write the failing campaign and reproduction tests**

```python
# tests/campaign/test_core.py
def test_mt_template_reproduction_cmd_includes_native_ipsec_mode(self) -> None:
    cfg = self._make_config(
        "10.20.20.8",
        5060,
        mode="real-ue-direct",
        methods=("INVITE",),
        target_msisdn="111111",
        impi="001010000123511",
        mt_invite_template="a31",
        ipsec_mode="native",
    )
    executor = CampaignExecutor(cfg)
    spec = CaseSpec(
        case_id=0,
        seed=0,
        method="INVITE",
        layer="wire",
        strategy="default",
    )
    cmd = executor._build_mt_template_reproduction_cmd(spec)
    self.assertIn("--ipsec-mode native", cmd)
    self.assertNotIn("--mt-local-port", cmd)

def test_mt_template_native_passes_target_ipsec_mode_to_sender(self) -> None:
    cfg = self._make_config(
        "10.20.20.8",
        5060,
        mode="real-ue-direct",
        methods=("INVITE",),
        target_msisdn="111111",
        impi="001010000123511",
        mt_invite_template="a31",
        ipsec_mode="native",
        pcap_enabled=False,
    )
    executor = CampaignExecutor(cfg)
    executor._sender = unittest.mock.Mock()
    executor._sender.send_artifact.return_value = self._make_send_result([180])
    executor._execute_mt_template_case(
        CaseSpec(case_id=0, seed=0, method="INVITE", layer="wire", strategy="identity")
    )
    sent_target = executor._sender.send_artifact.call_args.args[1]
    self.assertEqual(sent_target.ipsec_mode, "native")

def test_native_mt_template_keeps_observer_response_as_raw_evidence(self) -> None:
    cfg = self._make_config(
        "10.20.20.8",
        5060,
        mode="real-ue-direct",
        methods=("INVITE",),
        target_msisdn="111111",
        impi="001010000123511",
        mt_invite_template="a31",
        ipsec_mode="native",
        pcap_enabled=False,
    )
    executor = CampaignExecutor(cfg)
    executor._sender = unittest.mock.Mock()
    send_result = self._make_send_result([100, 180]).model_copy(
        update={
            "responses": (
                SocketObservation(
                    source="pcscf-log",
                    status_code=100,
                    reason_phrase="Trying",
                    classification="provisional",
                    raw_text="INFO: reply SIP/2.0 100 Trying Call-ID: native@example.com",
                ),
                SocketObservation(
                    source="pcscf-log",
                    status_code=180,
                    reason_phrase="Ringing",
                    classification="provisional",
                    raw_text="INFO: reply SIP/2.0 180 Ringing Call-ID: native@example.com",
                ),
            )
        }
    )
    executor._sender.send_artifact.return_value = send_result
    case = executor._execute_mt_template_case(
        CaseSpec(case_id=0, seed=0, method="INVITE", layer="wire", strategy="identity")
    )
    self.assertIsNotNone(case.raw_response)
    self.assertIn("180 Ringing", case.raw_response or "")

def test_native_invite_teardown_uses_observer_responses(self) -> None:
    executor = self._make_executor()
    executor._config = executor._config.model_copy(update={"ipsec_mode": "native"})
    native_target = self._make_target().model_copy(update={"ipsec_mode": "native"})
    send_result = self._make_send_result([100, 180]).model_copy(
        update={
            "responses": (
                SocketObservation(
                    source="pcscf-log",
                    status_code=100,
                    reason_phrase="Trying",
                    classification="provisional",
                ),
                SocketObservation(
                    source="pcscf-log",
                    status_code=180,
                    reason_phrase="Ringing",
                    classification="provisional",
                ),
            )
        }
    )
    cancel_200 = self._make_send_result([200])
    executor._sender = unittest.mock.Mock()
    executor._sender.send_artifact.return_value = cancel_200
    events = executor._teardown_invite(
        "INVITE sip:foo\r\nCSeq: 1 INVITE\r\n\r\n",
        native_target,
        send_result,
        executor._config,
    )
    self.assertIn("teardown:cancel:ok:200", events)
```

```python
# tests/sender/test_cli.py
@patch(
    "volte_mutation_fuzzer.sender.cli.RealUEDirectResolver.resolve",
    return_value=ResolvedRealUETarget(
        host="10.20.20.8",
        port=8100,
        label="msisdn:111111",
        observer_events=("resolver:test:111111->10.20.20.8:8100",),
        impi="001010000123511",
    ),
)
@patch(
    "volte_mutation_fuzzer.sender.cli.RealUEDirectResolver.resolve_protected_ports",
    return_value=(8100, 8101),
)
@patch(
    "volte_mutation_fuzzer.sender.cli.SIPSenderReactor.send_artifact",
    return_value=SendReceiveResult(
        target=TargetEndpoint(host="10.20.20.8", port=8100, mode="real-ue-direct", ipsec_mode="native"),
        artifact_kind="wire",
        bytes_sent=128,
        outcome="provisional",
        responses=(
            SocketObservation(
                source="pcscf-log",
                status_code=180,
                reason_phrase="Ringing",
                classification="provisional",
                raw_text="SIP/2.0 180 Ringing",
            ),
        ),
        send_started_at=1.0,
        send_completed_at=1.2,
        observer_events=("native-ipsec:send:ok",),
    ),
)
def test_send_request_mt_native_omits_mt_local_port_behavioral_dependency(self) -> None:
    result = self.runner.invoke(
        app,
        [
            "send",
            "request",
            "INVITE",
            "--mode",
            "real-ue-direct",
            "--mt",
            "--target-msisdn",
            "111111",
            "--ipsec-mode",
            "native",
            "--impi",
            "001010000123511",
        ],
    )
    self.assertEqual(result.exit_code, 0, msg=result.output)
```

- [ ] **Step 2: Run the focused campaign/CLI tests and confirm they fail**

Run: `pytest tests/campaign/test_core.py tests/sender/test_cli.py -k "native and (mt_template or send_request)" -v`

Expected:
- Reproduction command still emits old `--mt-local-port`
- Campaign target construction does not carry `ipsec_mode="native"`
- MT CLI path still assumes container bind bypass semantics only
- CLI tests fail unless resolver/protected-port lookups are patched and IMPI is supplied explicitly
- Native normal responses are not yet preserved as evidence in `CaseResult.raw_response`

- [ ] **Step 3: Implement the campaign and CLI integration**

```python
# src/volte_mutation_fuzzer/campaign/core.py
self._target = TargetEndpoint(
    host=config.target_host,
    port=config.target_port,
    transport=config.transport,
    mode=config.mode,
    timeout_seconds=config.timeout_seconds,
    msisdn=config.target_msisdn,
    source_ip=config.source_ip,
    bind_container=config.bind_container,
    ipsec_mode=config.ipsec_mode,
)
```

```python
# src/volte_mutation_fuzzer/campaign/core.py
target_update = {
    "host": ue_ip,
    "port": port_pc,
    "ipsec_mode": config.ipsec_mode,
}
if config.ipsec_mode in ("null", "bypass"):
    target_update["bind_port"] = config.mt_local_port
    target_update["source_ip"] = None
    target_update["bind_container"] = "pcscf"
elif config.ipsec_mode == "native":
    target_update["bind_port"] = None
    target_update["source_ip"] = None
    target_update["bind_container"] = "pcscf"
```

```python
# src/volte_mutation_fuzzer/campaign/core.py
native_ipsec_arg = (
    f" --ipsec-mode {cfg.ipsec_mode}"
    if cfg.mode == "real-ue-direct" and cfg.ipsec_mode is not None
    else ""
)
mt_local_port_arg = (
    f" --mt-local-port {cfg.mt_local_port}"
    if cfg.mode == "real-ue-direct"
    and cfg.mt_invite_template is not None
    and cfg.ipsec_mode in ("null", "bypass")
    else ""
)
```

```python
# src/volte_mutation_fuzzer/sender/cli.py
target = _build_target(
    host=None,
    port=port_pc,
    msisdn=target_msisdn,
    transport=transport,
    mode=mode,
    timeout_seconds=timeout,
    label=label,
    ipsec_mode=ipsec_mode,
)
if ipsec_mode in ("null", "bypass"):
    target = target.model_copy(update={"bind_container": "pcscf", "bind_port": mt_local_port})
elif ipsec_mode == "native":
    target = target.model_copy(update={"bind_container": "pcscf", "bind_port": None})
```

```python
# src/volte_mutation_fuzzer/campaign/core.py
raw_response: str | None = None
if send_result.final_response is not None:
    final_raw = send_result.final_response.raw_text or None
    if config.ipsec_mode == "native":
        raw_response = final_raw
    elif verdict.verdict in ("suspicious", "crash", "stack_failure"):
        raw_response = final_raw
```

- [ ] **Step 4: Re-run the focused campaign/CLI tests**

Run: `pytest tests/campaign/test_core.py tests/sender/test_cli.py -k "native and (mt_template or send_request or teardown)" -v`

Expected:
- Native reproduction command is correct
- Campaign and sender CLI both pass `ipsec_mode="native"` into the sender
- Native MT command tests are hermetic because resolver and IMPI dependencies are patched
- Native provisional/final observer responses survive into `CaseResult.raw_response`

- [ ] **Step 5: Commit the campaign integration slice**

```bash
git add tests/campaign/test_core.py tests/sender/test_cli.py src/volte_mutation_fuzzer/campaign/core.py src/volte_mutation_fuzzer/sender/cli.py
git commit -m "feat: integrate native ipsec into campaign and send flows"
```

### Task 5: Update Docs And Run Verification

**Files:**
- Modify: `docs/USAGE.md`
- Modify: `docs/A31_REAL_UE_GUIDE.md`
- Modify: `README.md`

- [ ] **Step 1: Write the failing verification checklist into the docs changeset**

```markdown
## Native IPsec mode

- `--ipsec-mode native` uses the live negotiated IMS IPsec/xfrm tuple
- outer-wire pcap should show ESP, not plaintext SIP
- response evidence comes from observer-backed results, not direct socket recv
- malformed payloads fall back to tuple-only observer correlation and emit low-confidence events
```

- [ ] **Step 2: Run the full automated verification suite before editing docs**

Run: `pytest tests/campaign/test_contracts.py tests/campaign/test_core.py tests/sender/test_real_ue.py tests/sender/test_ipsec_native.py tests/sender/test_core.py tests/sender/test_cli.py -v`

Expected:
- All tests added in Tasks 1-4 pass
- Existing `null` / `bypass` behavior remains green
- Native path verification covers preflight, tuple-only fallback, polling observer, and normal-response evidence retention

- [ ] **Step 3: Update the user-facing docs**

```markdown
# docs/USAGE.md
- `--ipsec-mode native`: live xfrm/IPsec path, UDP only, response confirmation via observer
- `--ipsec-mode null`: plaintext container/netns path
- `--ipsec-mode bypass`: plaintext selector-bypass path
- native observer uses bounded polling and may emit `correlation:low-confidence` for malformed payloads

# docs/A31_REAL_UE_GUIDE.md
- native mode requires an already registered UE and live xfrm state
- Wireshark on `br-volte` will usually show ESP/ciphertext in native mode
- malformed payloads are still injectable because the sender uses a raw injector, not a normal protected-port bind
- `response_code` and response snippet come from observer-backed evidence, not a direct recv socket

# README.md
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --impi 001010000123511 \
  --methods INVITE --layer wire --strategy identity \
  --mt-invite-template a31 \
  --ipsec-mode native \
  --preserve-contact --preserve-via \
  --max-cases 1
```

- [ ] **Step 4: Run a manual live-lab verification**

Run:

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --impi 001010000123511 \
  --methods INVITE --layer wire --strategy identity \
  --mt-invite-template a31 \
  --ipsec-mode native \
  --preserve-contact --preserve-via \
  --max-cases 1 --timeout 15
```

Expected:
- campaign result contains observer-backed `response_code` or timeout reason
- `observer_events` include `native-ipsec:port-map:*` and `native-ipsec:send:ok`
- per-case pcap shows ESP traffic on the wire

- [ ] **Step 5: Commit docs and verification notes**

```bash
git add docs/USAGE.md docs/A31_REAL_UE_GUIDE.md README.md
git commit -m "docs: document native ipsec real-ue mode"
```
