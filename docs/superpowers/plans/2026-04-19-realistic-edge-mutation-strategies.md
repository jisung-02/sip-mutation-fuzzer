# Realistic Edge Mutation Strategies Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add realistic malformed SIP mutation strategies that resemble serializer/proxy/replay damage, expose them through the existing mutator/campaign surfaces, and keep them reproducible for `real-ue-direct` testing.

**Architecture:** Extend the editable wire/byte representations so they can express realistic formatting damage and tail corruption, then add deterministic strategy-specific execution paths in `SIPMutator` instead of relying on random target/operator selection alone. Finally, thread the new strategy names into CLI and campaign scheduling so the same cases can be reproduced locally and in MT-template campaigns.

**Tech Stack:** Python 3.12, Pydantic, Typer, existing `SIPMutator`, `EditableSIPMessage`, `EditablePacketBytes`, `pytest`

---

## File Structure

- Modify: `src/volte_mutation_fuzzer/mutator/editable.py`
  Add realistic wire rendering knobs and byte tail helpers.
- Modify: `src/volte_mutation_fuzzer/mutator/contracts.py`
  Document new strategy names in config comments if helpful, but avoid widening the contract shape unless needed.
- Modify: `src/volte_mutation_fuzzer/mutator/core.py`
  Add deterministic wire/byte strategy handlers and MT-specific alias desync logic.
- Modify: `src/volte_mutation_fuzzer/mutator/cli.py`
  Keep the interface stable, but expose the new strategy names in help examples/tests.
- Modify: `src/volte_mutation_fuzzer/campaign/core.py`
  Allow campaign scheduling for the new strategies.
- Modify: `tests/mutator/test_editable.py`
  Lock in new rendering/tail helper behavior.
- Modify: `tests/mutator/test_core.py`
  Lock in deterministic strategy behavior.
- Modify: `tests/mutator/test_bytes.py`
  Lock in byte-tail corruption behavior.
- Modify: `tests/mutator/test_cli.py`
  Lock in CLI strategy execution.
- Modify: `tests/campaign/test_core.py`
  Lock in campaign strategy allowlists.
- Modify: `docs/USAGE.md`
  Add concise examples for the new strategies.

---

### Task 1: Extend Editable Wire/Byte Primitives For Realistic Damage

**Files:**
- Modify: `src/volte_mutation_fuzzer/mutator/editable.py`
- Test: `tests/mutator/test_editable.py`

- [ ] **Step 1: Write failing editable rendering tests**

```python
def test_render_supports_custom_header_separator(self) -> None:
    message = EditableSIPMessage(
        start_line=EditableStartLine(text="INVITE sip:ue@example.com SIP/2.0"),
        headers=(
            EditableHeader(name="Via", value="first-hop", separator=":"),
            EditableHeader(name="Call-ID", value="call-1", separator=" : "),
        ),
    )

    rendered = message.render()

    self.assertIn("Via:first-hop\r\n", rendered)
    self.assertIn("Call-ID : call-1\r\n", rendered)


def test_render_can_drop_final_blank_line(self) -> None:
    message = EditableSIPMessage(
        start_line=EditableStartLine(text="INVITE sip:ue@example.com SIP/2.0"),
        headers=(EditableHeader(name="Call-ID", value="call-1"),),
        emit_final_blank_line=False,
    )

    self.assertEqual(
        message.render(),
        "INVITE sip:ue@example.com SIP/2.0\r\nCall-ID: call-1\r\n",
    )


def test_render_supports_lf_only_messages(self) -> None:
    message = EditableSIPMessage(
        start_line=EditableStartLine(text="SIP/2.0 200 OK"),
        headers=(EditableHeader(name="Call-ID", value="call-1"),),
        line_ending="\n",
    )

    self.assertEqual(message.render(), "SIP/2.0 200 OK\nCall-ID: call-1\n\n")


def test_packet_bytes_append_and_tail_delete(self) -> None:
    packet_bytes = EditablePacketBytes(data=b"abcd")

    self.assertEqual(packet_bytes.append(b"XY").data, b"abcdXY")
    self.assertEqual(packet_bytes.tail_delete(1).data, b"abc")
    self.assertEqual(packet_bytes.tail_delete(2).data, b"ab")
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run: `uv run pytest tests/mutator/test_editable.py -k "separator or final_blank_line or lf_only or tail_delete" -q`

Expected:
- FAIL because `EditableHeader` has no `separator`
- FAIL because `EditableSIPMessage` does not accept `emit_final_blank_line` / `line_ending`
- FAIL because `EditablePacketBytes` has no `append` / `tail_delete`

- [ ] **Step 3: Implement the editable representation changes**

```python
class EditableHeader(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    name: str
    value: str
    separator: str = ": "

    def render(self) -> str:
        return f"{self.name}{self.separator}{self.value}"


class EditableSIPMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    start_line: EditableStartLine
    headers: tuple[EditableHeader, ...] = Field(default_factory=tuple)
    body: str = ""
    declared_content_length: int | None = Field(default=None, ge=0)
    line_ending: str = "\r\n"
    emit_final_blank_line: bool = True
    extra_blank_lines_after_headers: int = Field(default=0, ge=0)

    def render(self) -> str:
        rendered_headers = [header.render() for header in self.headers]
        if self.declared_content_length is not None and not self.header_values(
            _CONTENT_LENGTH_HEADER
        ):
            rendered_headers.append(f"{_CONTENT_LENGTH_HEADER}: {self.declared_content_length}")

        ending = self.line_ending
        rendered = ending.join([self.start_line.render(), *rendered_headers])
        if self.emit_final_blank_line:
            rendered += ending
        rendered += ending * (1 + self.extra_blank_lines_after_headers)
        rendered += self.body
        return rendered


class EditablePacketBytes(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    data: bytes = b""

    def append(self, value: bytes) -> Self:
        return self.model_copy(update={"data": self.data + value})

    def tail_delete(self, count: int) -> Self:
        if count < 0 or count > len(self.data):
            raise ValueError("tail delete count must be within current data bounds")
        return self.model_copy(update={"data": self.data[: len(self.data) - count]})
```

- [ ] **Step 4: Re-run the editable tests and verify they pass**

Run: `uv run pytest tests/mutator/test_editable.py -q`

Expected:
- PASS

- [ ] **Step 5: Commit**

```bash
git add src/volte_mutation_fuzzer/mutator/editable.py tests/mutator/test_editable.py
git commit -m "feat: extend editable SIP rendering for realistic malformed cases"
```

---

### Task 2: Add Deterministic Wire Strategies For Realistic Formatting Damage

**Files:**
- Modify: `src/volte_mutation_fuzzer/mutator/core.py`
- Test: `tests/mutator/test_core.py`

- [ ] **Step 1: Write failing wire-strategy tests**

```python
def test_header_whitespace_noise_mutates_separator_without_touching_value(self) -> None:
    mutator = SIPMutator()
    packet = self.build_request()

    case = mutator.mutate(
        packet,
        MutationConfig(seed=101, layer="wire", strategy="header_whitespace_noise"),
    )

    self.assertEqual(case.final_layer, "wire")
    self.assertEqual(case.records[0].operator, "header_whitespace_noise")
    assert case.wire_text is not None
    self.assertRegex(case.wire_text, r"(?m)^Via\\s*:\\s*")


def test_final_crlf_loss_drops_one_terminal_line_break(self) -> None:
    mutator = SIPMutator()
    packet = self.build_request()

    case = mutator.mutate(
        packet,
        MutationConfig(seed=102, layer="wire", strategy="final_crlf_loss"),
    )

    assert case.wire_text is not None
    self.assertTrue(case.wire_text.endswith("\r\n"))
    self.assertFalse(case.wire_text.endswith("\r\n\r\n"))


def test_duplicate_content_length_conflict_adds_second_conflicting_header(self) -> None:
    mutator = SIPMutator()
    packet = self.build_request()

    case = mutator.mutate(
        packet,
        MutationConfig(seed=103, layer="wire", strategy="duplicate_content_length_conflict"),
    )

    assert case.wire_text is not None
    self.assertGreaterEqual(case.wire_text.count("Content-Length:"), 2)
    self.assertEqual(case.records[0].operator, "duplicate_content_length_conflict")
```

- [ ] **Step 2: Run the focused wire-strategy tests and verify they fail**

Run: `uv run pytest tests/mutator/test_core.py -k "header_whitespace_noise or final_crlf_loss or duplicate_content_length_conflict" -q`

Expected:
- FAIL because the new strategy names are rejected as unsupported

- [ ] **Step 3: Allow the new wire strategy names**

```python
def _validate_supported_strategy(self, strategy: str, layer: str) -> None:
    if layer == "wire":
        if strategy not in {
            "default",
            "identity",
            "safe",
            "header_whitespace_noise",
            "final_crlf_loss",
            "duplicate_content_length_conflict",
            "alias_port_desync",
        }:
            raise ValueError(f"unsupported wire mutation strategy: {strategy}")
        return
```

- [ ] **Step 4: Implement deterministic wire strategy handlers**

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
) -> MutatedCase:
    del definition
    self._snapshot_context(context)
    rng = self._rng_from_seed(config.seed)

    if target is None and config.strategy == "header_whitespace_noise":
        current_message, record = self._apply_header_whitespace_noise(editable_message, rng)
        return MutatedCase(
            original_packet=packet,
            wire_text=self._finalize_wire_message(current_message),
            records=(record,),
            seed=config.seed,
            strategy=config.strategy,
            final_layer="wire",
        )

    if target is None and config.strategy == "final_crlf_loss":
        current_message = editable_message.model_copy(update={"emit_final_blank_line": False})
        record = self._record_mutation(
            target=MutationTarget(layer="wire", path="message:final_blank_line"),
            operator="final_crlf_loss",
            before=True,
            after=False,
        )
        return MutatedCase(
            original_packet=packet,
            wire_text=self._finalize_wire_message(current_message),
            records=(record,),
            seed=config.seed,
            strategy=config.strategy,
            final_layer="wire",
        )

    if target is None and config.strategy == "duplicate_content_length_conflict":
        current_message, record = self._apply_duplicate_content_length_conflict(
            editable_message,
            rng,
        )
        return MutatedCase(
            original_packet=packet,
            wire_text=self._finalize_wire_message(current_message),
            records=(record,),
            seed=config.seed,
            strategy=config.strategy,
            final_layer="wire",
        )

    # existing paths remain unchanged below
```

```python
def _apply_header_whitespace_noise(
    self,
    editable_message: EditableSIPMessage,
    rng: random.Random,
) -> tuple[EditableSIPMessage, MutationRecord]:
    candidate_indices = [
        index
        for index, header in enumerate(editable_message.headers)
        if header.name.casefold() not in _SAFE_PROTECTED_HEADER_NAMES
    ]
    if not candidate_indices:
        raise ValueError("no non-protected headers available for whitespace noise")
    index = candidate_indices[rng.randrange(len(candidate_indices))]
    separators = (":", ": ", ":  ", " : ", ":\t")
    before = editable_message.headers[index].separator
    after = separators[rng.randrange(len(separators))]
    headers = list(editable_message.headers)
    headers[index] = headers[index].model_copy(update={"separator": after})
    mutated = editable_message.model_copy(update={"headers": tuple(headers)})
    return mutated, self._record_mutation(
        target=MutationTarget(layer="wire", path=f"header[{index}]"),
        operator="header_whitespace_noise",
        before=before,
        after=after,
    )
```

```python
def _apply_duplicate_content_length_conflict(
    self,
    editable_message: EditableSIPMessage,
    rng: random.Random,
) -> tuple[EditableSIPMessage, MutationRecord]:
    declared = editable_message.header_values("Content-Length")
    base_value = declared[0] if declared else str(editable_message.declared_content_length or 0)
    conflicting = str(int(base_value) + rng.randrange(1, 10))
    mutated = editable_message.append_header("Content-Length", conflicting)
    return mutated, self._record_mutation(
        target=MutationTarget(layer="wire", path="header:Content-Length"),
        operator="duplicate_content_length_conflict",
        before=(base_value,),
        after=(base_value, conflicting),
    )
```

- [ ] **Step 5: Re-run the wire tests and verify they pass**

Run: `uv run pytest tests/mutator/test_core.py -k "header_whitespace_noise or final_crlf_loss or duplicate_content_length_conflict" -q`

Expected:
- PASS

- [ ] **Step 6: Commit**

```bash
git add src/volte_mutation_fuzzer/mutator/core.py tests/mutator/test_core.py
git commit -m "feat: add realistic wire mutation strategies"
```

---

### Task 3: Add Deterministic Byte Strategies For Tail Damage And Garbage

**Files:**
- Modify: `src/volte_mutation_fuzzer/mutator/core.py`
- Test: `tests/mutator/test_bytes.py`

- [ ] **Step 1: Write failing byte-strategy tests**

```python
def test_tail_chop_1_removes_only_last_byte(self) -> None:
    mutator = SIPMutator()
    packet = self.build_request()
    original_bytes = self.build_original_bytes(mutator, packet)

    case = mutator.mutate(
        packet,
        MutationConfig(seed=201, layer="byte", strategy="tail_chop_1"),
    )

    assert case.packet_bytes is not None
    self.assertEqual(case.packet_bytes, original_bytes[:-1])
    self.assertEqual(case.records[0].operator, "tail_chop_1")


def test_tail_garbage_appends_replay_like_suffix(self) -> None:
    mutator = SIPMutator()
    packet = self.build_request()
    original_bytes = self.build_original_bytes(mutator, packet)

    case = mutator.mutate(
        packet,
        MutationConfig(seed=202, layer="byte", strategy="tail_garbage"),
    )

    assert case.packet_bytes is not None
    self.assertTrue(case.packet_bytes.startswith(original_bytes))
    self.assertGreater(len(case.packet_bytes), len(original_bytes))
    self.assertEqual(case.records[0].operator, "tail_garbage")
```

- [ ] **Step 2: Run the focused byte-strategy tests and verify they fail**

Run: `uv run pytest tests/mutator/test_bytes.py -k "tail_chop_1 or tail_garbage" -q`

Expected:
- FAIL because the new byte strategy names are rejected as unsupported

- [ ] **Step 3: Allow the new byte strategy names**

```python
def _validate_supported_strategy(self, strategy: str, layer: str) -> None:
    if layer == "byte":
        if strategy not in {
            "default",
            "identity",
            "safe",
            "header_targeted",
            "tail_chop_1",
            "tail_garbage",
        }:
            raise ValueError(f"unsupported byte mutation strategy: {strategy}")
        return
```

- [ ] **Step 4: Implement deterministic byte strategy handlers**

```python
def _mutate_bytes(
    self,
    *,
    packet: PacketModel,
    editable_bytes: EditablePacketBytes,
    config: MutationConfig,
    context: DialogContext | None,
    target: MutationTarget | None,
) -> MutatedCase:
    self._snapshot_context(context)
    rng = self._rng_from_seed(config.seed)

    if target is None and config.strategy == "tail_chop_1":
        mutated = editable_bytes.tail_delete(1)
        record = self._record_mutation(
            target=MutationTarget(layer="byte", path="segment:tail"),
            operator="tail_chop_1",
            before=editable_bytes.data[-1:],
            after=b"",
        )
        return MutatedCase(
            original_packet=packet,
            packet_bytes=self._finalize_packet_bytes(mutated),
            records=(record,),
            seed=config.seed,
            strategy=config.strategy,
            final_layer="byte",
        )

    if target is None and config.strategy == "tail_garbage":
        suffix = b"\r\nX"
        mutated = editable_bytes.append(suffix)
        record = self._record_mutation(
            target=MutationTarget(layer="byte", path="segment:tail"),
            operator="tail_garbage",
            before=b"",
            after=suffix,
        )
        return MutatedCase(
            original_packet=packet,
            packet_bytes=self._finalize_packet_bytes(mutated),
            records=(record,),
            seed=config.seed,
            strategy=config.strategy,
            final_layer="byte",
        )

    # existing paths remain unchanged below
```

- [ ] **Step 5: Re-run the byte tests and verify they pass**

Run: `uv run pytest tests/mutator/test_bytes.py -q`

Expected:
- PASS

- [ ] **Step 6: Commit**

```bash
git add src/volte_mutation_fuzzer/mutator/core.py tests/mutator/test_bytes.py
git commit -m "feat: add deterministic byte tail mutation strategies"
```

---

### Task 4: Add MT-Focused Alias Port Desynchronization

**Files:**
- Modify: `src/volte_mutation_fuzzer/mutator/core.py`
- Test: `tests/mutator/test_core.py`

- [ ] **Step 1: Write the failing MT alias desync test**

```python
def test_alias_port_desync_rewrites_contact_alias_ports_but_keeps_shape(self) -> None:
    mutator = SIPMutator()
    message = parse_editable_from_wire(
        "INVITE sip:001010000123511@10.20.20.8:8100;alias=10.20.20.8~8101~1 SIP/2.0\r\n"
        "Contact: <sip:222222@10.20.20.9:31800;alias=10.20.20.9~31800~31100~1>\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )

    case = mutator.mutate_editable(
        message,
        MutationConfig(seed=301, layer="wire", strategy="alias_port_desync"),
    )

    assert case.wire_text is not None
    self.assertIn("alias=10.20.20.9~", case.wire_text)
    self.assertNotIn("alias=10.20.20.9~31800~31100~1", case.wire_text)
    self.assertEqual(case.records[0].operator, "alias_port_desync")
```

- [ ] **Step 2: Run the focused alias test and verify it fails**

Run: `uv run pytest tests/mutator/test_core.py -k alias_port_desync -q`

Expected:
- FAIL because the strategy is unsupported and no alias desync helper exists

- [ ] **Step 3: Implement alias port desync as a deterministic wire strategy**

```python
_ALIAS_PORT_PATTERN = re.compile(
    r"(;alias=[^~;>]+~)(?P<pc>\d+)(~)(?P<ps>\d+)(~1)"
)


def _apply_alias_port_desync(
    self,
    editable_message: EditableSIPMessage,
    rng: random.Random,
) -> tuple[EditableSIPMessage, MutationRecord]:
    for index, header in enumerate(editable_message.headers):
        if header.name.casefold() != "contact":
            continue
        match = _ALIAS_PORT_PATTERN.search(header.value)
        if match is None:
            continue
        pc = int(match.group("pc"))
        ps = int(match.group("ps"))
        replacement = f"{match.group(1)}{pc + rng.randrange(1, 10)}{match.group(3)}{ps + rng.randrange(1, 10)}{match.group(5)}"
        mutated_value = _ALIAS_PORT_PATTERN.sub(replacement, header.value, count=1)
        headers = list(editable_message.headers)
        headers[index] = header.model_copy(update={"value": mutated_value})
        mutated = editable_message.model_copy(update={"headers": tuple(headers)})
        return mutated, self._record_mutation(
            target=MutationTarget(layer="wire", path=f"header[{index}]"),
            operator="alias_port_desync",
            before=header.value,
            after=mutated_value,
        )
    raise ValueError("no Contact alias field available for alias_port_desync")
```

```python
if target is None and config.strategy == "alias_port_desync":
    current_message, record = self._apply_alias_port_desync(editable_message, rng)
    return MutatedCase(
        original_packet=packet,
        wire_text=self._finalize_wire_message(current_message),
        records=(record,),
        seed=config.seed,
        strategy=config.strategy,
        final_layer="wire",
    )
```

- [ ] **Step 4: Re-run the alias test and verify it passes**

Run: `uv run pytest tests/mutator/test_core.py -k alias_port_desync -q`

Expected:
- PASS

- [ ] **Step 5: Commit**

```bash
git add src/volte_mutation_fuzzer/mutator/core.py tests/mutator/test_core.py
git commit -m "feat: add MT alias port desync mutation strategy"
```

---

### Task 5: Expose The New Strategies Through CLI And Campaign

**Files:**
- Modify: `src/volte_mutation_fuzzer/mutator/cli.py`
- Modify: `src/volte_mutation_fuzzer/campaign/core.py`
- Modify: `tests/mutator/test_cli.py`
- Modify: `tests/campaign/test_core.py`
- Modify: `docs/USAGE.md`

- [ ] **Step 1: Write the failing CLI and campaign tests**

```python
def test_packet_command_accepts_realistic_wire_strategy(self) -> None:
    baseline_json = self.generate_request_baseline_json("OPTIONS")

    result = self.runner.invoke(
        self.app,
        ["packet", "--layer", "wire", "--seed", "17", "--strategy", "final_crlf_loss"],
        input=baseline_json,
    )

    payload = self.parse_output(result)
    self.assertEqual(payload["strategy"], "final_crlf_loss")
    self.assertEqual(payload["final_layer"], "wire")


def test_case_generator_allows_realistic_wire_and_byte_strategies(self) -> None:
    cfg = CampaignConfig(
        target_host="127.0.0.1",
        methods=("OPTIONS",),
        layers=("wire", "byte"),
        strategies=("final_crlf_loss", "tail_chop_1"),
        max_cases=10,
    )
    cases = list(CaseGenerator(cfg).generate())

    self.assertIn(("wire", "final_crlf_loss"), {(c.layer, c.strategy) for c in cases})
    self.assertIn(("byte", "tail_chop_1"), {(c.layer, c.strategy) for c in cases})
```

- [ ] **Step 2: Run the focused integration tests and verify they fail**

Run: `uv run pytest tests/mutator/test_cli.py tests/campaign/test_core.py -k "final_crlf_loss or tail_chop_1" -q`

Expected:
- FAIL because campaign `_SUPPORTED_STRATEGIES` does not include the new names

- [ ] **Step 3: Thread the strategies into CLI help and campaign allowlists**

```python
_SUPPORTED_STRATEGIES: dict[str, frozenset[str]] = {
    "model": frozenset({"default", "state_breaker"}),
    "wire": frozenset({
        "default",
        "identity",
        "header_whitespace_noise",
        "final_crlf_loss",
        "duplicate_content_length_conflict",
        "alias_port_desync",
    }),
    "byte": frozenset({
        "default",
        "identity",
        "tail_chop_1",
        "tail_garbage",
    }),
}
```

```python
layer: Annotated[
    str,
    typer.Option("--layer", help="Mutation layer: model, wire, byte, or auto."),
] = "auto"

strategy: Annotated[
    str,
    typer.Option(
        "--strategy",
        help=(
            "Mutation strategy name. Examples: default, final_crlf_loss, "
            "duplicate_content_length_conflict, tail_chop_1, alias_port_desync."
        ),
    ),
] = "default"
```

- [ ] **Step 4: Add concise usage documentation**

```markdown
### Realistic malformed examples

```bash
uv run fuzzer mutate packet --layer wire --strategy final_crlf_loss < baseline.json
uv run fuzzer mutate packet --layer wire --strategy duplicate_content_length_conflict < baseline.json
uv run fuzzer mutate packet --layer byte --strategy tail_chop_1 < baseline.json

# MT-template / real-UE focused
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --impi 001010000123511 \
  --methods INVITE \
  --layer wire \
  --strategy alias_port_desync \
  --mt-invite-template a31 \
  --ipsec-mode null \
  --max-cases 1
```
```

- [ ] **Step 5: Re-run the focused integration tests and verify they pass**

Run: `uv run pytest tests/mutator/test_cli.py tests/campaign/test_core.py -k "final_crlf_loss or tail_chop_1" -q`

Expected:
- PASS

Run: `uv run pytest tests/mutator tests/campaign -q`

Expected:
- PASS

- [ ] **Step 6: Commit**

```bash
git add \
  src/volte_mutation_fuzzer/mutator/cli.py \
  src/volte_mutation_fuzzer/campaign/core.py \
  tests/mutator/test_cli.py \
  tests/campaign/test_core.py \
  docs/USAGE.md
git commit -m "feat: expose realistic edge mutation strategies in cli and campaign"
```

---

## Self-Review

- Spec coverage:
  - Realistic wire rendering surface: covered in Task 1.
  - Deterministic realistic wire strategies: covered in Task 2.
  - Deterministic byte tail strategies: covered in Task 3.
  - MT-focused realistic alias corruption: covered in Task 4.
  - CLI/campaign usability and docs: covered in Task 5.

- Placeholder scan:
  - No `TODO`, `TBD`, or "appropriate handling" placeholders remain.

- Type consistency:
  - Strategy names are consistent across tasks:
    `header_whitespace_noise`, `final_crlf_loss`, `duplicate_content_length_conflict`, `tail_chop_1`, `tail_garbage`, `alias_port_desync`
  - Editable helpers are consistently named:
    `append`, `tail_delete`, `emit_final_blank_line`, `line_ending`

