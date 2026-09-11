# AI Agent Guide

This guide keeps agents anchored to code-checked behavior. If a claim is not
visible in `src/volte_mutation_fuzzer/`, keep it out of the operational docs.

## Priority Order

When documents disagree, use this order:

1. `AGENTS.md`, `CLAUDE.md`
2. current implementation under `src/volte_mutation_fuzzer/`
3. this file
4. `docs/USAGE.md`
5. `docs/ARCHITECTURE.md`
6. `docs/operations/`
7. `docs/reference/`

Historical PRDs, worklogs, and scratch notes were removed from the working docs
tree. Use git history only when old context is explicitly needed.

## Current Code Defaults

For `fuzzer campaign run`:

- CLI default mode is `real-ue-direct`.
- In real-UE mode, omitted `--target-msisdn` becomes `111111`.
- In real-UE mode, omitted `--ipsec-mode` becomes `native`.
- Omitted `--profile` becomes `legacy`.
- Omitted `--layer` becomes `model,wire,byte`, except `--packet-file` and
  `--corpus-dir` force `byte`.
- Omitted `--strategy` becomes `default,state_breaker` for legacy campaigns,
  except `--packet-file` defaults to `identity` and `--corpus-dir` defaults to
  `default`.
- `--mt` uses the bundled `mt_invite_3gpp.sip.tmpl` template for INVITE
  campaigns.
- `--mt` requires `real-ue-direct` and `target_msisdn`.
- `--packet-file` requires `real-ue-direct`, `target_msisdn`, `byte` layer, and
  `identity` strategy.
- `--corpus-dir` requires `real-ue-direct` and `target_msisdn`, accepts only
  `byte` layer, defaults the method set from corpus start-lines, and is
  mutually exclusive with `--mt` and `--packet-file`.
- `campaign sequence --scenario <name>` runs INVITE-dialog state-attack
  scenarios with chained mutation; INVITE methods only, mutually exclusive
  with `--mt`/`--packet-file`/`--corpus-dir`.
- Runtime feedback (`--feedback`, default on) promotes interesting payloads
  into `<campaign>/corpus/` during the run and drives last-seed continuation
  in corpus campaigns; `--no-feedback` disables it.
- Real-UE config auto-enables ADB and pcap unless explicitly disabled.
- If `--ios` is set and `--adb/--no-adb` is omitted, ADB is disabled.

The code does not define a fixed testbed device table. Treat MSISDN-to-IP and
device identity as runtime state.

## Mutation Semantics

- `mode` and `profile` are independent axes:
  - `mode`: sender/runtime path
  - `profile`: mutator policy
- `--strategy default` is not a concrete strategy. Results and replay should be
  read by the resolved concrete strategy from `profile + layer + seed`.
- `--layer auto` is profile-aware in mutator CLI paths.
- Do not add `--impi` to examples unless debugging IMPI resolution, making a
  self-contained reproduction, or following explicit user instruction.
- Corpus campaigns (`--corpus-dir`) mutate seed buffers at the `byte` layer;
  seed selection derives from the case seed, so replay reproduces the exact
  buffer. `campaign promote` recycles interesting-case sent bytes into a
  corpus directory.
- `--strategy splice` crosses two same-method corpus seeds at CRLF
  boundaries (legacy/parser_breaker profiles, corpus mode only).

## Files To Read Before Logic Changes

Profile axis, campaign persistence, replay, or report changes:

- `src/volte_mutation_fuzzer/mutator/profile_catalog.py`
- `src/volte_mutation_fuzzer/mutator/core.py`
- `src/volte_mutation_fuzzer/mutator/cli.py`
- `src/volte_mutation_fuzzer/campaign/contracts.py`
- `src/volte_mutation_fuzzer/campaign/cli.py`
- `src/volte_mutation_fuzzer/campaign/core.py`
- `src/volte_mutation_fuzzer/campaign/report.py`
- `src/volte_mutation_fuzzer/dialog/core.py`

Packet completeness or runtime honesty changes:

- `src/volte_mutation_fuzzer/sip/completeness.py`
- `docs/reference/sip-completeness.md`
- `src/volte_mutation_fuzzer/dialog/scenarios.py`

Real-UE target resolution or native IPsec changes:

- `src/volte_mutation_fuzzer/sender/real_ue.py`
- `src/volte_mutation_fuzzer/sender/ipsec_native.py`
- `src/volte_mutation_fuzzer/sender/core.py`

## Useful Commands

Default real-UE baseline:

```bash
uv run fuzzer campaign run \
  --methods INVITE \
  --profile legacy \
  --layer wire \
  --strategy identity \
  --max-cases 1
```

MT template baseline:

```bash
uv run fuzzer campaign run \
  --methods INVITE \
  --mt \
  --profile legacy \
  --layer wire \
  --strategy identity \
  --max-cases 1
```

Profile-focused run:

```bash
uv run fuzzer campaign run \
  --methods INVITE \
  --profile iphone_ims \
  --layer wire,byte \
  --strategy default \
  --ios \
  --max-cases 50
```

Report and replay:

```bash
uv run fuzzer campaign report <campaign.jsonl> --filter suspicious,crash,stack_failure
uv run fuzzer campaign replay <campaign.jsonl> --case-id <id>
```
