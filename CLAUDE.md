# VolteMutationFuzzer Agent Notes

## Current Scope

- Treat `fuzzer campaign run` as real-UE-first because the CLI default is
  `--mode real-ue-direct`.
- The code default for real-UE campaigns is `--target-msisdn 111111` and
  `--ipsec-mode native`.
- Softphone mode exists, but only use it when the user asks for softphone or
  when a local smoke/regression path is explicitly needed.
- Do not document fixed device-slot mappings unless current code or the user
  provides them in this turn. The code does not map `111111` to a fixed device
  model or UE IP.

## Documentation Priority

When docs disagree, use this order:

1. `AGENTS.md`, `CLAUDE.md`
2. `docs/AI_AGENT_GUIDE.md`
3. current implementation under `src/volte_mutation_fuzzer/`
4. `docs/USAGE.md`
5. `docs/ARCHITECTURE.md`
6. `docs/operations/`
7. `docs/reference/`

Current docs index: [docs/README.md](docs/README.md).

## Key Docs

- [Usage](docs/USAGE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Real-UE operations](docs/operations/real-ue.md)
- [Campaign commands](docs/operations/campaign-commands.md)
- [iOS collection](docs/operations/ios.md)
- [Server setup](docs/operations/server-setup.md)
- [Troubleshooting](docs/operations/troubleshooting.md)
- [SIP completeness](docs/reference/sip-completeness.md)
- [Fuzzer reference](docs/reference/fuzzer.md)

## Mutation Semantics

- `mode` and `profile` are independent axes:
  - `mode`: sender/runtime path
  - `profile`: mutator policy
- `--strategy default` is a request. Execution, storage, reports, and replay
  should use the concrete strategy resolved by `profile + layer + seed`.
- `--layer auto` is profile-aware in mutator CLI paths.
- Do not add `--impi` to examples unless debugging IMPI resolution, building a
  self-contained reproduction, or following an explicit user request.

## Files To Read Before Logic Changes

Profile/campaign/report/persistence:

- `src/volte_mutation_fuzzer/mutator/profile_catalog.py`
- `src/volte_mutation_fuzzer/mutator/core.py`
- `src/volte_mutation_fuzzer/mutator/cli.py`
- `src/volte_mutation_fuzzer/campaign/contracts.py`
- `src/volte_mutation_fuzzer/campaign/cli.py`
- `src/volte_mutation_fuzzer/campaign/core.py`
- `src/volte_mutation_fuzzer/campaign/report.py`
- `src/volte_mutation_fuzzer/dialog/core.py`

Runtime completeness:

- `src/volte_mutation_fuzzer/sip/completeness.py`
- `docs/reference/sip-completeness.md`
- `src/volte_mutation_fuzzer/dialog/scenarios.py`

## Baseline Command

```bash
uv run fuzzer campaign run \
  --methods INVITE \
  --profile legacy \
  --layer wire \
  --strategy identity \
  --max-cases 1
```

## Recommended Skills

- Planning larger changes: `writing-plans`, optionally `plan-eng-review`
- Debugging failures: `investigate`, `systematic-debugging`
- Explicit subagent work: `subagent-driven-development`
- Completion verification: `verification-before-completion`, `review`
- Documentation sync: `document-release`
