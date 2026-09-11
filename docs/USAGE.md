# Usage

## Install

```bash
uv sync
poe install
```

## Defaults From Code

`fuzzer campaign run` defaults:

| Setting | Code default |
| --- | --- |
| `--mode` | `real-ue-direct` |
| real-UE `--target-msisdn` | `111111` |
| real-UE `--ipsec-mode` | `native` |
| `--target-port` | `5060` |
| `--transport` | `UDP` |
| `--profile` | `legacy` |
| `--layer` | `model,wire,byte` |
| `--strategy` | `default,state_breaker` for legacy campaigns |
| `--max-cases` | `1000` |
| `--timeout` | `5.0` |
| `--cooldown` | `0.2` |
| `--circuit-breaker` | `10` |

Real-UE mode auto-enables ADB and pcap. Use `--no-adb` or `--no-pcap` to turn
them off. If `--ios` is set and ADB is not explicitly configured, ADB is turned
off.

## Baselines

Default real-UE INVITE baseline:

```bash
uv run fuzzer campaign run \
  --methods INVITE \
  --profile legacy \
  --layer wire \
  --strategy identity \
  --max-cases 1
```

3GPP MT-INVITE template baseline:

```bash
uv run fuzzer campaign run \
  --methods INVITE \
  --mt \
  --profile legacy \
  --layer wire \
  --strategy identity \
  --max-cases 1
```

Let the UE keep ringing instead of sending campaign teardown CANCEL:

```bash
uv run fuzzer campaign run \
  --methods INVITE \
  --mt \
  --profile legacy \
  --layer wire \
  --strategy identity \
  --no-teardown \
  --max-cases 1
```

## Profile Runs

Pixel-oriented profile:

```bash
uv run fuzzer campaign run \
  --methods INVITE \
  --profile pixel_ims \
  --pixel \
  --layer wire,byte \
  --strategy default \
  --mutations-per-case 2 \
  --max-cases 100
```

iPhone-oriented profile with iOS collection:

```bash
uv run fuzzer campaign run \
  --methods INVITE \
  --profile iphone_ims \
  --layer wire,byte \
  --strategy default \
  --ios \
  --mutations-per-case 2 \
  --max-cases 100
```

High-throughput MT MESSAGE run:

```bash
uv run fuzzer campaign run \
  --methods MESSAGE \
  --mt \
  --layer byte \
  --strategy default \
  --max-cases 10000 \
  --cooldown 0 \
  --timeout 0.01 \
  --circuit-breaker 0 \
  --no-pcap \
  --no-adb \
  --oracle-log-grace 0
```

## Corpus Campaigns

`--corpus-dir` mutates a directory of seed packets instead of generating fresh
packets. Seeds are raw byte buffers (`.sip`, `.bin`, `.bytes`, `.txt`; hidden
files skipped), each starting with a supported SIP request line; the campaign
method set defaults to the methods found in the corpus.

```bash
# Round 1: normal generated campaign
uv run fuzzer campaign run --methods INVITE --profile legacy --max-cases 500

# Recycle anomalies into seeds (crash/stack_failure/suspicious sent bytes)
uv run fuzzer campaign promote results/<campaign_id>/campaign.jsonl

# Round 2: re-fuzz the recycled seeds at the byte layer
uv run fuzzer campaign run \
  --corpus-dir results/<campaign_id>/corpus \
  --profile legacy \
  --strategy default \
  --max-cases 200
```

Corpus rules:

- `byte` layer only (`model`/`wire` are rejected); the seed is mutated, unlike
  `--packet-file` which sends verbatim.
- Byte-layer strategies apply (`default`, `identity`, `safe`,
  `header_targeted`, `tail_chop_1`, `tail_garbage`, `splice`).
- Which seed a case mutates is derived from its seed value, so reproduction
  commands re-select the same seed and replay the exact mutation.
- `--strategy splice` crosses two same-method seeds per case (head of one +
  tail of the other, cut at CRLF boundaries, deterministic from the seed).
  It needs at least two seeds for the method and is allowed for `legacy` and
  `parser_breaker` profiles only.

## Sequence Mode

`campaign sequence` runs cataloged multi-message state-attack scenarios — the
ordering anomalies single-packet mutation cannot express. Every step flagged
`mutate` in the scenario receives the mutation config (chained mutation), and
repeated steps retransmit the same seeded packet back-to-back.

```bash
uv run fuzzer campaign sequence --scenario invite_retransmit --repeats 3 \
  --profile legacy --strategy default --max-cases 10

uv run fuzzer campaign sequence --scenario invite_early_bye \
  --strategy null_byte_only --max-cases 10

uv run fuzzer campaign sequence --scenario invite_double_bye --max-cases 5
uv run fuzzer campaign sequence --scenario cancel_retransmit --repeats 2
```

Scenarios:

| Scenario | Pattern |
| --- | --- |
| `invite_retransmit` | mutated INVITE ×N back-to-back, then CANCEL |
| `invite_early_bye` | mutated INVITE → mutated BYE before any 1xx, then CANCEL |
| `invite_double_bye` | INVITE → ACK → mutated BYE → mutated BYE again |
| `cancel_retransmit` | INVITE → mutated CANCEL ×2 |

Rules:

- `--methods INVITE` only; sequence scenarios are INVITE-dialog based and
  carry their own cleanup steps.
- Mutually exclusive with `--mt`, `--packet-file`, and `--corpus-dir`;
  no `--response-codes`.
- `--repeats N` overrides the repeat count of repeated steps
  (retransmission pressure).
- Per-step outcomes land in `details.sequence_steps` in `campaign.jsonl`, so
  reports show which message in the chain misbehaved.

## Runtime Feedback

`--feedback` (on by default, `--no-feedback` to disable) closes part of the
feedback loop inside a running campaign:

- **Live promotion**: the moment a case is verdicted
  `crash`/`stack_failure`/`suspicious`, its exact sent bytes are written to
  `<campaign_dir>/corpus/case_<id>_<method>.bin|.sip` — the same layout
  `campaign promote` produces, so a follow-up campaign can point
  `--corpus-dir` at it without a promote step.
- **Last-seed continuation**: in corpus campaigns, after a hit, even-numbered
  cases mutate the most recently promoted payload (deepening around the
  anomaly) while odd-numbered cases keep rotating the static corpus
  (exploration).

Continuation depends on live responses, so replaying a continuation case
re-rolls it against the static corpus; the promoted seed itself is on disk
for manual reproduction.

## Profiles And Strategies

`--profile` controls mutation policy. It is independent from sender `--mode`.

| Profile | Layers with non-empty support |
| --- | --- |
| `legacy` | `model`, `wire`, `byte` |
| `delivery_preserving` | `model`, `wire`, `byte` |
| `ims_specific` | `wire`, `byte` |
| `parser_breaker` | `wire`, `byte` |
| `pixel_ims` | `wire`, `byte` |
| `iphone_ims` | `wire`, `byte` |

`--strategy default` is resolved into a concrete strategy from
`profile + layer + seed`. Persisted results and reproduction commands should be
read by the resolved strategy, not the requested `default` token.

Strategy allow-lists live in
`src/volte_mutation_fuzzer/mutator/profile_catalog.py`.

## Runtime Completeness

| Scope | Methods |
| --- | --- |
| `runtime_complete + real_ue_baseline` | `INVITE` |
| `runtime_complete + invite_dialog` | `ACK`, `BYE`, `CANCEL`, `INFO`, `PRACK`, `REFER`, `UPDATE` |
| `runtime_complete + stateless` | `MESSAGE`, `OPTIONS`, `SUBSCRIBE` |
| `generator_complete + generator_only` | `NOTIFY`, `PUBLISH`, `REGISTER` |

Details are in `docs/reference/sip-completeness.md`.

## Key Options

Target and runtime:

```text
--mode softphone|real-ue-direct
--target-msisdn <MSISDN>
--target-host <IP>
--target-port <PORT>
--transport UDP|TCP
--ipsec-mode native|null|bypass
```

Mutation:

```text
--methods INVITE,MESSAGE,OPTIONS
--response-codes 180,200,400
--with-dialog / --no-with-dialog
--profile legacy,delivery_preserving,ims_specific,parser_breaker,pixel_ims,iphone_ims
--layer model,wire,byte
--strategy identity,default,<concrete-strategy>
--mutations-per-case <N>
--seed-start <N>
```

Real-UE and template:

```text
--mt / --no-mt
--packet-file <path>
--corpus-dir <dir>
--impi <IMPI>
--preserve-via / --no-preserve-via
--preserve-contact / --no-preserve-contact
--pixel / --no-pixel
--no-teardown
--mt-local-port <PORT>
--from-msisdn <MSISDN>
```

Evidence:

```text
--pcap / --no-pcap
--pcap-interface <IF>
--adb / --no-adb
--adb-serial <SERIAL>
--adb-buffers main,system,radio,crash
--ios / --no-ios
--ios-udid <UDID>
--ios-diagnostics / --no-ios-diagnostics
--oracle-log-grace <SECONDS>
--wait-idle-timeout <SECONDS>
--output <RESULTS_DIR_NAME>
```

There is no `--pcap-dir` option in the current campaign CLI. Pcaps are written
under the campaign directory's `pcap/` folder. In real-UE mode, leaving
`--pcap-interface` as `any` is normalized by config validation to `br-volte`.

## Special Paths

- `--mt` uses the bundled `mt_invite_3gpp.sip.tmpl` INVITE template for INVITE
  campaigns.
- `--mt` requires `real-ue-direct` and `target_msisdn`.
- `--packet-file` is mutually exclusive with `--mt`.
- `--packet-file` sends raw bytes verbatim and supports only `byte` or `auto`
  layer, which resolves to `byte`, and only `identity` strategy.
- `--corpus-dir` is mutually exclusive with `--mt` and `--packet-file`,
  requires `real-ue-direct` and `target_msisdn`, restricts layers to `byte`
  (auto resolves to `byte`), and defaults the method set from the corpus
  start-lines. See "Corpus Campaigns" above.
- `--strategy splice` is corpus-only: it is rejected without `--corpus-dir`.

## IPsec Modes

- `native`: default real-UE mode, sends from the P-CSCF namespace through the
  negotiated IMS IPsec/xfrm session.
- `null`: plaintext path through the P-CSCF namespace.
- `bypass`: P-CSCF namespace path intended for xfrm policy bypass experiments.

Native runs may show ESP rather than readable SIP in external pcaps. Read
`observer_events`, SIP responses, and `campaign.jsonl` first.

## Results

```bash
uv run fuzzer campaign report <campaign.jsonl>
uv run fuzzer campaign report <campaign.jsonl> --filter suspicious,crash,stack_failure
uv run fuzzer campaign report <campaign.jsonl> --html
uv run fuzzer campaign replay <campaign.jsonl> --case-id <id>
uv run fuzzer campaign promote <campaign.jsonl> [--out <dir>]
uv run fuzzer campaign sequence --scenario <name> [options]
```

`campaign promote` copies the exact sent bytes of every
`crash`/`stack_failure`/`suspicious` case into a seed directory (default
`<campaign_dir>/corpus/`) plus a `manifest.json` with provenance; the
directory feeds `--corpus-dir` for the next round. With runtime feedback on
(see "Runtime Feedback"), interesting payloads land in `corpus/` during the
run, so promote is mainly for retroactively recycling older campaigns.

Typical output layout:

```text
results/<campaign>/
├── campaign.jsonl
├── pcap/
├── interesting/
├── adb_snapshots/
├── ios_snapshots/
└── corpus/            # after `campaign promote`
```

## Environment

```bash
export VMF_REAL_UE_PCSCF_IP=172.22.0.21
export VMF_MSISDN_TO_IP_<MSISDN>=<UE_IP>
export VMF_IMPI=<IMPI>
```

There is no hardcoded MSISDN-to-IP fallback in the current code.
