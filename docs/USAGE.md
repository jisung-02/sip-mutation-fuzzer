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

## IPsec Modes

- `native`: default real-UE mode, sends from the P-CSCF namespace through the
  negotiated IMS IPsec/xfrm session.
- `null`: plaintext path through the P-CSCF namespace.
- `bypass`: P-CSCF namespace path intended for xfrm policy bypass experiments.

Native runs may show ESP rather than readable SIP in external pcaps. Read
`observer_events`, SIP responses, and `results.jsonl` first.

## Results

```bash
uv run fuzzer campaign report <results.jsonl>
uv run fuzzer campaign report <results.jsonl> --filter suspicious,crash,stack_failure
uv run fuzzer campaign report <results.jsonl> --html
uv run fuzzer campaign replay <results.jsonl> --case-id <id>
```

Typical output layout:

```text
results/<campaign>/
├── results.jsonl
├── pcap/
├── interesting/
├── adb_snapshots/
└── ios_snapshots/
```

## Environment

```bash
export VMF_REAL_UE_PCSCF_IP=172.22.0.21
export VMF_MSISDN_TO_IP_<MSISDN>=<UE_IP>
export VMF_IMPI=<IMPI>
```

There is no hardcoded MSISDN-to-IP fallback in the current code.
