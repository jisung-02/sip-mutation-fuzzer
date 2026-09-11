# VolteMutationFuzzer

VoLTE/IMS SIP mutation fuzzer. The `fuzzer campaign run` CLI currently defaults
to the real-UE sender path and native IMS IPsec. Softphone mode still exists in
the codebase, but it is no longer the default campaign path.

## Quick Start

Install:

```bash
uv sync
poe install
```

Run the default real-UE INVITE baseline:

```bash
uv run fuzzer campaign run \
  --methods INVITE \
  --profile legacy \
  --layer wire \
  --strategy identity \
  --max-cases 1
```

Run a 3GPP MT-INVITE template baseline:

```bash
uv run fuzzer campaign run \
  --methods INVITE \
  --mt \
  --profile legacy \
  --layer wire \
  --strategy identity \
  --max-cases 1
```

Run a device-profile campaign:

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

Run a corpus campaign (mutate real/prior packets instead of generating new
ones), then recycle anomalies into the next round's seeds:

```bash
uv run fuzzer campaign run --corpus-dir ./corpus --max-cases 100
uv run fuzzer campaign promote results/<campaign_id>/campaign.jsonl
uv run fuzzer campaign run --corpus-dir results/<campaign_id>/corpus --max-cases 100
```

Run a sequence-mode state-attack scenario (retransmitted INVITEs, early or
double teardown, chained mutation across the dialog):

```bash
uv run fuzzer campaign sequence --scenario invite_retransmit --repeats 3 \
  --profile legacy --strategy default --max-cases 10
```

## Code-Checked Defaults

These come from `src/volte_mutation_fuzzer/campaign/cli.py` and
`src/volte_mutation_fuzzer/campaign/contracts.py`.

- CLI mode default: `--mode real-ue-direct`
- real-UE target default: `--target-msisdn 111111`
- real-UE IPsec default: `--ipsec-mode native`
- default profile: `legacy`
- default layers: `model,wire,byte`
- default strategies: `default,state_breaker` for legacy campaigns
- `--mt` uses bundled template `mt_invite_3gpp.sip.tmpl`
- `--packet-file` is real-UE only, raw-byte safe, and supports only `byte` layer
  plus `identity` strategy
- `--corpus-dir` mutates a directory of seed packets at the `byte` layer;
  `campaign promote` recycles interesting-case payloads into new seeds
- runtime feedback (on by default) promotes interesting payloads into
  `<campaign>/corpus/` live and lets corpus cases continue from the last hit;
  `--no-feedback` disables it
- `campaign sequence --scenario <name>` runs multi-message state-attack
  scenarios (`invite_retransmit`, `invite_early_bye`, `invite_double_bye`,
  `cancel_retransmit`)
- real-UE campaigns auto-enable ADB and pcap unless `--no-adb` or `--no-pcap`
  is set

No checked-in code maps an MSISDN to a fixed device model or fixed UE IP. Treat
device identity and UE IP as runtime state resolved from IMS registration, P-CSCF
logs, xfrm state, or explicit `VMF_MSISDN_TO_IP_<MSISDN>` override.

## Documentation

- [Docs index](docs/README.md)
- [Usage guide](docs/USAGE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Real-UE operations](docs/operations/real-ue.md)
- [Campaign commands](docs/operations/campaign-commands.md)
- [Troubleshooting](docs/operations/troubleshooting.md)
- [SIP/fuzzer reference](docs/reference/README.md)

## Source Layout

```text
src/volte_mutation_fuzzer/
├── generator/   # SIP packet generation and MT templates
├── mutator/     # model/wire/byte mutation engine
├── sender/      # real-ue-direct and direct send paths
├── oracle/      # verdict and anomaly classification
├── campaign/    # campaign config, execution, report/replay
├── capture/     # pcap capture
├── adb/         # Android evidence collection
├── ios/         # iPhone evidence collection
└── infra/       # route/testbed helpers
```
