# Campaign Commands

This file keeps copy-pasteable commands for the current runtime. Prefer these
over old worklogs or implementation notes.

## Real-UE INVITE Baseline

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --methods INVITE \
  --profile legacy \
  --layer wire \
  --strategy identity \
  --ipsec-mode native \
  --max-cases 1
```

## Pixel IMS Profile

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --methods INVITE \
  --pixel \
  --profile pixel_ims \
  --layer wire,byte \
  --strategy default \
  --ipsec-mode native \
  --mutations-per-case 2 \
  --max-cases 100
```

## iPhone IMS Profile

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn <MSISDN> \
  --methods INVITE \
  --profile iphone_ims \
  --layer wire,byte \
  --strategy default \
  --ipsec-mode native \
  --ios \
  --mutations-per-case 2 \
  --max-cases 100
```

## MESSAGE Native Burst

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --methods MESSAGE \
  --mt \
  --layer byte \
  --strategy identity \
  --ipsec-mode native \
  --max-cases 30 \
  --cooldown 0 \
  --timeout 1 \
  --output message-native-burst
```

For load-only runs, reduce evidence overhead explicitly:

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --methods MESSAGE \
  --mt \
  --layer byte \
  --strategy default \
  --ipsec-mode native \
  --max-cases 10000 \
  --cooldown 0 \
  --timeout 0.01 \
  --circuit-breaker 0 \
  --no-pcap \
  --no-adb \
  --oracle-log-grace 0
```

## Report And Replay

```bash
uv run fuzzer campaign report <campaign.jsonl> --filter suspicious,crash,stack_failure
uv run fuzzer campaign replay <campaign.jsonl> --case-id <id>
```

## Corpus Mode And Promotion

`--corpus-dir` runs a campaign over a directory of seed packets instead of
freshly generated ones. Every recognized file (`.sip`, `.bin`, `.bytes`,
`.txt`, hidden files skipped) must start with a supported SIP request line;
its method joins the campaign method set automatically.

- Seeds are raw bytes, so corpus mode is `byte`-layer only (`model`/`wire`
  are rejected). Unlike `--packet-file`, the seed **is mutated** — strategy
  picks the byte-layer operator pool (`default`, `identity`, `safe`,
  `header_targeted`, `tail_chop_1`, `tail_garbage`, `splice`).
- Which seed a case uses is derived from its seed value, so the reproduction
  command in `campaign.jsonl` re-selects the same seed and replays the exact
  same mutation.
- `--strategy splice` crosses two same-method seeds per case: the head of one
  and the tail of another, both cut at CRLF boundaries (deterministic from
  the seed). Requires at least two seeds for the method; available for the
  `legacy` and `parser_breaker` profiles.

```bash
uv run fuzzer campaign run \
  --corpus-dir ./corpus \
  --profile legacy \
  --layer byte \
  --strategy default \
  --mutations-per-case 2 \
  --max-cases 100

# AFL-style splicing between corpus seeds
uv run fuzzer campaign run \
  --corpus-dir ./corpus \
  --profile parser_breaker \
  --strategy splice \
  --max-cases 100
```

`campaign promote` closes the feedback loop: it recycles the exact sent bytes
of every `crash`/`stack_failure`/`suspicious` case (from
`interesting/case_<id>/sent.bin` or `sent.sip`) into a corpus directory the
next campaign can consume.

```bash
uv run fuzzer campaign promote <campaign.jsonl>            # → <campaign_dir>/corpus/
uv run fuzzer campaign promote <campaign.jsonl> --out ./corpus-round2
```

The output contains one file per promoted case plus a `manifest.json` with
verdict/strategy/seed provenance (`manifest.json` is never loaded as a seed).
Typical workflow:

```bash
# round 1: fresh generated campaign
uv run fuzzer campaign run --methods INVITE --profile legacy --max-cases 500
# recycle anomalies into seeds
uv run fuzzer campaign promote results/<campaign_id>/campaign.jsonl
# round 2: re-fuzz the anomalies
uv run fuzzer campaign run --corpus-dir results/<campaign_id>/corpus --max-cases 200
```

Note: with runtime feedback on (default), the anomalies are already landing
in `results/<campaign_id>/corpus/` during round 1, and round-2 corpus cases
continue mutating the most recent hit (`--no-feedback` disables both).

## Sequence Mode

Multi-message state-attack scenarios — ordering anomalies a single mutated
packet cannot express. Chained mutation applies to every `mutate`-flagged
step; repeated steps retransmit the same seeded packet.

```bash
uv run fuzzer campaign sequence --scenario invite_retransmit --repeats 3 \
  --profile legacy --strategy default --max-cases 10

uv run fuzzer campaign sequence --scenario invite_early_bye \
  --strategy null_byte_only --max-cases 10

uv run fuzzer campaign sequence --scenario invite_double_bye --max-cases 5
uv run fuzzer campaign sequence --scenario cancel_retransmit --repeats 2
```

## Defaults That Matter

- `campaign run` defaults to `real-ue-direct`.
- Real-UE default target is `111111`.
- Real-UE default IPsec mode is `native`.
- Legacy profile defaults to `default,state_breaker` when strategy is omitted.
- `--strategy default` is resolved by `profile + layer + seed`.
- `--impi` is not normally included. Use it only for IMPI debugging or self-contained reproduction.
