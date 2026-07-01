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
uv run fuzzer campaign report <results.jsonl> --filter suspicious,crash,stack_failure
uv run fuzzer campaign replay <results.jsonl> --case-id <id>
```

## Defaults That Matter

- `campaign run` defaults to `real-ue-direct`.
- Real-UE default target is `111111`.
- Real-UE default IPsec mode is `native`.
- Legacy profile defaults to `default,state_breaker` when strategy is omitted.
- `--strategy default` is resolved by `profile + layer + seed`.
- `--impi` is not normally included. Use it only for IMPI debugging or self-contained reproduction.
