---
name: fuzz
description: VoLTE fuzzer를 실행한다. "퍼징 해줘", "퍼징 돌려", "fuzz", "캠페인 실행", "INVITE 퍼징" 등을 요청할 때 사용한다. 사용자가 타깃, 메서드, 전략 등을 지정하면 적절한 명령을 구성하고 실행한다.
---

# VoLTE Fuzzer 실행기

사용자가 퍼징을 요청하면 상황에 맞는 campaign run 명령을 구성하고 실행한다.

## 실행 전 확인

### 1. 타깃 확인
사용자가 타깃을 명시하지 않으면 질문한다:
- **A31 실기기** → `--mode real-ue-direct --target-msisdn 111111 --impi 001010000123511 --mt-invite-template a31 --ipsec-mode null`
- **소프트폰** → `--target-host <ip> --target-port <port>`

### 2. 출력 경로 결정
```
results/<target>_<date>_<time>.jsonl
```
예: `results/a31_20260412_1530.jsonl`

## 명령 구성

### A31 실기기 기본 템플릿
```bash
uv run fuzzer campaign run \
  --mode real-ue-direct --target-msisdn 111111 \
  --impi 001010000123511 --mt-invite-template a31 \
  --ipsec-mode null --preserve-contact --preserve-via \
  --methods INVITE \
  --layer wire,byte --strategy identity,default \
  --timeout 6 --cooldown 0.1 --no-process-check \
  --max-cases <N> \
  --output <path>
```

### 소프트폰 기본 템플릿
```bash
uv run fuzzer campaign run \
  --target-host <ip> --target-port <port> \
  --methods INVITE,OPTIONS,MESSAGE \
  --layer model,wire,byte --strategy default,state_breaker \
  --timeout 3 --cooldown 0.1 \
  --max-cases <N> \
  --output <path>
```

### 옵션 매핑

사용자 요청에서 다음을 파악한다:

| 사용자 표현 | CLI 옵션 |
|------------|----------|
| "빠르게", "터보" | `--timeout 3 --cooldown 0.05` |
| "꼼꼼하게", "천천히" | `--timeout 10 --cooldown 0.5` |
| "pcap 뜨면서" | `--pcap --pcap-dir results/pcap` |
| "pcap 브릿지에서" | `--pcap --pcap-interface br-volte` |
| "adb 연결해서" | `--adb --adb-serial <serial>` |
| "wire만" | `--layer wire` |
| "byte만" | `--layer byte` |
| "identity만", "baseline" | `--strategy identity --layer wire` |
| "N개만" | `--max-cases N` |
| "이어서", "resume" | `--resume` |
| "crash 분석" | `--crash-analysis` |

### 옵션이 불명확할 때 기본값

| 항목 | 기본값 |
|------|--------|
| max-cases | 100 (빠른 탐색), 1000 (본격 퍼징) |
| layer | wire,byte (A31), model,wire,byte (소프트폰) |
| strategy | identity,default (A31), default,state_breaker (소프트폰) |
| timeout | 6 (A31), 3 (소프트폰) |

## 실행

명령을 구성한 후 사용자에게 보여주고 확인을 받는다:

```
다음 명령으로 퍼징을 시작합니다:

uv run fuzzer campaign run \
  [구성된 명령]

실행할까요?
```

사용자가 승인하면 실행한다. 캠페인은 오래 걸릴 수 있으므로 `run_in_background`로 실행하고 결과를 기다린다.

## 실행 중 모니터링

실행이 시작되면:
1. stderr 출력을 통해 진행 상황 확인 (각 케이스 verdict)
2. CIRCUIT BREAKER 트리거 여부 확인
3. ADB WARNING 여부 확인
4. INFRA FAILURE 여부 확인

## 실행 완료 후

자동으로 `/fuzz-analyze` 스킬과 동일한 분석을 수행한다:
1. summary 출력
2. 주요 발견 사항 (crash/suspicious) 하이라이트
3. 다음 퍼징 제안
