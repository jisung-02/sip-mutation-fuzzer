# AI Agent Guide

LLM 기반 에이전트가 이 저장소를 다룰 때 빠르게 현재 기준을 잡고, 오래된 softphone-first 문맥에 끌려가지 않도록 돕는 운영 가이드다.

## 1. 우선순위와 진실의 원천

문서가 서로 충돌하면 아래 순서를 우선한다.

1. `AGENTS.md`, `CLAUDE.md`
2. 이 문서 `docs/AI_AGENT_GUIDE.md`
3. 현재 운용 문서:
   - `docs/USAGE.md`
   - `docs/ARCHITECTURE.md`
   - `docs/A31_REAL_UE_GUIDE.md`
   - `docs/iOS_LOG_COLLECTION.md`
   - `docs/Fuzzer.md`
4. 실제 구현:
   - `src/volte_mutation_fuzzer/mutator/`
   - `src/volte_mutation_fuzzer/campaign/`
   - `src/volte_mutation_fuzzer/sender/`
5. 과거 기획/리서치/플랜 문서:
   - `docs/기획/*`
   - `docs/결과/*`
   - `docs/superpowers/plans/*`

특히 `docs/기획/PHASE4_PRD.md`, softphone 비교 리서치, 오래된 superpowers plan 문서는 히스토리 참고용이지 현재 실행 기준이 아니다. 현재 기본 기준은 `real-ue-direct` 와 실기기 퍼징이다.

## 2. 현재 기본 운영 원칙

- 기본 설명, 구현, 검증, 예시는 `real-ue-direct` 와 실기기 경로를 우선한다.
- softphone 경로는 사용자가 명시적으로 요청할 때만 본격적으로 다룬다.
- `mode` 와 `profile` 은 서로 독립 축이다.
- `mode` 는 sender 와 실행 흐름 축이다.
- `profile` 은 mutator 가 어떤 변이 계열을 사용할지 정하는 축이다.
- `strategy=default` 는 요청값일 뿐이고, 실제 실행에는 `profile + layer + seed` 로 해석된 concrete strategy 가 남는다.
- 결과, report, replay, evidence 에는 requested strategy 가 아니라 resolved strategy 를 기준으로 읽어야 한다.
- SIP packet completeness 는 `runtime_complete` 와 `generator_complete` 로 나뉜다.
- `runtime_complete` 는 자동으로 "실기기 validated"를 뜻하지 않는다. 반드시 `baseline_scope`까지 함께 읽어야 한다.
- 현재 `INVITE`만 `real_ue_baseline` 이고, `ACK/BYE/CANCEL/INFO/PRACK/REFER/UPDATE`는 `invite_dialog`, `MESSAGE/OPTIONS`는 `stateless` runtime path 다.
- `NOTIFY/PUBLISH/REGISTER/SUBSCRIBE`는 현재 `generator_complete`다. 생성/변이는 가능하지만 honest runtime prerequisite state 는 저장소가 아직 소유하지 않는다.
- 캠페인 명령 세트나 복붙용 예시를 만들 때는 기본적으로 `--impi` 를 추천하지 않는다.
- 현재 기본 운영 가정은 `VMF_IMPI` 또는 real-ue resolver 가 안정적으로 IMPI 를 제공하는 환경이다.
- `--impi` 는 아래 경우에만 붙이는 편이 맞다.
  - IMPI resolution 문제를 디버깅할 때
  - 환경 독립적인 self-contained 재현 명령을 만들어야 할 때
  - 사용자가 명시적으로 `--impi` 포함 명령을 원할 때

## 3. 최근 변경 기준으로 이해해야 할 구조

### Mutation axis

- 입력 baseline:
  - 일반 경로: `Generator` 가 만든 `SIPRequest` / `SIPResponse`
  - MT template 경로: `EditableSIPMessage`
- mutation layer:
  - `model`
  - `wire`
  - `byte`
- mutation profile:
  - `legacy`
  - `delivery_preserving`
  - `ims_specific`
  - `parser_breaker`

### Profile 의미

| Profile | 의미 |
| --- | --- |
| `legacy` | 기존 동작과 가장 가까운 호환성 기본값 |
| `delivery_preserving` | 전달 가능성을 최대한 보존하는 약한 변이 계열 |
| `ims_specific` | IMS/3GPP 헤더, alias, routing 정합성을 겨냥한 계열 |
| `parser_breaker` | CRLF, length, tail truncation 등 parser 경계 조건 계열 |

### `default` strategy 해석

- `default` 는 concrete strategy 자체가 아니다.
- 실제 strategy 는 `profile` 과 `layer`, `seed` 에 따라 결정된다.
- 같은 baseline 과 같은 `profile/layer/seed` 면 동일한 concrete strategy 와 동일한 결과를 재현할 수 있어야 한다.

### CLI 동작에서 중요한 점

- `uv run fuzzer mutate ... --layer auto` 는 이제 profile-aware 로 동작한다.
- 예를 들어 `parser_breaker` 나 `ims_specific` 는 더 이상 무조건 `model` 로 떨어지지 않는다.
- invalid profile 입력은 traceback 이 아니라 정상적인 CLI validation error 로 처리된다.

## 4. 수정 시 먼저 봐야 할 구현 파일

profile 축이나 campaign persistence 를 건드릴 때는 아래 파일을 먼저 읽는 편이 안전하다.

- `src/volte_mutation_fuzzer/mutator/profile_catalog.py`
  - profile/layer/strategy 허용 규칙의 단일 소스
- `src/volte_mutation_fuzzer/mutator/core.py`
  - resolved strategy, profile-aware mutation selection
- `src/volte_mutation_fuzzer/mutator/cli.py`
  - profile-aware auto layer 와 CLI validation
- `src/volte_mutation_fuzzer/campaign/contracts.py`
  - `profiles`, `profile`, `strategy` 저장 계약
- `src/volte_mutation_fuzzer/campaign/core.py`
  - case scheduling, result persistence, replay/reproduction command
- `src/volte_mutation_fuzzer/campaign/report.py`
  - HTML report 의 profile/layer/strategy 표시
- `src/volte_mutation_fuzzer/dialog/core.py`
  - dialog 경로의 mutation metadata 전파

packet completeness / runtime honesty 를 건드리거나 설명해야 할 때는 아래도 먼저 본다.

- `src/volte_mutation_fuzzer/sip/completeness.py`
  - 메서드별 `tier`, `runtime_path`, `baseline_scope` 의 단일 소스
- `docs/프로토콜/SIP-메시지-완성도-매트릭스.md`
  - 사람이 읽는 completeness 해설과 note
- `src/volte_mutation_fuzzer/dialog/scenarios.py`
  - `invite_dialog`, `invite_ack`, `invite_cancel`, `invite_prack` 경로

## 5. 권장 문서 읽기 순서

### 구현 전에

1. `AGENTS.md`
2. `docs/AI_AGENT_GUIDE.md`
3. `docs/USAGE.md`
4. `docs/ARCHITECTURE.md`

### real-ue-direct / 실기기 작업 전

1. `docs/A31_REAL_UE_GUIDE.md`
2. `docs/SERVER_SETUP.md`
3. 필요하면 `docs/iOS_LOG_COLLECTION.md`

### mutator / fuzzing semantics 이해가 필요할 때

1. `docs/Fuzzer.md`
2. `src/volte_mutation_fuzzer/mutator/profile_catalog.py`
3. `src/volte_mutation_fuzzer/mutator/core.py`

## 6. AI가 바로 쓰기 좋은 명령 예시

명령 세트 예시는 현재 운영 가정에 맞춰 `--impi` 없이 적는 것을 기본으로 한다. IMPI 가 환경변수나 resolver 로 안정적으로 채워진다고 보고, self-contained 재현 명령이 필요할 때만 `--impi` 를 추가한다.

### 실기기 baseline 확인

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --methods INVITE \
  --profile legacy \
  --layer wire \
  --strategy identity \
  --mt-invite-template a31 \
  --ipsec-mode null \
  --preserve-contact --preserve-via \
  --max-cases 1
```

### runtime-complete 를 과장하지 않는 smoke 예시

```bash
# stateless runtime smoke
uv run fuzzer campaign run \
  --target-host 127.0.0.1 --target-port 5060 \
  --methods OPTIONS,MESSAGE \
  --profile legacy \
  --layer model \
  --strategy identity \
  --max-cases 2

# invite-dialog runtime smoke
uv run fuzzer campaign run \
  --target-host 127.0.0.1 --target-port 5060 \
  --methods INFO,REFER \
  --profile legacy \
  --layer model \
  --strategy identity \
  --max-cases 2
```

### IMS-specific 중심 실기기 퍼징

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --methods INVITE \
  --profile ims_specific \
  --layer wire,byte \
  --strategy default \
  --mt-invite-template a31 \
  --ipsec-mode null \
  --max-cases 20
```

### parser-breaker 중심 빠른 검사

```bash
uv run fuzzer mutate request OPTIONS --profile parser_breaker --seed 19
uv run fuzzer mutate request OPTIONS --profile parser_breaker --strategy tail_chop_1 --seed 23
```

### 결과 분석

```bash
uv run fuzzer campaign report results/<campaign>/results.jsonl
```

읽을 때는 `profile`, resolved `strategy`, `mutation_ops`, `reproduction_cmd` 를 같이 본다.

## 7. 권장 Skill / Workflow 매핑

아래는 현재 Codex / gstack / superpowers 계열 환경에서 특히 잘 맞는 조합이다.

- 큰 변경이나 다단계 구현:
  - `writing-plans`
  - 필요 시 `plan-eng-review`
- 사용자가 subagent 방식이나 병렬 작업을 명시적으로 원할 때:
  - `subagent-driven-development`
  - `dispatching-parallel-agents`
- 버그, 실패, 테스트 깨짐:
  - `investigate`
  - `systematic-debugging`
- 구현 완료 직전:
  - `requesting-code-review` 또는 `review`
  - `verification-before-completion`
- 문서 동기화:
  - `document-release`

중요한 점:

- subagent 는 사용자가 명시적으로 원할 때만 쓰는 편이 안전하다.
- review 없이 큰 mutator/campaign 변경을 끝냈다고 가정하지 않는다.
- docs 변경이 code semantics 를 설명하는 경우에는 실제 구현과 테스트 기준으로 다시 대조한다.

## 8. profile 축 관련 수정 시 체크리스트

- `mode` 와 `profile` 을 섞어서 설명하지 않았는가
- `strategy=default` 를 concrete strategy 처럼 설명하지 않았는가
- result / report / replay / evidence 중 하나라도 `profile` 또는 resolved `strategy` 를 놓치지 않았는가
- mutator CLI 와 campaign CLI 가 같은 semantics 를 유지하는가
- HTML report 와 JSON 결과가 같은 축을 보여주는가

## 9. 검증 명령 추천

profile 축, mutator CLI, campaign persistence, report surface 를 건드렸다면 우선 아래를 돌린다.

```bash
uv run pytest \
  tests/mutator/test_contracts.py \
  tests/mutator/test_core.py \
  tests/mutator/test_cli.py \
  tests/campaign/test_contracts.py \
  tests/campaign/test_core.py \
  tests/campaign/test_cli.py \
  tests/campaign/test_dashboard.py \
  tests/campaign/test_report.py \
  tests/campaign/test_evidence.py \
  tests/dialog/test_core.py \
  -q
```

mutator CLI / report 만 만졌다면 아래 빠른 검증으로 시작할 수 있다.

```bash
uv run pytest tests/mutator/test_cli.py tests/campaign/test_report.py -q
```

## 10. AI가 피해야 할 흔한 실수

- 오래된 softphone-first 문서를 현재 기본 동작으로 오해하는 것
- `default` strategy 결과를 그대로 `default` 로 기록해야 한다고 생각하는 것
- reproduction command 에 requested strategy 를 넣고 resolved strategy 를 잃어버리는 것
- HTML report 에서는 축을 추가했는데 JSON result 나 evidence 에는 반영하지 않는 것
- `ims_specific` 나 `parser_breaker` 를 `model` layer 기본값으로 취급하는 것
- `runtime_complete` 메서드를 모두 실기기 validated 로 뭉뚱그려 말하는 것
- `baseline_scope` 를 빼고 "지원됨"이라고만 적어 인간이나 다른 AI가 범위를 과대평가하게 만드는 것
- `PRACK`를 단순히 "18x가 오면 가능"이라고 설명하는 것
- `INFO` 기본값이 `dtmf`라는 점, `REFER`가 bodyless 기본값이라는 점을 놓치는 것
