# AI Agent Guide Explained

이 문서는 [`AI_AGENT_GUIDE.md`](AI_AGENT_GUIDE.md)가 왜 추가됐는지, 그리고 앞으로 AI가 이 저장소를 어떤 기준으로 읽고 행동하게 되는지를 사람이 빠르게 이해할 수 있도록 설명하는 문서다.

## 왜 이 문서를 만들었나

이 저장소는 시간이 지나면서 문서 층이 많이 쌓였다. 그 과정에서 아래 같은 혼선이 생길 수 있다.

- 과거 softphone-first 기획 문서와 현재 real-ue-direct 운영 기준이 함께 존재함
- mutator 쪽은 최근에 `profile` 축이 추가되었는데, 예전 문서에는 그 개념이 없음
- `strategy=default` 를 단순 문자열로 보면 되지만, 실제 실행에서는 concrete strategy 로 해석되어 저장됨
- 사람은 문맥을 자연스럽게 보정할 수 있지만, AI는 오래된 문서나 주변 문맥을 그대로 믿고 잘못된 방향으로 갈 수 있음

그래서 AI가 먼저 무엇을 읽고, 무엇을 현재 기준으로 삼고, 어떤 표현을 조심해야 하는지 명시적으로 고정하는 가이드가 필요했다.

## 이번에 실제로 바뀐 것

이번 정리로 아래가 추가되거나 보강됐다.

- [`AI_AGENT_GUIDE.md`](AI_AGENT_GUIDE.md)
  - AI 전용 운영 가이드
- [`AGENTS.md`](../AGENTS.md)
  - 현재 우선순위와 AI 작업 루틴 반영
- [`CLAUDE.md`](../CLAUDE.md)
  - 같은 기준을 Claude 계열 지침에도 반영
- [`docs/README.md`](README.md)
  - AI 관련 문서가 인덱스에 보이도록 추가
- [`README.md`](../README.md)
  - AI 가이드 링크 추가
  - softphone-first 성격의 오래된 문서를 historical reference 로 보도록 문구 보정

즉, AI는 앞으로 루트 지침과 AI 가이드를 먼저 보고, 그 다음에 usage/architecture/code 순서로 내려가게 된다.

## 지금 AI가 따라야 하는 핵심 기준

### 1. 기본 기준은 real-ue-direct

현재 저장소의 기본 운영 기준은 softphone 이 아니라 `real-ue-direct` 와 실기기 퍼징이다.

의미:

- 기본 설명 예시는 실기기 기준이 우선
- A31, MT template, IMS 경로, iOS 로그 수집 같은 흐름을 먼저 생각함
- softphone 은 사용자가 명시적으로 요청할 때만 적극적으로 다룸

### 2. `mode` 와 `profile` 은 다른 축이다

이 부분이 최근 가장 중요하게 정리된 내용이다.

- `mode`
  - sender 와 실행 경로 축
  - 예: `softphone`, `real-ue-direct`
- `profile`
  - mutator 가 어떤 종류의 변이를 고를지 정하는 축
  - 예: `legacy`, `delivery_preserving`, `ims_specific`, `parser_breaker`

즉, AI는 더 이상 `mode` 와 `profile` 을 섞어서 설명하면 안 된다.

### 3. `default` strategy 는 요청값일 뿐이다

사용자가 `--strategy default` 를 주더라도, 실제 실행에서는 다음 조합으로 concrete strategy 가 결정된다.

- `profile`
- `layer`
- `seed`

그래서 결과를 볼 때는 다음을 같이 봐야 한다.

- `profile`
- resolved `strategy`
- `mutation_ops`
- `reproduction_cmd`

이제 AI는 “결과에 `default` 가 남아 있겠지”라고 가정하면 안 된다.

### 4. mutator CLI 도 profile-aware 로 이해해야 한다

최근 수정으로 `mutator` CLI 의 `--layer auto` 도 profile-aware 하게 동작한다.

예를 들면:

- `parser_breaker` 는 자동으로 compatible layer 로 내려감
- invalid profile 입력은 traceback 이 아니라 정상적인 CLI validation error 로 처리됨

즉, AI는 예전처럼 “auto 면 결국 model”이라고 설명하면 안 된다.

### 5. 복붙용 명령 세트에서는 `--impi` 를 기본 추천하지 않는다

현재 운영 가정은 보통 아래 둘 중 하나가 안정적이라는 것이다.

- `VMF_IMPI` 환경변수가 이미 잡혀 있음
- resolver 가 IMPI 를 안정적으로 복원함

그래서 AI가 캠페인 명령 세트, 예시 명령, 복붙용 운영 명령을 만들 때는 `--impi` 를 기본으로 붙이지 않게 했다.

`--impi` 는 아래처럼 특별한 경우에만 붙이는 것이 현재 기준이다.

- IMPI resolution 실패를 디버깅할 때
- 다른 환경으로 옮겨도 바로 돌아야 하는 self-contained 재현 명령이 필요할 때
- 사용자가 명시적으로 `--impi` 를 포함한 명령을 원할 때

## 사람이 기대할 수 있는 변화

이제 AI에게 작업을 시키면 아래 쪽으로 더 안정적으로 움직여야 한다.

- 실기기 기준 설명이 먼저 나옴
- softphone 쪽으로 불필요하게 새지 않음
- mutation profile 축을 이해한 상태로 제안함
- 결과/replay/report 에서 resolved strategy 를 기준으로 읽음
- 오래된 plan 문서보다 현재 usage/architecture/implementation 을 먼저 봄

## 사람이 읽을 때 추천 순서

AI 가이드를 만든 이유를 이해하고 싶다면 아래 순서가 가장 빠르다.

1. [`AGENTS.md`](../AGENTS.md)
2. [`AI_AGENT_GUIDE.md`](AI_AGENT_GUIDE.md)
3. [`USAGE.md`](USAGE.md)
4. [`ARCHITECTURE.md`](ARCHITECTURE.md)

실기기 퍼징 자체를 바로 보고 싶다면 아래 순서가 좋다.

1. [`A31_REAL_UE_GUIDE.md`](A31_REAL_UE_GUIDE.md)
2. [`USAGE.md`](USAGE.md)
3. 필요 시 [`iOS_LOG_COLLECTION.md`](iOS_LOG_COLLECTION.md)

mutator/profile 축이 궁금하면 아래를 보면 된다.

1. [`Fuzzer.md`](Fuzzer.md)
2. [`AI_AGENT_GUIDE.md`](AI_AGENT_GUIDE.md)
3. 구현 기준으로 `src/volte_mutation_fuzzer/mutator/profile_catalog.py`

## AI에게 이렇게 말하면 된다

앞으로 AI에게 작업을 맡길 때는 아래처럼 말하면 의도가 더 정확하게 들어간다.

### 실기기 기준으로 보게 하고 싶을 때

```text
real-ue-direct 기준으로만 봐줘
```

### profile 축을 명시하고 싶을 때

```text
ims_specific profile 기준으로 설명해줘
parser_breaker profile 기준으로 테스트 전략 제안해줘
```

### 오래된 softphone 문맥으로 새는 걸 막고 싶을 때

```text
softphone 얘기는 빼고 현재 기준만 정리해줘
```

### AI가 헷갈리는 것 같을 때

```text
docs/AI_AGENT_GUIDE.md 기준으로 다시 설명해줘
```

## 이 문서는 무엇이 아니냐

이 문서는 구현 명세서가 아니다.

- 상세 CLI 옵션 정의는 [`USAGE.md`](USAGE.md)
- 내부 데이터 흐름은 [`ARCHITECTURE.md`](ARCHITECTURE.md)
- 퍼징 철학과 재현성 규칙은 [`Fuzzer.md`](Fuzzer.md)
- 실기기 운용 절차는 [`A31_REAL_UE_GUIDE.md`](A31_REAL_UE_GUIDE.md)

이 문서의 역할은 “AI가 왜 그렇게 행동하게 만들었는지”를 사람이 이해하도록 돕는 것이다.

## 한 줄 요약

이제 AI는 이 저장소를 볼 때 과거 softphone-first 문맥보다 현재 `real-ue-direct` 와 `profile` 축 semantics 를 먼저 읽도록 정렬되어 있다.
