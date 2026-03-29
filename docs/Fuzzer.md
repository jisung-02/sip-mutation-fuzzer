# 퍼저(Fuzzer) 개요 및 필수 기능

## 1. 퍼저란 무엇인가

퍼저(Fuzzer)는 소프트웨어나 프로토콜 구현체에 **의도적으로 비정상·반정상 입력을 주입**하여 취약점, 버그, 충돌(crash)을 자동으로 발견하는 보안 테스트 도구다.

퍼저는 세 가지 핵심 구성 요소로 이루어진다:

```
Poet (입력 생성기) → Courier (전달자) → Oracle (판정기)
```

| 구성 요소 | 역할 | 이 프로젝트에서의 대응 |
|-----------|------|----------------------|
| **Poet** | 변이/생성된 테스트 케이스 제작 | `generator` + `mutator` |
| **Courier** | 대상 시스템에 테스트 케이스 전달 | `sender` |
| **Oracle** | 응답·프로세스 상태를 분석해 이상 판정 | `oracle` |

퍼저가 생성하는 입력이 "버그"를 유발했는지 알려면 오라클(Oracle)이 반드시 필요하다. 크래시·비정상 응답이 없으면 퍼저는 아무것도 탐지하지 못한다.

---

## 2. 퍼저의 종류

### 2.1 입력 생성 전략 기준

| 유형 | 설명 | 장점 | 단점 |
|------|------|------|------|
| **생성 기반 (Generation-based)** | 프로토콜 사양/문법을 기반으로 입력을 처음부터 생성 | 구조적으로 유효한 입력, 깊은 코드 경로 도달 | 사양 모델링 비용 높음 |
| **변이 기반 (Mutation-based)** | 유효한 시드 입력에 변이를 가해 새 입력 생성 | 구현 간단, 실존 트래픽 재사용 가능 | 시드 품질에 의존 |
| **커버리지 유도 (Coverage-guided)** | 코드 커버리지 피드백으로 새로운 경로를 탐색 | 체계적 탐색 (AFL, libFuzzer) | 대상 계측(instrumentation) 필요 |

이 프로젝트는 **변이 기반**에 해당한다. SIP 카탈로그에서 유효한 패킷을 생성한 뒤, 다수의 변이 전략(mutation strategy)을 적용한다.

### 2.2 상태(Statefulness) 기준

| 유형 | 설명 |
|------|------|
| **Stateless** | 각 패킷을 독립적으로 전송. 빠르지만 dialog 내부 메시지 도달 불가 |
| **Stateful** | 프로토콜 상태 기계(state machine)를 추적하며 메시지 시퀀스를 구성. SIP INVITE→PRACK→BYE 같은 dialog 내 메시지 테스트 가능 |

SIP/VoLTE 퍼징에서 stateful 접근은 필수적이다. INTERSTATE, KiF 같은 선행 연구가 stateful SIP 퍼저의 필요성을 입증했다. 현재 이 프로젝트는 stateless tier1 퍼징을 구현했으며, stateful dialog는 로드맵 항목이다.

---

## 3. 퍼저가 갖춰야 하는 핵심 기능

### 3.1 입력 생성 (Poet)

- **시드 입력 관리**: 유효한 기준 패킷을 시드로 보관. 시드 품질이 탐색 깊이를 결정
- **변이 전략 다양성**: 단일 전략으로는 공격면을 제한적으로 커버. 여러 전략 조합이 필요
  - *model-layer*: 필드값 교체, 필드 삭제/추가
  - *wire-layer*: 헤더 순서 변경, 값 경계(boundary) 주입
  - *byte-layer*: 비트 플립, 랜덤 바이트 삽입 (파서 버그 탐색)
- **재현성(Reproducibility)**: 동일 시드로 동일 변이가 재현되어야 버그 보고 및 패치 검증이 가능

### 3.2 전달 (Courier)

- **프로토콜 정확성**: 변이가 전송 계층을 깨지 않아야 함. UDP/TCP 위에서 정상 소켓 통신
- **응답 수집**: 대상의 응답(SIP 상태코드, 본문)을 캡처해 오라클에 전달
- **타임아웃 처리**: 응답 없음(drop, crash)을 정해진 시간 내에 판정
- **쿨다운(Cooldown)**: 연속 전송 시 대상 과부하 방지 및 타이밍 경합 회피

### 3.3 오라클 (Oracle) — 퍼저의 핵심

오라클이 없으면 퍼저는 "총을 쏘는 것"만 하고 "맞았는지"를 알지 못한다.

**오라클이 탐지해야 하는 이상(anomaly) 유형:**

| 판정(Verdict) | 의미 | 탐지 방법 |
|--------------|------|----------|
| `crash` | 대상 프로세스가 종료됨 | 프로세스 생존 확인 (`pgrep`) |
| `timeout` | 응답 없음 (패킷 drop 또는 hang) | 소켓 타임아웃 |
| `suspicious` | 비정상 응답 (5xx/6xx, 파싱 실패, 비정상 지연) | SIP 상태코드 + 응답 시간 분석 |
| `stack_failure` | 스택 트레이스 감지 | stderr/로그 패턴 매칭 |
| `normal` | 정상 동작 | 위 조건 미해당 |
| `unknown` | 인프라 오류로 판정 불가 | 전송 자체 실패 |

**오라클의 두 가지 축:**
1. **Socket Oracle**: 응답 코드 + 응답 시간 기반 판정
2. **Process Oracle**: 프로세스 생존 여부로 crash 확정

두 오라클을 결합해 "소켓은 응답했지만 프로세스가 죽었다"는 엣지 케이스까지 처리해야 한다.

### 3.4 캠페인 관리 (Campaign)

- **자동화된 루프**: 수백~수천 케이스를 사람 개입 없이 실행
- **케이스 명세(Spec)**: 각 케이스는 method/layer/strategy/seed의 조합으로 정의. 재현 가능해야 함
- **결과 저장 (Crash-safe)**: 캠페인 중 크래시가 나도 이미 수집된 결과가 보존되어야 함. JSONL 형식이 적합 (append-only)
- **재현 명령 생성**: 각 케이스마다 동일 입력을 재현하는 CLI 명령을 저장

### 3.5 분석 및 보고 (Report)

- **집계 요약**: total/normal/suspicious/timeout/crash 건수
- **필터링**: suspicious, crash만 추출해 우선 분석
- **재실행(Replay)**: 특정 케이스 ID로 동일 패킷 재전송 → 재현성 검증

---

## 4. 프로토콜 퍼저 특유의 고려 사항

### 4.1 상태 기계 (State Machine)

SIP는 stateful 프로토콜이다. INVITE 이후에는 PRACK, UPDATE, BYE가 와야 하며, dialog-ID(Call-ID, From-tag, To-tag)가 일치해야 한다. Stateless 퍼저는 이 대화(dialog) 내부로 진입하지 못한다.

```
INVITE ──→ 100 Trying
       ──→ 180 Ringing
       ──→ 200 OK      ← 여기서부터 dialog 내부
              └──→ ACK
                   └──→ BYE  ← stateful 퍼저만 도달 가능
```

### 4.2 결정론(Determinism) vs 랜덤성

- **랜덤 퍼저**: 빠르게 넓은 공간을 탐색. 재현성 없음
- **결정론적 퍼저**: 동일 시드 → 동일 변이. 버그 보고 및 회귀 테스트에 필수
- 이 프로젝트는 **결정론적**: `seed` 값 하나로 전체 변이 시퀀스 재현 가능

### 4.3 실행 속도

SIP 퍼저는 소켓 왕복 지연(RTT) 때문에 AFL 같은 in-process 퍼저보다 느리다. INTERSTATE 연구에서는 초당 5회 미만의 실행 속도를 보고했다. 쿨다운 0.2s 기본값은 UDP 폭풍 방지와 처리 여유 시간을 위한 설계다.

### 4.4 공격면(Attack Surface) 우선순위

모든 메시지를 동일 비중으로 퍼징하는 것은 비효율적이다. Tier 시스템으로 공격면 우선순위를 구조화해야 한다:

| Tier | 대상 메서드 | 이유 |
|------|------------|------|
| **tier1** | OPTIONS, INVITE, MESSAGE, REGISTER | dialog context 불필요, 모든 UA가 처리, 취약점 밀도 높음 |
| **tier2** | PRACK, UPDATE, INFO | dialog 내부, stateful 퍼저 필요 |
| **tier3** | SUBSCRIBE, NOTIFY, PUBLISH, REFER | 구현 다양성 높음, 처리율 낮음 |

---

## 5. 이 프로젝트의 구현 현황

```
Phase 1: SIP 패킷 생성기 (generator)        ✅ 완료
Phase 2: 변이 엔진 (mutator)                ✅ 완료
Phase 3: 전송기 (sender)                    ✅ 완료
Phase 4: 오라클 + 캠페인 자동화 (oracle/campaign) ✅ 완료 (M1)
Phase 5: Stateful dialog 퍼징              🔲 로드맵
Phase 6: 커버리지 유도 + LLM 변이 생성      🔲 로드맵
```

### 현재 검증된 명령

```bash
# 단일 패킷 생성 → 변이 → 전송
uv run fuzzer request OPTIONS | \
  uv run fuzzer mutate packet --strategy state_breaker --layer wire --seed 42 | \
  uv run fuzzer send packet --target-host 10.11.207.81 --target-port 5060

# 자동 캠페인 실행 (tier1 × 100케이스)
uv run fuzzer campaign run \
  --target-host 10.11.207.81 \
  --target-port 5060 \
  --scope tier1 \
  --max-cases 100 \
  --output results/campaign.jsonl

# 결과 분석
uv run fuzzer campaign report results/campaign.jsonl
uv run fuzzer campaign report results/campaign.jsonl --filter suspicious,crash

# 특정 케이스 재실행
uv run fuzzer campaign replay results/campaign.jsonl --case-id 5
```

---

## 6. 참고 자료

1. [Fuzzing - Wikipedia](https://en.wikipedia.org/wiki/Fuzzing)
2. [What is Fuzzing: The Poet, the Courier, and the Oracle (Black Duck)](https://www.blackduck.com/content/dam/black-duck/en-us/whitepapers/what-is-fuzzing.pdf)
3. [Mutation-Based Fuzzing - The Fuzzing Book](https://www.fuzzingbook.org/html/MutationFuzzer.html)
4. [A Survey of Network Protocol Fuzzing: Model, Techniques and Directions](https://arxiv.org/html/2402.17394v1)
5. [A Survey of Protocol Fuzzing (ACM CSUR 2024)](https://wcventure.github.io/FuzzingPaper/Paper/ACM_CSUR24_Protocol_Fuzzing.pdf)
6. [INTERSTATE: A Stateful Protocol Fuzzer for SIP (DEF CON 15)](https://www.defcon.org/images/defcon-15/dc15-presentations/dc-15-harris.pdf)
7. [ProFuzzBench: A Benchmark for Stateful Protocol Fuzzing](https://arxiv.org/pdf/2101.05102)
8. [Telecom 4G/VoLTE/5G Security & Fuzzing (Fuzzing Labs)](https://fuzzinglabs.com/telecom-4g-volte-5g-security-fuzzing/)
9. [IoTFuzzSentry: Protocol Guided Mutation Based Fuzzer](https://arxiv.org/abs/2509.09158)
