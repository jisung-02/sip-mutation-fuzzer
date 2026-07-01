---
name: fuzz-next
description: 이전 퍼징 결과를 기반으로 다음 퍼징 전략을 지능적으로 제안하고 실행한다. "다음 퍼징", "더 돌려", "계속", "집중 공격", "next" 등을 요청할 때 사용한다.
---

# 지능형 다음 퍼징 전략기

이전 캠페인 결과를 분석해서 가장 효과적인 다음 퍼징 전략을 결정하고 실행한다.

## 전략 결정 프로세스

### 1단계: 이전 결과 로드

```bash
# 가장 최근 결과 파일
ls -t results/*.jsonl | head -1

# footer에서 summary 추출
tail -1 <path> | jq '.summary'
```

### 2단계: 전략 선택 매트릭스

이전 결과의 verdict 분포에 따라 다음 전략을 결정한다:

#### 케이스 A: crash/stack_failure 발견 → 집중 공격 (Exploit Deepening)

crash를 유발한 케이스의 seed, layer, strategy를 파악한다:

```bash
jq -r 'select(.type=="case" and (.verdict=="crash" or .verdict=="stack_failure")) | 
  "\(.seed) \(.layer) \(.strategy) \(.method)"' <path>
```

**전략**: 해당 seed 주변 탐색
```bash
# crash seed가 42였다면, 40~50 범위 집중
--seed-start 40 --max-cases 20 --layer <crash_layer> --strategy <crash_strategy>
```

#### 케이스 B: suspicious 다수 → 변이 강화 (Boundary Probing)

suspicious 케이스의 패턴을 분석:
- 특정 응답 코드에 집중 → 해당 파서 경계 탐색
- 특정 레이어에서만 → 해당 레이어 집중

**전략**: 
```bash
# byte 레이어에서 suspicious가 많았다면
--layer byte --strategy default --max-cases 2000
```

#### 케이스 C: 전부 normal → 탐색 확장 (Coverage Expansion)

현재 퍼징이 아직 경계를 건드리지 못함.

**전략 후보**:
1. **레이어 전환**: model만 했으면 → wire,byte 추가
2. **메서드 확장**: INVITE만 했으면 → OPTIONS, MESSAGE, REGISTER 추가
3. **응답 코드 퍼징**: `--response-codes 200,401,486,500`
4. **timeout 단축**: `--timeout 2`로 타이트하게
5. **seed 점프**: `--seed-start <높은 값>`으로 새로운 변이 공간 탐색

#### 케이스 D: timeout 다수 → 인프라 점검

**전략**:
1. SA 상태 확인: `docker exec pcscf ip xfrm state`
2. 포트 재조회 확인
3. timeout 임계값 조정: `--timeout 10`으로 늘려서 확인
4. identity baseline 재실행으로 기본 연결 검증

#### 케이스 E: infra_failure → 환경 복구

**전략**:
1. UE 재등록 대기 (수분)
2. SA 상태 재확인
3. identity baseline으로 복구 확인 후 재시작

## 출력 형식

```
## 다음 퍼징 전략

### 이전 결과 요약
[간략한 이전 캠페인 통계]

### 분석
[왜 이 전략을 선택했는지]

### 제안 명령
```bash
uv run fuzzer campaign run \
  [구성된 명령]
```

### 기대 효과
[이 전략으로 무엇을 발견할 수 있는지]

실행할까요?
```

## 연속 퍼징 시나리오

사용자가 "계속 돌려" 등으로 반복 요청 시:

1. 매번 이전 결과를 분석
2. 전략을 자동 조정
3. 출력 파일명에 라운드 번호 부여: `results/a31_round2_20260412.jsonl`
4. 누적 발견 사항 추적

## 시드 관리

- 이전 캠페인의 max seed를 파악: `jq -r 'select(.type=="case") | .seed' <path> | sort -n | tail -1`
- 다음 캠페인은 그 다음 seed부터 시작하여 중복 방지
- crash seed 주변 탐색 시에는 seed 범위를 명시적으로 지정
