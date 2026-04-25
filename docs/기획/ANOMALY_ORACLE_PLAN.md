# Anomaly-aware Oracle (Real-time) + Post-campaign Outlier 분석

> 작성: 2026-04-25
> 상태: plan only — 아직 구현 안 됨
> 배경: 2026-04-25 native UDP IPsec 검증 후 21 케이스 중 1 건의 400 응답 (`Multiple values in single-value header Content-Length`) 과 1 건의 timeout 이 모두 `normal` 또는 `timeout` 으로 묻혀버려서 oracle 이 outlier 를 surface 못한다는 문제 식별. 자세한 맥락은 [`docs/이슈/2026-04-25-워크로그.md`](../이슈/2026-04-25-워크로그.md) §5 참조.

---

## 0. Goal / Non-goal

**Goal**
- 캠페인 진행 중 outlier 케이스가 즉시 `suspicious` 로 분류되어 화면 카운터에 나타남
- 캠페인 종료 후 jsonl 만 갖고도 "이상한 케이스 N개" 를 자동 추출하는 CLI 명령
- 두 경로가 **같은 anomaly 정의** 를 공유 (한 곳만 튜닝하면 됨)

**Non-goal**
- 과거 jsonl 레코드를 retroactive 하게 rewrite 하지 않음 (immutable append-only)
- Sub-second 판정 정확도 추구 안 함 (case 단위 판정으로 충분)
- Mutation 종류별 의미적 그룹핑 (예: "헤더 삭제 류는 다 묶어서") 은 v1 범위 밖

---

## 1. 공유 모듈: `oracle/anomaly.py`

핵심 로직 한 곳에 집중 — live 와 post-hoc 둘 다 import.

```python
@dataclass
class AnomalySignal:
    severity: Literal["low", "medium", "high"]
    reason: str          # "response_code=400 (1/21, 4.8%)"
    metric: str          # "response_code" | "reason_phrase" | "elapsed_ms"

class AnomalyDetector:
    def __init__(self, *,
                 min_samples: int = 10,
                 code_rarity_threshold: float = 0.10,
                 reason_rarity_threshold: float = 0.10,
                 timing_z_threshold: float = 3.0,
                 group_by_method: bool = True): ...

    def update(self, case_result: CaseResult) -> None:
        """Add this case's stats to running distribution."""

    def evaluate(self, case_result: CaseResult) -> AnomalySignal | None:
        """Return non-None if this case is an outlier vs current state."""

    def snapshot(self) -> AnomalySnapshot:
        """Frozen view of current distributions, used by post-hoc tooling."""
```

**Tracked metrics** (per method group):
- response_code histogram
- reason_phrase histogram (lowercase, whitespace-normalized, code-stripped)
- elapsed_ms running mean + stddev (Welford 누적)
- verdict histogram (sanity)

**Outlier rule (v1)**:
- code rarity: 해당 method 내 같은 response_code 가 < 10% AND total ≥ 10 → `medium`
- 처음 보는 reason_phrase prefix → `low` (잡음 가능성)
- timing z-score > 3 → `low`
- code rarity < 5% AND total ≥ 20 → `high`

**Tests** (`tests/oracle/test_anomaly.py`):
- bootstrap: 첫 9 케이스는 evaluate=None
- 10 째 새 코드 등장 → low/medium 신호
- 20 케이스 후 1/20 outlier → medium, 1/40 → high
- multi-method 분리 (MESSAGE 19/20 = 500, INVITE 1/1 = 200 → 둘 다 정상으로 처리)

---

## 2. Phase A: Live integration (Option 1)

### 2.1 Campaign executor 에 hook

`campaign/core.py:_execute_case` 에서 base oracle 호출 직후:

```python
verdict = self._base_oracle.judge(...)
self._anomaly_detector.update(case_result)
signal = self._anomaly_detector.evaluate(case_result)
if signal and verdict.verdict == "normal":
    verdict = verdict.with_upgrade(
        new_verdict="suspicious",
        reason=f"anomaly:{signal.metric}:{signal.reason}",
    )
```

**Verdict 업그레이드 룰**:
- `normal` → `suspicious` 만 허용. `crash`/`stack_failure`/`timeout` 은 손대지 않음
- 업그레이드 reason 은 base reason 에 ` | anomaly:...` 로 append

### 2.2 결과 jsonl 에 신호 기록

`CaseResult.details` 에 `"anomaly": {"metric": ..., "reason": ..., "severity": ...}` 키 추가. 이미 `details` 가 dict[str, object] 라 새 필드 안 만들어도 됨.

### 2.3 CLI 플래그

```
--anomaly-detection / --no-anomaly-detection   (기본 on)
--anomaly-min-samples N                         (기본 10)
--anomaly-rarity-threshold P                    (기본 0.10)
```

`CampaignConfig` 에 동일 필드 3개 추가.

### 2.4 Progress UI

지금 캠페인 진행 화면이 `normal X / suspicious Y / timeout Z` 카운터를 보여주는데, anomaly 로 업그레이드된 케이스는 자연스럽게 `suspicious` 칸에 들어감. 추가 UI 변경 없음.

### 2.5 영향 범위

- `oracle/anomaly.py` 신규
- `campaign/core.py`: detector 인스턴스화 + judge 직후 호출 (~10줄)
- `campaign/contracts.py`: CampaignConfig 에 3 필드
- 기존 oracle 코드 수정 없음 (래핑)

### 2.6 테스트

- `tests/oracle/test_anomaly.py`: 단위 테스트
- `tests/campaign/test_core.py`: 기존 verdict 테스트가 모두 anomaly 비활성 상태에서 pass 해야 함 (default on 이면 fixture 가 작아서 bootstrap 미달 → reclassify 안 일어남, 그래도 명시적으로 `--no-anomaly-detection` 으로 lock)
- 새 통합 테스트: 21 case 중 1 case 만 다른 코드 → suspicious 로 분류되는지

---

## 3. Phase B: Post-campaign 도구 (Option 2)

### 3.1 새 subcommand

```
uv run fuzzer campaign outliers <jsonl-or-dir>
    [--method MESSAGE]
    [--top N]
    [--format table|jsonl|markdown]
```

내부 구현: AnomalyDetector 를 jsonl 전체로 한 번 update → 그 다음 모든 케이스에 대해 evaluate → severity 별로 정렬 → 출력.

### 3.2 출력 형식

**table (기본)**:
```
=== Outliers in MESSAGE (n=50) ===
case_id verdict      code  reason                                          severity  rarity
15      normal       400   Bad Request (Multiple values in single-value..) high      1/50 (2%)
1       timeout      —     no response received within timeout             medium    1/50 (2%)
37      normal       408   Request Timeout                                 medium    2/50 (4%)
...

=== Distribution ===
response_code: 500 (45), 400 (1), 408 (2), — (2)
verdict:       normal (48), timeout (2)
```

**jsonl (스크립팅용)**: `{"case_id": 15, "anomaly": {...}}` 한 줄씩.

**markdown**: report.html 또는 PR 코멘트에 붙여넣기 좋음.

### 3.3 Phase 1 의 detector 재사용

post-hoc 모드는 `update(...)` 를 N 번 호출해서 분포 채우고, 그 다음 evaluate. 같은 클래스 같은 룰. Phase 1/2 를 한 모듈로 묶는 이유.

### 3.4 영향 범위

- `campaign/cli.py`: `outliers` 서브커맨드 추가 (~50줄)
- `campaign/outliers.py` 신규 모듈 (table/jsonl/markdown 렌더러)
- `tests/campaign/test_outliers.py`

### 3.5 기존 `campaign report` 와 관계

기존 `campaign report` 는 oracle verdict 기반 필터링. `outliers` 는 distribution-aware. 별개로 둠 — `report` 는 fast scan, `outliers` 는 분석용. 충분한 distance 가 있으면 합치지 않음.

---

## 4. Phase C (선택): report.html 에 통합

기존 report.html 생성 로직에 "Outliers" 섹션 추가. 전체 분포 테이블 + 상위 N outlier 행 (case 행으로 anchor 링크). Phase B 의 detector 재사용.

영향: `campaign/report.py` (~30줄). 우선순위 낮음, B 가 만족스러우면 생략 가능.

---

## 5. Edge cases / 고려사항

- **Bootstrap noise**: 첫 N=10 동안은 evaluate=None. min_samples 미달 시 절대 신호 안 냄.
- **Slow-moving majority**: case 0 이 처음엔 majority 였다가 후반에 minority 가 되는 시나리오. **jsonl 은 immutable 하니** 과거 레코드의 verdict 는 안 바꿈. post-hoc tool 은 최종 분포로 다시 평가하니 거기서 정정.
- **Multi-method campaign**: MESSAGE / INVITE / OPTIONS 동시 돌면 method 별로 분리해서 distribution 추적 (group_by_method=True 기본).
- **Reason phrase 정규화**: A16 의 `"400 Bad Request (Multiple values...)"` 의 괄호 안 detail 은 mutation 마다 미묘하게 달라질 수 있음. anomaly 매칭은 status code 기준으로 먼저, reason 은 prefix 비교 (괄호 앞까지) 로.
- **Stable pattern false positive**: "헤더 X 삭제 mutation 은 항상 timeout" 같은 패턴이면 매번 anomaly 신호. v1 은 그대로 두고, v2 에서 mutation_op 별 normalization 추가 (rolling 5건 같은 패턴이 나오면 더 이상 신호 안 냄).

---

## 6. 작업 순서 / 공수

| Phase | 작업 | 추정 |
|---|---|---|
| 0 | 이 plan 검토/조정 | 30분 |
| 1 | `oracle/anomaly.py` + 단위 테스트 | 2~3시간 |
| 2 | live integration + CLI flag + 통합 테스트 | 2시간 |
| 3 | post-campaign `outliers` subcommand + 출력 포맷 + 테스트 | 2~3시간 |
| 4 (선택) | report.html 통합 | 1시간 |
| 5 | 문서 갱신 (`docs/USAGE.md`, `CLAUDE.md`) | 1시간 |

총 1~1.5일. Phase 1+2 만 먼저 들어가도 사용자가 "캠페인 도중 화면에서 suspicious 카운터로 outlier 인지" 하는 가치는 즉시 확보됨. Phase 3 은 다음 캠페인 사이클에서 추가해도 무방.

---

## 7. 의문점 / 결정 필요

1. **min_samples 기본값** — 10 으로 충분한지 50 으로 보수적으로 할지. v1 은 10 으로 가고 사용 후 조정 권장.
2. **group_by_method**: 단일 method 캠페인이 대부분이면 default off 도 무방. 하지만 multi-method 안전을 위해 default on 유지 추천.
3. **timing 신호**: elapsed_ms outlier 가 의미 있는지 (네트워크 지연 vs UE 처리 시간 분리 어려움). v1 은 끄고, B 의 post-hoc 분석에만 노출하는 옵션 고려.
4. **reason phrase 정규화 규칙**: 괄호 stripping 외에 더 엄격한 normalize 필요한지 — 먼저 raw prefix 비교로 두고 false positive 보면서 조정.
