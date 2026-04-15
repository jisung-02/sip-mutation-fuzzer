# 2026-04-15 · ADB `take_snapshot` 내부 병렬화

## 목적
퍼징 캠페인의 케이스당 elapsed 시간 중 상당 비중을 차지하는 `AdbConnector.take_snapshot` 의 직렬 subprocess 호출을 **동작 변경 없이** 병렬화한다.

동작 보존이 절대 요구이므로 이 문서의 범위는 `#2 snapshot 내부 병렬화` 하나로 제한한다. `#1 백그라운드 워커`, `#3 logcat_all.txt 재구성`, `#4 persistent logcat 스트림`, `#5~#8` 은 이번 변경에서 **제외**한다.

## 배경

### 현 구조 (`src/volte_mutation_fuzzer/adb/core.py:91-219`)
`take_snapshot` 한 번은 아래 subprocess 호출을 **직렬**로 수행한다.

1. `dumpsys telephony.registry` → `telephony.txt`
2. `dumpsys ims` → `ims.txt`
3. `netstat -tlnup` → `netstat.txt`
4. `logcat -d -b main` → `logcat_main.txt`
5. `logcat -d -b system` → `logcat_system.txt`
6. `logcat -d -b radio` → `logcat_radio.txt`
7. `logcat -d -b crash` → `logcat_crash.txt`
8. `logcat -d -b main,system,radio,crash` → `logcat_all.txt`
9. `dumpsys meminfo` → `meminfo.txt`
10. `dmesg` → `dmesg.txt`

추가로 dump 이전에 `get_device_time()` 1회, `bugreport=True` 시 `adb bugreport` 1회.

### 독립성
1~10 모두 adbd에 대한 읽기 전용 쿼리이며 서로 의존하지 않는다. adbd 는 한 디바이스에서 다중 shell 세션을 허용한다.

`get_device_time()` 은 **dump 이전**에 앵커를 캡처하여 다음 스냅샷과의 overlap 허용을 보장한다는 기존 계약(`core.py:138-144` 주석)을 가지므로 병렬 대상에서 제외한다.

## 변경 범위

### 수정 파일
- `src/volte_mutation_fuzzer/adb/core.py` — `take_snapshot` 의 1~10 호출을 `ThreadPoolExecutor` 로 감쌈
- `tests/adb/test_core.py` — 기존 테스트는 그대로 통과해야 하며, 병렬 실행·에러 수집 순서 보증을 위한 테스트 보강

### 수정하지 않는 파일
- `AdbSnapshotResult` 스키마 (`adb/contracts.py`)
- `take_snapshot` 외부 인터페이스 (함수 시그니처, 반환값, 파일 경로, 파일 내용)
- `_execute_case` / `_execute_mt_template_case` (`campaign/core.py`)

## 설계

### 실행 순서 (2-phase)
기존 직렬 구현의 **앵커 위치**(telephony/ims/netstat 이후, logcat dump 이전)를 그대로 유지한다. 앵커를 맨 앞으로 옮기면 logcat 슬라이스 overlap 크기가 달라져 "단순 병렬화"를 벗어나므로 phase를 나눈다.

```
1. base_dir.mkdir
2. Phase 1 — ThreadPoolExecutor(max_workers=_SNAPSHOT_MAX_WORKERS):
       telephony / ims / netstat 병렬 실행 후 조인
3. logcat_next_since = get_device_time()        # 직렬 (앵커 계약)
4. Phase 2 — ThreadPoolExecutor(max_workers=_SNAPSHOT_MAX_WORKERS):
       logcat ×4 (per-buffer) + logcat combined + meminfo + dmesg 병렬
5. bugreport (선택) — 기존대로 직렬
6. AdbSnapshotResult 조립 후 반환
```

`_SNAPSHOT_MAX_WORKERS = 8` 은 module-level 상수로 두어 튜닝 가능. 선택 이유는 "가장 느린 단일 호출(`dumpsys meminfo`) 이 전체 시간을 지배하도록" 이며 그 이상은 adbd/USB 세션 경합 우려.

### 에러 수집
- `errors: list[str]` 에 대한 접근은 `threading.Lock` 으로 보호
- 병렬 실행이므로 `errors` tuple 내 항목 **순서는 비결정적**
  - 기존에도 호출 순서가 바뀌면 순서가 바뀌는 수준이라 공식 계약은 아니지만, 테스트가 순서에 의존하면(`test_take_snapshot_records_shell_failures`) 테스트를 "원소 집합 동등" 비교로 완화
  - 소비 측 (`campaign/core.py` 의 `logger.warning`) 은 순서 비의존

### 워커 수
`max_workers=8` — 10개 태스크 중 logcat 4개는 동일 원격 프로세스(`adb` CLI)지만 서로 다른 버퍼 세션이라 경합 적다. meminfo가 가장 느리다는 가정 하에 이 값으로 수렴 예상. 운영 중 부족/과잉 관찰되면 튜닝.

### subprocess 타임아웃
개별 호출 타임아웃은 기존 값 유지 (10~60s). 개별 태스크 예외는 기존과 동일하게 `errors` 에 기록하고 해당 경로는 `None` 으로 둔다.

## 동작 보존 검증 (불변식)

| 불변식 | 검증 방법 |
|---|---|
| 출력 파일 목록·경로 동일 | `tmp_path` 기반 통합 테스트 |
| 각 파일 내용 동일 | 목(mock) subprocess로 같은 stdout 주고 바이트 비교 |
| `logcat_next_since` 가 dump 이전 시점을 반영 | `get_device_time` 이 먼저 호출됨을 테스트로 검증 |
| `AdbSnapshotResult` 필드 (paths, errors) 의미 동일 | 기존 테스트 모두 통과 |
| `bugreport=True` 동작 | 기존 테스트 통과 |
| 예외 메시지 포맷 동일 | `"dumpsys meminfo failed: meminfo boom"` 같은 문자열 그대로 |

## 테스트 전략

### 기존 테스트 (통과 유지)
- `test_take_snapshot_writes_meminfo_and_dmesg`
- `test_take_snapshot_records_shell_failures` — **errors 순서 의존 제거** 필요 (set/sorted 비교로 전환)
- `test_take_snapshot_creates_output_dir_for_bugreport`

### 신규 테스트
- `test_take_snapshot_runs_dumps_concurrently`: 호출 중 `max_concurrent ≥ 2` 와 wall-clock 이 직렬 예상치의 75% 미만임을 검증 (단순 병렬 실행 여부)
- `test_take_snapshot_captures_device_time_before_logcat`: 앵커(`date`)가 첫 `logcat` 호출보다 먼저 실행됨을 검증. telephony / ims / netstat 는 앵커 양쪽 어디에 있어도 무관
- `test_take_snapshot_partial_failure_does_not_block_others`: 한 태스크가 raise 해도 나머지 경로가 모두 기록됨

## 측정 계획

### Before
- 현재 `take_snapshot` 한 번의 wall-clock 시간 실측 없음
- `_execute_case` 케이스당 elapsed 중 snapshot 비중 실측 없음

### 방법
1. 변경 **이전** 브랜치에서 `take_snapshot` 시작~종료 `time.perf_counter()` 로그 추가 (debug 레벨), 10 케이스 샘플 수집
2. 병렬화 적용 후 같은 케이스 수로 재측정
3. 케이스당 전체 elapsed (`CaseResult.elapsed_ms`) 와 함께 비교

### 판정 기준
- snapshot wall-clock 이 최소 2× 단축되고
- 모든 기존 테스트가 통과하며
- 결과 파일 내용이 baseline 캠페인 결과와 바이트 단위로 동일해야 PR 승인

## 위험 및 대응

| 위험 | 대응 |
|---|---|
| adbd 동시 세션 한도 초과로 일부 호출 실패 | 기존 `errors` 경로로 자연스럽게 drop — 실패 빈도 관측되면 `max_workers` 축소 |
| 디바이스 CPU 부하로 개별 호출이 더 느려져 총합은 비슷 | 측정으로 확인, 효과 없으면 롤백 |
| `errors` 순서 변화로 외부 도구가 깨짐 | 현 코드베이스 내 의존 없음 (logger.warning 만 소비). 외부 문서화된 계약 아님 |
| 테스트 플레이크 (동시성 race) | 타이밍이 아닌 "호출 집합" 에 대해 assertion — 동시성은 "겹침 구간 존재"만 검증 |

## 비대상 (이번 변경에서 제외)

- `#1` 백그라운드 워커 (snapshot 을 핫패스에서 분리) — 설계 변경, 별도 RFC
- `#3` `logcat_all.txt` 를 per-buffer 결과로 재구성 — 시간순 머지 정렬 구현 필요, 별도 작업
- `#4` persistent `logcat` 스트림으로 전환 — 슬라이스 의미론 변경
- `#5` `dumpsys meminfo` 범위 축소 — 수집 데이터 감소
- `#6` send timeout 단축 — verdict 분포 변화
- `#7` cooldown 제거 — 디바이스 거동 변화 가능성
- `#8` pcap ring-buffer — 파일 구조 변화

## 작업 체크리스트

1. [ ] `adb/core.py::take_snapshot` 를 ThreadPoolExecutor 기반으로 리팩터
2. [ ] 에러 수집 스레드 세이프 (lock)
3. [ ] `tests/adb/test_core.py` 의 `errors` 순서 의존 테스트 완화
4. [ ] 신규 테스트 3종 추가
5. [ ] `uv run pytest tests/adb/ -v` 통과
6. [ ] `uv run pytest tests/ -q` 전체 회귀 (pre-existing 실패 2건은 무시)
7. [ ] 측정 로그 임시 추가 → before/after 벤치마크 → 로그 제거 또는 debug 레벨 유지 결정

## 참고

- 관련 이슈 분석: 이 대화에서 정리한 `OPTIONS/MESSAGE 케이스 속도 병목` 논의
- 관련 코드: `src/volte_mutation_fuzzer/adb/core.py:91-219`
- 관련 테스트: `tests/adb/test_core.py:86-160`
