# Oracle 패턴 매칭 고도화 — 5-Tier + Process Tag Filter

> 작성: 2026-04-25
> 상태: plan only — 아직 구현 안 됨
> 자매 문서: [`ANOMALY_ORACLE_PLAN.md`](./ANOMALY_ORACLE_PLAN.md) (majority-aware verdict)
> 발단 자료: [`docs/이슈/2026-04-25-워크로그.md`](../이슈/2026-04-25-워크로그.md) §5 — 65 case 캠페인에서 7건 "interesting" 분석 결과 4건이 SIP echo FP, 거의 매번 BluetoothPowerStatsCollector 의 무관한 java exception 이 verdict 를 오염

## 0. 배경 — 무엇이 잘못됐나

현 oracle (`src/volte_mutation_fuzzer/adb/patterns.py` + `oracle/core.py`) 가 ~20개 regex + 4 category (`fatal_signal`/`ims_anomaly`/`call_anomaly`/`system_anomaly`) + 3 severity (`critical`/`warning`/`info`) 로 구성. 어떤 패턴이라도 매칭되면 verdict 가 일률적으로 `stack_failure` 로 승급.

500회 캠페인 중 65 case 시점 분석에서 드러난 두 종류의 false positive:

### FP 종류 1: Self-echo (SIP rejection 자체 logcat 기록)

```
04-25 09:07:28.898 I/SIPMSG[0,2]( 2815): [-->] SIP/2.0 500 Server Internal Error [CSeq: 1 MESSAGE]
```

A16 IMS 가 fuzz 거절로 보낸 500 응답을 자기 logcat 에 echo 한 줄. `[-->]` 화살표가 **outbound** 표시. 우리 fuzzer 가 보낸 mutated MESSAGE 에 대한 정상적인 거절이지 IMS 스택 자체의 실패가 아닌데, 현 oracle 의 `sip_server_error` regex (`SIP/2\.0\s+5(?:00|02|03|04|05)\b|5\d\d\s+Server Internal Error`) 가 이걸 잡아서 `stack_failure` 로 승급.

영향: 지금 `stack_failure` 4건 모두 이 FP.

### FP 종류 2: 무관 프로세스의 java exception

```
04-25 09:07:29.457 E/BluetoothPowerStatsCollector( 1601):
  java.util.concurrent.ExecutionException: java.lang.RuntimeException: error: 11
    at java.util.concurrent.CompletableFuture.reportGet(...)
    at com.android.server.power.stats.BluetoothPowerStatsCollector.collectStats(...)
```

Android 의 `BluetoothPowerStatsCollector` 가 **주기적으로** Bluetooth energy 정보를 못 가져와서 던지는 시스템 자체 noise. 우리 SIP fuzzing 과 무관. 발생 주기가 fuzz case 와 겹치면 매번 java exception 패턴이 매칭. case 18, 36, 43, 44 의 `reason` 에 `java\.lang\.\w*Exception|...` 텍스트가 박힌 게 이 때문.

영향: java exception 패턴 매칭 자체는 거의 모든 case 에서 발생할 수 있음. 진짜 IMS 관련 exception 과 구분 필요.

### 진짜 신호는 묻혀있음

이 FP 들과 같은 verdict (`stack_failure`) 칸에:
- case 37 (duplicate Call-ID → RILJ "Unexpected response! serial: 3000")
- case 40 (mutate Supported → RILJ "Unexpected response! serial: 3005", 8회)

이 두 RIL desync 신호 — IMS app layer 거절이 modem RIL transaction tracker 와 desync 됐다는 의미 있는 신호 — 가 FP 와 구분 안 되어 묻힘.

---

## 1. 두 축의 보강

### 축 1: 5-Tier 분류 (신호 강도)

| Tier | 의미 | 매핑 verdict | 매칭 예시 |
|---|---|---|---|
| **T1** | 네이티브 크래시 / 프로세스 사망 | `crash` | SIGSEGV / SIGABRT / tombstone / `Process .* has died` / `FATAL EXCEPTION:` |
| **T2** | Watchdog / 서비스 재시작 / 모뎀 리셋 | `stack_failure` | Watchdog hang / lowmemorykiller / `system_server died` / Modem reset / RILD crashed / Binder died / ImsService restart |
| **T3** | IMS 세션 단절 / RIL 비동기 / VoLTE 강제 dereg | `suspicious` | `ImsRegistrationCallback.*onUnregistered` / IMS connection died / RILJ `Unexpected response! serial=\d+` / VoLTE Disabled / SIM `STATE_LOADED→ABSENT` |
| **T4** | Java exception **with stack trace context** | stack 있으면 `stack_failure`, 없으면 `suspicious` | `FATAL EXCEPTION:` 이후 5줄 안에 `at \S+\(\S+:\d+\)` 따라붙음 |
| **T5** | Self-echo (자기 응답을 자기 logcat 에 표시) | **승급 없음** | `\[-->\] SIP/2\.0 [45]\d\d` |

```python
TIER_TO_VERDICT = {
    1: "crash",
    2: "stack_failure",
    3: "suspicious",
    4: "stack_failure",  # only if stack-context confirmed
    5: None,             # ignore — do not promote verdict
}
```

T5 가 같은 case 윈도우 내에서 발견되면 동일 라인의 T2/T3 매칭을 **cancel** (echo 와 진짜 5xx 가 같은 라인 그룹에 있으면 echo 우선).

### 축 2: Process Tag Filter (신호 source 신뢰도)

logcat 라인 형식: `MM-DD HH:MM:SS.NNN <Severity>/<TagName>( PID): <message>`.

`<TagName>` 으로 IMS/Telephony 관련 프로세스만 인정:

#### Whitelist (이 tag 에서 나온 매칭은 무조건 신호)
```
com.sec.imsservice          # Samsung IMS service main process
com.sec.epdg                # Samsung ePDG
com.android.phone           # Android phone process
com.samsung.android.cidmanager
com.android.providers.telephony
SemImsService               # Samsung IMS framework
[IMS                        # Samsung IMS native ([IMS6.0]/[IMS5.0])
SIPMSG                      # Samsung SIP message logger (단, [-->]는 T5 로 cancel)
ImsService
ImsManager
ImsRegistration
RILJ                        # Radio Interface Layer Java
SecRIL
RILD
TelephonyProvider
```

#### Blacklist (이 tag 에서 나온 매칭은 무조건 무시)
```
BluetoothPowerStatsCollector
WifiNl80211Manager
NetworkStatsManager
PowerStatsService
KeyguardViewMediator
ActivityManager             # 단, "Process .* has died" 같은 T1/T2 핵심 패턴은 예외 처리
WindowManager
PackageManager
```

#### 중간 (whitelist/blacklist 어디에도 없는 tag)
- T1/T2 패턴: 그래도 인정 (시스템 전체 영향 신호라 source 무관)
- T3/T4 패턴: **무시** (IMS 외 신호일 가능성 큼)

### 두 축의 결합 — 매칭 결정 흐름

```
for each logcat line:
    extract tag = parse_logcat_tag(line)
    for pattern in patterns:
        if pattern.regex matches line:
            if tag in BLACKLIST and pattern.tier not in (1, 2):
                continue   # noise 제거
            if tag not in WHITELIST and pattern.tier in (3, 4):
                continue   # IMS 무관 신호는 T3/T4 한정 무시
            return Match(pattern, tier=pattern.tier, line, tag)
```

T1, T2 는 **시스템 전체 영향** 이라 어느 프로세스에서 나오든 인정.  
T3, T4 는 **IMS/Telephony 컨텍스트** 가 의미 있어서 whitelist 에서만 인정.  
T5 는 어느 case 윈도우든 발견되면 동일 윈도우의 T2/T3 cancel.

---

## 2. 변경 범위

### 2.1 `adb/contracts.py`

```python
AnomalyCategory = Literal[
    "fatal_signal",        # T1
    "service_restart",     # T2 (신규)
    "session_disruption",  # T3 (신규, 기존 ims_anomaly 흡수)
    "java_exception",      # T4 (신규)
    "echo_response",       # T5 (신규, negative)
    # 기존 호환
    "ims_anomaly", "call_anomaly", "system_anomaly",
]
```

`AdbAnomalyEvent` 에 두 필드 추가:
```python
tier: int                # 1~5
source_tag: str | None   # logcat tag (BluetoothPowerStatsCollector 등)
```

### 2.2 `adb/patterns.py`

```python
class AnomalyPattern:
    def __init__(self, name, regex, severity, category, *,
                 tier: int,
                 require_stack_context: bool = False,
                 cancel_on_tag_blacklist: bool = True): ...
```

기존 ~20 패턴 재분류 + 신규 추가:
- T1: SIGSEGV / SIGABRT / tombstone / native_crash / libc_abort / FATAL EXCEPTION
- T2: **신규** — Watchdog (`Watchdog: WATCHDOG`), Modem reset (`subSys-RestartLevel|CRASH NOTIFICATION`), `system_server died`, `RILD has crashed`, `Process .* has died`, `Killing .*lowmemorykiller`
- T3: **재분류** — RILJ Unexpected response, ImsRegistration unregister, VoLTE Disabled, SIM STATE_LOADED→ABSENT, IMS connection died
- T4: **신규** — `FATAL EXCEPTION:` (multi-line context required)
- T5: **신규** — `SIPMSG\[.*\]: \[-->\] SIP/2\.0 [45]\d\d`

`sip_server_error` 의 regex 좁히기:
- 기존: `SIP/2\.0\s+5(?:00|02|03|04|05)\b|5\d\d\s+Server Internal Error`
- 변경: `(?<!\[-->\] )SIP/2\.0\s+5\d\d` (echo 화살표 직후는 제외) 또는 T5 매칭 시 cancel.

### 2.3 `adb/core.py` — logcat 파서

logcat 라인 정규식에서 tag 분리:

```python
LOGCAT_LINE = re.compile(
    r"^\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} "
    r"[VDIWEF]/(?P<tag>[^(]+)\(\s*\d+\):\s*(?P<msg>.*)$"
)
```

`source_tag` 를 추출해서 매칭 시 whitelist/blacklist 검사.

새 모듈 상수:
```python
WHITELIST_TAGS = frozenset({...})
BLACKLIST_TAGS = frozenset({...})
```

env override 가능: `VMF_ADB_WHITELIST_TAGS`, `VMF_ADB_BLACKLIST_TAGS` (콤마 구분).

### 2.4 `oracle/core.py`

ADB anomaly → verdict 매핑을 단일 `stack_failure` 가 아니라 tier 기반:

```python
verdict = TIER_TO_VERDICT.get(adb_result.tier)
if verdict is None:
    # T5 (echo) — verdict 변경 안 함
    return base_verdict
return OracleVerdict(verdict=verdict, ...)
```

T4 stack-context 검증: 매칭 라인 이후 5줄 sliding window 안에 `at \S+\(\S+:\d+\)` 따라붙는지. 없으면 T4 → suspicious 로 강등.

T5 cancel 로직: 같은 case 윈도우 내에 T5 매칭이 있으면 동일 윈도우의 T2/T3 매칭을 무효화.

### 2.5 신규 모듈 `oracle/reclassifier.py`

기존 jsonl 의 `details.adb_warning` 데이터로 새 룰 적용한 verdict 계산:

```bash
uv run fuzzer campaign reclassify <jsonl-or-dir> [--out <path>]
```

원본 immutable. `<dir>/campaign_reclassified.jsonl` 로 출력 + 변경 매트릭스 (`OLD verdict × NEW verdict`) 출력.

**중요**: 기존 jsonl 에 `matched_line` 만 있고 logcat tag 가 명시 안 돼있을 수 있음. matched_line 자체를 다시 logcat 정규식으로 파싱해서 tag 추출 — 데이터 보존됨.

### 2.6 `ios/patterns.py`

iOS 도 동일 tier 도입. 단 logfile 형식이 달라 별도 regex 셋. v1 은 ADB 만, iOS 는 v1 검증 후.

### 2.7 테스트

`tests/oracle/fixtures/` 에 실제 캠페인 데이터를 fixture 로:
- `logcat_t1_native_crash.txt` (합성 — testbed 에서 본 적 없음)
- `logcat_t2_modem_reset.txt` (합성)
- `logcat_t3_ril_desync.txt` — **case 37/40 의 실제 RILJ Unexpected response 라인**
- `logcat_t4_java_exception_with_stack.txt` — 합성 (FATAL EXCEPTION + stack)
- `logcat_t4_java_exception_no_stack.txt` — **case 18 의 실제 BluetoothPowerStatsCollector** — should be **suppressed by blacklist**
- `logcat_t5_echo.txt` — **case 18/36/43/44 의 실제 `[-->] SIP/2.0 500` 라인**

각 fixture 에 대한 단위 테스트:
- T1 → verdict=crash
- T2 → verdict=stack_failure
- T3 → verdict=suspicious
- T4 with stack → stack_failure, no stack → suspicious
- T5 → no verdict change
- BluetoothPowerStatsCollector 라인은 어떤 패턴 매칭이든 verdict 변화 없음
- RILJ 라인은 T3 신호로 인정

### 2.8 문서

- `docs/AI_AGENT_GUIDE.md` 의 oracle 섹션 갱신
- `docs/USAGE.md` 에 reclassify subcommand + tag override env vars
- `CLAUDE.md` 의 "Oracle 판정 기준" 표 갱신
- `docs/이슈/2026-04-25-워크로그.md` 6.1 punch list 의 oracle 항목 진행 상태 갱신

---

## 3. Phase 와 우선순위

### Phase A — Tag filter (가장 효과 큼, 가장 작은 작업)

1. logcat 정규식으로 tag 추출
2. WHITELIST_TAGS / BLACKLIST_TAGS 상수
3. 매칭 시 tag 기반 cancel (T3/T4 만 비-whitelist 차단, T1/T2 는 무관)
4. 단위 테스트 (BluetoothPowerStatsCollector fixture)

→ 작업 ~3시간. **즉시 BluetoothPowerStatsCollector 류 noise 제거** → 캠페인 노이즈 대폭 감소.

### Phase B — T5 echo cancel + sip_server_error regex 좁힘

1. T5 패턴 추가
2. sip_server_error 좁힘 (echo 제외)
3. 단위 테스트 (case 18/36/43/44 fixture)

→ 작업 ~2시간. **즉시 4건 FP stack_failure → normal 강등**.

### Phase C — Tier 기반 verdict 분리

1. `AnomalyCategory` 와 `tier` 필드 도입
2. `TIER_TO_VERDICT` 매핑
3. 기존 패턴 재분류 + T1/T2 신규 패턴 (Watchdog, Modem reset 등)
4. T4 multi-line stack-context 검증 로직
5. 통합 테스트

→ 작업 ~4시간. case 37/40 가 `suspicious` 로 분리됨.

### Phase D — Retroactive reclassifier

1. `oracle/reclassifier.py`
2. `campaign reclassify` subcommand
3. 변경 매트릭스 출력
4. 기존 캠페인 jsonl fixture 로 검증

→ 작업 ~2시간. 이미 돌린 캠페인 재분석 가능.

### Phase E — iOS 동등 적용 (선택)

→ 작업 ~3시간. v1 보류.

### Phase F — 문서 + ANOMALY_ORACLE_PLAN 와 통합

→ 작업 ~1.5시간.

| Phase | 시간 | 누적 효과 |
|---|---|---|
| A | 3h | BluetoothPowerStatsCollector 류 java exception noise 제거 |
| B | 2h | SIP echo FP 제거 |
| A+B | 5h | 현재 FP 4~6건 즉시 해결 |
| +C | 9h | RIL desync 와 일반 stack_failure 분리, 진짜 crash 분리 |
| +D | 11h | 기존 jsonl 재분석 가능 |
| +F | 12.5h | 문서 + ANOMALY plan 과 연계 |

총 (A+B+C+D+F) **~12.5시간**, 약 1.5일.

---

## 4. ANOMALY_ORACLE_PLAN 과 관계

[`ANOMALY_ORACLE_PLAN.md`](./ANOMALY_ORACLE_PLAN.md) 는 **majority-aware verdict** — 캠페인 전체 분포에서 outlier 인 case 를 `suspicious` 로 자동 승격.

이 문서 (5-Tier + Tag filter) 는 **패턴 매칭 정밀도** — 한 case 의 logcat 안에서 진짜 신호와 노이즈를 구분.

둘은 **직교**:
- Tag filter 가 BluetoothPowerStatsCollector 같은 노이즈를 사전 차단 → 매 case 의 verdict 가 깨끗해짐
- Majority-aware 가 전체 분포에서 rare verdict 를 강조 → 캠페인 단위 outlier 식별

병행 적용하면:
- A16 캠페인 1000회 중 대다수 normal/500
- BluetoothPowerStatsCollector noise 는 tag filter 로 사전 제거
- RILJ Unexpected response (case 37, 40 류) 는 T3 → suspicious 로 정확히 분류
- 그 위에 majority-aware 로 "같은 mutation 류에서 보통 500 인데 이번엔 408" 같은 거 추가 강조

추천 진행 순서:
1. Phase A (tag filter) — **즉시 노이즈 80% 감소 효과**
2. Phase B (T5 echo)
3. Phase C (tier 분리)
4. Phase D (reclassifier)
5. ANOMALY_ORACLE_PLAN Phase A (live majority-aware) — tier 시스템 위에 얹는 형태가 깨끗
6. ANOMALY_ORACLE_PLAN Phase B (post-hoc outlier CLI)

---

## 5. 리스크와 완화

| 리스크 | 완화 |
|---|---|
| Whitelist 가 너무 좁아서 진짜 IMS 신호가 새 tag 에서 나오면 놓침 | env override (`VMF_ADB_WHITELIST_TAGS`) 로 운영 중 즉시 추가 가능. T1/T2 는 어쨌든 인정 |
| Blacklist 도 운영 환경 (Pixel/iPhone/A31) 에 따라 다른 noise tag 가 있을 수 있음 | Blacklist 는 명시적 list 만, 모르는 tag 는 차단하지 않음 (whitelist-not-listed → T3/T4 만 차단) |
| T5 echo cancel 이 진짜 5xx 도 같이 죽일 수 있음 | echo 의 마커 (`[-->]`) 에 의존. 이 마커 자체가 Samsung 특화 — 다른 단말은 다른 마커일 수 있음. 단말별 echo pattern 분기 가능 |
| Multi-line stack context (T4) 가 logcat 인터리빙 (다른 프로세스 로그가 끼어듦) 으로 누락 | 5줄 sliding window 안에 stack frame 있으면 인정. 너무 엄격하지 않게 |
| 기존 캠페인 jsonl 의 verdict 가 새 룰로 retroactive 하게 바뀌면 외부 도구가 깨질 수 있음 | reclassifier 는 별도 출력. 원본 immutable |
| Tag 추출 정규식이 변형된 logcat 형식 (예: `[V/Tag:` vs `V/Tag(`) 에 실패 | logcat 파서를 robust 하게 — fallback 으로 tag=None 인 경우는 모든 patterns 통과 (현 동작과 동일) |

---

## 6. 결정 필요 사항

1. **WHITELIST 의 정확한 멤버십**: 위 리스트가 A16 기준 충분한지. Pixel / 다른 단말 가서 부족하면 즉시 추가. v1 은 A16 기준으로 시작.
2. **Tag 매칭 방식**: 정확 일치 (`==`) vs prefix 매칭 (`startswith`) vs substring (`in`). `[IMS6.0]` 같은 변형 brand 가 있어서 **substring 또는 prefix** 추천. 보수적으로는 prefix.
3. **Reclassifier default 동작**: 기존 캠페인의 verdict 를 "원본 그대로 유지 + 별도 output" 이 default. 동의?
4. **iOS 적용 시점**: v1 에서 제외해도 무방. 다음 캠페인 사이클에서.
5. **`require_stack_context=True` (T4)** 의 window 크기: 5줄이 적당한지 10줄까지 봐야 하는지. logcat 인터리빙 빈도 보고 결정.

---

## 7. 현 데이터 기반 즉시 검증 가능한 것

500회 캠페인 jsonl 이 이미 있음. Phase A+B 만 들어가면 **재퍼징 없이** 즉시:

- case 18, 36, 43, 44 → java exception (BluetoothPowerStatsCollector) + sip_server_error (echo) 둘 다 무시 → verdict=`normal` 로 정정
- case 37, 40 → RILJ Unexpected response (RILJ tag, T3) → verdict=`suspicious` 유지/정정
- case 39 → "Malformed From" parser drop → 그대로 timeout

기대 결과: 500회 중 **진짜 의심 케이스가 2건 (37, 40)** 으로 압축. SNR 대폭 개선.
