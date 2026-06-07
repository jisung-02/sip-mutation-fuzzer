# iOS(iPhone) 로그 수집 구현 가이드

Ubuntu 호스트에서 USB로 연결된 iPhone을 대상으로, VolteMutationFuzzer의 Android(`adb`) 수집 파이프라인과 평행한 iOS 수집 모듈을 붙이기 위한 상세 설계·구현 문서입니다.

- **전제 환경**: Ubuntu 22.04+, iPhone(iOS 15+), USB 연결, Jailbreak 없음
- **pcap 가용성 전제**: VoLTE 트래픽은 baseband 내부로 흐르므로 호스트 pcap 미확보 가정
- **1차 목표**: crash / stack_failure / suspicious verdict를 로컬 디바이스 신호만으로 판정
- **제외**: `sysdiagnose` (10분 / 수 GB로 퍼징 루프에 부적합)

---

## 1. 설치

### 1.1 Ubuntu 패키지

```bash
sudo apt update
sudo apt install -y \
    libimobiledevice6 \
    libimobiledevice-utils \
    ideviceinstaller \
    usbmuxd \
    libplist-utils
```

설치 후 확인:
```bash
idevice_id --version           # 예: 1.3.0
ideviceinfo --version
idevicesyslog --version
idevicecrashreport --version
```

### 1.2 `usbmuxd` 데몬 기동

```bash
sudo systemctl enable --now usbmuxd
systemctl status usbmuxd       # active (running) 확인
```

### 1.3 사용자 권한 (udev 규칙)

일반 사용자로 iPhone에 접근하려면:

```bash
# /etc/udev/rules.d/39-usbmuxd.rules 가 패키지 설치 시 생성되어 있음
sudo udevadm control --reload-rules
sudo udevadm trigger
```

필요 시 사용자를 `plugdev` 그룹에 추가:
```bash
sudo usermod -aG plugdev $USER
# 재로그인
```

### 1.4 Python 의존성

프로젝트 `pyproject.toml`에 새로 추가할 의존성은 **없습니다**. `libimobiledevice` CLI를 `subprocess`로 호출하는 구조를 유지합니다 (기존 `adb` 패턴과 동일).

선택적으로 Python 바인딩을 쓰려면:
```bash
uv add pymobiledevice3   # 순수 Python 구현, USB/WiFi 지원
```
단, 본 문서 1차 구현은 CLI 기반으로 진행합니다.

---

## 2. iPhone 준비

### 2.1 기본 설정

1. USB 연결 후 iPhone에서 **"이 컴퓨터를 신뢰하시겠습니까?"** → **신뢰**
2. **설정 → 개인정보 및 보안 → 분석 및 향상**
   - **iPhone 분석 공유**: 켬 (크래시 리포트 생성 활성화)
   - **iCloud 분석 공유**: 꺼도 무관
3. 화면 잠금 해제 유지 (수집 중 잠기면 일부 로그 제한됨)

### 2.2 연결 검증

```bash
idevice_id -l
# 00008110-001A2B3C4D5E6789

ideviceinfo -u 00008110-001A2B3C4D5E6789 -k ProductType
# iPhone13,2

ideviceinfo -u 00008110-001A2B3C4D5E6789 -k ProductVersion
# 17.5.1
```

### 2.3 (선택) Apple Carrier Profile

기본 상태에서도 crash 감지는 완전하게 동작합니다. 하지만 SIP 응답 코드·IMS 상태 등 상세 필드가 `<private>`로 redact되므로, suspicious 판정 품질을 올리려면 Apple Developer에서 **Baseband** 또는 **Carrier** profile을 설치합니다.

- 다운로드: <https://developer.apple.com/bug-reporting/profiles-and-logs/>
- 설치: `.mobileconfig` → iPhone에 AirDrop/메일 전달 → 설정에서 승인 → 재부팅

설치 여부 확인:
```bash
ideviceprovision list -u <UDID>
```

본 문서의 1차 구현은 **Carrier Profile 미설치 전제**입니다.

---

## 3. 사용할 도구 요약

Android `adb` 명령과 평행 대응:

| Android | iOS (경량) | 용도 | 소요 시간 |
|---|---|---|---|
| `adb devices -l` | `idevice_id -l` + `ideviceinfo` | 디바이스 식별 | 즉시 |
| `adb logcat` (stream) | `idevicesyslog` | 실시간 로그 스트림 | 상시 |
| `adb logcat -d -T ...` | 스트림 collector + 호스트 시간 slice | 케이스 경계 로그 추출 | 즉시 |
| `adb shell dumpsys meminfo` | `idevicediagnostics diagnostics All` | 진단 스냅샷 | 1~2초 |
| `adb bugreport` (크래시) | `idevicecrashreport -k -e <dir>` | 크래시 리포트 pull | 1~3초 |
| `adb shell dumpsys ims` | ❌ 불가 (Carrier Profile 필요) | — | — |

**제외**: `sysdiagnose` — 2~10분, 200MB~1GB로 부적합.

---

## 4. 파일 구조 (결과물)

캠페인 디렉터리 레이아웃. Android 구조와 평행하게 구성합니다.

```
<campaign_root>/20260415_103000_abc12345/
├── summary.json                   # 캠페인 메타 + verdict 분포
├── results.jsonl                  # 케이스별 verdict 한 줄씩
│
├── ios_baseline/                  # 캠페인 시작 시 1회
│   ├── device_info.json           # UDID, 모델, iOS 버전, 빌드
│   └── installed_profiles.txt     # 설치된 프로비저닝 프로파일 목록
│
└── cases/
    ├── case_0000/
    │   ├── sent.sip
    │   ├── response.sip           # (pcap 있을 때만)
    │   ├── verdict.json
    │   └── ios/
    │       ├── syslog.txt         # 스트림 collector가 [start, end]로 slice
    │       ├── syslog_commcenter.txt   # CommCenter 프로세스 필터
    │       ├── syslog_springboard.txt  # SpringBoard 필터 (수신 UI)
    │       ├── crashes/           # 이 케이스 동안 신규 .ips
    │       │   └── (비어 있거나 CommCenter-2026-04-15-103412.ips)
    │       ├── diagnostics.json   # (선택) idevicediagnostics 결과
    │       └── anomalies.json     # IosAnomalyDetector 매칭 결과
    └── case_N/
```

### 4.1 `ios_baseline/device_info.json` 예시
```json
{
  "udid": "00008110-001A2B3C4D5E6789",
  "device_name": "iPhone 12",
  "product_type": "iPhone13,2",
  "product_version": "17.5.1",
  "build_version": "21F90",
  "captured_at": "2026-04-15T10:30:00+09:00"
}
```

### 4.2 `cases/case_N/ios/syslog.txt` 예시
```
Apr 15 10:32:17 iPhone CommCenter[127] <Notice>: [IMS] Registration attempt started
Apr 15 10:32:17 iPhone CommCenter[127] <Notice>: SIP request: <private>
Apr 15 10:32:17 iPhone SpringBoard[89] <Notice>: incoming call UI presented
Apr 15 10:32:18 iPhone CommCenter[127] <Notice>: SIP response code: 180
Apr 15 10:32:20 iPhone CommCenter[127] <Notice>: SIP response code: 200
```

### 4.3 `cases/case_N/ios/crashes/CommCenter-*.ips` 예시 (요약)
```json
{
  "app_name": "CommCenter",
  "timestamp": "2026-04-15 10:34:12",
  "exception": {"type": "EXC_BAD_ACCESS", "signal": "SIGSEGV"},
  "faultingThread": 0,
  "threads": [{
    "triggered": true,
    "frames": [
      {"imageOffset": 5432, "symbol": "SIPParser::parseHeader"},
      {"imageOffset": 1234, "symbol": "SIPTransaction::onMessage"}
    ]
  }]
}
```

### 4.4 `cases/case_N/ios/anomalies.json` 예시
```json
[{
  "timestamp": 1744682217.123,
  "severity": "critical",
  "category": "fatal_signal",
  "pattern_name": "EXC_BAD_ACCESS",
  "matched_line": "Apr 15 10:34:12 iPhone CommCenter[127] <Error>: EXC_BAD_ACCESS at 0x00000000",
  "process": "CommCenter"
}]
```

### 4.5 `cases/case_N/verdict.json` (Android와 동일 포맷)
```json
{
  "case_id": "case_0042",
  "verdict": "crash",
  "response_code": null,
  "ios_crashes": 1,
  "ios_anomalies": 3
}
```

---

## 5. 수집 파이프라인

### 5.1 시퀀스 (한 케이스 기준)

```
[캠페인 시작]
  └─ IosSyslogCollector.start()  ── idevicesyslog 스트림 subprocess 상주
  └─ ios_baseline 수집 (1회)

[케이스 N 시작]
  ├─ case_start_ts = time.time()
  ├─ (송신 / 응답 대기)
  ├─ case_end_ts = time.time()
  │
  └─ IosConnector.take_snapshot(output_dir, since=case_start_ts, until=case_end_ts)
      ├─ 병렬 실행:
      │   ├─ IosSyslogCollector.slice(since, until)  → syslog*.txt  (메모리, 즉시)
      │   ├─ idevicecrashreport -k -e <dir>/crashes  (1~3초)
      │   └─ idevicediagnostics diagnostics All      (1~2초, 선택)
      └─ IosAnomalyDetector.feed(lines + crashes)    → anomalies.json

[케이스 N+1 시작]
  ...
[캠페인 종료]
  └─ IosSyslogCollector.stop()
```

핵심 차이: Android는 `logcat -d -T <anchor>`로 디바이스 링 버퍼를 시간 필터 덤프하지만, iOS에는 시간 필터가 없어서 **상시 스트림을 메모리에 쌓고 케이스 경계마다 호스트 시간으로 slice**합니다.

### 5.2 시간 slice 정확도

- `idevicesyslog` 출력 라인은 `Apr 15 10:32:17` 형식 디바이스 시간을 포함
- collector는 **호스트 수신 시각**과 **디바이스 로그 시각**을 둘 다 기록
- slice는 호스트 수신 시각 기준 (케이스 송신 타임라인과 동일 도메인)
- 사이드 이펙트: 호스트-디바이스 클럭 오프셋 있어도 일관성 보존

---

## 6. 감지 로직 (Oracle)

### 6.1 패턴 정의 (`ios/patterns.py` 신규)

Android `adb/patterns.py`와 동일한 `AnomalyPattern` 구조를 재사용합니다.

```python
# src/volte_mutation_fuzzer/ios/patterns.py
from volte_mutation_fuzzer.adb.patterns import AnomalyPattern

IOS_ANOMALY_PATTERNS: tuple[AnomalyPattern, ...] = (
    # ── fatal_signal (critical) ────────────────────────────────
    AnomalyPattern(
        name="EXC_BAD_ACCESS",
        regex=r"EXC_BAD_ACCESS",
        severity="critical",
        category="fatal_signal",
    ),
    AnomalyPattern(
        name="EXC_CRASH_SIGABRT",
        regex=r"Abort trap: 6|SIGABRT",
        severity="critical",
        category="fatal_signal",
    ),
    AnomalyPattern(
        name="ReportCrash_saved",
        regex=r"ReportCrash.*Saved crash report",
        severity="critical",
        category="fatal_signal",
    ),
    AnomalyPattern(
        name="launchd_terminated_crash",
        regex=r"com\.apple\.CommCenter.*terminated due to (crash|signal)",
        severity="critical",
        category="fatal_signal",
    ),
    AnomalyPattern(
        name="jetsam_kill",
        regex=r"CommCenter.*jetsam",
        severity="critical",
        category="fatal_signal",
    ),
    AnomalyPattern(
        name="kernel_panic",
        regex=r"AppleAVE2?.*panic|watchdog.*panic",
        severity="critical",
        category="fatal_signal",
    ),

    # ── ims_anomaly (warning) ──────────────────────────────────
    AnomalyPattern(
        name="ims_registration_failed",
        regex=r"\[IMS\].*[Rr]egistration failed",
        severity="warning",
        category="ims_anomaly",
    ),
    AnomalyPattern(
        name="ims_deregistration",
        regex=r"\[IMS\].*[Dd]eregistration",
        severity="warning",
        category="ims_anomaly",
    ),
    AnomalyPattern(
        name="sip_transaction_timeout",
        regex=r"SIP transaction timeout",
        severity="warning",
        category="ims_anomaly",
    ),

    # ── call_anomaly (warning) ─────────────────────────────────
    AnomalyPattern(
        name="callkit_call_failed",
        regex=r"CallKit.*(failed|error)",
        severity="warning",
        category="call_anomaly",
    ),

    # ── system_anomaly (info) ──────────────────────────────────
    AnomalyPattern(
        name="assertion_failed",
        regex=r"Assertion failed|NSInternalInconsistencyException",
        severity="info",
        category="system_anomaly",
    ),
)
```

### 6.2 판정 규칙 (pcap 없는 전제)

```python
def judge_ios_case(signals) -> str:
    # 1. 크래시 — 가장 확실
    if signals.new_ips_files:
        return "crash"
    if signals.any_match(category="fatal_signal"):
        return "crash"

    # 2. 에러 라인 급증 → stack_failure
    if signals.error_line_count >= ERROR_BURST_THRESHOLD:
        return "stack_failure"

    # 3. IMS 이상 이벤트
    if signals.any_match(category="ims_anomaly"):
        return "suspicious"
    if signals.any_match(category="call_anomaly"):
        return "suspicious"

    # 4. 정상 경로 — SpringBoard 수신 UI
    if signals.springboard_incoming_call_ui:
        return "normal"

    # 5. 아무 신호 없음 — pcap 부재 시 timeout을 확정 못 함
    return "no_signal"
```

### 6.3 verdict 달성도 (pcap 부재 기준)

| verdict | 달성도 | 주된 근거 |
|---|---|---|
| `crash` | 100% | `.ips` 파일 + syslog fatal 패턴 |
| `stack_failure` | 90% | syslog `<Error>`/`<Fault>` 라인 집계 |
| `suspicious` | 50~60% | syslog 라벨 (상세 원인은 redact) |
| `normal` | 60~70% | SpringBoard "incoming call UI" 이벤트 |
| `no_signal` (timeout 대체) | — | 어떤 신호도 매치되지 않음 |

crash 감지는 Android 동급, 그 외는 pcap 없으면 Android보다 약합니다. 이는 퍼징 목적(크래시 발굴)에는 큰 문제가 되지 않습니다.

---

## 7. 프로젝트 통합 설계

### 7.1 신규 모듈 구조

```
src/volte_mutation_fuzzer/ios/
├── __init__.py
├── contracts.py      # IosDeviceInfo, IosSnapshotResult, IosCollectorConfig
├── core.py           # IosConnector, IosSyslogCollector, IosAnomalyDetector
└── patterns.py       # IOS_ANOMALY_PATTERNS
```

### 7.2 `contracts.py` 스케치

```python
from pydantic import BaseModel, ConfigDict

class IosDeviceInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    udid: str
    product_type: str | None = None
    product_version: str | None = None
    build_version: str | None = None
    error: str | None = None

class IosCollectorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    udid: str | None = None
    filter_processes: tuple[str, ...] = ("CommCenter", "SpringBoard", "identityservicesd")

class IosSnapshotResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    syslog_path: str | None = None
    crashes_dir: str | None = None
    new_crash_files: tuple[str, ...] = ()
    diagnostics_path: str | None = None
    anomalies_path: str | None = None
    errors: tuple[str, ...] = ()
```

### 7.3 `core.py` 스케치

```python
class IosConnector:
    def __init__(self, udid: str | None = None) -> None:
        self._udid = udid

    def _cmd(self, binary: str, *args: str) -> list[str]:
        base = [binary]
        if self._udid:
            base.extend(["-u", self._udid])
        base.extend(args)
        return base

    def check_device(self) -> IosDeviceInfo: ...

    def take_snapshot(
        self,
        output_dir: str,
        *,
        syslog_since: float | None = None,
        syslog_until: float | None = None,
        collector: "IosSyslogCollector",
    ) -> IosSnapshotResult:
        # 1) collector.slice(since, until) → syslog*.txt
        # 2) idevicecrashreport -k -e <dir>/crashes
        # 3) idevicediagnostics diagnostics All > diagnostics.json
        # 4) anomalies.json 작성
        ...


class IosSyslogCollector:
    """idevicesyslog 스트림을 상주시키며 라인을 메모리 버퍼에 적재."""

    def __init__(self, config: IosCollectorConfig | None = None) -> None: ...
    def start(self) -> None: ...            # subprocess.Popen(idevicesyslog ...)
    def stop(self) -> None: ...
    def slice(self, since_ts: float, until_ts: float) -> list[SyslogLine]: ...
    @property
    def is_healthy(self) -> bool: ...


class IosAnomalyDetector:
    """AdbAnomalyDetector와 동일 인터페이스 — 패턴만 다름."""
    ...
```

### 7.4 `CampaignExecutor` 통합 지점

`src/volte_mutation_fuzzer/campaign/core.py`에서 기존 `adb_enabled` 경로와 평행으로:

```python
# CampaignExecutor.__init__
if config.ios_enabled:
    self._ios_collector = IosSyslogCollector(
        IosCollectorConfig(udid=config.ios_udid)
    )

# CampaignExecutor.run() 시작 시
if config.ios_enabled:
    self._ios_collector.start()
    # baseline 수집 ...

# 케이스 경계
case_start_ts = time.time()
# ... 송신 / 대기 ...
case_end_ts = time.time()

if config.ios_enabled:
    IosConnector(udid=config.ios_udid).take_snapshot(
        ios_snapshot_dir,
        syslog_since=case_start_ts,
        syslog_until=case_end_ts,
        collector=self._ios_collector,
    )

# CampaignExecutor.run() 종료 시
if config.ios_enabled:
    self._ios_collector.stop()
```

### 7.5 CLI 옵션 (campaign/config.py)

기존 `--adb-*` 옵션과 평행:

```
--ios-enabled                      iPhone 로그 수집 활성화
--ios-udid <UDID>                  대상 디바이스 UDID (USB iPhone 1대면 생략)
--ios-diagnostics                  케이스별 idevicediagnostics 실행 (기본 off)
--ios-crash-clear-on-pull          .ips pull 후 디바이스 쪽 삭제 (기본 on)
```

---

## 8. 테스트 전략

`tests/ios/test_core.py`를 추가해 Android 테스트(`tests/adb/test_core.py`) 구조를 그대로 미러링:

- `IosConnector.check_device()` — `subprocess.run` mock으로 `idevice_id -l` 출력 주입
- `IosConnector.take_snapshot()` — tmp_path + mock으로 파일 생성 검증
- `IosSyslogCollector.slice()` — 큐에 라인 주입 후 타임스탬프 필터링 확인
- `IosAnomalyDetector` — 각 `IOS_ANOMALY_PATTERNS`에 대한 match/no-match 테스트
- `IosSyslogCollector._reader_loop` — EOF 후 재연결 / 최대 재시도 후 dead 마킹

---

## 9. 알려진 제약과 대처

| 제약 | 영향 | 대처 |
|---|---|---|
| SIP 헤더·Call-ID 등 `<private>` redact | suspicious 판정 품질 저하 | Carrier Profile 설치 시 해결 |
| `sysdiagnose`는 2~10분 | 케이스별 수집 불가 | 완전 제외, crash reports로 대체 |
| `idevicesyslog`에 시간 필터 없음 | 디바이스 링 버퍼 재활용 불가 | 스트림 collector + 호스트 시간 slice |
| `netstat`, `dumpsys` 상응 명령 없음 | 소켓/IMS 상태 스냅샷 불가 | `idevicediagnostics`로 부분 대체 |
| iPhone 잠금 상태에서 로그 제한 | 일부 이벤트 누락 | 잠금 해제 유지 운용 규정 |
| 연속 크래시 시 reboot | 케이스 루프 중단 | collector health check → 자동 재접속 |

---

## 10. 구현 순서 (권장)

1. **1단계** (최소 동작) — `IosSyslogCollector` + `idevicecrashreport` 단독
   - 캠페인 중 스트림 상주, 케이스 경계 slice, crash pull
   - verdict 판정: `crash` / `stack_failure`만
2. **2단계** (패턴 확장) — `IosAnomalyDetector` + `patterns.py`
   - `suspicious`, `normal` verdict 추가
3. **3단계** (통합) — `CampaignExecutor` 훅업 + CLI 옵션
4. **4단계** (선택) — `idevicediagnostics`, `ios_baseline` 수집
5. **테스트** — 각 단계마다 단위 테스트 추가

**최소 1단계만 붙여도 크래시 발굴 목적은 달성**됩니다.
