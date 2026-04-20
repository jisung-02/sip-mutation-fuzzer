# VolteMutationFuzzer

**VoLTE/IMS SIP 프로토콜 변이 퍼징 도구**

## 현재 작업 지침

- 현재 프로젝트 분석, 구현, 검증, 문서화는 `real-ue-direct` 및 실기기 퍼징 경로를 우선 기준으로 한다.
- 별도 요청이 없는 한 현재 소프트폰 모드는 범위 밖으로 간주하고 고려하지 않는다.
- 소프트폰 모드 관련 설명, 제안, 디버깅, 검증은 사용자가 명시적으로 요청한 경우에만 진행한다.

## AI 작업 루틴

- 에이전트 온보딩과 최신 판단 기준은 [`docs/AI_AGENT_GUIDE.md`](docs/AI_AGENT_GUIDE.md)를 먼저 본다.
- 문서가 충돌하면 우선순위는 `AGENTS.md` → `CLAUDE.md` → `docs/AI_AGENT_GUIDE.md` → `docs/USAGE.md` / `docs/ARCHITECTURE.md` → 구현 코드 순으로 본다.
- `mode` 와 `profile` 은 독립 축이다. `mode` 는 sender/실행 경로, `profile` 은 mutator 정책 축이다.
- `--strategy default` 는 요청값이고, 실제 실행/저장/재현은 `profile + layer + seed` 로 해석된 concrete strategy 기준으로 읽는다.
- `mutator` CLI 의 `--layer auto` 는 profile-aware 로 동작한다. non-legacy profile 도 compatible layer 를 자동 선택한다.
- 캠페인 명령 세트나 복붙용 예시를 만들 때는 보통 `--impi` 를 기본 추천하지 않는다. 현재 운영 가정은 `VMF_IMPI` 또는 resolver 가 안정적으로 IMPI 를 제공하는 환경이다.
- `--impi` 는 IMPI resolution 디버깅, 환경 독립적인 self-contained 재현 명령, 또는 사용자가 명시적으로 요구한 경우에만 붙이는 쪽을 기본으로 한다.
- profile 축이나 campaign/report/persistence 를 건드릴 때는 아래 파일을 먼저 읽는다.
  - `src/volte_mutation_fuzzer/mutator/profile_catalog.py`
  - `src/volte_mutation_fuzzer/mutator/core.py`
  - `src/volte_mutation_fuzzer/mutator/cli.py`
  - `src/volte_mutation_fuzzer/campaign/core.py`
  - `src/volte_mutation_fuzzer/campaign/report.py`
  - `src/volte_mutation_fuzzer/dialog/core.py`

## 권장 Skill

- 큰 변경 전 계획 수립: `writing-plans`, 필요 시 `plan-eng-review`
- 버그/실패 조사: `investigate`, `systematic-debugging`
- 사용자가 명시적으로 subagent 방식을 원할 때: `subagent-driven-development`
- 완료 직전 검증/리뷰: `requesting-code-review`, `review`, `verification-before-completion`
- 문서 동기화: `document-release`

Samsung Galaxy A31 등 실제 UE를 대상으로 한 MT-INVITE 변이 퍼징을 통해 취약점을 발견할 수 있는 도구입니다.

## 🎯 Quick Start

### Samsung A31 실기기 퍼징
```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --methods INVITE --layer wire --strategy identity \
  --mt-invite-template a31 \
  --ipsec-mode null \
  --preserve-contact --preserve-via \
  --max-cases 10
```

### iPhone 로그 수집과 함께 (libimobiledevice)
USB로 iPhone 1대만 연결되어 있으면 UDID 자동 선택:
```bash
uv run fuzzer campaign run \
  --target-host 127.0.0.1 --target-port 5060 \
  --methods OPTIONS --max-cases 10 \
  --ios
```
상세는 [iOS_LOG_COLLECTION.md](docs/iOS_LOG_COLLECTION.md) 참조.

### 소프트폰 퍼징  
```bash
uv run fuzzer campaign run \
  --target-host 127.0.0.1 --target-port 5060 \
  --methods OPTIONS,INVITE --max-cases 100
```

## 🏗️ 프로젝트 구조

```
src/volte_mutation_fuzzer/
├── generator/          # SIP 패킷 생성 (templates, real_ue_mt_template)
├── mutator/           # 변이 엔진 (model, wire, byte 레이어)
├── sender/            # 송신 엔진 (real-ue-direct, container_exec)
├── oracle/            # 응답 판정 (normal, suspicious, crash)
├── campaign/          # 캠페인 실행 (config, core)
├── capture/           # pcap 캡처
├── adb/               # Android 디버그 브릿지 연동
├── ios/               # iPhone 로그 수집 (libimobiledevice 기반)
└── infra/             # 인프라 설정 (라우팅 등)
```

## 📚 상세 문서

### 🔧 시스템 가이드
- **[AI Agent Guide](docs/AI_AGENT_GUIDE.md)** - AI/에이전트용 우선순위, 문서 읽기 순서, skill 추천, profile 축 가이드
- **[시스템 아키텍처](docs/ARCHITECTURE.md)** - 전체 구성 요소 및 데이터 흐름
- **[사용법 가이드](docs/USAGE.md)** - 상세 CLI 옵션 및 설정
- **[문제 해결](docs/TROUBLESHOOTING.md)** - 자주 발생하는 문제와 해결책

### 📱 실기기 퍼징
- **[A31 Real-UE 가이드](docs/A31_REAL_UE_GUIDE.md)** - Samsung A31 실기기 퍼징 완벽 가이드
- **[iOS 로그 수집 가이드](docs/iOS_LOG_COLLECTION.md)** - iPhone(libimobiledevice) 수집 설계·구현 문서
- **[서버 환경 설정](docs/SERVER_SETUP.md)** - IMS 서버 환경 구성 방법

### 🔬 기술 분석  
- **[A31 평문 UDP 통과 원리](docs/이슈/A31-평문-UDP-통과-원리.md)** - IPsec bypass 기술 분석
- **[IPsec 접근방식 비교](docs/이슈/Capstone-vs-VolteMutationFuzzer-IPsec-접근방식-비교.md)** - null encryption vs xfrm bypass

## 🎯 주요 기능

### 1. **실기기 지원**
- Samsung Galaxy A31 (MSISDN: 111111) 검증 완료
- 실제 수신 벨 울림 + 180 Ringing 응답 확인
- pcap 캡처 + adb 자동 스냅샷
- **iPhone**: USB로 1대 연결되어 있으면 `--ios` 한 줄로 자동 활성 (UDID auto-resolve, syslog 스트림 + crash report pull)

### 2. **다중 변이 레이어**
- **model**: SIP 구조 인식 변이 
- **wire**: SIP 텍스트 레벨 변이
- **byte**: 바이트 레벨 변이

### 3. **IPsec 우회 방식**
- **null**: null encryption + 호스트 IP spoofing (간단)
- **bypass**: xfrm policy selector 회피 (호환성)

### 4. **자동화 기능**
- MSISDN → UE IP 자동 resolve (111111 → 10.20.20.8)
- port_pc/port_ps 동적 조회 (재등록 시마다 변경)
- Via sent-by ↔ bind_port 자동 동기화

## 🔑 핵심 성과

### Samsung A31 실기기 울림 성공 (2026-04-11)
✅ **조건 1**: Source IP = 172.22.0.21 (P-CSCF)  
✅ **조건 2**: 3GPP MT-INVITE 완전 포맷 (Record-Route, P-headers, AMR SDP)  
✅ **조건 3**: Request-URI 동적 포트 (port_pc/port_ps 매번 조회)  
✅ **조건 4**: 평문 UDP 통과 (ESP 불필요)  
✅ **조건 5**: IP 단편화 회피 (fragment guard)  

**결과**: A31 화면에 수신 UI 표시 + 실제 벨 울림 + fuzzer는 180 Ringing 수신

## 🛠️ 개발 환경

### 요구사항
- Python 3.12+, uv package manager
- Docker (IMS 서버 환경)
- Samsung A31 (MSISDN 111111, UE IP 10.20.20.8)
- 서버: ubuntu@163.180.185.51

### 설치
```bash
git clone <repo>
cd volte-mutation-fuzzer
uv sync
```

### 환경 변수
```bash
# 커스텀 MSISDN → IP 매핑
export VMF_MSISDN_TO_IP_111111=10.20.20.8
export VMF_REAL_UE_PCSCF_IP=172.22.0.21
```

## 📈 사용 시나리오

### 1. **Baseline 검증** (identity)
```bash
--strategy identity  # 무변이, oracle 역할
```
예상: A31 울림 + normal verdict

### 2. **변이 퍼징** (default)
```bash  
--strategy default --layer wire,byte --max-cases 100
```
예상: 다양한 verdict 분포 (normal/suspicious/timeout/crash)

### 3. **집중 분석** (특정 verdict)
```bash
--methods INVITE --layer byte --strategy default --max-cases 1000
# 결과 필터링: fuzzer campaign report results.jsonl --filter suspicious,crash
```

## ⚡ 성능 최적화

- **병렬 송신**: UDP + 짧은 timeout으로 빠른 케이스 처리
- **동적 resolve**: port_pc/port_ps 매번 live 조회로 정확성 보장  
- **선택적 캡처**: --pcap 옵션으로 필요시에만 packet capture
- **ADB 연동**: crash/stack_failure 시에만 자동 스냅샷

## 🔍 Oracle 판정 기준

| Verdict | 조건 |
|---------|------|
| **normal** | 180/200 응답, 프로세스 살아있음 |
| **suspicious** | 4xx/5xx 에러, 비정상 응답 |  
| **timeout** | 응답 없음 (timeout 초과) |
| **crash** | 프로세스 종료 감지 |
| **stack_failure** | adb logcat 또는 iOS syslog/`.ips` 크래시 리포트에서 anomaly 감지 |

## 📝 최근 업데이트

**2026-04-15**:
- iOS(iPhone) 로그 수집 모듈 추가 (`src/volte_mutation_fuzzer/ios/`)
- `--ios` / `--ios-udid` / `--ios-filter-processes` / `--ios-diagnostics` CLI 플래그
- `IosOracle` 통합으로 syslog/`.ips` 기반 stack_failure verdict 자동 판정
- 캠페인 결과에 `ios_baseline/` + 케이스별 `ios_snapshots/case_N/` 생성
- USB 1대 연결 시 UDID auto-resolve (옵션 생략 가능)

**2026-04-11**: 
- A31 실기기 퍼징 성공 (5가지 조건 모두 만족)
- `--ipsec-mode` 플래그로 사용자 편의성 개선
- MSISDN 자동 resolve로 중복 입력 제거

**주요 개선**:
```bash
# Before (복잡)
--target-host 10.20.20.8 --target-msisdn 111111 --source-ip 172.22.0.21

# After (간단)
--target-msisdn 111111 --ipsec-mode null
```

---

## 📞 문의

프로젝트 관련 문의사항이나 기술 지원이 필요한 경우, 관련 문서를 먼저 확인해주세요:

1. **[A31 Real-UE 가이드](docs/A31_REAL_UE_GUIDE.md)** - 실기기 퍼징 전용 가이드
2. **[문제 해결 가이드](docs/TROUBLESHOOTING.md)** - 자주 발생하는 문제들
3. **[시스템 아키텍처](docs/ARCHITECTURE.md)** - 내부 구조 이해
