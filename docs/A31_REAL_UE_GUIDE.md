# Real-UE Direct 퍼징 가이드

> **목표**: 현재 testbed 에 등록된 실기기 UE를 대상으로 MT-INVITE 변이 퍼징을 수행하고, baseline identity 케이스에서 정상 응답을 확인한 뒤 fuzzing 으로 확장하는 것.
>
> A31 관련 내용은 2026-04-11 성공 이력을 설명하는 historical baseline 이다. 현재 운영에서는 `111111 = A31`, `UE IP = 10.20.20.8` 을 고정값으로 보지 않는다. `--target-msisdn` 과 live resolver 결과를 우선 신뢰한다.

## 📱 현재 testbed 기준

| 구성요소 | 정보 |
|---------|------|
| **111111** | Pixel 9 / Galaxy A17 회전, UE IP 가변 |
| **222222** | iPhone 16e, UE IP `10.20.20.2` |
| **P-CSCF IP** | 172.22.0.21 |
| **서버** | ubuntu@163.180.185.51 |
| **매핑 기준일** | 2026-04-27 |

## 📜 A31 historical baseline

| 구성요소 | 2026-04-11 스냅샷 |
|---------|-------------------|
| **UE** | Samsung Galaxy A31 |
| **MSISDN** | 111111 |
| **UE IP** | 10.20.20.8 |
| **IMPI** | 001010000123511 |
| **검증일** | 2026-04-11 |

이 스냅샷은 평문 UDP 통과 원리와 성공 조건을 설명하기 위한 기록이다. 현재 슬롯은 다른 디바이스로 회전 중일 수 있으므로, 실행 전 `kamctl`, P-CSCF 로그, xfrm state 기반 live resolver 결과를 확인한다.

## 🎯 성공 조건 5가지

A31이 실제로 수신 벨을 울리려면 **다음 5가지 조건이 모두 충족**되어야 합니다:

### 1. **Source IP = 172.22.0.21** (등록된 P-CSCF IP)
- A31 IMS 앱이 **source IP 화이트리스트** 적용
- P-CSCF 아닌 IP에서 오면 조용히 drop (100 Trying은 자동 응답)
- **해결**: `--ipsec-mode null` (host spoofing), `--ipsec-mode bypass` (docker exec), 또는 `--ipsec-mode native` (실제 협상된 IPsec 경로)

### 2. **3GPP MT-INVITE 완전 포맷**
- 최소한의 SIP는 `400 Parsing Failed` 또는 무시됨
- **필수 헤더**: 3× Record-Route, P-Asserted-Identity, P-Access-Network-Info, P-Charging-Vector 등
- **필수 SDP**: AMR/AMR-WB 코덱 + curr/des:qos preconditions
- **해결**: `--mt-invite-template a31` (완전한 capture 기반 template)

### 3. **Request-URI 동적 포트**
```
sip:<impi>@<ue-ip>:<port_pc>;alias=<ue-ip>~<port_ps>~1
                                ^^^^                    ^^^^  
                              port_pc               port_ps
```
- `port_pc`/`port_ps`는 **재등록마다 순환** (7900/7901 → 8000/8001 → 8100/8101)
- **송신 목적지는 port_pc** (A31의 수신 포트)
- **해결**: 매 실행마다 `resolve_protected_ports()` 자동 조회

### 4. **전송 경로를 명확히 선택**
- `null`/`bypass`는 평문 UDP 우회 경로다.
- `native`는 실제 협상된 IMS IPsec/xfrm 세션을 사용한다.
- `null`/`bypass` 원리: Kamailio xfrm policy가 보호 포트에만 걸리므로 selector를 비껴가면 평문 UDP가 통과한다.
- `native` 원리: `pcscf` 쪽 live xfrm state를 따라 실제 보호 포트/selector로 송신한다.
- **해결**:
  - `null`/`bypass`: `--mt-local-port 15100`처럼 보호 포트를 피하는 sent-by/bind 조합 사용
  - `native`: 살아 있는 등록/xfrm 세션이 전제이며 `--target-msisdn` 기준으로 live 매핑 해석

### 5. **IP 단편화 회피**
- LTE 무선 구간에서 평문 UDP 단편화 시 A31이 첫 조각만 보고 `400 Parsing Failed`
- **해결**: fragment guard (1400 bytes 이하) 또는 TCP 사용

## 🚀 빠른 시작

### Identity 케이스 (baseline 검증)
```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn <TARGET_MSISDN> \
  --methods INVITE --layer wire --strategy identity \
  --mt-invite-template a31 \
  --ipsec-mode null \
  --preserve-contact --preserve-via \
  --mt-local-port 15100 \
  --max-cases 1 --timeout 10 --no-process-check
```

**기대 결과**:
```
[1/1] INVITE wire/identity seed=0 → normal (180, 10206ms)
[vmf campaign] completed: total=1 normal=1 suspicious=0 timeout=0 crash=0
```
- 대상 UE 화면에 수신 UI 표시 + 벨 울림
- fuzzer는 180 Ringing 수신

### 변이 퍼징 (실제 fuzzing)
```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn <TARGET_MSISDN> \
  --methods INVITE --layer wire,byte --strategy identity,default \
  --mt-invite-template a31 \
  --ipsec-mode null \
  --preserve-contact --preserve-via \
  --mt-local-port 15100 \
  --max-cases 50 --timeout 10 --no-process-check \
  --pcap --pcap-interface br-volte --pcap-dir results/real-ue/pcap \
  --adb --adb-serial <ANDROID_SERIAL> \
  --output results/real-ue/campaign.jsonl
```

**기대 결과**:
- Case 0 (identity): 매번 normal verdict (baseline)
- 후속 케이스들: 다양한 verdict 분포 (normal/suspicious/timeout/crash)
- `crash`/`stack_failure` 시 자동 adb 스냅샷
- 전체 과정 pcap 캡처

## 🔧 IPsec 모드 선택

### null encryption (추천)
```bash
--ipsec-mode null
```
**전제조건**:
- Kamailio: `ipsec_preferred_ealg "null"` 설정
- Host: `net.ipv4.ip_nonlocal_bind=1` 설정
- A31이 null encryption 수락

**장점**: 간단한 host spoofing, docker 불필요
**단점**: 서버 설정 변경 필요

### xfrm bypass (호환성)
```bash
--ipsec-mode bypass  
```
**전제조건**: 기존 AES-CBC 환경 그대로

**장점**: 서버 설정 변경 없음, 높은 호환성
**단점**: docker exec 오버헤드

### native IPsec (실제 연결 사용)
```bash
--ipsec-mode native
```
**전제조건**:
- UE가 이미 등록되어 있고 live xfrm state가 남아 있어야 함
- 현재 구현 범위는 `real-ue-direct + UDP`
- MT 경로에서는 `--target-msisdn`이 필요함

**장점**: 실제 협상된 IMS IPsec 경로를 그대로 사용
**단점**: outer wire 기준으로는 ESP가 보일 가능성이 높아 평문 SIP를 바로 읽기 어려움

### Wireshark / pcap 가시성
- `null` / `bypass`: 외부 pcap에서 평문 SIP가 보일 수 있음
- `native`: outer wire 기준으로 ESP 또는 암호화 payload가 보여서 평문 SIP가 바로 보이지 않을 수 있음
- `native` 응답 확인은 Wireshark의 평문 가독성보다 fuzzer의 `observer_events`, `responses`, `raw_response`를 우선 기준으로 본다

## 📊 결과 분석

### Verdict 해석
| Verdict | 의미 | UE 상태 |
|---------|------|----------|
| **normal** | 파싱 가능한 SIP 응답 (1xx/2xx 뿐 아니라 3xx/4xx/5xx/6xx 에러 응답도 포함) | 벨 울림 또는 well-formed 거부 → 스택이 정상 처리 |
| **suspicious** | 응답이 valid SIP 로 파싱 안 됨 (`invalid_response`) | 파서 혼란 가능성. 4xx/5xx well-formed 에러는 여기 아님 |
| **timeout** | 무응답 | 패킷 drop 또는 무시 (스택 hang 가능성) |
| **crash** | 프로세스 종료 | **잠재적 취약점!** |
| **stack_failure** | Stack trace 발견 | **잠재적 취약점!** |

> 4xx/5xx 응답은 verdict 가 `normal` 로 남고 상태 코드는 `response_code` 필드에 기록된다. 거부 응답 분포를 보려면 `response_code` 로 따로 필터링한다.

### 처리 시간과 로그 수집 정책

실기기 캠페인에서는 `elapsed_ms`와 실제 케이스 처리 시간이 다를 수 있다.

- `elapsed_ms`: 송신 후 응답/오라클 판정까지의 네트워크 중심 시간
- `case_wall_ms`: 한 케이스가 끝날 때까지 걸린 실제 시간
  - 오라클 grace window
  - ADB snapshot
  - evidence 저장
  - 기타 동기 post-processing

`report.html`의 `Wall` 컬럼과 `campaign.jsonl`의 `case_wall_ms`를 throughput 판단 기준으로 보는 것이 맞다.

real-ue-direct 모드에서는 오라클 로그 grace가 메서드별로 자동 조정된다.

- `INVITE`: `8.0s`
- `ACK`, `CANCEL`, `PRACK`, `BYE`, `UPDATE`, `REFER`, `INFO`: `2.0s`
- 그 외 메서드: `1.0s`

이 설정 때문에 non-INVITE 케이스는 wall-clock이 줄어들 수 있지만, `INVITE`는 지연 크래시 탐지를 위해 의도적으로 더 느리게 유지된다.

ADB snapshot도 verdict에 따라 경량/전체로 나뉜다.

- `normal`, `timeout`, `unknown`, `infra_failure`: `light`
  - `telephony.txt`
  - `logcat_*.txt`, `logcat_all.txt`
- `suspicious`, `crash`, `stack_failure`: `full`
  - 위 경량 항목 모두
  - `ims.txt`, `netstat.txt`, `meminfo.txt`, `dmesg.txt`

### 중요 케이스 식별
```bash
# suspicious/crash만 필터링
uv run fuzzer campaign report results/real-ue/campaign.jsonl --filter suspicious,crash

# 특정 케이스 재현
uv run fuzzer campaign replay results/real-ue/campaign.jsonl --case-id 42
```

## 🔍 실시간 모니터링

### 현재 UE 포트 확인
```bash
# 방법 1: Kamailio 로그
docker logs pcscf --since 5m | grep 'Term UE connection'
# 출력 예: Term UE connection information : IP is <ue-ip> and Port is <port_pc>

# 방법 2: xfrm state
docker exec pcscf ip xfrm state | grep -A3 '<ue-ip>'
# sport 중 최솟값 = port_pc
```

### 실시간 pcap 분석
```bash
# br-volte 인터페이스 모니터링 (컨테이너 간 통신 포함)
sudo tcpdump -i br-volte -w live.pcap 'host <ue-ip>'

# fuzzer 송신 확인
sudo tcpdump -i br-volte -A 'src 172.22.0.21 and dst <ue-ip> and port <port_pc>'
```

`native` 모드에서는 `-A`로 평문 SIP가 바로 보이지 않을 수 있다. 이 경우 `esp` 필터와 campaign 결과의 `observer_events`/`responses`를 함께 확인한다.

### Android UE 로그 수집
```bash
# ADB 연결 확인
adb devices

# 실시간 로그 모니터링  
adb -s <SERIAL> logcat | grep -E 'IMS|SIP|VoLTE|crash|FATAL'

# 특정 시점 로그 덤프
adb -s <SERIAL> logcat -d > real_ue_logs_$(date +%Y%m%d_%H%M%S).txt
```

## 🛠️ 문제 해결

### ❌ timeout (응답 없음)

**원인 1**: Source IP 불일치
```bash
# 확인: pcap에서 송신 source IP
tcpdump -r case_000001.pcap -n | head -5

# 해결: ipsec-mode 확인
--ipsec-mode null    # 172.22.0.21로 spoofing 되어야 함
```

**원인 2**: port_pc 변경됨
```bash
# 확인: 현재 UE 포트
docker logs pcscf --since 5m | tail -20

# 해결: UE VoLTE 재등록 후 재시도
```

**원인 3**: Via sent-by ↔ bind port 불일치
```bash
# 확인: Via 헤더의 sent-by 포트와 실제 bind 포트 일치하는지
grep "Via:" case_000001.pcap

# 해결: --mt-local-port와 template Via 동기화 확인
```

### ⚠️ 4xx/5xx 에러 응답 (verdict 는 normal, response_code 가 4xx/5xx)

**원인**: MT template 불완전. verdict 는 `normal` 로 남지만 UE 가 200/180 대신 4xx/5xx 로 거부한 것이므로, 벨이 울리길 기대했다면 비정상이다. `response_code` 로 걸러서 확인한다.
```bash
# 확인: UE 응답
grep -E "SIP/2\.0 [45]" case_000001.pcap

# 해결: 정확한 template 사용
--mt-invite-template a31 --preserve-contact --preserve-via
```

### ❌ crash/stack_failure

**🎉 성공!** 이것이 바로 찾는 취약점입니다.

```bash
# 자동 수집된 데이터 확인
ls results/real-ue/adb_snapshots/case_XXXXXX/

# 수동 재현
uv run fuzzer campaign replay results/real-ue/campaign.jsonl --case-id XXXXXX
```

## 🎭 고급 시나리오

### 장시간 퍼징 (overnight)
```bash
nohup uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn <TARGET_MSISDN> \
  --methods INVITE --layer wire,byte --strategy default \
  --mt-invite-template a31 \
  --ipsec-mode null \
  --max-cases 10000 --timeout 5 \
  --output results/real-ue/overnight_$(date +%Y%m%d).jsonl \
  > overnight.log 2>&1 &
```

### 특정 헤더 집중 공격
```bash
# P-headers만 변이
--layer wire --strategy default  # P-Asserted-Identity, P-Access-Network-Info 등

# SDP만 변이
# TODO: SDP 전용 mutator 추가 예정
```

### 다중 UE 환경
```bash
# 현재 testbed 예:
# 111111: Pixel 9 / Galaxy A17 회전, UE IP 가변
# 222222: iPhone 16e, UE IP 10.20.20.2
--target-msisdn 222222  # live resolver 또는 VMF_MSISDN_TO_IP_222222 기준
```

## 📈 성능 튜닝

### 처리량 최적화
```bash
--timeout 3 --cooldown 0.1  # 빠른 케이스 처리
--max-cases 1000            # 배치 크기 조정
--no-process-check          # 프로세스 체크 생략
```

### 리소스 절약  
```bash
# pcap 비활성화 (디스크 절약)
# --pcap 옵션 제거

# ADB 선택적 사용 (crash/stack_failure만)
--adb --adb-serial <SERIAL>  # crash 시에만 스냅샷
```

## 🔗 관련 문서

- **[A31 평문 UDP 통과 원리](../이슈/A31-평문-UDP-통과-원리.md)** - XFRM 정책 분석
- **[IPsec 접근방식 비교](../이슈/Capstone-vs-VolteMutationFuzzer-IPsec-접근방식-비교.md)** - null vs bypass
- **[시스템 요구사항](../이슈/A31-real-ue-direct-시스템-요구사항.md)** - 서버 환경 설정
- **[운영 지침](../이슈/A31-real-ue-direct-운영-지침.md)** - 검증된 명령어와 주의사항

---

## ⚠️ 주의사항

1. **윤리적 사용**: 본인 소유 또는 허가받은 장비에만 사용
2. **서비스 영향**: 대상 UE에 수신 벨이 울리므로 테스트 환경에서만 실행
3. **재등록 주기**: UE가 주기적으로 재등록하면 port_pc/port_ps 변경됨
4. **리소스 모니터링**: 장시간 실행 시 디스크 사용량 (pcap) 및 배터리 소모 확인

**성공 기준**: 대상 UE 화면에 실제 수신 UI가 표시되고 벨이 울리며, fuzzer가 180 Ringing을 수신하는 것.
