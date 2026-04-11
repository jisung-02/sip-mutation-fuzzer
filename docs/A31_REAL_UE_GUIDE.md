# Samsung A31 Real-UE Direct 퍼징 완벽 가이드

> **목표**: Samsung Galaxy A31 실기기를 대상으로 MT-INVITE 변이 퍼징을 수행하여 실제로 벨이 울리고 180 Ringing 응답을 받는 것

## 📱 검증된 환경

| 구성요소 | 정보 |
|---------|------|
| **UE** | Samsung Galaxy A31 |
| **MSISDN** | 111111 |
| **UE IP** | 10.20.20.8 |
| **IMPI** | 001010000123511 |
| **P-CSCF IP** | 172.22.0.21 |
| **서버** | ubuntu@163.180.185.51 |
| **검증일** | 2026-04-11 |

## 🎯 성공 조건 5가지

A31이 실제로 수신 벨을 울리려면 **다음 5가지 조건이 모두 충족**되어야 합니다:

### 1. **Source IP = 172.22.0.21** (등록된 P-CSCF IP)
- A31 IMS 앱이 **source IP 화이트리스트** 적용
- P-CSCF 아닌 IP에서 오면 조용히 drop (100 Trying은 자동 응답)
- **해결**: `--ipsec-mode null` (host spoofing) 또는 `--ipsec-mode bypass` (docker exec)

### 2. **3GPP MT-INVITE 완전 포맷**
- 최소한의 SIP는 `400 Parsing Failed` 또는 무시됨
- **필수 헤더**: 3× Record-Route, P-Asserted-Identity, P-Access-Network-Info, P-Charging-Vector 등
- **필수 SDP**: AMR/AMR-WB 코덱 + curr/des:qos preconditions
- **해결**: `--mt-invite-template a31` (완전한 capture 기반 template)

### 3. **Request-URI 동적 포트**
```
sip:001010000123511@10.20.20.8:8100;alias=10.20.20.8~8101~1
                                ^^^^                    ^^^^  
                              port_pc               port_ps
```
- `port_pc`/`port_ps`는 **재등록마다 순환** (7900/7901 → 8000/8001 → 8100/8101)
- **송신 목적지는 port_pc** (A31의 수신 포트)
- **해결**: 매 실행마다 `resolve_protected_ports()` 자동 조회

### 4. **평문 UDP로 충분** (ESP 불필요)
- A31 커널 XFRM이 sport=15100에 대해 IPsec enforcement 안 함
- **원리**: Kamailio xfrm policy가 port 5103/6103에만 걸림 → selector 미매치 → 평문 통과
- **해결**: `--mt-local-port 15100` (Kamailio 점유 포트 회피)

### 5. **IP 단편화 회피**
- LTE 무선 구간에서 평문 UDP 단편화 시 A31이 첫 조각만 보고 `400 Parsing Failed`
- **해결**: fragment guard (1400 bytes 이하) 또는 TCP 사용

## 🚀 빠른 시작

### Identity 케이스 (baseline 검증)
```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --impi 001010000123511 \
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
- A31 화면에 수신 UI 표시 + 벨 울림
- fuzzer는 180 Ringing 수신

### 변이 퍼징 (실제 fuzzing)
```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --impi 001010000123511 \
  --methods INVITE --layer wire,byte --strategy identity,default \
  --mt-invite-template a31 \
  --ipsec-mode null \
  --preserve-contact --preserve-via \
  --mt-local-port 15100 \
  --max-cases 50 --timeout 10 --no-process-check \
  --pcap --pcap-interface br-volte --pcap-dir results/a31/pcap \
  --adb --adb-serial <A31_SERIAL> \
  --output results/a31/campaign.jsonl
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

## 📊 결과 분석

### Verdict 해석
| Verdict | 의미 | A31 상태 |
|---------|------|----------|
| **normal** | 180/200 응답 | 벨 울림 → 정상 처리 |
| **suspicious** | 4xx/5xx 에러 | 파싱 실패 또는 거부 |
| **timeout** | 무응답 | 패킷 drop 또는 무시 |
| **crash** | 프로세스 종료 | **잠재적 취약점!** |
| **stack_failure** | Stack trace 발견 | **잠재적 취약점!** |

### 중요 케이스 식별
```bash
# suspicious/crash만 필터링
uv run fuzzer campaign report results/a31/campaign.jsonl --filter suspicious,crash

# 특정 케이스 재현
uv run fuzzer campaign replay results/a31/campaign.jsonl --case-id 42
```

## 🔍 실시간 모니터링

### A31 현재 포트 확인
```bash
# 방법 1: Kamailio 로그
docker logs pcscf --since 5m | grep 'Term UE connection'
# 출력: Term UE connection information : IP is 10.20.20.8 and Port is 8100

# 방법 2: xfrm state
docker exec pcscf ip xfrm state | grep -A3 '10.20.20.8'
# sport 중 최솟값 = port_pc
```

### 실시간 pcap 분석
```bash
# br-volte 인터페이스 모니터링 (컨테이너 간 통신 포함)
sudo tcpdump -i br-volte -w live.pcap 'host 10.20.20.8'

# fuzzer 송신 확인
sudo tcpdump -i br-volte -A 'src 172.22.0.21 and dst 10.20.20.8 and port 8100'
```

### A31 로그 수집
```bash
# ADB 연결 확인
adb devices

# 실시간 로그 모니터링  
adb -s <SERIAL> logcat | grep -E 'IMS|SIP|VoLTE|crash|FATAL'

# 특정 시점 로그 덤프
adb -s <SERIAL> logcat -d > a31_logs_$(date +%Y%m%d_%H%M%S).txt
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
# 확인: 현재 A31 포트
docker logs pcscf --since 5m | tail -20

# 해결: A31 VoLTE 재등록 후 재시도
```

**원인 3**: Via sent-by ↔ bind port 불일치
```bash
# 확인: Via 헤더의 sent-by 포트와 실제 bind 포트 일치하는지
grep "Via:" case_000001.pcap

# 해결: --mt-local-port와 template Via 동기화 확인
```

### ❌ suspicious (400/4xx 에러)

**원인**: MT template 불완전
```bash
# 확인: A31 응답
grep -E "SIP/2\.0 [45]" case_000001.pcap

# 해결: 정확한 template 사용
--mt-invite-template a31 --preserve-contact --preserve-via
```

### ❌ crash/stack_failure

**🎉 성공!** 이것이 바로 찾는 취약점입니다.

```bash
# 자동 수집된 데이터 확인
ls results/a31/adb_snapshots/case_XXXXXX/

# 수동 재현
uv run fuzzer campaign replay results/a31/campaign.jsonl --case-id XXXXXX
```

## 🎭 고급 시나리오

### 장시간 퍼징 (overnight)
```bash
nohup uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --impi 001010000123511 \
  --methods INVITE --layer wire,byte --strategy default \
  --mt-invite-template a31 \
  --ipsec-mode null \
  --max-cases 10000 --timeout 5 \
  --output results/a31/overnight_$(date +%Y%m%d).jsonl \
  > overnight.log 2>&1 &
```

### 특정 헤더 집중 공격
```bash
# P-headers만 변이
--layer wire --strategy default  # P-Asserted-Identity, P-Access-Network-Info 등

# SDP만 변이
# TODO: SDP 전용 mutator 추가 예정
```

### 다중 UE 환경 (향후 지원 예정)
```bash
# A31: MSISDN 111111, IP 10.20.20.8
# Test UE: MSISDN 222222, IP 10.20.20.9
--target-msisdn 222222  # 자동으로 10.20.20.9 resolve
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
2. **서비스 영향**: A31에 수신 벨이 울리므로 테스트 환경에서만 실행
3. **재등록 주기**: A31이 주기적으로 재등록하면 port_pc/port_ps 변경됨
4. **리소스 모니터링**: 장시간 실행 시 디스크 사용량 (pcap) 및 배터리 소모 확인

**성공 기준**: A31 화면에 실제 수신 UI가 표시되고 벨이 울리며, fuzzer가 180 Ringing을 수신하는 것 📞✅