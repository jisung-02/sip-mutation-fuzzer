# VolteMutationFuzzer 문제 해결 가이드

## 🚨 일반적인 문제들

### ❌ timeout (응답 없음)

#### 1. Source IP 문제
**증상**: 모든 케이스가 timeout
```bash
# 확인방법
sudo tcpdump -i br-volte -n 'src host' | head -5
```
**해결책**:
```bash
# null mode: host spoofing 확인
--ipsec-mode null  # source IP가 172.22.0.21이어야 함

# bypass mode: container 확인  
--ipsec-mode bypass  # pcscf container에서 송신되어야 함
```

#### 2. 포트 변경 문제
**증상**: 이전에는 동작했는데 갑자기 timeout
```bash
# 확인방법: A31 현재 포트 조회
docker logs pcscf --since 5m | grep 'Term UE connection'
# 또는
docker exec pcscf ip xfrm state | grep -A3 '10.20.20.8'
```
**해결책**: A31 VoLTE 재등록 후 재시도

#### 3. Via sent-by 불일치
**증상**: A31이 벨을 울리지만 fuzzer는 timeout
```bash
# 확인방법: pcap에서 Via 헤더 확인
tcpdump -r case_000001.pcap -A | grep "Via:"
```
**해결책**:
```bash
--mt-local-port 15100  # Via와 실제 bind port 일치 확인
```

### ⚠️ 4xx/5xx 에러 응답 (verdict 는 normal, response_code 가 4xx/5xx)

> 4xx/5xx well-formed 에러 응답은 verdict 가 `normal` 로 남는다 (UE 스택이 정상적으로 거부한 것). 상태 코드는 `response_code` 필드에 기록되므로 거부 케이스는 그걸로 필터링한다. `suspicious` 는 응답이 valid SIP 로 파싱조차 안 될 때만 붙는다.

#### 1. 불완전한 MT template
**증상**: 400 Parsing Failed, 415 Unsupported Media Type
```bash
# 확인방법
grep "SIP/2.0 4" results/campaign.jsonl
```
**해결책**:
```bash
# 완전한 template + 보존 플래그 사용
--mt-invite-template a31 --preserve-contact --preserve-via
```

#### 2. IMPI/MSISDN 불일치
**증상**: 403 Forbidden, 404 Not Found
**해결책**: IMPI와 MSISDN이 실제 가입자 정보와 일치하는지 확인
```bash
--target-msisdn 111111 --impi 001010000123511  # A31 전용
```

### ❌ Configuration Error

#### 1. MSISDN auto-resolution 실패
**에러**: `Unknown MSISDN '999999'`
**해결책**:
```bash
# 환경변수로 커스텀 매핑 추가
export VMF_MSISDN_TO_IP_999999=192.168.1.100

# 또는 직접 host 지정
--target-host 192.168.1.100 --target-msisdn 999999
```

#### 2. real-ue-direct validation 실패
**에러**: `real-ue-direct requires either target_host or target_msisdn`
**해결책**:
```bash
# 둘 중 하나는 반드시 필요
--target-msisdn 111111  # 권장 (auto-resolve)
# 또는
--target-host 10.20.20.8
```

#### 3. MT template 조건 불만족
**에러**: `mt_invite_template requires target_msisdn`
**해결책**:
```bash
--mt-invite-template a31 --target-msisdn 111111 --impi 001010000123511
```

### ❌ 네트워크/연결 문제

#### 1. Docker 네트워크 접근 불가
**증상**: `docker exec pcscf` 명령어 실패
```bash
# 확인
docker ps | grep pcscf
docker network ls | grep volte
```
**해결책**:
```bash
# Docker 서비스 재시작
sudo systemctl restart docker

# IMS 컨테이너 재시작
cd /path/to/ims-setup && docker-compose restart
```

#### 2. UE 라우팅 실패
**증상**: `route check failed for 10.20.20.8`
```bash
# 확인
ip route | grep 10.20.20
ping 10.20.20.8
```
**해결책**:
```bash
# 수동 라우트 추가
sudo ip route add 10.20.20.0/24 via 172.22.0.8 dev br-volte

# 또는 자동 설정
uv run fuzzer infra setup-route --target-host 10.20.20.8
```

#### 3. br-volte 인터페이스 없음
**증상**: pcap 캡처 실패
```bash
# 확인  
ip link show | grep br-volte
```
**해결책**: Docker 네트워크 재생성 또는 다른 인터페이스 사용
```bash
--pcap-interface any  # 모든 인터페이스
```

## 🔧 디버깅 도구

### 실시간 모니터링
```bash
# 1. fuzzer 진행상황
tail -f results/campaign.jsonl

# 2. A31 상태 확인
docker logs pcscf --follow | grep -E 'Term UE|REGISTER'

# 3. 네트워크 트래픽
sudo tcpdump -i br-volte -A 'host 10.20.20.8 and port 8100'

# 4. ADB 로그 (A31)
adb -s <SERIAL> logcat | grep -E 'IMS|SIP|VoLTE|FATAL|crash'
```

### 상세 분석
```bash
# 1. 특정 케이스 재현
uv run fuzzer campaign replay results/campaign.jsonl --case-id 42

# 2. pcap 분석
wireshark case_000042.pcap
# 또는
tcpdump -r case_000042.pcap -A | less

# 3. SIP 메시지 추출
tcpdump -r case_000042.pcap -A | grep -A20 "INVITE\|SIP/2.0"
```

## 🏥 복구 절차

### A31 IMS 재등록
```bash
# 1. VoLTE 토글 (A31 화면)
Settings → Mobile networks → VoLTE calls → OFF → ON

# 2. 등록 확인
docker logs pcscf --since 2m | grep 'Term UE connection'

# 3. 새 포트 확인
docker exec pcscf ip xfrm state | grep -A3 '10.20.20.8'
```

### iPhone IMS 안 올라옴 (셀 attach 는 됐는데 IMS PDN/SIP 없음)

**증상**: open5gs/srsenb 에는 붙는데(MME `Attach complete`, SMF `APN[internet]` 할당) IMS 가 안 잡힘.
P-CSCF 에 xfrm SA 0개, `kamctl ul show` 비어있음, REGISTER 로그 없음. iPhone syslog 에도
`ims`/`volte`/`sip`/`register`/`pdn` 활동이 전혀 안 보임.

**원인**: iPhone 이 **VoLTE 를 켜지 않아 IMS APN PDN 자체를 시도하지 않음**. 테스트 SIM 의
캐리어 번들이 `com.apple.CarrierLab` (generic) 인 경우 VoLTE 가 기본 비활성이라 단말이
IMS 로 안 올라온다. EPS(데이터) attach 와 IMS 등록은 별개 PDN 이라 데이터만 붙고 IMS 는
빠질 수 있다.

**해결책**: iPhone 에서 VoLTE 강제 활성화 (2026-06-07 SIM 111111 in iPhone 16e 로 검증됨).
```
설정 → 셀룰러 → 셀룰러 데이터 옵션 → 음성 및 데이터 → VoLTE 켜기
```
토글이 안 보이면 CarrierLab 번들이 막는 것 — 비행기모드 토글 또는 재부팅 후 재시도.
자동 PLMN 선택이 외부 RF 에 밀리면 manual PLMN select 로 `00101` 선택.

**확인**:
```bash
# IMS APN PDN 올라왔는지 (10.20.20.x = IMS 풀)
docker logs smf --since 5m 2>&1 | grep -iE 'APN\[ims\]|10.20.20'
# SIP 수신 + 라이브 IP 확인
docker logs pcscf --since 5m 2>&1 | grep -iE 'register|subscribe|10.20.20'
```

**주의 — IMS PDN 플래핑/stale SA**: VoLTE 막 켠 직후 단말이 IMS PDN 을 반복 재수립하며
매번 새 IP 를 받는다 (`10.20.20.2` → `10.20.20.3` → ...). 옛 IP 의 xfrm SA 가 stale 로
남아 P-CSCF NATPING 이 408(Fail Counter 증가) 을 찍는다. **라이브 UE 는 NATPING OPTIONS 에
200 으로 응답하는 IP** 다. 퍼징 전 아래로 라이브 IP 를 확정한 뒤(또는 세션이 안정될 때까지
대기한 뒤) 돌린다. stale SA 가 resolver 를 오염시키면 408 timeout 만 난다.
```bash
docker logs pcscf --since 2m 2>&1 | grep -iE 'OPTIONS.*10.20.20.*(200|408)'
```

### iPhone MT-INVITE 퍼징 — 도달/링 트러블슈팅 (2026-06-07)

**무엇에 대한 트러블슈팅인가:** SIM 111111 을 꽂은 iPhone 16e(iOS 26.1) 를 native
IPsec 로 MT-INVITE 퍼징할 때, 캠페인은 정상 완료(verdict 분포까지 나옴)되는데 실제로는
**변이 INVITE 가 단말에 한 건도 도달하지 않던** 문제. "허공에 쏘는데 결과만 그럴듯하게
나오는" 상황이라 verdict 만 보면 발견이 안 됐다. 동시에 baseline(identity) INVITE 가
"안 울린다" 도 추적했다. 표면은 하나(안 닿는다/안 울린다)인데 **원인이 4겹**이라 순서대로
판별해야 한다.

| 증상 | 진짜 원인 | 해결 |
|------|-----------|------|
| 도달 0% (verdict 는 timeout/정상처럼 보임) | `--timeout 0.01` → native send 전송 미완 | timeout ≥ 0.2 |
| 도중부터 `unknown`(resolve 실패) | usrloc 빈 채 UE IP 이동 → resolver 실패 | `VMF_MSISDN_TO_IP` 핀 |
| `unknown` + `Fail Counter`/`Unregistering` | 486 keepalive → P-CSCF 가 UE de-register | cfg fix(486=alive) 또는 cooldown |
| 도달은 되는데 안 울림 | precondition 미충족/제거, teardown CANCEL | curr:qos met + `--no-teardown` |

> 핵심 교훈: **verdict 는 도달을 보장하지 않는다.** 반드시 단말 syslog 의 `Is a INVITE`
> 카운트로 도달률을 따로 검증한다. (아래 판정법)

증상이 비슷해도 원인이 4겹이라 순서대로 확인한다.

**도달 여부 판정법** — verdict 가 아니라 단말 syslog 의 INVITE 파서 진입으로 본다:
```bash
# 도달률 = (Is a INVITE 수) / (송신 케이스 수). 100% 가 목표.
grep -c 'Is a INVITE' results/<dir>/syslog_full.txt
grep -c '<-- 172.22.0.21.*INVITE' results/<dir>/syslog_full.txt
# 단말이 받은 게 OPTIONS(secure TCP) 뿐이면 = NATPING keepalive 만, INVITE 미도달.
```

**원인 1 — `--timeout` 0.01 이면 패킷이 아예 안 나간다 (제일 흔함).**
native IPsec send 가 그 짧은 시간에 전송을 못 끝내 0% 도달. timeout 별 도달률:
`0.01 → 0%`, `0.1 → ~79%`, `0.2 → ~100%`, `0.3 → 100%`. **fuzzing 도 `--timeout 0.2`
이상**으로 둔다. (verdict timeout 은 응답을 안 기다린 것일 뿐 도달과 무관.)

**원인 2 — resolver 가 이동한 UE IP 를 못 찾는다.**
kamailio usrloc 이 비어(`kamctl ul show` → `Domains: []`) live resolver 가 실패하면
INVITE 가 엉뚱한/옛 IP 로 가 미도달. 현재 라이브 IP 를 직접 핀한다:
```bash
docker logs pcscf --since 60s 2>&1 | grep -oE '10.20.20.[0-9]+:[0-9]+.*200'  # 라이브 IP 확인
sudo VMF_MSISDN_TO_IP_111111=<live-ip> uv run fuzzer campaign run ...           # 핀
```
IP 는 재등록마다 바뀌니(.2→.3→.7…) 돌리기 직전 확인. de-reg 가 잦으면 더 자주 바뀐다.

**원인 3 — 486 keepalive → P-CSCF 가 UE 를 de-register (자기가 자기를 죽임).**
INVITE 로 폰이 busy 면 P-CSCF 의 NATPING OPTIONS 에 **486 Busy Here** 로 답하고,
P-CSCF cfg 의 keepalive 가 비-200 을 fail 로 세서 ~10회 넘으면 contact 를 제거
(`Fail Counter is N` → `Unregistering`). 그러면 이후 케이스가 `unknown`(resolve 실패).
- 회피(운영): `--cooldown 1` 로 case 사이 폰이 idle→OPTIONS 200 답하게 → 카운터 리셋.
- 근본(서버): `infrastructure/pcscf/kamailio_pcscf.cfg` 의 `event_route[uac:reply]` 에서
  **응답이 오면 코드 무관 alive** 로 처리(무응답 timeout 만 fail). 이 fix 적용 후엔
  `--cooldown 0` 으로 돌려도 de-reg 안 난다. (kamailio 재시작 필요.) 확인:
  ```bash
  docker logs pcscf --since 2m 2>&1 | grep -c 'Fail Counter'   # fix 됐으면 0
  ```

**원인 4 — 도달은 했는데 안 울린다 (precondition / teardown).**
도달(`Is a INVITE`)은 되는데 벨이 안 울리는 건 콜 셋업 협상 문제다:
- SDP 의 `a=des:qos mandatory local sendrecv` + `a=curr:qos local none`(미충족) →
  iOS 가 183 ServerEarly 에서 precondition 완료(PRACK/UPDATE) 대기 → 180 안 감.
  (precondition 을 통째로 빼면 iOS 가 `580 Precondition Failure` 로 거부 — VoLTE 는
  precondition 필수.) → 템플릿에서 `a=curr:qos local sendrecv`(이미 충족)로 두면 ring.
- 그 다음엔 캠페인이 INVITE 마다 CANCEL teardown 을 보내 `487 Request Terminated` 로
  끊어 울리기 전에 종료한다. baseline ring 확인은 `--no-teardown` 으로.
- 단, **fuzzing 목적이면 ring 까지 갈 필요 없다** — 변이 INVITE 가 파서에 도달(`Is a
  INVITE`)하면 충분. ring 은 baseline(identity) 검증용.

**권장 fuzzing 명령 (도달 100% + de-reg 없음):**
```bash
sudo VMF_MSISDN_TO_IP_111111=<live-ip> uv run fuzzer campaign run \
  --target-msisdn 111111 --impi 001010000123511 --from-msisdn 222222 \
  --methods INVITE --profile iphone_ims --strategy default --layer wire \
  --mt --ipsec-mode native --ios \
  --cooldown 0 --timeout 0.2 --max-cases 300 \
  --circuit-breaker 0 --no-pcap --no-adb --oracle-log-grace 0
```

### Docker 환경 재시작
```bash
# 1. 컨테이너 재시작
docker restart pcscf scscf icscf hss

# 2. 네트워크 확인  
docker network inspect br-volte

# 3. 라우팅 복구
sudo ip route add 10.20.20.0/24 via 172.22.0.8 dev br-volte
```

### 환경 초기화
```bash
# 1. 결과 디렉토리 정리
rm -rf results/*

# 2. Docker 볼륨 정리 (주의!)
docker volume prune

# 3. Python 환경 재설정
uv sync --reinstall
```

## 📊 성능 최적화

### `elapsed_ms` 와 `case_wall_ms` 해석

**증상**: 보고서에서 `elapsed_ms`는 낮은데 실제 캠페인은 느리게 진행됨

실기기 경로에서는 두 숫자의 의미가 다르다.

- `elapsed_ms`
  - 송신과 응답/오라클 판정 중심 시간
  - 네트워크 round-trip이나 응답 지연을 볼 때 사용
- `case_wall_ms`
  - 케이스가 끝날 때까지 걸린 실제 시간
  - 오라클 grace window, ADB snapshot, evidence 저장 같은 동기 후처리까지 포함
  - throughput 판단은 이 값을 기준으로 보는 것이 맞음

특히 real-ue-direct에서는 메서드별 grace 기본값이 다르다.

- `INVITE`: `8.0s`
- `ACK`, `CANCEL`, `PRACK`, `BYE`, `UPDATE`, `REFER`, `INFO`: `2.0s`
- 그 외 메서드: `1.0s`

그래서 `INVITE`는 의도적으로 `case_wall_ms`가 더 크게 나올 수 있고, non-INVITE는 같은 환경에서도 더 빨라지는 것이 정상이다.

ADB snapshot도 verdict에 따라 비용이 달라진다.

- `normal`, `timeout`, `unknown`, `infra_failure`: `light`
  - `telephony.txt` + logcat만 수집
- `suspicious`, `crash`, `stack_failure`: `full`
  - `ims/netstat/meminfo/dmesg`까지 추가 수집

확인 순서:

1. `report.html`의 `Wall` 컬럼이 높은 케이스가 어떤 메서드/ verdict 인지 본다.
2. `INVITE`인지, `suspicious/crash/stack_failure`인지 먼저 확인한다.
3. `elapsed_ms`는 짧고 `case_wall_ms`만 길다면, 네트워크보다 grace window / snapshot 비용일 가능성이 높다.

### 처리 속도 개선
```bash
# 1. Timeout 단축
--timeout 3  # 기본 5초 → 3초

# 2. Cooldown 최소화  
--cooldown 0.05  # 기본 0.2초 → 0.05초

# 3. 프로세스 체크 생략
--no-process-check

# 4. pcap 비활성화 (디스크 절약)
# --pcap 옵션 제거
```

### 메모리 사용량 최적화
```bash
# 1. 케이스 분할 실행
--max-cases 500  # 큰 배치 대신 작은 배치

# 2. ADB 선택적 사용
--adb  # crash/stack_failure 시에만 스냅샷

# 3. 결과 파일 분할
--output results/batch_$(date +%H%M).jsonl
```

## 🔍 특수한 문제들

### A31 특이 동작

#### 1. "조용한 거부" 
**증상**: timeout이지만 100 Trying 응답
**원인**: source IP 화이트리스트 실패
**해결**: `--ipsec-mode` 확인

#### 2. "부분 성공"
**증상**: 벨은 울리지만 fuzzer timeout
**원인**: Via sent-by 불일치
**해결**: `--mt-local-port` 동기화

#### 3. "간헐적 실패"
**증상**: 같은 케이스가 때로는 성공, 때로는 실패
**원인**: A31 재등록으로 포트 변경
**해결**: 매 실행마다 `resolve_protected_ports()`

### IPsec 모드 관련

#### null mode 문제
**전제조건 확인**:
```bash
# 1. Kamailio 설정
docker exec pcscf grep ipsec_preferred_ealg /etc/kamailio/kamailio_pcscf.cfg
# 출력: ipsec_preferred_ealg "null"

# 2. Host 설정
sysctl net.ipv4.ip_nonlocal_bind
# 출력: net.ipv4.ip_nonlocal_bind = 1

# 3. A31 협상 결과
docker exec pcscf ip xfrm state | grep 'enc.*null'
```

#### bypass mode 문제
**전제조건 확인**:
```bash
# 1. pcscf 컨테이너 접근
docker exec pcscf ping 10.20.20.8

# 2. xfrm 정책 존재
docker exec pcscf ip xfrm policy | grep '10.20.20.8'

# 3. Python3 사용 가능
docker exec pcscf python3 --version
```

## 🚨 응급 상황

### fuzzer 무한 대기
```bash
# Ctrl+C로 중단 안 될 때
pkill -f "fuzzer campaign"
pkill -f "python.*fuzzer"
```

### A31 응답 없음 (벽돌화?)
```bash
# 1. 기본 연결성 확인
ping 10.20.20.8
adb devices

# 2. 강제 재부팅 (최후 수단)
adb reboot

# 3. IMS 서비스 재시작 (A31)
Settings → Apps → SIM Toolkit → Force Stop
Settings → Mobile networks → VoLTE → OFF → ON
```

### Docker 네트워크 충돌
```bash
# 1. 네트워크 정리
docker network prune

# 2. br-volte 재생성  
docker network rm br-volte
docker network create --driver bridge --subnet=172.22.0.0/16 br-volte

# 3. 컨테이너 재시작
docker-compose down && docker-compose up -d
```

---

## 📞 추가 지원

더 복잡한 문제가 발생한 경우:

1. **[A31 Real-UE 가이드](A31_REAL_UE_GUIDE.md)** - A31 특화 가이드
2. **[시스템 아키텍처](ARCHITECTURE.md)** - 내부 동작 이해
3. **GitHub Issues** - 새로운 버그 신고

**로그 첨부 시 포함할 정보**:
- fuzzer 명령어 전체
- 에러 메시지
- `docker logs pcscf --since 5m`
- `adb logcat` (A31 문제 시)
- 관련 pcap 파일 (가능하면)
