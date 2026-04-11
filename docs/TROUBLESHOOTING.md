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

### ❌ suspicious (4xx/5xx 에러)

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