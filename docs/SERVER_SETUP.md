# 서버 환경 설정 가이드

> **검증된 환경**: ubuntu@163.180.185.51 (2026-04-11 기준)

## 🏗️ 기본 환경

### 시스템 정보
```bash
OS: Ubuntu 22.04 LTS
Docker: 24.0+
Python: 3.12+
```

### 필수 패키지
```bash
sudo apt update
sudo apt install -y python3 python3-pip docker.io docker-compose
sudo apt install -y tcpdump wireshark-cli adb

# uv 패키지 매니저
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## 🐳 IMS Docker 환경

### 컨테이너 구성
```yaml
# br-volte 네트워크 (172.22.0.0/16)
services:
  pcscf:     # 172.22.0.21 - P-CSCF (Kamailio)
  scscf:     # 172.22.0.20 - S-CSCF  
  icscf:     # 172.22.0.19 - I-CSCF
  hss:       # HSS (Open5GS)
  pyhss:     # IMS HSS (PyHSS)
  upf:       # 172.22.0.8 - UPF (GTP 터널 종료점)
```

### Kamailio P-CSCF 설정

#### IPsec 모드 설정
**Null Encryption 모드** (권장):
```bash
# /etc/kamailio/kamailio_pcscf.cfg
modparam("ims_ipsec_pcscf", "ipsec_preferred_ealg", "null")
```

**AES-CBC 모드** (기본):
```bash
modparam("ims_ipsec_pcscf", "ipsec_preferred_ealg", "aes-cbc")
```

#### 재시작
```bash
docker restart pcscf
```

## 🔧 Host 시스템 설정

### Sysctl 설정
**Null encryption 모드 사용 시**:
```bash
sudo tee /etc/sysctl.d/99-volte-fuzzer.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.ip_nonlocal_bind = 1
EOF

sudo sysctl --system
```

### UE 라우팅 설정
```bash
# A31 UE subnet → UPF 경유
sudo ip route add 10.20.20.0/24 via 172.22.0.8 dev br-volte

# 영구 설정 (재부팅 시에도 유지)
echo "10.20.20.0/24 via 172.22.0.8 dev br-volte" | \
  sudo tee -a /etc/netplan/99-volte-routes.yaml
```

## 📱 UE 설정

### Samsung A31 구성
| 설정 | 값 |
|------|---|
| **MSISDN** | 111111 |
| **IMPI** | 001010000123511 |
| **UE IP** | 10.20.20.8 |
| **APN** | ims |
| **VoLTE** | 활성화 |

### ADB 설정
```bash
# USB 디버깅 활성화 (A31)
Settings → Developer options → USB debugging → ON

# ADB 연결 확인
adb devices
# 출력: SM_A315F_XXXXXX device

# 시리얼 번호 확인
adb get-serialno
```

### Test MO UE (소프트폰)
| 설정 | 값 |
|------|---|
| **MSISDN** | 222222 |
| **UE IP** | 10.20.20.9 |
| **포트** | 31800 (PC), 31100 (PS) |

## 🔍 환경 검증

### 1. Docker 네트워크 확인
```bash
# br-volte 네트워크 존재 확인
docker network ls | grep br-volte

# 컨테이너 IP 확인
docker network inspect br-volte | jq '.[].Containers'

# P-CSCF 접근 확인
docker exec pcscf ip addr show
```

### 2. IMS 등록 상태 확인
```bash
# A31 등록 확인
docker logs pcscf --since 5m | grep -E 'REGISTER|Term UE'

# IPsec SA 확인
docker exec pcscf ip xfrm state | grep '10.20.20.8'

# 현재 port_pc/port_ps 확인
docker exec pcscf ip xfrm state | grep -A3 'src 10.20.20.8'
```

### 3. 연결성 테스트
```bash
# Host → UE 연결
ping 10.20.20.8

# P-CSCF → UE 연결
docker exec pcscf ping 10.20.20.8

# UE → P-CSCF 연결 (A31에서)
# Settings → Network → Ping → 172.22.0.21
```

## 🚀 Fuzzer 설치

### 프로젝트 설정
```bash
# 프로젝트 체크아웃
cd /home/ubuntu/Desktop
git clone <repository> fuzzer
cd fuzzer

# 의존성 설치
uv sync

# 환경변수 설정
cat >> ~/.bashrc <<EOF
export VMF_REAL_UE_PCSCF_IP=172.22.0.21
export VMF_MSISDN_TO_IP_111111=10.20.20.8
export VMF_MSISDN_TO_IP_222222=10.20.20.9
EOF

source ~/.bashrc
```

### 기본 동작 확인
```bash
# Identity 케이스 (baseline)
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --impi 001010000123511 \
  --methods INVITE --layer wire --strategy identity \
  --mt-invite-template a31 \
  --ipsec-mode null \
  --preserve-contact --preserve-via \
  --max-cases 1 --timeout 10 --no-process-check

# 기대 결과: normal (180, XXXXms) + A31 벨 울림
```

## 🔧 고급 설정

### PyHSS 가입자 관리
```bash
# PyHSS REST API (포트 8080)
curl http://localhost:8080/docs/

# 가입자 추가 (JSON)
curl -X POST http://localhost:8080/subscriber/ \
  -H "Content-Type: application/json" \
  -d '{
    "imsi": "001010000123511", 
    "msisdn": "111111",
    "apn": [{"apn": "ims", "qci": 5}]
  }'
```

### Kamailio 모니터링
```bash
# 실시간 로그
docker logs pcscf --follow

# SIP 트레이스 활성화
docker exec pcscf kamctl fifo sip_trace on

# 통계 확인
docker exec pcscf kamctl stats
```

### 네트워크 트래픽 분석
```bash
# br-volte 전체 트래픽
sudo tcpdump -i br-volte -w traffic.pcap

# A31 관련 트래픽만
sudo tcpdump -i br-volte 'host 10.20.20.8' -w a31_traffic.pcap

# SIP 메시지만 (포트 기반)
sudo tcpdump -i br-volte 'port 5060 or port 8100' -A
```

## 📊 모니터링 및 로깅

### 시스템 모니터링
```bash
# 디스크 사용량 (pcap 파일들)
du -sh results/

# 메모리 사용량
free -h
docker stats

# 네트워크 상태
ss -tuln | grep -E ':5060|:8100'
```

### 로그 수집
```bash
# IMS 컨테이너 로그
for container in pcscf scscf icscf hss; do
  docker logs $container > logs/${container}_$(date +%Y%m%d).log
done

# A31 로그 (ADB)
adb logcat -d > logs/a31_$(date +%Y%m%d_%H%M).log

# 시스템 로그
journalctl -u docker > logs/docker_$(date +%Y%m%d).log
```

## 🔄 유지보수

### 정기 작업
```bash
# Docker 정리 (주간)
docker system prune -f
docker volume prune -f

# 로그 로테이션 (일간)
find logs/ -name "*.log" -mtime +7 -delete

# pcap 아카이브 (월간)
tar -czf archive/pcaps_$(date +%Y%m).tar.gz results/pcap/
rm -rf results/pcap/*
```

### 백업
```bash
# 설정 백업
tar -czf backup/config_$(date +%Y%m%d).tar.gz \
  /etc/kamailio/ \
  /etc/sysctl.d/99-volte-fuzzer.conf \
  docker-compose.yml

# 결과 백업
rsync -av results/ backup/results_$(date +%Y%m%d)/
```

## 🆘 복구 절차

### 전체 환경 재구성
```bash
# 1. Docker 환경 정리
docker-compose down
docker system prune -a -f

# 2. 네트워크 재생성
docker network rm br-volte
docker network create --driver bridge --subnet=172.22.0.0/16 br-volte

# 3. 컨테이너 재시작
docker-compose up -d

# 4. 라우팅 복구
sudo ip route add 10.20.20.0/24 via 172.22.0.8 dev br-volte

# 5. A31 재등록
# VoLTE OFF → ON
```

---

## 📋 체크리스트

**환경 구축 완료 확인**:
- [ ] Docker 컨테이너 모두 실행 중
- [ ] br-volte 네트워크 생성됨  
- [ ] UE 라우팅 설정됨
- [ ] A31 IMS 등록 완료
- [ ] port_pc/port_ps 조회 가능
- [ ] fuzzer identity 케이스 성공
- [ ] A31 실제 벨 울림 확인

**트러블슈팅 준비**:
- [ ] ADB 연결 확인
- [ ] tcpdump/wireshark 사용 가능
- [ ] Docker 로그 접근 가능
- [ ] 백업/복구 절차 숙지

이 환경에서 A31 실기기 퍼징이 안정적으로 동작합니다! 🎯