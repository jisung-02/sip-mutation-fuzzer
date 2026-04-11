# A31 real-ue-direct 시스템 요구사항

> 이 문서는 fuzzer가 **코드 레벨 변경 없이** 동작하려면 호스트/컨테이너/단말에
> 미리 갖춰져 있어야 하는 모든 시스템 레벨 조건을 정리한다. 각 항목이 **왜**
> 필요한지까지 설명해서, 다른 환경으로 이식할 때도 같은 원리를 적용할 수 있게
> 한다.
>
> 코드 레벨 구조는 `A31-real-ue-direct-해결-과정.md` 참고.

---

## 0. 역할 분리 — 코드 vs 시스템

| 레이어 | 책임 |
|---|---|
| **코드** | Via/bind_port 동기화, 템플릿 렌더링, port_pc 동적 조회, 송신 경로 선택 |
| **시스템** | IMS 인프라 기동, UE 등록 상태, 호스트 라우팅, 커널 파라미터, 도구 설치 |

코드는 "**이미 동작 중인 IMS + 등록된 단말**"을 **전제**한다. 전제가 깨지면
아무리 코드가 완벽해도 패킷이 단말에 도달하지 않는다.

---

## 1. IMS 인프라 (Docker 컨테이너)

### 1-1. 기동해야 할 컨테이너들

```bash
docker ps | grep -E 'pcscf|scscf|icscf|upf|hss|mongo|pyhss|enb'
```

| 컨테이너 | 역할 | IP | 왜 필요한가 |
|---|---|---|---|
| `pcscf` | Kamailio P-CSCF (+ IPsec) | 172.22.0.21 | **우리가 이 컨테이너의 네임스페이스 안에서 송신한다.** A31이 등록 때 P-CSCF IP를 화이트리스트해서, 이 IP 외에서 오는 INVITE는 drop. 그래서 pcscf 컨테이너 netns에서 소켓을 열어야 커널이 자동으로 172.22.0.21을 source로 골라준다. |
| `icscf` | I-CSCF | 172.22.0.19 | 호 라우팅 경로의 일부. fuzzer가 직접 건드리진 않지만, A31이 IMS에 정상 등록되려면 I-CSCF가 서있어야 HSS 조회 → S-CSCF 할당이 된다. |
| `scscf` | S-CSCF | 172.22.0.20 | IMS 세션 제어. REGISTER 인증 + 사용자 프로파일 적용 + iFC trigger. A31이 등록 상태를 유지하려면 필수. |
| `upf` (ogstun2 보유) | User Plane Function | 172.22.0.8 | **UE IP 대역(10.20.20.0/24)으로 가는 GTP 터널의 종단.** 호스트 라우트가 `10.20.20.0/24 via 172.22.0.8`로 가기 때문에, UPF가 죽으면 pcscf→A31 경로가 단절된다. |
| `hss` / `mongo` | Open5GS HSS + DB | - | EPC 인증 (IMSI → K/OP → AUTH 벡터 생성). LTE attach 자체에 필요. |
| `pyhss` | IMS HSS | - | IMS 인증 (REGISTER 의 AKA). `kamailio.cfg`가 pyhss로 MAR/SAR/LIR 메시지 보냄. 죽으면 A31이 IMS 재등록 실패. |
| eNB 프로세스 | 무선 기지국 (srsRAN/Amarisoft/...) | - | **실제 RF 신호 송출.** 이게 없으면 A31이 camp 못 해서 LTE 자체가 안 붙는다. |

### 1-2. pcscf 컨테이너 내부 도구

```bash
docker exec pcscf which python3 tcpdump ip
```

| 도구 | 왜 필요한가 |
|---|---|
| `python3` | fuzzer가 `docker exec -i pcscf python3 -c <DRIVER_SCRIPT>`로 드라이버 스크립트 실행. 없으면 컨테이너 안에서 송신 불가. |
| `ip` (iproute2) | `ip xfrm state`로 A31의 현재 port_pc를 읽어온다. 이게 없으면 port 조회 fallback이 실패. |
| `tcpdump` (옵션) | 컨테이너 내부 packet capture 필요 시. 호스트 tcpdump로도 `br-volte` interface 캡처 가능하므로 필수는 아님. |

### 1-3. Kamailio (pcscf 내부) IPsec 설정

Kamailio P-CSCF가 REGISTER 흐름에서 `ipsec_create`/`ipsec_forward` 모듈로
xfrm state/policy를 자동 등록한다. Kamailio 설정이 잘못되어 있으면:

- A31 REGISTER에 200 OK는 나오지만 **xfrm state가 안 만들어짐** → 이후 SIP는
  drop
- `docker exec pcscf ip xfrm state`에 아무것도 없음 → fuzzer가 port_pc 조회 실패

정상이면 REGISTER 직후 4개 SA가 보인다 (A31↔pcscf 양방향 × 2쌍).

---

## 2. 호스트 네트워크 라우팅

### 2-1. UE 서브넷 라우트

```bash
ip route show | grep 10.20.20
# 10.20.20.0/24 via 172.22.0.8 dev br-volte
```

#### 왜 필요한가

- **UE IP 대역(10.20.20.0/24)은 GTP 터널 안에만 존재한다.**
- Docker 컨테이너가 `10.20.20.8`로 패킷을 보내면, 호스트 라우팅 테이블이
  "이건 UPF(172.22.0.8)한테 주면 GTP로 포장해서 eNB → A31까지 전달된다"는 걸
  알려줘야 한다.
- 없으면 pcscf 컨테이너의 `sendto(..., ("10.20.20.8", ...))` 가
  `Network is unreachable` 에러로 실패.

#### 설정 방법

```bash
# fuzzer 내장 명령
uv run fuzzer infra add-ue-routes

# 또는 수동
sudo ip route add 10.20.20.0/24 via 172.22.0.8 dev br-volte
```

**주의**: 호스트 재부팅하면 사라진다. 영속화하려면 netplan/systemd-networkd/
`/etc/network/interfaces`에 추가.

### 2-2. Docker 브리지 `br-volte`

```bash
docker network inspect br-volte
```

- 서브넷 `172.22.0.0/16`
- 모든 IMS 컨테이너가 이 브리지에 연결되어 있어야 서로 통신
- MTU는 보통 1500 (호스트와 동일)

#### 왜 `br-volte`가 중요한가

- **pcap 캡처 인터페이스**: `tcpdump -i br-volte` 하면 컨테이너 간 트래픽
  전체가 보인다. `--pcap-interface br-volte` 옵션이 이걸 활용.
- **fragmentation 허용**: Docker 브리지는 커널이 IP 재조립을 정상 처리. 2460
  바이트 MT INVITE도 단편화해서 보내도 A31에 도달 OK.
- **컨테이너 간 라우팅**: pcscf(172.22.0.21) → UPF(172.22.0.8)가 L2 스위칭
  (브리지 내부)이라 별도 라우트 불필요.

---

## 3. UE(A31) 상태

### 3-1. 하드웨어 / 물리 상태

| 조건 | 왜 |
|---|---|
| 전원 ON | 당연 |
| 화면 켜짐 | 잠금 상태라도 됨. 화면 완전히 꺼져있으면 일부 단말은 SIP 응답이 느려질 수 있음. |
| LTE camped | eNB에서 RRC Connection 성립. 안 그러면 GTP 터널 자체가 없음. |
| 방해금지 OFF | **Samsung "방해 금지" 모드가 ON이면 INVITE 도달해도 벨 안 울림.** 조용히 무시. |
| 비행기모드 OFF | 당연 |
| 실험실 SIM 장착 | IMSI `001010000123511`가 HSS DB에 프로비저닝되어 있어야 함 |
| **VoLTE 기능 ON** | Settings → Connections → Mobile networks → VoLTE calls. OFF면 IMS REGISTER 자체를 안 보냄 → 등록 상태 없음 |

### 3-2. IMS 등록 상태

```bash
docker exec pcscf ip xfrm state | grep -c 'dst 10.20.20.8'
```

- 결과 ≥ 2 여야 함 (A31↔pcscf 양방향 SA)
- 결과 0 = A31이 IMS 미등록
- xfrm state가 있는데 오래된 경우도 있음 (`lastused` 확인)

#### A31 재등록 강제 방법

한 가지 방법이 안 들으면 순서대로 시도:

1. A31에서 **VoLTE 토글** OFF → ON
2. 셀룰러 데이터 OFF → ON
3. 비행기모드 ON → 10초 → OFF
4. SIM 뺐다 끼우기
5. A31 재부팅
6. pcscf 컨테이너 재시작 (`docker restart pcscf`)

### 3-3. port_pc 동적 순환

- A31이 재등록할 때마다 port_pc/port_ps가 다른 값으로 바뀐다 (Kamailio IPsec
  모듈의 port counter).
- 검증된 값: 7900/7901, 8000/8001, 8100/8101, ...
- fuzzer는 **케이스 실행 시점에** 라이브 조회하므로 보통 문제없음.
- **주의**: 긴 캠페인 중에 A31이 재등록하면 중간부터 포트가 stale. 대량 돌릴
  때는 A31을 건드리지 않기.

---

## 4. 호스트 사용자 권한

### 4-1. Docker 그룹

```bash
groups ubuntu | grep docker
```

#### 왜

`docker exec`, `docker logs`가 `sudo` 없이 동작해야 fuzzer가 interactive
password prompt에 막히지 않는다. 없으면:

```bash
sudo usermod -aG docker ubuntu
# 재로그인 필요
```

### 4-2. passwordless sudo (tcpdump 한정)

```bash
sudo visudo
# 추가:
ubuntu ALL=(ALL) NOPASSWD: /usr/bin/tcpdump
```

#### 왜

- `--pcap` 옵션 쓰면 fuzzer가 `sudo tcpdump`로 캡처 시작.
- 비밀번호 prompt가 뜨면 fuzzer가 멈춘다 (stdin이 서브프로세스에 연결 안 됨).
- 캡처 없이 돌리면 불필요.

### 4-3. adb (crash snapshot 한정)

```bash
adb devices
```

#### 왜

- `--adb --adb-serial <serial>` 옵션 쓰면 crash/stack_failure 발생 시 A31에서
  logcat/tombstone 덤프.
- A31을 USB로 호스트에 연결 + 개발자 옵션 + USB 디버깅 + RSA 키 승인 필요.
- 크래시 스냅샷 수집 안 할 거면 생략 가능.

---

## 5. 호스트 커널 파라미터

### 5-1. IP forwarding

```bash
sysctl net.ipv4.ip_forward
```

#### 왜

- Docker 컨테이너 간 통신 + 컨테이너→외부 라우팅 전부 호스트 커널의 forwarding
  에 의존.
- `0`이면 `br-volte` 안의 pcscf가 `10.20.20.8`로 패킷을 내보내도 UPF로 넘어가지
  않음.
- Docker를 설치하면 보통 자동으로 `1` 설정됨. 확인만 하면 됨.

**고치기**:
```bash
sudo sysctl -w net.ipv4.ip_forward=1
# 영속화
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
```

### 5-2. Return-Path Filter (`rp_filter`)

```bash
sysctl net.ipv4.conf.all.rp_filter
sysctl net.ipv4.conf.br-volte.rp_filter
```

#### 왜

- Linux가 들어오는 패킷의 source IP로 reverse-path 검증을 한다 (RFC 3704).
- `rp_filter=1` (strict mode)이면: 패킷이 들어온 인터페이스가 source IP로 가는
  최적 경로와 **다르면** drop.
- 우리 시나리오: A31 → UPF(GTP 터널) → br-volte → pcscf. 응답은 반대로 오는데,
  호스트의 routing view에서 `10.20.20.8`이 `172.22.0.8`(UPF) 경유라고 기억하면
  rp_filter가 "br-volte로 들어온 10.20.20.8 source는 이상해"라고 판정해서 drop
  할 수 있다.
- **권장값**: `0` (disabled) 또는 `2` (loose mode).

**고치기**:
```bash
sudo sysctl -w net.ipv4.conf.all.rp_filter=2
sudo sysctl -w net.ipv4.conf.br-volte.rp_filter=2
```

### 5-3. conntrack 한도 (대량 퍼징 시)

```bash
sysctl net.netfilter.nf_conntrack_max
sysctl net.netfilter.nf_conntrack_buckets
```

#### 왜

- 기본 `65536` 정도는 수십만 케이스 퍼징 시 고갈될 수 있다.
- 고갈되면 새 TCP/UDP 연결이 silently drop.
- 대규모 캠페인 전에 늘려두기:

```bash
sudo sysctl -w net.netfilter.nf_conntrack_max=262144
```

### 5-4. UDP receive buffer (옵션)

```bash
sysctl net.core.rmem_max
sysctl net.core.rmem_default
```

#### 왜

- `recvfrom`이 짧은 시간에 여러 응답 받을 때 버퍼 오버플로우 가능.
- 보통 기본값(200KB 내외)으로 충분. A31 응답 100/180 단 2개는 수백 바이트.

---

## 6. eNB / 무선 링크

### 6-1. 기동 상태

- 실험실 eNB 프로세스 (srsRAN, Amarisoft, open5gs-enb 등)가 떠 있어야 함
- RF 하드웨어 (USRP, bladeRF, Amarisoft card 등) 연결 + 드라이버 정상
- EARFCN/PLMN(`001-01`)이 A31과 호환

### 6-2. S1 연결

- eNB ↔ MME 사이 S1-C 연결 UP
- MME가 죽어있으면 A31 attach 자체가 안 됨

### 6-3. 왜 fuzzer가 이걸 신경 써야 하나

- eNB가 없으면 A31이 LTE에 붙지 않음 → EPS bearer 없음 → IMS 못 등록 → xfrm SA
  없음 → fuzzer port 조회 실패
- **인프라 전체 스택이 살아있어야** fuzzer 첫 패킷이 의미 있다.

---

## 7. fuzzer 설치 상태

### 7-1. 리포지토리 동기화

```bash
rsync -av --exclude='.venv' --exclude='__pycache__' \
    /Users/chaejisung/Desktop/volte-mutation-fuzzer/ \
    ubuntu@163.180.185.51:/home/ubuntu/Desktop/fuzzer/
```

- 노트북에서 개발, 서버에서 실행하는 flow
- `.venv`와 `__pycache__`는 제외 (서버 architecture 의존)

### 7-2. Python 가상 환경

```bash
cd /home/ubuntu/Desktop/fuzzer
uv sync
# 또는
python3 -m venv .venv && .venv/bin/pip install -e .
```

- `fuzzer` CLI 진입점이 `.venv/bin/fuzzer`로 생성되어야 함
- 의존성 (`typer`, `pydantic`, `scapy` 등) 설치 완료

### 7-3. 환경 변수 (옵션)

| 변수 | 기본값 | 언제 필요 |
|---|---|---|
| `VMF_REAL_UE_PCSCF_IP` | `172.22.0.21` | P-CSCF IP가 다른 환경 |
| `VMF_REAL_UE_SDP_OWNER_IP` | `172.22.0.16` | SDP `o=` 라인의 주소 |
| `VMF_REAL_UE_SDP_AUDIO_PORT` | `49196` | SDP audio 포트 |

기본값은 현재 실험실 기준이므로 다른 환경 이식 시 덮어쓰기.

---

## 8. 포트 점유 검증

### 8-1. `--mt-local-port` 포트 비어있는가

```bash
docker exec pcscf ss -ulnp | grep 15100
```

아무것도 안 나와야 함.

#### 왜

- fuzzer 드라이버 스크립트가 `sock.bind(("172.22.0.21", 15100))` 시도.
- 이미 다른 프로세스가 점유 중이면 `EADDRINUSE` 에러.

#### 피해야 할 포트

Kamailio P-CSCF가 점유 중인 포트 (건드리면 안 됨):

| 포트 | 용도 |
|---|---|
| `5060` | plain UDP/TCP SIP |
| `5100–5103` | P-CSCF 보호 클라이언트 포트 (IPsec) |
| `6101–6103` | P-CSCF 보호 서버 포트 (IPsec) |

**기본값 15100은 이들과 겹치지 않는 안전 구간**. 충돌하면 다른 5자리 high port
(`15200`, `25100` 등)로 변경.

---

## 9. 방화벽 / iptables

```bash
sudo iptables -L -n -v | grep -E 'DROP|REJECT'
sudo iptables -t nat -L -n
```

#### 왜

- Docker가 기본적으로 필요한 NAT/FORWARD 룰을 자동 추가
- 추가 보안 룰(UFW, 커스텀 iptables)이 있으면 `172.22.0.0/16 ↔ 10.20.20.0/24`
  트래픽이 차단될 수 있다
- 차단되면 호스트 수준에서 silently drop → fuzzer는 그냥 timeout으로 관측

**확인 포인트**:
- `DOCKER-USER` 체인에 DROP 없어야 함
- `FORWARD` 체인 기본 정책 `ACCEPT` (또는 Docker 룰이 먼저 매치)
- UFW 사용 중이면 `172.22.0.0/16` 아웃바운드 허용

---

## 10. 체크리스트 — 실행 전 한 번에 확인

```bash
#!/bin/bash
# A31 real-ue-direct pre-flight check

echo "=== 1. Docker containers ==="
docker ps --format '{{.Names}}' | grep -E 'pcscf|scscf|icscf|upf|hss|pyhss' | sort

echo "=== 2. Host route ==="
ip route show 10.20.20.0/24

echo "=== 3. A31 IMS registration (xfrm SAs) ==="
docker exec pcscf ip xfrm state | grep -c 'dst 10.20.20.8'

echo "=== 4. A31 port_pc (expected 4 hits) ==="
docker exec pcscf ip xfrm state | grep -E 'sel src 10.20.20.8.*sport'

echo "=== 5. python3 in pcscf ==="
docker exec pcscf python3 --version

echo "=== 6. Port 15100 free in pcscf netns ==="
if docker exec pcscf ss -ulnp 2>/dev/null | grep -q ':15100 '; then
    echo "OCCUPIED — use different port"
else
    echo "free"
fi

echo "=== 7. rp_filter (expect 0 or 2) ==="
sysctl -n net.ipv4.conf.all.rp_filter
sysctl -n net.ipv4.conf.br-volte.rp_filter 2>/dev/null

echo "=== 8. ip_forward ==="
sysctl -n net.ipv4.ip_forward

echo "=== 9. Docker access (no sudo) ==="
docker ps > /dev/null && echo "OK" || echo "FAIL (add to docker group)"

echo "=== 10. fuzzer entry point ==="
ls -la /home/ubuntu/Desktop/fuzzer/.venv/bin/fuzzer 2>/dev/null || echo "MISSING"
```

**모두 PASS면 코드 레벨 실행 준비 완료.** 하나라도 실패하면 해당 섹션으로 가서
해결 후 재실행.

---

## 11. "왜 이렇게 많은가" — 한 줄 요약

IMS는 **여러 레이어의 보안/신호 체인**을 통과해야 단말이 울린다:

```
[fuzzer code] → [docker exec] → [pcscf netns] → [br-volte bridge] →
[UPF GTP] → [eNB RF] → [A31 modem] → [A31 IMS stack] → [A31 SIP parser] → [벨]
```

각 단계가 다 살아있고 올바른 값으로 설정되어야 **맨 끝이 울린다**. 한 레이어만
틀어져도 fuzzer는 `timeout`으로 관측하고 그 이상 모른다. 그래서 **시스템 레벨
pre-flight check가 코드 디버깅보다 먼저**다.

---

## 12. 관련 문서

- `docs/이슈/A31-real-ue-direct-INVITE-성공-기록.md` — 5가지 성공 조건 원문
- `docs/이슈/A31-real-ue-direct-운영-지침.md` — 운영자 체크리스트 + 실행 명령
- `docs/이슈/A31-real-ue-direct-해결-과정.md` — 개념 설명 + 코드 레벨 삽질
  히스토리 (IPsec/ESP/XFRM 이론 설명 포함)
- `worklog_20260411.md` — 전체 작업 로그
- `memory/reference_fuzzer_server.md` — SSH/컨테이너/라우팅 요약 (Claude 메모리,
  영어)
