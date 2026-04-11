# Capstone vs VolteMutationFuzzer IPsec 접근방식 비교 및 null ealg 전환 가이드

> **요약**: Capstone은 Kamalio `ipsec_preferred_ealg "null"`로 암호화를 껍데기만 
> 남겨 호스트에서 평범한 UDP 송신을 가능하게 했다. 현재 프로젝트는 실제 AES-CBC 
> 암호화 환경에서 xfrm policy selector 미매치 트릭으로 평문을 통과시킨다. 
> 두 방식의 "왜 평문이 통했나"에 대한 답이 완전히 다르며, 각각의 장단점과 
> 현실성이 상이하다.

---

## 1. Capstone 방식의 핵심 — "null encryption" IMS IPsec

### Kamailio 설정의 핵심 한 줄

```
modparam("ims_ipsec_pcscf", "ipsec_preferred_ealg", "null")
```

### 3GPP IPsec Encryption Algorithm 표준

3GPP TS 33.203이 IMS IPsec에서 허용하는 encryption algorithm:

- **aes-cbc** (기본 — AES 128 CBC)
- **des-ede3-cbc** (3DES)  
- **null** (암호화 없음 — 무결성만)

### null ealg 동작 원리

`ipsec_preferred_ealg "null"` 설정 시:

1. UE가 REGISTER하면서 Security-Client 헤더로 알고리즘 제안
2. Kamailio가 Security-Server로 응답할 때 **ealg=null을 우선 선택**
3. UE가 동의하면 이후 IPsec SA는 **"암호화 없음, HMAC만"** 모드로 수립
4. ESP 패킷의 payload가 **평문 그대로** 들어감 (ESP 헤더와 ICV만 붙음)

즉 **껍데기만 IPsec이고 내용은 평문**이다. tcpdump로 봐도 SIP 내용이 보인다.

### 공격자(Fuzzer) 관점에서의 이점

- ESP 헤더를 직접 만들 수 없어도
- Kamailio가 만든 SA에 실제 암호화 키가 없으니까
- `docker exec pcscf ...`로 컨테이너 안에서 평문 UDP를 보내면
- 커널 xfrm이 패킷을 ESP로 감싸는데 **암호화는 안 함**
- UE가 받으면 ESP 벗기고 평문 payload 그대로 앱 레이어로 올림

**결과**: fuzzer는 평문 UDP로 작성한 SIP를 보내기만 하면, 중간에 알아서 ESP 껍데기 입혀서 UE까지 도달한다. **암호화 키 없이도**.

### Capstone 시스템 설정

```bash
# /etc/sysctl.d/99-volte-fuzzer.conf
net.ipv4.ip_nonlocal_bind = 1
net.ipv4.conf.all.rp_filter = 0
```

- **ip_nonlocal_bind=1**: 호스트에서 P-CSCF IP(172.22.0.21) spoof 가능
- **rp_filter=0**: 응답 패킷 reverse-path check 완전 비활성화

---

## 2. VolteMutationFuzzer 방식과의 차이

### 현재 프로젝트의 서버 상태

```bash
docker exec pcscf ip xfrm state | grep -A3 '10.20.20.8'
```

결과:
```
src 172.22.0.21 dst 10.20.20.8
    proto esp spi 0x... reqid ...
    auth-trunc hmac(sha1) 0x...
    enc cbc(aes) 0x5c3f3c5ad8292899a01310517752f8c9
    ^^^^^^^^^^^^
    실제 AES-CBC 키가 들어있음 (128 bits)
```

현재 서버는 **null 모드가 아니라 aes-cbc 모드**다. Kamailio가 실제 암호화 키를 협상해서 SA에 올린 상태.

### 현재 방식의 평문 통과 원리

AES-CBC 환경에서 평문을 보내면:

- **pcscf sport가 5103/6103**이면: xfrm policy 매치 → 커널이 AES 암호화 시도 → 
  ESP 생성 실패 또는 잘못된 암호문 → UE 복호화 실패 → drop
- **pcscf sport가 15100**이면: xfrm policy 매치 안 됨 → **평문 UDP 그대로 나감** → 
  UE 커널이 ESP 기대 없으므로 → UE 앱 레이어가 받음 → **성공** (우리 케이스)

즉 **암호화 설정이 기본값(aes-cbc)인 상태에서도 동작하도록 selector 회피 트릭**을 썼다.

---

## 3. 두 방식 비교표

| 항목 | Capstone | VolteMutationFuzzer |
|------|----------|---------------------|
| **Kamailio ealg** | null (무암호화 IPsec) | default (aes-cbc) |
| **실제 ESP 페이로드** | 평문 (무결성만) | 실제 AES 암호문 |
| **송신 주체** | 호스트 프로세스 | pcscf 컨테이너 netns 안 |
| **source IP 맞추기** | ip_nonlocal_bind=1로 호스트에서 spoof 가능 | netns 자동 선택 (172.22.0.21) |
| **rp_filter** | all=0 (완전 비활성화) | 기본 (엄격하지 않으면 OK) |
| **xfrm policy 회피** | 필요 없음 (null이라 암호화 키 없음) | sport=15100 (Kamailio 점유 포트 회피) |
| **공격 가정** | 실험용 IMS core를 통째로 설정 가능 | 기본 IMS 설정도 뚫을 수 있음 |
| **현실성** | 낮음 (실제 통신사는 aes-cbc/des 강제) | 높음 (어떤 설정이든 동작) |
| **구현 복잡도** | 낮음 (평범한 소켓 송신) | 높음 (docker exec 드라이버 + Via 포트 동기화) |

---

## 4. 용도별 선호도

| 용도 | 선호 |
|------|------|
| **빠른 PoC, 교내 실험실** | Capstone (설정 한 줄로 끝) |
| **실제 통신사 환경 연구** | VolteMutationFuzzer (기본 설정 가정) |
| **CVE 재현 실험** | 둘 다 가능 (Capstone이 간단) |
| **Production 보안 검증** | VolteMutationFuzzer (현실적 조건) |

### 핵심 철학 차이

- **Capstone**: "환경을 단순화"하는 방법
- **VolteMutationFuzzer**: "주어진 환경에서 뚫는" 방법

---

## 5. 현재 프로젝트를 null ealg 기반으로 수정하는 방법

### 0. 사전 검증 (코드 수정 전)

가장 중요한 가정: **"A31이 null ealg를 수락할 것인가?"**

Samsung 폰은 보안상 null encryption을 거부할 수 있다. REGISTER negotiate 실패하면 IMS 서비스 자체가 안 붙는다.

#### 0-1. 서버에서 Kamailio 설정 변경

```bash
ssh ubuntu@163.180.185.51

# 원본 백업
cp infrastructure/pcscf/kamailio_pcscf.cfg \
   infrastructure/pcscf/kamailio_pcscf.cfg.backup_aes

# 변경 확인/수정
grep ipsec_preferred_ealg infrastructure/pcscf/kamailio_pcscf.cfg
# 다음으로 변경:
modparam("ims_ipsec_pcscf", "ipsec_preferred_ealg", "null")

# pcscf 재시작 + A31에서 VoLTE 토글
docker restart pcscf
# A31: Settings → Mobile networks → VoLTE calls OFF → ON
```

#### 0-2. 협상 결과 확인

```bash
# 로그에서 협상 과정 확인
docker logs pcscf --since 2m | grep -iE 'security-client|security-server|ealg|Creating.*IPSec'
```

**기대 결과**:
- `Security-Client: ... ealg=aes-cbc, ealg=null, ...` ← A31이 null을 offer
- `Security-Server: ... ealg=null` ← Kamailio가 null 선택
- `ipsec_create... ealg=null` ← SA 생성

```bash
# xfrm state 확인
docker exec pcscf ip xfrm state | grep -A3 '10.20.20.8' | head -20
```

**성공 시 기대 결과**:
```
src 172.22.0.21 dst 10.20.20.8
    proto esp spi 0x... reqid ...
    auth-trunc hmac(sha1) 0x...
    enc ecb(cipher_null) 0x           ← 이게 떠야 함!
                ^^^^
```

`enc cbc(aes)` 대신 `enc ecb(cipher_null)`이면 성공. A31이 null ealg를 수락한 것.

**실패 케이스**:
- A31 REGISTER가 401/403으로 떨어지고 재시도 루프 → null 거부
- Security-Client에 ealg=null이 없음 → 삼성 firmware가 아예 제공 안 함
- → 이 계획 포기, 원상복구 (백업으로 되돌리고 aes-cbc 유지)

### 1. 검증 성공 시 — 코드 단순화 계획

#### 1-1. 호스트 sysctl 설정 (capstone과 동일)

```bash
sudo tee /etc/sysctl.d/99-volte-fuzzer.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.ip_nonlocal_bind = 1
EOF
sudo sysctl --system
```

**설정 이유**:
- **ip_nonlocal_bind=1**: 호스트에 없는 IP(172.22.0.21)를 소켓 source로 bind 가능 ← **핵심**
- **rp_filter=0**: 응답이 br-volte로 들어올 때 reverse-path check 통과
- **ip_forward=1**: 호스트 → UPF → GTP 경로 라우팅

#### 1-2. Fuzzer 코드 변경점

**(a) container_exec.py 삭제 또는 deprecate**

```python
# 더 이상 docker exec 드라이버 필요 없음
# - _DRIVER_SCRIPT 제거
# - send_via_container 함수 제거
# - ContainerSendResult 제거
```

**(b) TargetEndpoint.bind_container 제거**

```python
# Before
class TargetEndpoint(BaseModel):
    ...
    bind_container: str | None = None
    bind_port: int | None = None

# After
class TargetEndpoint(BaseModel):
    ...
    source_ip: str | None = None       # 새 필드: 호스트가 spoof할 source IP
    bind_port: int | None = None       # 유지: Via sent-by 일치용
```

**(c) sender/core.py::_send_real_ue_direct 단순화**

```python
# Before: bind_container 분기 → docker exec
if target.bind_container is not None:
    return self._send_via_container(...)

# After: source_ip 설정되면 host에서 직접 spoof 송신
if target.source_ip is not None:
    return self._send_with_spoofed_source(
        artifact=artifact,
        source_ip=target.source_ip,
        source_port=target.bind_port or 0,
        dest_host=resolved.host,
        dest_port=resolved.port,
        transport=target.transport,
        timeout=target.timeout_seconds,
    )
```

**새 헬퍼 _send_with_spoofed_source**:

```python
def _send_with_spoofed_source(
    self, *, artifact, source_ip, source_port, dest_host, dest_port, transport, timeout,
) -> tuple[TargetEndpoint, bytes, list[SocketObservation], tuple[str, ...]]:
    """호스트에서 ip_nonlocal_bind로 source IP를 spoof해서 송신.
    
    pcscf 컨테이너 netns 진입 없이 동일 효과. 전제:
    - net.ipv4.ip_nonlocal_bind = 1
    - net.ipv4.conf.*.rp_filter = 0 (응답 수신용)
    - Kamailio가 null ealg로 협상 완료된 상태 (A31이 평문 ESP 수락)
    """
    observer_events = [f"spoof-source:{source_ip}:{source_port}"]

    payload, normalization_events = prepare_real_ue_direct_payload(
        artifact,
        local_host=source_ip,
        local_port=source_port,
        rewrite_via=not artifact.preserve_via,
        rewrite_contact=not artifact.preserve_contact,
    )
    observer_events.extend(normalization_events)

    if transport.upper() == "TCP":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        # ip_nonlocal_bind=1 덕분에 로컬에 없는 IP도 bind 가능
        sock.bind((source_ip, source_port))

        if transport.upper() == "TCP":
            sock.connect((dest_host, dest_port))
            sock.sendall(payload)
            data = sock.recv(65535)
            observations = [self._parse_response(data, (dest_host, dest_port))] if data else []
        else:
            sock.sendto(payload, (dest_host, dest_port))
            observations = self._read_udp_observations(sock, collect_all_responses=True)
    finally:
        sock.close()

    return resolved_target, payload, observations, tuple(observer_events)
```

**(d) campaign/core.py::_execute_mt_template_case 변경**

```python
# Before
mt_target = self._target.model_copy(
    update={"port": port_pc, "bind_port": config.mt_local_port}
)

# After
mt_target = self._target.model_copy(
    update={
        "port": port_pc,
        "source_ip": pcscf_ip,               # 172.22.0.21
        "bind_port": config.mt_local_port,
    }
)
```

bind_container 관련 참조 전부 제거.

**(e) CLI 옵션 정리**

```bash
# 삭제
--bind-container

# 이름 변경 또는 신규
--source-ip           # 기본: 172.22.0.21 (pcscf IP)
--mt-local-port       # 유지
```

**(f) CampaignConfig 정리**

```python
# Before
bind_container: str | None = None

# After
source_ip: str = "172.22.0.21"
```

### 2. 테스트 시나리오

#### 2-1. 회귀 확인 (softphone 경로)

```bash
uv run fuzzer campaign run --target-host 127.0.0.1 --target-port 5060 \
  --methods OPTIONS --max-cases 5
```

호스트 소프트폰은 source IP spoof 없이 기존 동작해야 함.

#### 2-2. A31 identity 케이스

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct --transport UDP \
  --target-host 10.20.20.8 --target-msisdn 111111 \
  --impi 001010000123511 \
  --methods INVITE --layer wire --strategy identity \
  --mt-invite-template a31 \
  --source-ip 172.22.0.21 \
  --preserve-contact --preserve-via \
  --mt-local-port 15100 \
  --max-cases 1 --timeout 10 --no-process-check
```

**기대**: `normal (180, ...)` — 이전 docker exec 경로와 동일 결과.

#### 2-3. 암호화 모드 원상복구 테스트

Kamailio를 다시 aes-cbc로 되돌렸을 때 새 경로가 실패하고 docker exec 경로만 통하는지 확인. 이게 우리가 왜 이 전환이 "설정 의존적"인지를 증명한다.

### 3. 남는 문제 / 주의사항

#### 3-1. Via sent-by ↔ bind_port 동기화는 여전히 필요

null ealg든 aes-cbc든 SIP 레이어 문제(Via 응답 경로)는 그대로다. `--mt-local-port` 메커니즘은 유지되어야 함.

#### 3-2. xfrm policy 미매치 조건도 여전히 중요

null ealg는 암호화만 NOP이지, xfrm policy는 여전히 `proto esp`를 요구한다. sport=5103/6103으로 보내면 여전히 커널이 ESP 래핑을 시도한다. `--mt-local-port 15100` 같은 high port 사용은 계속 필수.

#### 3-3. 양쪽 모드 동시 지원 vs. 전환

두 가지 선택지:

**A. 전환 (simpler)**: bind_container 경로 완전 제거, source_ip 경로만 남김
- 장점: 코드 단순
- 단점: aes-cbc 서버에서는 더 이상 동작 안 함 (되돌릴 수 없음)

**B. 공존 (safer)**: 두 경로 모두 지원, CLI에서 선택
- 장점: 어느 서버 설정이든 대응
- 단점: 코드 복잡도 유지

**권장**: **B**. `--bind-container`와 `--source-ip`를 양쪽 다 지원하고, 둘 중 하나가 설정되면 각 경로로 분기. 검증 끝난 후에 사용자가 판단해서 A로 정리.

#### 3-4. 현실성 저하

**null ealg는 실험실 전용**이다. 이 경로만 쓰면:
- 상용 통신사 환경에서 재현성 0
- 학술 논문이나 진짜 CVE 연구용으로는 부적합
- 빠른 PoC / 교내 시연용으로는 적합

docker exec 경로를 남겨두면 **"기본 설정 환경에서도 뚫을 수 있다"**는 가치를 유지할 수 있다.

---

## 6. 구체 작업 순서

| 순서 | 작업 | 레벨 |
|------|------|------|
| 1 | `kamailio_pcscf.cfg` 백업 + ealg null 설정 | 서버 |
| 2 | pcscf 재시작 + A31 재등록 | 서버 + 단말 |
| 3 | xfrm state `enc ecb(cipher_null)` 확인 | 서버 |
| 4 | sysctl `ip_nonlocal_bind=1`, `rp_filter=0` | 호스트 |
| 5 | `TargetEndpoint.source_ip` 필드 추가 | 코드 |
| 6 | `_send_with_spoofed_source` 헬퍼 추가 | 코드 |
| 7 | `_send_real_ue_direct` 분기에 source_ip 추가 | 코드 |
| 8 | `CampaignConfig.source_ip`, CLI `--source-ip` 옵션 | 코드 |
| 9 | `_execute_mt_template_case`에서 source_ip 주입 | 코드 |
| 10 | identity 케이스 E2E 검증 | 테스트 |
| 11 | (옵션) bind_container 경로 제거 vs 공존 결정 | 리팩터 |

---

## 7. 한 줄 요약

**Capstone은 Kamailio를 `ipsec_preferred_ealg "null"`로 설정해서 IPsec 암호화 자체를 껍데기만 남겼다. 그래서 호스트에서 평범한 UDP 송신으로도 UE에 도달한다. VolteMutationFuzzer는 암호화가 실제로 동작하는(aes-cbc) 환경에서 xfrm policy selector 미매치 트릭으로 평문이 통과하게 만들었다. 두 방법이 "왜 평문이 통했나"에 대한 답이 완전히 다르다.**

---

## 8. 다음 스텝

- **먼저 서버에서 Kamailio를 null ealg로 바꾸고 A31이 재등록 받아지는지 확인**
- 받아지면 `_send_with_spoofed_source` 헬퍼를 추가하고 `TargetEndpoint`에 `source_ip` 필드 신설  
- `bind_container` 경로는 남겨두고 공존시키는 걸 권장 (둘 다 쓸 수 있는 상태가 연구적으로 더 가치 있음)

진행할까? 아니면 먼저 **서버 ealg 변경 + A31 재등록 검증만** 해보고 갈지 결정?