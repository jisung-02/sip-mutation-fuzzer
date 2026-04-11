# A31이 벨 울리는 데 필요한 것들 — 처음부터

> 이 문서는 A31 real-ue-direct MT INVITE 퍼징 통합 과정에서 겪은 삽질의 전체
> 여정과 최종 해결 원리를 설명한다. 다른 단말/다른 IMS 환경으로 확장할 때도
> 같은 계층적 접근이 필요하므로 학습용 기록으로 남긴다.

---

## 0. 왜 이게 어려운가

일반 SIP 서버랑 다르게 **IMS에 등록된 실제 단말**은 그냥 SIP INVITE 아무거나
보낸다고 받지 않는다. 여러 층의 보호가 겹겹이 쌓여있다:

```
[fuzzer] ---?---> [여러 검증 레이어] ---> [A31 벨 울림]
                  1. 커널 IPsec
                  2. IMS 앱 레이어 source-IP 필터
                  3. SIP 파서 (헤더/포맷 검증)
                  4. 다이얼로그 상태 머신
```

각 레이어가 서로 다른 이유로 drop할 수 있어서, **어디서 막히는지 구분하는
게 핵심**이었다.

---

## 1. IPsec / ESP / XFRM — 이게 뭔가

### IPsec이란

IMS는 P-CSCF와 UE 사이 SIP 트래픽을 **IPsec**으로 암호화·인증한다
(3GPP TS 33.203). REGISTER 중에 SA(Security Association)를 협상해서, 이후
오가는 SIP는 평문이 아니라 ESP(Encapsulating Security Payload)로 감싸진
상태로 흐른다.

### ESP

ESP는 IP 헤더 뒤에 붙는 프로토콜 번호 50의 페이로드로, 안에 원래 UDP/TCP
패킷을 암호화해서 넣는다.

```
원래:     [IP][UDP][SIP text]
ESP 후:   [IP][ESP header][암호화된 UDP+SIP][ESP trailer][auth]
```

### Linux XFRM

Linux 커널의 IPsec 구현체 이름이 **XFRM**이다. 두 가지 테이블이 있다:

- **xfrm state** (SA, Security Association): "어떤 키로 어떻게 암호화할지"
- **xfrm policy** (SP, Security Policy): "어떤 트래픽에 SA를 적용할지"

예시:

```
# state: 172.22.0.21 → 10.20.20.8 방향, AES-CBC로 암호화, 키=xxx
src 172.22.0.21 dst 10.20.20.8
    proto esp spi 0x... mode transport
    enc cbc(aes) 0x5c3f3c5a...

# policy: sport=5103, dport=8101 트래픽은 위 SA 적용
src 172.22.0.21/32 dst 10.20.20.8/32 sport 5103 dport 8101
    dir out
    tmpl src 172.22.0.21 dst 10.20.20.8 proto esp
```

정책 selector(`sport`, `dport`)가 **정확히 일치하는 패킷만** 커널이 자동으로
ESP로 감싼다. 일치 안 하면 평문으로 나간다.

---

## 2. A31의 방어선 — 뭐가 검사되는가

수동 테스트에서 맨땅에 헤딩해가며 알아낸 건데, A31은 **XFRM + 앱 레이어
필터**가 동시에 동작한다:

### 2-1. 커널 XFRM (IPsec 레이어)

- A31 커널이 들어온 ESP 패킷을 복호화한다
- **근데 신기한 점**: P-CSCF IP(172.22.0.21)에서 오는 **평문 UDP**도 통과시킨다
- 아마 3GPP 스펙이 아니라 삼성 커널 설정 이슈

이게 어떤 의미냐면 — **ESP 매칭 포트(5103) 맞춰서 보낼 필요가 없다**. 평문으로
보내도 커널은 안 막는다.

### 2-2. IMS 앱 레이어 (SIP 스택)

- SIP 파서가 받은 패킷의 **source IP를 체크**
- 등록했던 P-CSCF(172.22.0.21) IP에서 온 게 아니면 → **조용히 drop**
- 심지어 이때 SIP 트랜잭션 레이어는 100 Trying을 자동 응답할 수도 있어서,
  네트워크 상으로는 "뭔가 받긴 했네?" 싶지만 실제로는 앱까지 올라가지 않음

### 2-3. SIP 파서 (헤더/SDP 검증)

- 최소한의 INVITE (손수 쓴 간단한 것) → `400 Parsing Failed`
- 3GPP 풀 포맷 (Record-Route ×3, P-*, 완전한 AMR SDP, preconditions 등) → OK
- 실제 capture에서 뽑은 걸 **그대로 replay**해야 안정적

---

## 3. 처음에 왜 실패했는가 — 4단계 삽질

### 실패 ①: port_pc 조회가 아예 안 됨

```
[ERROR] could not resolve protected ports for UE via container 'pcscf'
```

**원인**: `xfrm state` 출력 파서 버그.

xfrm state 출력 포맷:

```
src 10.20.20.8 dst 172.22.0.21
    proto esp spi 0x... reqid ...
    ...
    sel src 10.20.20.8/32 dst 172.22.0.21/32 sport 8100 dport 5103
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
         이 줄은 "sel"로 시작한다
```

내 파서: `if stripped.startswith("sport"):` → **매치 안 됨**. "sel"로 시작하니까.

**고침**: `"sel "`로 시작하고 `sport`/`dport` 포함하는 라인을 매치. 그리고 SA
헤더 `src X dst Y`로 방향 추적.

### 실패 ②: port_pc vs port_ps 혼동

파서 고친 후 결과: `(8101, 8102)` — 여전히 틀림.

왜?

A31↔pcscf 사이엔 **SA가 여러 개** 있다:

```
sel src 10.20.20.8/32 dst 172.22.0.21/32 sport 8100 dport 5103  ← port_pc 쓰는 SA
sel src 10.20.20.8/32 dst 172.22.0.21/32 sport 8101 dport 6103  ← port_ps 쓰는 SA
```

내 파서는 A31 sport를 다 수집하긴 했는데 **마지막 값만 덮어썼다**. 마지막이
8101이면 port_pc=8101로 오해 → `(8101, 8102)`.

**고침**: A31 sport를 전부 리스트에 모은 뒤 `min()`이 port_pc, `+1`이 port_ps.
관례상 port_ps는 port_pc보다 항상 큰 홀수 바로 다음 번호.

### 실패 ③: 잘못된 rabbit hole — ESP 매칭에 파고들기

검색해보니 xfrm policy가 **정확한 sport/dport 쌍**에만 ESP를 적용하는 걸 발견:

```
src 172.22.0.21 dst 10.20.20.8 sport 5103 dport 8101 → ESP 적용
```

여기서 "아, 내가 랜덤 포트에서 보내니까 ESP가 안 씌워져서 A31이 drop하는
거구나!" 라고 **잘못** 결론. Kamailio가 쓰는 5103 포트 바인딩 시도하려다가
포트 충돌하고, 별 삽질 다 함.

**문제**: 이 추론은 그럴듯한데 **메모리 노트가 명시적으로 반박**하고 있었다:

> "Plaintext UDP works — ESP/IPsec is not required. You can use any source
> port."

A31의 커널은 P-CSCF IP에서 오는 건 평문이어도 통과시킨다. ESP 매칭할 필요 없다.

**교훈**: 기록된 검증 결과가 있으면 그걸 먼저 믿어야 한다. 이론에 끌려가지
말기.

### 실패 ④: 목적지 포트를 port_ps로 잘못 설정

"MT INVITE니까 server port로 보내야겠지"라고 생각해서
`mt_target.port = port_ps`로 수정.

**근거 확인**: 서버의 `/tmp/send_mt_invite.py` (수동으로 성공했던 원본 스크립트):

```python
sock.sendto(payload, (UE_IP, UE_PORT_PC))   # ← port_pc로 보냄
```

**이유**: A31이 REGISTER 때 자기 Contact에 port_pc를 박아서 올리고, 이후 받는
요청은 그 port_pc에서 listen한다. port_ps는 A31이 **내보낼 때** 쓰는 포트.
요청은 port_pc, 응답은 port_ps에서 나옴 (그렇지만 Via 따라가므로 bind 포트로
돌아옴).

**고침**: `port_pc`로 되돌림. 이때부터 A31이 실제로 벨을 울렸다.

---

## 4. 벨 울림 확인 — 그런데 fuzzer는 "timeout"?

위 4개 다 고치고 나서:

- A31 화면에 **수신 UI 뜸** ✓
- 사용자가 직접 확인: **"된다"**
- 근데 fuzzer 결과: `timeout (6073ms)` ✗

### 원인: Via sent-by ↔ 실제 소켓 포트 불일치

SIP 프로토콜 규칙: 서버는 응답을 요청의 **Via 헤더에 적힌 sent-by 포트**로
돌려준다.

내가 보낸 INVITE:

```
Via: SIP/2.0/UDP 172.22.0.21:5100;branch=...
                              ^^^^
                              "응답은 여기로 줘"
```

드라이버 스크립트:

```python
sock.bind((bind_host, 0))  # 0 = 아무 랜덤 포트
```

결과:

- 실제 UDP source port: 47321 (예)
- Via에 적힌 포트: 5100
- A31 응답: **5100번으로 전송**
- 내 소켓(47321)은 못 받음 → `recvfrom` 타임아웃

패킷은 정상 도달 → 벨 울림 ✓
응답만 엉뚱한 포트로 감 → 수신 실패 ✗

---

## 5. 최종 해결 — 3자 동기화

**Via 헤더 포트 = 드라이버 bind 포트 = `preserve_via=True`**

세 개가 한 값으로 일치해야 한다.

### 코드 레벨 변화

```python
# 1. 드라이버 스크립트에 bind_port argv 추가
sock.bind((bind_host, bind_port))  # 0이 아니면 특정 포트에 명시 바인딩

# 2. TargetEndpoint에 bind_port 필드 추가
target = TargetEndpoint(..., bind_container="pcscf", bind_port=15100)

# 3. 템플릿 slots의 local_port도 같은 값
slots = build_default_slots(..., local_port=15100)

# 4. preserve_via=True로 normalize 단계에서 Via 건드리지 않음
artifact = SendArtifact(wire_text=..., preserve_via=True, preserve_contact=True)
```

이러면:

1. 템플릿 Via에 `172.22.0.21:15100`이 박힘
2. `preserve_via=True`라 fuzzer가 덮어쓰지 않음
3. 드라이버가 소켓을 15100에 명시 바인딩
4. A31이 15100으로 응답 → 같은 소켓에서 `recvfrom` → 수집 성공

### 검증 결과

```
[1/1] INVITE wire/identity seed=0 → normal (180, 10206ms)
[vmf campaign] completed: total=1 normal=1 suspicious=0 timeout=0 crash=0 stack_failure=0
```

- A31 벨 울림 ✓
- 180 Ringing 수신 ✓
- oracle `normal` 판정 ✓

---

## 6. 핵심 인사이트 3개

### ① ESP는 "할 수 있으면 하는 것", 꼭 필요한 건 아니었다

IMS 표준 레이어에서 보면 IPsec이 필수처럼 보이지만, **실제 단말 구현**은
P-CSCF IP만 맞으면 평문도 받는다. 표준과 구현의 간극.

### ② "패킷 도달"과 "응답 수신"은 다른 문제

벨이 울린다 ≠ 응답이 우리 프로세스에 돌아온다. SIP의 Via 메커니즘 때문에
응답 경로는 요청 경로와 다른 소켓으로 갈 수 있다. **양방향 테스트**가 필수.

### ③ 한 번 작동했던 실측 데이터는 이론보다 우선한다

메모리에 "plaintext UDP works"라고 분명히 적혀 있었는데도 ESP 이론에
끌려가서 시간 버렸다. **기록된 검증 결과 먼저 신뢰**, 이론은 그걸 설명하는
용도로만 써야 함.

---

## 7. 지금의 흐름 한 장 요약

```
fuzzer CLI: --mt-local-port 15100
  │
  ├─ slots.local_port = 15100           ← 템플릿 Via sent-by
  │    rendered INVITE의 "Via: SIP/2.0/UDP 172.22.0.21:15100"
  │
  ├─ target.bind_port = 15100           ← 드라이버 bind
  │    sock.bind(("172.22.0.21", 15100))
  │
  └─ artifact.preserve_via = True       ← normalize 단계 Via 건드리지 말기
       (preserve_contact=True도 함께)

송신:
  pcscf 컨테이너 netns 안
    sock.bind(("172.22.0.21", 15100))  ← 소스 IP 통과 조건 1
    sock.sendto(wire, ("10.20.20.8", 8100))  ← port_pc로 송신 (조건 3)
         │
         │  br-volte → UPF → GTP → A31
         │  (평문 UDP, 조건 4; Docker 내부망이라 fragmentation OK, 조건 5)
         ▼
    A31 커널: source IP 172.22.0.21 → 통과
    A31 IMS 앱: P-CSCF 화이트리스트 → 통과 (조건 1)
    A31 SIP 파서: 3GPP 풀 포맷 → 통과 (조건 2)
    A31 UI: 수신 화면 + 벨

수신:
    A31 → 172.22.0.21:15100 (Via sent-by 그대로)
         │
         ▼
    pcscf 컨테이너 → sock.recvfrom()
         │
         ▼
    SocketObservation(100 Trying), SocketObservation(180 Ringing)
         │
         ▼
    Oracle: verdict = "normal"
```

**조건 1~5가 전부 성립 + Via/bind/preserve 3자 동기화 = A31 벨 울림 + 응답
수신 + oracle normal 판정.**

---

## 8. 관련 문서

- `docs/이슈/A31-real-ue-direct-INVITE-성공-기록.md` — 2026-04-11 최초 수동
  검증 기록 (성공 조건 5가지 원문)
- `docs/이슈/A31-real-ue-direct-운영-지침.md` — 운영자 관점 체크리스트 +
  서버 환경 + 실행 명령
- `worklog_20260411.md` — phase-1 → phase-1.5 전체 작업 로그 (커밋 3개 포함)
- `memory/project_a31_real_ue_direct_breakthrough.md` — Claude 자동 메모리
  (영어 원문)
