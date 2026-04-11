# A31 real-ue-direct MT INVITE 전달 성공 기록

**작성일**: 2026-04-11
**검증 대상**: Samsung Galaxy A31 (MSISDN `111111`, IMPI `001010000123511`)
**목표**: fuzzer가 `real-ue-direct` 모드로 보낸 INVITE로 실 단말을 실제로 울리게 만들기 (180 Ringing + 수신 화면)

---

## 요약 (TL;DR)

fuzzer가 호스트 네임스페이스에서 보낸 INVITE는 Samsung A31에서 IMS 애플리케이션 레이어가 조용히 버렸다. 해결은 다음 세 가지의 **동시 충족**이었다.

1. **Source IP를 P-CSCF 컨테이너(172.22.0.21)로 맞춘다** — `docker exec pcscf python3 ...` 로 P-CSCF 네트워크 네임스페이스 안에서 송신.
2. **진짜 MT INVITE 와이어 포맷을 그대로 복제한다** — Wireshark로 떠 둔 ICSCF→SCSCF 구간 INVITE를 기반으로, 모든 Record-Route / P-*/Contact/SDP 헤더를 유지하고 Request-URI만 `ipsec_forward()` 이후 형태로 바꿨다.
3. **IP 단편화를 피한다** — 평문 UDP에서는 단편화된 두 번째 조각이 단말 SIP 파서에 들어가지 못한다. 사이즈가 한 조각에 들어가거나 TCP를 써야 한다.

이 셋을 모두 맞춘 뒤에는 **평문 UDP**로도 A31이 정상적으로 180 Ringing을 내고 수신 화면을 오래 띄웠고, 사용자가 수동으로 Decline 해서 대화가 종료됐다.

---

## 1. 무엇이 안 됐었나

그 전까지의 상황:

| 시나리오                                                   | 결과                    |
| ---------------------------------------------------------- | ----------------------- |
| fuzzer(호스트) → UPF → GTP → A31, 퍼저 생성 INVITE, UDP    | `100 Trying` 만 옴      |
| 동일, TCP                                                  | A31이 TCP 연결 바로 종료 |
| nsenter로 P-CSCF netns, 퍼저 생성 INVITE (작은 템플릿), UDP | `400 Parsing Failed`    |
| nsenter로 P-CSCF netns, 실제 호 포맷, 평문 UDP              | **180 Ringing + 수신 화면** |

`100 Trying`만 오는 상황이 가장 헷갈렸는데, 이는 A31의 SIP **트랜잭션 레이어**가 단순히 “INVITE가 보호 포트(`port_pc`)에 도착했으므로 100 Trying 자동 응답”까지만 처리하고, IMS **애플리케이션 레이어**(ImsService)가 그 뒤에서 조용히 버리고 있던 것이었다. logcat에는 INVITE 수신에 대한 어떤 로그도 남지 않았다.

---

## 2. 핵심 발견 세 가지

### 2.1 Samsung IMS는 source IP 화이트리스트를 돌린다

A31의 ImsService는 자신이 IMS 등록 시 학습한 **P-CSCF IP (172.22.0.21)** 에서 오지 않은 INVITE를 애플리케이션 레이어에서 드롭한다.

- 커널 XFRM은 평문도 (현재 등록에서) 통과시킨다 → `100 Trying`까지는 나간다.
- 그 위 IMS 앱 레이어가 `source IP == registered P-CSCF IP` 검사를 해서 불일치면 silent drop.
- 그래서 host 네임스페이스에서 `172.22.0.1`/`172.22.0.8` 등으로 보내면 단말 화면에는 아무것도 뜨지 않는다.

**대응**: P-CSCF 컨테이너의 네트워크 네임스페이스 안에서 송신하면 커널이 기본 라우트를 따라 자연스럽게 `172.22.0.21`을 source IP로 채운다.

```bash
# 비밀번호 없이 동작 (docker 그룹 기준)
docker exec pcscf python3 /tmp/send_mt_invite.py

# 또는 sudo가 열려 있다면
PID=$(docker inspect --format '{{.State.Pid}}' pcscf)
sudo nsenter -t "$PID" -n python3 /tmp/send_mt_invite.py
```

### 2.2 Samsung IMS는 “실제 호 포맷”을 꽤 엄격하게 검증한다

처음엔 source IP만 고치면 될 줄 알았지만, 그렇게 해도 fuzzer가 만든 **짧은 INVITE 템플릿**은 `400 Parsing Failed`로 거절당했다. (A31이 실제로 응답을 생성해서 보낸 점에서, source IP 필터는 이미 뚫린 상태였다.)

Wireshark로 실제 호 한 번(br-volte의 ICSCF→SCSCF 구간)을 떠서 비교하니, 실제 MT INVITE는 다음을 모두 포함하고 있었다:

- 3개의 `Record-Route` (mo@SCSCF UDP/TCP, mo@P-CSCF)
- `From: <sip:222222@ims.mnc001.mcc001.3gppnetwork.org>;tag=...`
- `To: "111111"<tel:111111;phone-context=ims.mnc001.mcc001.3gppnetwork.org>`
- `Contact:` 원본 MO UE 값 (`alias=...`, `+sip.instance="<urn:gsma:imei:...>"`, `+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"`, `audio;video;+g.3gpp.mid-call;+g.3gpp.srvcc-alerting;+g.3gpp.ps2cs-srvcc-orig-pre-alerting`)
- `Accept-Contact`, `P-Access-Network-Info`, `P-Preferred-Service`, `P-Early-Media`, `P-Charging-Vector`, `P-Visited-Network-ID`, `P-Asserted-Identity`
- `Supported: 100rel,histinfo,join,norefersub,precondition,replaces,timer,sec-agree`
- AMR-WB / AMR 코덱 전부 포함한 SDP (`curr:qos`, `des:qos` precondition 포함)

이 중 어느 하나라도 빠지면 단말이 “수신 가능한 호”로 판정하지 않는다는 가설을 세우고, 실제 캡처를 최대한 보존한 채 `Request-URI`만 P-CSCF `ipsec_forward()` 이후의 값(`sip:001010000123511@10.20.20.8:8000;alias=10.20.20.8~8001~1`)으로 치환했다.

**결과**: 최초 시도부터 성공.

### 2.3 평문 UDP에서는 IP 단편화가 치명적

실제 호의 MT INVITE는 2812 바이트(IP 단편 2개)였는데 정상 동작했다. 이유는 ESP 캡슐화 덕이다: 암호문이 IP 레이어에서 단편화되어 나가더라도 A31 커널이 단편을 **먼저 재조립**한 뒤 복호화하고, 평문 SIP는 한 덩어리로 SIP 스택에 들어간다.

반면 우리가 평문 UDP로 같은 크기를 그냥 보내면, 단말 쪽에서 IP 재조립은 되더라도 (혹은 안 되고) SIP 파서가 첫 단편만 보고 `400 Parsing Failed`를 낸다는 사실을 실험으로 확인했다. (이전 시도에서 1649바이트 INVITE가 두 조각으로 단편화되면서 `400 Parsing Failed` 반복.)

**대응**:
- 평문 UDP 경로에서는 페이로드를 GTP 조정 MTU 이하로 유지한다.
- 또는 TCP를 쓴다 (A31은 `port_pc` 상 TCP도 받아준다 — source IP가 맞을 때).
- 오늘 성공한 replay는 SDP를 유지했지만 헤더 최적화로 한 조각에 들어갔다.

---

## 3. 실제 검증 흐름

### 3.1 실제 호 1회 캡처

사용자가 실제 소프트폰(222222, 10.20.20.9)에서 A31(111111)로 한 번 발신 → Wireshark로 `br-volte` 인터페이스 떴음. ICSCF→SCSCF 구간의 INVITE가 평문이라 이 구간을 기준 템플릿으로 사용.

해당 캡처에서 뽑은 핵심 값:
- From tag: `JJkcbHB`
- Call-ID: `IIkcbHBhJ@10.20.20.9`
- Contact: `<sip:222222@10.20.20.9:31800;alias=10.20.20.9~31100~1>;...`
- P-Charging-Vector icid: `495653AC1600155B000000D101000000`
- SDP owner: `rue 3251 3251 IN IP4 172.22.0.16`, 오디오 포트 49196

### 3.2 A31 현재 보호 포트 조회

`port_pc`/`port_ps`는 재등록 때마다 바뀌므로 송신 직전에 확인했다.

```bash
docker logs pcscf --since 5m | grep 'Term UE connection'
# 결과: "Term UE connection information : IP is 10.20.20.8 and Port is 8000"
docker exec pcscf ip xfrm state | grep -A1 '10.20.20.8'
# 결과: sport 5102 dport 8000 등 — port_pc=8000, port_ps=8001 확인
```

### 3.3 Request-URI 치환

Kamailio의 `ipsec_forward()`가 내부적으로 쓰는 포맷을 그대로 복제.

```
INVITE sip:001010000123511@10.20.20.8:8000;alias=10.20.20.8~8001~1 SIP/2.0
```

### 3.4 실행 스크립트

스크립트 `/tmp/send_mt_invite.py`를 P-CSCF 컨테이너에 `docker cp`로 넣고 `docker exec pcscf python3`로 실행. 핵심은:

- `socket.bind(("172.22.0.21", 0))` — 컨테이너 네임스페이스 안에 있으므로 이 IP가 실제로 잡힌다.
- `sock.sendto(payload, ("10.20.20.8", 8000))` — 평문 UDP.
- `recvfrom` 루프로 100 Trying/180 Ringing을 수신.

헤더·SDP 전문은 메모리 항목(`project_a31_real_ue_direct_breakthrough.md`)에 명시된 목록을 그대로 쓴다.

### 3.5 결과

- A31 화면에 수신 UI가 뜨고 벨이 울림.
- Wireshark에 `180 Ringing` 응답 정상 수신.
- 상당 시간 울린 뒤 사용자가 Decline.

---

## 4. 왜 그동안 안 됐는가 — 오해 목록

- **“fuzzer 쪽 UDP recvfrom 코드가 깨진 거 아닌가”** → 맞았고 먼저 고쳤다 (`src/volte_mutation_fuzzer/sender/core.py`의 UDP 경로를 `connect()`가 아닌 unconnected `bind()+sendto()/recvfrom()`으로 전환). 이 수정이 없었다면 A31이 `port_ps`에서 보내는 응답을 커널이 드롭했다. 그러나 이것만으로는 호가 울리지 않았다.
- **“IPsec ESP가 필수일 것”** → 지금 등록된 SA의 XFRM 정책이 매우 타이트(출발지 포트 5102)라 퍼저 포트와 매칭되지 않지만, 그래도 평문이 A31에서 받아들여졌다. A31 쪽 XFRM이 INPUT 방향을 엄격히 강제하지 않는 상태였고, 덕분에 source IP만 맞으면 평문이 IMS 앱에 도달했다.
- **“단편화는 단말이 알아서 재조립할 것”** → 평문 경로에서는 결과적으로 `400 Parsing Failed`로 관측됨. ESP 경로와 달리 SIP 파서까지 완전한 메시지가 전달되지 않는다.
- **“헤더는 최소 집합만 있으면 SIP 파서가 통과시킬 것”** → 파서는 통과해도 Samsung IMS 앱 레이어가 “수신 가능한 MT 호” 판정을 위해 P-*, Record-Route, Contact feature tags 등을 본다. 최소 셋은 부족했다.

---

## 5. fuzzer에 반영할 과제 (다음 스텝)

1. **Wire-text MT template**
   오늘 성공한 replay 스크립트의 INVITE 본문을 fuzzer의 real-ue-direct MT 템플릿으로 승격. 변수 슬롯: Call-ID, From-tag, `port_pc`/`port_ps`, MO Contact alias, PANI, ICID, SDP owner/IP.
2. **Port 자동 조회**
   `src/volte_mutation_fuzzer/sender/real_ue.py`의 real-ue resolver를 확장해 송신 직전 `docker logs pcscf` 또는 `ip xfrm state`를 파싱해서 현재 `port_pc`/`port_ps`를 얻는다.
3. **P-CSCF netns 경유 송신**
   real-ue-direct 모드에 `--via-netns pcscf` 옵션(또는 기본 동작으로) 추가. 내부적으로 `docker exec pcscf ...`로 재진입하거나, 퍼저를 `pcscf` 네임스페이스에서 항상 기동.
4. **단편화 가드**
   평문 UDP 경로에서 페이로드가 GTP MTU를 넘을 때 자동으로 TCP로 폴백하거나 명시적 에러.
5. **Campaign 통합**
   dialog orchestrator가 MT INVITE를 만들 때 위 템플릿을 사용하도록 연결.

---

## 6. 재현 체크리스트

```text
[ ] A31이 IMS 등록 상태인지 확인 (docker logs pcscf | grep REGISTER)
[ ] 현재 port_pc/port_ps 확인 (docker logs pcscf --since 5m | grep 'Term UE connection')
[ ] Request-URI의 port 값을 이에 맞게 갱신
[ ] Call-ID, From tag, branch를 신규 값으로
[ ] 페이로드 크기가 MTU 한 조각 이내인지 확인
[ ] docker exec pcscf python3 /tmp/send_mt_invite.py
[ ] 단말 화면에 수신 UI, Wireshark에서 180 Ringing 확인
```

---

## 참고

- 관련 memory 항목: `project_a31_real_ue_direct_breakthrough.md`, `reference_fuzzer_server.md`
- 변경된 sender 코드: `src/volte_mutation_fuzzer/sender/core.py` (UDP recvfrom 경로)
- 서버 스크립트: `ubuntu@163.180.185.51:/tmp/send_mt_invite.py`

---
     ---
     Follow-ups (phase 2, 이 PR에서 다루지 않음)

     - ACK/BYE/re-INVITE 다이얼로그 경로에서도 MT template replay 가능하게
     DialogOrchestrator 확장.
     - port_pc/port_ps rotation을 감지해서 중간 campaign 중 자동 re-sync.
     - A31 외 다른 단말용 MT template 추가 (mt_invite_<model>.sip.tmpl).
     - resolve_ue_protected_ports가 multi-UE 환경에서 IMPI 기반으로 올바르게
     필터링하도록 확장 (현재는 가장 최근 Term UE connection 로그를 그냥 사용).

