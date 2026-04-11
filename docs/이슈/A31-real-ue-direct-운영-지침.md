# A31 real-ue-direct 운영 지침

> 이 문서는 Claude 자동 메모리(`memory/project_a31_real_ue_direct_breakthrough.md`,
> `memory/reference_fuzzer_server.md`)의 핵심 내용을 한국어로 번역·정리한 것이다.
> 원본은 영어로 저장되어 있으며, 여기서는 재현과 운영에 필요한 부분만 추렸다.
>
> 마지막 검증: **2026-04-11** (end-to-end, identity 케이스 → A31 실기기 벨 울림 +
> `normal (180)` verdict).

---

## 1. 개요

Samsung Galaxy A31(MSISDN `111111`)은 fuzzer가 보낸 MT-INVITE에 대해
**다음 조건이 전부 충족될 때에만** 실제로 수신 UI를 표시하고 벨을 울린다
(180 Ringing 응답 + incoming-call 화면).

조건이 하나라도 어긋나면 다음 중 하나의 증상을 보인다:

- 100 Trying만 돌아오고 수신 화면 없음 (source IP 오류)
- 400 Parsing Failed (헤더/SDP 포맷 불일치)
- 아예 무응답 (source IP + 앱 레이어 드롭)
- 벨은 울리지만 fuzzer는 timeout으로 판정 (Via 포트 미일치)

---

## 2. 성공 조건 5가지

### 2-1. Source IP = **172.22.0.21** (등록된 P-CSCF IP)

A31의 IMS 애플리케이션 레이어는 등록 시점에 사용된 P-CSCF의 IP를 **화이트리스트**
한다. 그 외 IP에서 오는 INVITE는 SIP 트랜잭션 레이어가 100 Trying을 자동 응답할
수는 있어도 **앱 레이어에서 조용히 버린다** (수신 UI 없음).

- 호스트에서 직접 송신 → 드롭
- pcscf 컨테이너의 기본 인터페이스 IP(가상 브리지 IP 등) → 드롭
- **pcscf 컨테이너의 네트워크 네임스페이스 안에서 송신 + source IP
  172.22.0.21** → OK

**구현**: `docker exec -i pcscf python3 -c <driver>` 로 컨테이너 안에서 소켓을
연다. 커널이 자동으로 172.22.0.21을 source로 선택한다.

### 2-2. 3GPP MT-INVITE 완전 포맷 (post-`ipsec_forward`)

최소한의 손수 작성한 INVITE는 A31이 `400 Parsing Failed`를 반환하거나 무시한다.
**실제 capture된 MT-INVITE를 그대로 replay하는 형태**여야 한다.

필수 헤더:

- `Record-Route` × 3 (다중 홉 경로)
- `From` (tag 포함)
- `To: "<msisdn>"<tel:<msisdn>;phone-context=ims.mnc001.mcc001.3gppnetwork.org>`
- `Contact` — originating UE의 `alias=...`, `+sip.instance`, `+g.3gpp.icsi-ref`,
  `audio`, `video` 등 feature tag 전부
- `P-Asserted-Identity`
- `P-Access-Network-Info` (3GPP-E-UTRAN-FDD + cell ID)
- `P-Charging-Vector` (icid-value + icid-generated-at)
- `P-Visited-Network-ID`
- `P-Preferred-Service` (ims.icsi.mmtel)
- `P-Early-Media: supported`
- `Supported: ..., precondition, sec-agree, ...`

필수 SDP 본문:

- AMR/AMR-WB 6개 코덱 (107 AMR-WB, 106 AMR-WB octet-align, 105/104 AMR,
  101/102 telephone-event)
- `a=curr:qos local none`, `a=curr:qos remote none`
- `a=des:qos mandatory local sendrecv`, `a=des:qos optional remote sendrecv`
- `a=ptime:20`, `a=maxptime:240`, `a=rtcp:<port>`

### 2-3. Request-URI 포맷

```
sip:<IMPI>@10.20.20.8:<port_pc>;alias=10.20.20.8~<port_ps>~1
```

- 테스트 가입자 IMPI: `001010000123511`
- `port_pc` / `port_ps`는 **재등록마다 순환**한다. 검증된 값: 7900/7901,
  8000/8001, 8100/8101 (모두 서로 다른 세션에서 관측)
- **sendto 목적지 포트는 `port_pc`이며 `port_ps`가 아니다** — 서버의
  `/tmp/send_mt_invite.py`가 `sendto(..., (UE_IP, UE_PORT_PC))`로 송신하는 것으로
  확정

#### 현재 port_pc 조회 방법 (live)

**방법 1**: Kamailio 로그
```bash
docker logs pcscf --since 5m | grep 'Term UE connection'
```
`Term UE connection information : IP is ... and Port is N`의 `N`이 port_pc다.

**방법 2**: xfrm state
```bash
docker exec pcscf ip xfrm state
```
A31(10.20.20.8) → pcscf(172.22.0.21) 방향 SA들의 `sel ... sport N dport M` 라인
에서 **sport 중 최솟값 = port_pc**, `port_pc + 1 = port_ps`.

A31→pcscf SA가 2개 존재하고 각각 sport=port_pc, sport=port_ps다. `min()`으로
port_pc를 특정한다.

### 2-4. 평문 UDP로 충분 (ESP/IPsec 불필요)

직관과 달리, pcscf 컨테이너의 xfrm policy가 포트 `5102/6102`(port_cc/port_cs)에만
ESP를 적용하도록 설정되어 있지만, **A31의 커널 XFRM은 신뢰 P-CSCF IP에서 온
트래픽에 대해 ESP를 엄격하게 요구하지 않는다**. 따라서:

- 아무 source 포트나 사용 가능
- xfrm policy 매칭 시도 불필요 (삽질 주의)
- `docker exec pcscf python3 ...` 내부에서 SIP를 평문 UDP로 그냥 보내면 된다

### 2-5. IP 단편화는 over-the-air LTE 경로에서만 치명적

전체 UDP payload가 MTU를 초과할 때:

- **실제 LTE 무선 구간**: 평문 UDP 단편은 UE 커널 SIP 파서가 첫 조각만 보고
  `400 Parsing Failed`로 응답. ESP 캡슐화된 경우는 커널이 재조립 후 복호화
  하기 때문에 괜찮음.
- **Docker `br-volte` 브리지 내부**: IP 단편화 재조립이 정상 동작하므로 안전.
  fuzzer가 `bind_container`를 쓸 때는 패킷이 컨테이너 간 브리지만 타므로
  단편화 제한이 필요 없다.

따라서 fuzzer의 host-level fragmentation guard는 `bind_container is None`인
경우에만 적용되어야 한다 (`campaign/core.py`에 이미 반영됨).

---

## 3. Via sent-by ↔ 드라이버 bind 포트 동기화

이건 phase-1.5에서 뒤늦게 발견한 **"벨은 울리지만 fuzzer는 timeout"** 증상의
원인이다.

### 증상

1. 드라이버가 `sock.bind((bind_host, 0))`로 **랜덤 포트** 바인딩
2. 템플릿의 Via 헤더는 `SIP/2.0/UDP 172.22.0.21:15100`처럼 **고정 포트** 박음
3. A31은 INVITE를 받고 벨을 울림 ✓
4. A31이 100 Trying / 180 Ringing을 **Via의 sent-by 포트(15100)**로 돌려보냄
5. 드라이버 소켓은 랜덤 포트에 있으므로 응답을 못 받음
6. `recvfrom` 타임아웃 → fuzzer verdict `timeout`

### 해결

세 가지 값이 **한 포트로 일치**해야 한다:

1. 템플릿 Via의 sent-by 포트 (`slots.local_port`)
2. 드라이버 UDP/TCP 소켓의 실제 bind 포트
3. `artifact.preserve_via = True` — normalize 단계에서 Via 건드리지 않음

fuzzer 구현은 `CampaignConfig.mt_local_port`(기본 15100)를 위 세 값 전부에
동일하게 주입한다. CLI에서는 `--mt-local-port <N>`으로 변경 가능하며, 포트가
다른 프로세스와 충돌하면 다른 high port를 지정하면 된다.

---

## 4. 검증된 실행 명령 (phase-1 baseline)

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct --transport UDP \
  --target-host 10.20.20.8 --target-msisdn 111111 \
  --impi 001010000123511 \
  --methods INVITE --layer wire --strategy identity \
  --mt-invite-template a31 --bind-container pcscf \
  --preserve-contact --preserve-via \
  --mt-local-port 15100 \
  --max-cases 1 --timeout 10 --no-process-check
```

**기대 결과**:

```
[1/1] INVITE wire/identity seed=0 → normal (180, 10206ms)
[vmf campaign] completed: total=1 normal=1 suspicious=0 timeout=0 crash=0 stack_failure=0
```

- A31 화면에 수신 UI 표시 + 벨 울림
- 100 Trying / 180 Ringing이 수집되어 oracle이 `normal` 판정
- verdict normal=1, 나머지 0

---

## 5. 서버 환경 레퍼런스

### 5-1. 접속

- SSH: `ssh ubuntu@163.180.185.51` (SSH alias 없음, 원 호스트네임 직접 사용)
- sudo는 인터랙티브 비밀번호 필요. 웬만하면 `docker exec` 우선 (`sudo nsenter`
  대신)
- fuzzer 체크아웃: `/home/ubuntu/Desktop/fuzzer/` (노트북 리포와 `rsync`로 동기화
  유지)
- entry point: `.venv/bin/fuzzer`

### 5-2. `br-volte` Docker 네트워크 (`172.22.0.0/16`)

- `pcscf` — Kamailio P-CSCF, IP `172.22.0.21`. `python3` / `tcpdump` 설치됨.
  A31 IPsec XFRM SA가 이 netns에 존재한다 (`docker exec pcscf ip xfrm state`).
  5100/5101/5102/6102 포트가 Kamailio에 점유됨.
- `scscf` — `172.22.0.20`, 포트 6060 UDP/TCP
- `icscf` — `172.22.0.19`
- `hss` / `mongo` — Open5GS HSS + MongoDB
- `pyhss` — IMS용 PyHSS. REST API `http://localhost:8080/docs/`

### 5-3. UE 라우팅

- 호스트 라우트: `10.20.20.0/24 via 172.22.0.8 dev br-volte`
- br-volte의 컨테이너 → `10.20.20.x` 트래픽은 자동으로 UPF(`172.22.0.8`) 경유 →
  GTP → 실제 UE 순으로 흐른다.

### 5-4. 단말 / 가입자

- **Samsung A31**: MSISDN `111111`, IMPI `001010000123511`, UE IP `10.20.20.8`
  - `port_pc` / `port_ps`는 재등록마다 순환. 현재값은 pcscf 로그 또는 xfrm state
    로부터 조회.
- **Test MO 소프트폰**: MSISDN `222222`, 호스트 `10.20.20.9` (포트 예: 31800/31100,
  A31과 마찬가지로 순환)

---

## 6. 커밋 히스토리 요약

| 커밋 | 요약 |
|---|---|
| `062d7f3` | MT INVITE 템플릿 퍼징 파이프라인 초안 (13 files, 1227+ insertions) |
| `a8afff4` | xfrm 파서 수정 + port_pc 목적지 복구 + bind_container frag guard bypass |
| `6b0695f` | Via sent-by ↔ 드라이버 bind port 동기화, `--mt-local-port` 옵션 |

---

## 7. phase-2 (변이 퍼징) 예시 명령

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct --transport UDP \
  --target-host 10.20.20.8 --target-msisdn 111111 \
  --impi 001010000123511 \
  --methods INVITE --layer wire,byte --strategy identity,default \
  --mt-invite-template a31 --bind-container pcscf \
  --preserve-contact --preserve-via --mt-local-port 15100 \
  --max-cases 10 --timeout 10 --no-process-check \
  --pcap --pcap-interface br-volte --pcap-dir results/a31/pcap \
  --adb --adb-serial <A31 serial>
```

- case 0 (`identity`)은 매번 A31 벨 울림 + `normal (180)` baseline
- 후속 케이스는 wire/byte 변이 혼합, verdict 분포 관찰
- `crash` / `stack_failure` 발생 시 adb snapshot 자동 덤프
- `br-volte` 인터페이스 pcap으로 컨테이너 내부 송수신까지 전체 기록

---

## 8. 관련 파일

### 핵심 소스

- `src/volte_mutation_fuzzer/generator/templates/mt_invite_a31.sip.tmpl`
- `src/volte_mutation_fuzzer/generator/real_ue_mt_template.py`
- `src/volte_mutation_fuzzer/sender/container_exec.py`
- `src/volte_mutation_fuzzer/sender/real_ue.py`
- `src/volte_mutation_fuzzer/sender/core.py` (`_send_via_container`)
- `src/volte_mutation_fuzzer/sender/contracts.py` (`TargetEndpoint.bind_container`,
  `bind_port`, `SendArtifact.preserve_via/contact`)
- `src/volte_mutation_fuzzer/campaign/core.py` (`_execute_mt_template_case`)
- `src/volte_mutation_fuzzer/campaign/contracts.py`, `campaign/cli.py`
- `src/volte_mutation_fuzzer/mutator/editable.py` (`parse_editable_from_wire`)
- `src/volte_mutation_fuzzer/mutator/core.py` (`mutate_editable`)

### 서버 측 참고

- `/tmp/send_mt_invite.py` — 수동 검증에 사용한 원본 replay 스크립트. 템플릿이
  바이트 단위로 여기에 대응된다 (randomize된 branch/ftag/Call-ID/icid 제외).

### 관련 문서

- `docs/이슈/A31-real-ue-direct-INVITE-성공-기록.md` — 2026-04-11 수동 검증
  최초 기록 (5가지 성공 조건 원문)
- `worklog_20260411.md` — phase-1 → phase-1.5 전체 작업 로그
