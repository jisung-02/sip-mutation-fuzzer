# Phase 4 Sender/Reactor 사전 리서치

기준 일자: 2026-03-18

## 1. 문서 목적
이 문서는 **Phase 4(Sender/Reactor) 구현 계획 이전에 필요한 조사 결과**를 정리한 것이다.

이번 문서는 구현 계획서가 아니다.
먼저 현재 코드베이스, 기존 연구실 망 실험 자산, 웹 기반 공식 문서를 바탕으로 **가능한 구현 방법들을 넓게 조사**하고, 각 방법의 장단점과 현실성을 비교하는 데 목적이 있다.

대상 완료 기준은 다음과 같다.

- 단일 테스트 케이스 전송이 가능하다.
- 응답/타임아웃/실패가 구분되어 기록된다.
- 요청과 응답의 상관관계를 추적할 수 있다.

## 2. 조사 방법과 신뢰도 표기
### 2.1 조사 방법
- 현재 저장소 코드와 문서를 직접 읽어 현재 Phase 1~3 산출물과 제약을 확인했다.
- 사용자가 제공한 이전 연구실 프로젝트 `/Users/chaejisung/Desktop/Project/fuzzer(capstone)`의 코드와 문서를 직접 읽어, 실제 Kamailio/Open5GS 기반 실험 경로를 확인했다.
- Kamailio, Open5GS, SIPp, PJSIP, RFC 문서를 웹으로 검색하고 공식/원문 위주로 확인했다.

### 2.2 신뢰도 표기
- `로컬 확인`: 현재 저장소 또는 이전 프로젝트의 실제 파일을 읽고 확인한 내용
- `공식 문서 확인`: 공식 사이트/공식 문서/RFC에서 확인한 내용
- `추론`: 위 두 근거를 바탕으로 한 설계 추론. 문서 안에서 명시적으로 구분한다.

## 3. 현재 코드베이스 파악
### 3.1 현재 구현 상태
`로컬 확인`

현재 저장소는 사실상 Phase 1~3까지만 구현되어 있다.

- `sip/`
  - SIP 공통 타입
  - request/response Pydantic 모델
  - catalog / schema
- `generator/`
  - 정상 baseline packet 생성
  - `DialogContext`, `RequestSpec`, `ResponseSpec`
- `mutator/`
  - `MutationConfig`, `MutationTarget`, `MutationRecord`, `MutatedCase`
  - model / wire / byte 변조
- 아직 없는 것
  - `sender/`
  - `reactor/`
  - `oracle/`
  - `controller/`

즉 Phase 4는 현재 코드베이스에 없는 **새 계층**이다.

### 3.2 Sender/Reactor가 현재 코드에서 받아야 하는 입력
`로컬 확인`

현재 Sender/Reactor가 받아야 할 입력 후보는 사실상 아래 둘이다.

1. `Generator` 출력
   - 정상 Pydantic `SIPRequest` / `SIPResponse`
2. `Mutator` 출력
   - `MutatedCase`
   - 내부 결과는 `mutated_packet`, `wire_text`, `packet_bytes` 중 하나 이상

따라서 Phase 4는 단순히 “문자열을 보낸다”가 아니라, 아래 세 종류를 모두 고려해야 한다.

- 정상 모델 기반 패킷 전송
- wire 텍스트 기반 비정상 패킷 전송
- raw bytes 기반 비정상 패킷 전송

이 점 때문에 Sender는 **직렬화/전송 책임**, Reactor는 **응답/타임아웃/실패/관찰 책임**으로 나누는 것이 자연스럽다.

### 3.3 현재 코드에서 Phase 4가 추가로 결정해야 하는 것
`로컬 확인`

아직 비어 있는 핵심 결정 포인트는 다음과 같다.

- 어디로 보낼 것인가
  - P-CSCF
  - I/S-CSCF
  - UE IMS IP 직접
- 어떤 transport를 지원할 것인가
  - UDP
  - TCP
  - TLS
- 어떤 artifact를 전송 우선순위로 삼을 것인가
  - `packet_bytes`
  - `wire_text`
  - `mutated_packet`
- 어떤 채널을 Reactor의 “반응”으로 인정할 것인가
  - 같은 소켓의 SIP 응답
  - 별도 SIP sniffer
  - Kamailio siptrace / DB / RPC
  - PCAP
  - ADB/logcat

## 4. 이전 연구실 프로젝트에서 확인한 것
대상 경로:
`/Users/chaejisung/Desktop/Project/fuzzer(capstone)`

### 4.1 실제로 존재했던 큰 구조
`로컬 확인`

이전 프로젝트는 이미 다음 구성을 가지고 있었다.

- Open5GS EPC
- Kamailio IMS
- Docker Compose 기반 IMS/EPC 토폴로지
- `sender.py`: SIP 메시지 송신 + 응답 수신
- `dumpipe.py`: P-CSCF 우회 direct-to-UE 전송
- `ue_lookup.py`: MSISDN -> UE IP/port 조회
- `sip_sniffer.py`: 실시간 SIP 트래픽 감시
- `pcap_capture.py`: tcpdump 기반 PCAP 저장
- `adb_monitor.py`: 단말 로그/메모리/커널 로그 수집

즉, **Phase 4의 실무적 후보 조합이 이미 한 번 구현된 적은 있다.**
다만 구조와 품질은 지금 저장소의 SRP/Phase 1~3 스타일과는 다르다.

### 4.2 이전 `sender.py`가 했던 일
`로컬 확인`

이전 `sender.py`는 꽤 직접적인 Sender였다.

- UDP/TCP 소켓 생성
- SIP 문자열 전송
- 단일 응답 수신
- SIP 응답 파싱
- `SendResult`로 결과 저장

장점:
- 단순하고 바로 동작시킬 수 있다
- Phase 4 완료 기준인 “단일 테스트 케이스 전송”, “응답/타임아웃/실패 구분”을 빠르게 만족시킬 수 있다

한계:
- 현재 저장소의 `MutatedCase` / `wire_text` / `packet_bytes` 구조와 직접 맞물려 있지는 않다
- transaction correlation이 최소 수준이다
- reactor가 “소켓 응답”에 강하게 묶여 있다

### 4.3 이전 `dumpipe.py`가 보여주는 중요한 점
`로컬 확인`

이전 프로젝트는 **P-CSCF를 우회하여 UE IMS IP로 직접 SIP를 보내는 경로**를 이미 실험 대상으로 삼았다.

핵심 아이디어:
- UE가 IMS REGISTER 시 Contact에 자신의 IMS IP/port를 광고한다
- 이를 조회한 뒤
- host에서 UE IMS subnet으로 라우팅을 잡고
- UE에 직접 UDP 전송한다

이 경로의 의미:
- P-CSCF에서 드랍될 malformed packet도 UE까지 보낼 수 있다
- parser robustness / lower-level stack test에 유리하다
- 단말을 더 직접 자극할 수 있다

반면 약점:
- 실제 VoLTE signalling 경로를 완전히 재현하지 않는다
- 상용 UE와 네트워크 구성에 따라 direct delivery가 차단될 수 있다
- UE IP discovery가 별도 문제다

### 4.4 이전 `ue_lookup.py`가 보여주는 중요한 점
`로컬 확인`

이전 프로젝트는 UE IP를 아래 순서로 찾으려 했다.

1. S-CSCF `kamctl ul show`
2. S-CSCF MySQL location 테이블 직접 조회
3. P-CSCF 로그 파싱
4. P-CSCF `kamctl` 폴백

이건 Phase 4에서 아주 중요한 힌트다.

즉, direct-to-UE 경로를 쓰려면 Phase 4는 단순 전송기만 있으면 안 되고, 아래 둘 중 하나가 필요하다.

- `TargetResolver` 계층
- 또는 UE IP를 외부에서 정적으로 넘기는 운영 규칙

### 4.5 이전 `sip_sniffer.py` / `pcap_capture.py` / `adb_monitor.py`가 보여주는 점
`로컬 확인`

Reactor를 소켓 응답 하나로만 보면 부족하다는 점을 보여준다.

- `sip_sniffer.py`
  - 네트워크 상에서 흐르는 SIP request/response 자체를 잡는다
- `pcap_capture.py`
  - 사후 분석 가능한 원본 증거를 남긴다
- `adb_monitor.py`
  - 단말 측 관찰 채널을 제공한다

Phase 4 범위만 보면 ADB는 필수는 아니지만, 적어도 Reactor 설계가 “소켓 응답만 인정”하는 구조로 가면 곧 한계가 온다.

## 5. 웹 조사 결과
## 5.1 Open5GS / Kamailio 기반 실험 환경 현실성
### Open5GS 공식 문서
`공식 문서 확인`

Open5GS 공식 문서는 VoLTE를 지원한다고 명시하고 있고, 최근 문서에는 **Kamailio IMS + Open5GS 기반 VoLTE setup**와 **Dockerized VoLTE setup**가 따로 존재한다.

특히 Dockerized VoLTE 문서에는 다음이 명시되어 있다.

- Docker + Docker Compose 기반 VoLTE study setup
- Sysmocom USIM 사용
- commercial eNB 또는 srsENB 사용 가능
- UE로 Mi 9 Pro 5G, Oneplus 5, iPhone X 이상, Nokia 5.3 등 상용 단말 테스트 기록
- `UE_IPV4_IMS`를 별도로 설정

이건 사용자가 말한 “실제 연구실 망 + 프로그래밍된 SIM + 상용 단말” 조건이 **충분히 현실적인 경로**임을 뒷받침한다.

관련 링크:
- [Open5GS Docs](https://open5gs.org/open5gs/docs/)
- [VoLTE Setup with Kamailio IMS and Open5GS](https://open5gs.org/open5gs/docs/tutorial/02-VoLTE-setup/)
- [Dockerized VoLTE Setup](https://open5gs.org/open5gs/docs/tutorial/03-VoLTE-dockerized/)
- [Open5GS Features](https://open5gs.org/open5gs/features/)

### Open5GS infoAPI
`공식 문서 확인`

Open5GS는 최신 문서 기준으로 `infoAPI`를 제공하며, MME/SMF 쪽에서 UE/session data를 JSON HTTP endpoint로 노출할 수 있다고 문서화하고 있다.

중요한 점:
- LTE UE 정보: `MME /ue-info`
- PDU/PDN info: `SMF /pdu-info`
- APN/DNN, UE activity, PDN state 같은 정보 조회 가능

추론:
- direct-to-UE 경로를 구현할 경우, 예전 프로젝트처럼 `kamctl/MySQL/log scraping`만 고집하지 않고
- **Open5GS infoAPI 기반 UE/session resolution**을 새로운 선택지로 둘 수 있다

주의:
- 공식 문서상 infoAPI는 “latest main branch” 성격이 강하다
- 현재 연구실 환경의 Open5GS 버전에 실제로 있는지 확인이 필요하다

관련 링크:
- [Open5GS JSON infoAPI for accessing UE, gNB/eNB, and session data](https://open5gs.org/open5gs/docs/tutorial/07-infoAPI-UE-gNB-session-data/)

## 5.2 Kamailio를 Sender/Reactor 쪽에 활용할 수 있는 기능
### UAC module
`공식 문서 확인`

Kamailio `uac` 모듈은 config에서 SIP 요청을 생성해서 보낼 수 있고, `uac_req_send()`와 `event_route[uac:reply]`를 제공한다.

문서상 확인되는 점:
- Kamailio config에서 자체적으로 SIP request 전송 가능
- final reply 뿐 아니라 failure/timeout 쪽 event route 처리 가능
- 401/407 인증 시 event route를 두 번 탈 수 있음
- `uac_auth()` 사용 시 CSeq 자동 증가가 안 되므로 dialog/CSeq tracking이 필요할 수 있음

의미:
- P-CSCF 내부 또는 별도 Kamailio helper에서 **Kamailio-embedded Sender/Reactor**를 만들 수 있다
- 특히 “Kamailio가 이미 transaction state를 가지고 있는 상황”을 활용하면 correlation이 쉬워진다

약점:
- malformed `wire_text` / arbitrary `packet_bytes`를 그대로 보내는 쪽에는 불리하다
- Kamailio config 언어/route 안으로 로직이 들어가면 현재 Python 코드베이스와 경계가 무거워진다

관련 링크:
- [Kamailio UAC module](https://www.kamailio.org/docs/modules/stable/modules/uac.html)

### siptrace module
`공식 문서 확인`

Kamailio `siptrace` 모듈은 incoming/outgoing SIP message를 DB에 저장하거나 캡처 서버로 duplicate할 수 있고, transaction/dialog tracing도 가능하다고 문서화되어 있다.

의미:
- Reactor가 직접 응답을 기다리지 않더라도
- Kamailio 레벨에서 **전송 증거와 수신 증거를 별도 trace 채널로 확보**할 수 있다

장점:
- 네트워크를 거친 실제 SIP 흐름을 남기기 좋다
- 나중에 Phase 5 Oracle과도 자연스럽게 연결된다

약점:
- Kamailio를 실제 경로에 태우는 구조일 때 의미가 크다
- direct-to-UE bypass 경로에서는 가치가 작아진다

관련 링크:
- [Kamailio siptrace module](https://www.kamailio.org/docs/modules/stable/modules/siptrace.html)

### ims_usrloc_pcscf / ims_registrar_pcscf
`공식 문서 확인`

Kamailio IMS 문서는 P-CSCF contact 저장을 위한 `ims_usrloc_pcscf`와 P-CSCF registrar 관련 `ims_registrar_pcscf`를 제공한다고 설명한다.
특히 `ims_usrloc_pcscf`는 contact를 저장하는 storage engine이며, `match_contact_host_port` 같은 매칭 옵션을 둔다.

의미:
- UE contact(IP/port) 정보를 Kamailio 쪽에서 얻는 전략은 여전히 유효하다
- direct-to-UE 경로에서 Kamailio usrloc/DB/RPC를 target resolution 채널로 쓸 수 있다

관련 링크:
- [Kamailio ims_usrloc_pcscf module](https://kamailio.org/docs/modules/stable/modules/ims_usrloc_pcscf.html)
- [Kamailio ims_registrar_pcscf module](https://www.kamailio.org/docs/modules/5.7.x/modules/ims_registrar_pcscf.html)

### dialog / tmx / tm
`공식 문서 확인`

Kamailio `dialog` 문서는 dialog state 관리와 CSeq tracking, local generated request header 보강 기능을 제공한다.
`tmx` 문서는 `t_reply_callid(callid, cseq, code, reason)`, `t_suspend()`, `t_continue()` 같은 transaction control helper를 제공한다.
`tm` 문서는 transaction callback, retransmission, timeout, fork handling이 transaction layer 수준에서 관리된다고 설명한다.

의미:
- Reactor를 Kamailio 내부에서 구현하는 고급 방법도 있다
- 예를 들어 특정 request를 proxy가 받은 뒤 async 처리 후 `t_continue()` 또는 `t_reply_callid()`로 반응을 줄 수 있다

하지만 이 경로는 현재 Python 코드베이스와 거리가 멀다.
초기 Phase 4보다는 “향후 Kamailio-embedded reactor” 후보에 가깝다.

관련 링크:
- [Kamailio dialog module](https://www.kamailio.org/docs/modules/stable/modules/dialog.html)
- [Kamailio tmx module](https://www.kamailio.org/docs/modules/5.9.x/modules/tmx.html)
- [Kamailio tm module](https://www.kamailio.org/docs/modules/devel/modules/tm.html)

## 5.3 SIP transaction / correlation / timeout에 대한 RFC 근거
### RFC 3261
`공식 문서 확인`

RFC 3261은 response와 client transaction의 매칭에 대해 다음 축을 쓴다.

- top Via branch
- CSeq method

server transaction/request matching 쪽에서는 다음 요소가 중요하다.

- branch
- top Via sent-by
- method

즉, Sender/Reactor의 최소 correlation key는 적어도 아래를 포함해야 한다.

- `top_via_branch`
- `call_id`
- `cseq_number`
- `cseq_method`
- 필요 시 `sent_by`

또한 RFC 3261 / 관련 정정 문서들은 INVITE와 non-INVITE의 timeout / retransmission이 다르다는 점을 분명히 한다.

의미:
- Phase 4에서 “응답/타임아웃/실패”를 구분하려면 단순 소켓 timeout으로 끝내지 말고
- **transaction-aware timeout 정책**을 둬야 한다

관련 링크:
- [RFC 3261](https://www.rfc-editor.org/rfc/inline-errata/rfc3261.html)
- [RFC 6026](https://www.rfc-editor.org/rfc/rfc6026)

### RFC 3581
`공식 문서 확인`

RFC 3581은 NAT 환경에서 response routing과 binding lifetime 문제를 다룬다.
특히 INVITE transaction은 provisional 이후 final response가 늦게 올 수 있어 NAT binding lifetime을 고려해야 한다고 설명한다.

의미:
- 연구실 망에서 UE가 NAT, firewall, IMS routing policy 뒤에 있으면
- direct UDP 송신은 “보냈다”와 “응답이 돌아온다”가 항상 같지 않다
- Reactor는 “무응답 = 단말 무반응”으로 단정하면 안 된다

관련 링크:
- [RFC 3581](https://www.rfc-editor.org/rfc/rfc3581)

## 5.4 SIPp를 Sender/Reactor 후보로 쓸 수 있는가
`공식 문서 확인`

SIPp 공식 문서는 아래를 제공한다.

- UDP/TCP/TLS/SCTP transport modes
- user-agent 성격의 multi-socket mode
- `recv`의 `request`, `response`, `timeout`, `ontimeout`, `response_txn`
- `start_rtd` / `rtd` 기반 RTT 측정
- `FailedTimeoutOnRecv`, `OutOfCallMsgs`, `Retransmissions` 같은 통계
- `-trace_msg`, `-trace_err`, `-trace_stat`, `-trace_counts` 같은 기록

의미:
- SIPp는 **정상/준정상 SIP 시나리오**를 다루는 Sender/Reactor 후보로 매우 강하다
- request-response correlation, timeout handling, statistics, scenario DSL이 이미 있다

약점:
- 현재 프로젝트의 `MutatedCase.packet_bytes` 같은 raw malformed bytes를 곧바로 먹이기 어렵다
- SIP parser/transaction machine 안에서 “예상 가능한 SIP”를 다루는 쪽에 더 가깝다
- 즉, parser robustness용 byte fuzzing sender의 1차 구현체로는 맞지 않을 수 있다

관련 링크:
- [SIPp transport modes](https://sipp.readthedocs.io/en/latest/transport.html)
- [SIPp own scenarios reference](https://sipp.readthedocs.io/en/v3.6.1/scenarios/ownscenarios.html)
- [SIPp error handling](https://sipp.readthedocs.io/en/v3.6.1/error.html)
- [SIPp statistics](https://sipp.readthedocs.io/en/latest/statistics.html)

## 5.5 PJSIP/PJSUA2를 Sender/Reactor 후보로 쓸 수 있는가
`공식 문서 확인`

PJSUA2 문서는 다음을 보여준다.

- `makeCall()`로 outgoing call 생성
- `onIncomingCall()`로 incoming call 처리
- `onCallTsxState()`로 transaction state 변화 감시
- `onCallRxReinvite()` / `onCallRxOffer()` / `onInstantMessage()` 같은 event callback

의미:
- PJSIP는 **정상적인 UAC/UAS behavior**, in-dialog handling, re-INVITE/UPDATE/MESSAGE 류 관리에 강하다
- Reactor를 callback 기반으로 짜기 좋다

약점:
- malformed wire/bytes 전송기보다는 full SIP stack이다
- 현재 프로젝트의 phase 4가 “mutation artifact delivery”라는 점을 생각하면 지나치게 무거울 수 있다
- 상용 단말 상대 fuzzing에서 stack 자체가 메시지를 교정하거나 거부할 가능성이 있다

관련 링크:
- [PJSUA2 Call documentation](https://docs.pjsip.org/en/2.12.1/pjsua2/call.html)

## 6. 가능한 구현 방법들
아래 비교는 **실제로 현재 프로젝트에서 Phase 4 후보가 될 수 있는 방법**만 남긴 것이다.

### 방법 A. Python custom sender + socket response reactor
설명:
- 현재 프로젝트 안에 `sender`와 `reactor`를 새로 만든다
- `mutated_packet` / `wire_text` / `packet_bytes`를 전송 가능한 bytes로 바꾼 뒤 UDP/TCP/TLS로 보낸다
- 같은 소켓에서 immediate SIP response를 기다린다

장점:
- 현재 코드베이스와 가장 자연스럽게 맞는다
- `MutatedCase`를 직접 입력으로 받을 수 있다
- byte mutation까지 손상 없이 보낼 수 있다
- SRP를 유지하기 쉽다

단점:
- P-CSCF 경유 모드에서 network trace를 별도 수집하지 않으면 Reactor가 빈약해진다
- dialog/transaction 처리, retransmission, timeout policy를 우리가 직접 설계해야 한다

적합도:
- **매우 높음**

### 방법 B. Python custom sender + direct-to-UE dumpipe mode
설명:
- 방법 A의 sender에 `mode=direct`를 추가한다
- UE IMS IP를 구해 P-CSCF를 우회하고 UE로 직접 보낸다

장점:
- malformed message delivery 가능성이 높다
- 이전 연구실 프로젝트에 선행 자산이 있다
- parser robustness / lower-level input delivery 실험에 유리하다

단점:
- UE IP discovery가 별도 과제다
- 운영상 route setup 필요
- 실제 IMS path realism이 떨어진다

적합도:
- **높음**

### 방법 C. Python custom sender + P-CSCF path mode
설명:
- 방법 A의 sender에 `mode=pcscf`를 추가한다
- 변조 메시지를 P-CSCF 5060/TCP/UDP/TLS로 보낸다

장점:
- 실제 IMS path에 더 가깝다
- Kamailio siptrace/DB/RPC와 결합하기 쉽다
- network-realistic behavior 관찰이 가능하다

단점:
- P-CSCF에서 malformed packet이 먼저 드랍될 수 있다
- 단말까지 못 가는 패킷이 늘어난다

적합도:
- **높음**

### 방법 D. SIPp 기반 Sender/Reactor
설명:
- Python이 SIPp scenario/XML과 trace 파일을 생성하고 SIPp를 subprocess로 실행한다

장점:
- timeout, RTT, correlation, trace가 이미 성숙해 있다
- 정상/준정상 SIP signalling 실험에는 강하다

단점:
- 임의 raw bytes, heavily malformed message delivery에는 부적합하다
- current `MutatedCase`와 직접 연결이 부자연스럽다

적합도:
- **중간**

### 방법 E. PJSIP 기반 Sender/Reactor
설명:
- PJSUA2 또는 PJSIP wrapper를 붙여 UAC/UAS event 기반 엔진으로 운영한다

장점:
- callback 기반 reactor가 강력하다
- call/dialog handling이 풍부하다

단점:
- fuzzing보다 SIP UA 구현체 쪽에 가깝다
- malformed bytes를 보존하기 어렵다
- 현재 프로젝트의 “mutation artifact delivery”와 맞지 않을 수 있다

적합도:
- **중간 이하**

### 방법 F. Kamailio embedded sender/reactor
설명:
- P-CSCF 또는 별도 Kamailio 노드에서 `uac_req_send`, `event_route[uac:reply]`, `siptrace`, `tmx` 등을 사용한다

장점:
- IMS path 안에서 transaction state를 활용할 수 있다
- Kamailio trace와 자연스럽게 연결된다

단점:
- Python 코드베이스에서 벗어난다
- raw malformed bytes 전송에는 부적합하다
- 초기 Phase 4 구현 난도가 높다

적합도:
- **낮음~중간**

## 7. Reactor 관찰 채널은 단일 채널로 끝내지 않는 것이 좋다
`추론`

Phase 4 완료 기준만 보면 “응답/타임아웃/실패”만 구분해도 된다.
하지만 실제 연구실 망과 상용 단말 조건을 고려하면, 아래처럼 관찰 채널을 분리하는 것이 더 정직하다.

### 최소 채널
- `socket reactor`
  - 같은 소켓에서 온 응답

### 권장 보조 채널
- `network trace reactor`
  - SIP sniffer
  - Kamailio siptrace
  - PCAP

### 향후 확장 채널
- `device-side reactor`
  - ADB/logcat
  - bugreport
  - dmesg / meminfo

즉, 구현 시작은 socket-only로 할 수 있어도, 구조는 multi-observer를 염두에 두는 것이 안전하다.

## 8. 현실적인 결론
### 8.1 현재 프로젝트에 가장 맞는 1차 방향
`추론`

가장 현실적인 1차 Phase 4 방향은 다음 조합이다.

1. **Python native Sender/Reactor를 현재 저장소 안에 구현한다**
2. Sender mode를 최소 두 개 둔다
   - `pcscf`
   - `direct`
3. Reactor channel을 최소 두 단계로 설계한다
   - 1차: socket response
   - 2차: optional trace observer
4. target resolution 전략을 분리한다
   - static IP
   - MSISDN -> UE IP
   - Open5GS infoAPI
   - Kamailio usrloc/log 기반 fallback

이 방향의 장점:
- 현재 `MutatedCase` 구조를 그대로 살릴 수 있다
- 기존 lab 환경과 연결된다
- 향후 Oracle/Controller와도 자연스럽게 연결된다

### 8.2 왜 단일 경로가 아니라 두 모드가 필요한가
`추론`

`pcscf`만 쓰면:
- malformed packet이 proxy에서 소실될 수 있다

`direct`만 쓰면:
- 실제 IMS path realism이 약해진다

따라서 연구 목표가 “단말 지향 SIP fuzzing”이라면 둘 중 하나만 택하기보다, **실험 목적에 따라 송신 경로를 바꾸는 2-mode 구조**가 가장 설득력 있다.

## 9. 계획 전에 추가로 확인해야 할 질문
이 문서는 아직 계획 문서가 아니므로, 아래 질문은 “다음 단계 계획 수립 전 확인 항목”으로 남긴다.

1. 실제 연구실 환경에서 UE IMS subnet으로 host/direct route가 항상 가능한가
2. 현재 Open5GS 버전에 infoAPI가 있는가
3. 상용 UE가 SIP를 UDP 5060으로만 받는가, TCP/TLS/IPsec도 같이 고려해야 하는가
4. P-CSCF를 거치지 않은 direct packet이 단말에서 실제로 처리되는 범위는 어디까지인가
5. Phase 4의 “응답”에 provisional(1xx)도 포함할 것인가, final response만 볼 것인가
6. Reactor에서 같은 소켓 응답과 network trace 응답이 충돌할 때 어느 쪽을 진실로 볼 것인가

## 10. 이번 조사에서 얻은 핵심 결론
- **현재 코드베이스와 가장 잘 맞는 것은 Python native Sender/Reactor다.**
- **실제 연구실 망 경험상 direct-to-UE 경로는 실용적인 옵션이다.**
- **Open5GS 공식 문서는 Kamailio IMS + Open5GS + 상용 UE + 프로그래밍된 SIM 기반 VoLTE 환경이 현실적임을 뒷받침한다.**
- **Open5GS infoAPI는 UE/session discovery의 새로운 후보가 될 수 있다.**
- **Kamailio는 UAC/siptrace/dialog/tmx로 강한 보조 수단이 되지만, 현재 프로젝트의 1차 Sender 본체로 삼기에는 무겁다.**
- **SIPp/PJSIP는 좋은 후보이지만, malformed wire/bytes를 직접 다루는 현재 프로젝트 목적에는 보조 옵션에 가깝다.**

## 11. 참고한 주요 근거
### 현재 저장소
- `docs/기획/PRD.md`
- `docs/기획/MUTATOR_PRD.md`
- `src/volte_mutation_fuzzer/generator/*`
- `src/volte_mutation_fuzzer/mutator/*`

### 이전 연구실 프로젝트
- `/Users/chaejisung/Desktop/Project/fuzzer(capstone)/README.md`
- `/Users/chaejisung/Desktop/Project/fuzzer(capstone)/docs/sender.md`
- `/Users/chaejisung/Desktop/Project/fuzzer(capstone)/docs/dumpipe.md`
- `/Users/chaejisung/Desktop/Project/fuzzer(capstone)/docs/ue_lookup.md`
- `/Users/chaejisung/Desktop/Project/fuzzer(capstone)/fuzzer/fuzzer/sender.py`
- `/Users/chaejisung/Desktop/Project/fuzzer(capstone)/fuzzer/fuzzer/dumpipe.py`
- `/Users/chaejisung/Desktop/Project/fuzzer(capstone)/fuzzer/tools/ue_lookup.py`
- `/Users/chaejisung/Desktop/Project/fuzzer(capstone)/fuzzer/monitor/sip_sniffer.py`
- `/Users/chaejisung/Desktop/Project/fuzzer(capstone)/fuzzer/monitor/pcap_capture.py`
- `/Users/chaejisung/Desktop/Project/fuzzer(capstone)/fuzzer/monitor/adb_monitor.py`

### 공식 문서 / RFC
- [Open5GS Docs](https://open5gs.org/open5gs/docs/)
- [VoLTE Setup with Kamailio IMS and Open5GS](https://open5gs.org/open5gs/docs/tutorial/02-VoLTE-setup/)
- [Dockerized VoLTE Setup](https://open5gs.org/open5gs/docs/tutorial/03-VoLTE-dockerized/)
- [Open5GS Features](https://open5gs.org/open5gs/features/)
- [Open5GS JSON infoAPI](https://open5gs.org/open5gs/docs/tutorial/07-infoAPI-UE-gNB-session-data/)
- [Kamailio UAC module](https://www.kamailio.org/docs/modules/stable/modules/uac.html)
- [Kamailio siptrace module](https://www.kamailio.org/docs/modules/stable/modules/siptrace.html)
- [Kamailio ims_usrloc_pcscf module](https://kamailio.org/docs/modules/stable/modules/ims_usrloc_pcscf.html)
- [Kamailio ims_registrar_pcscf module](https://www.kamailio.org/docs/modules/5.7.x/modules/ims_registrar_pcscf.html)
- [Kamailio dialog module](https://www.kamailio.org/docs/modules/stable/modules/dialog.html)
- [Kamailio tmx module](https://www.kamailio.org/docs/modules/5.9.x/modules/tmx.html)
- [Kamailio tm module](https://www.kamailio.org/docs/modules/devel/modules/tm.html)
- [RFC 3261](https://www.rfc-editor.org/rfc/inline-errata/rfc3261.html)
- [RFC 3581](https://www.rfc-editor.org/rfc/rfc3581)
- [RFC 6026](https://www.rfc-editor.org/rfc/rfc6026)
- [SIPp transport modes](https://sipp.readthedocs.io/en/latest/transport.html)
- [SIPp own scenarios reference](https://sipp.readthedocs.io/en/v3.6.1/scenarios/ownscenarios.html)
- [SIPp error handling](https://sipp.readthedocs.io/en/v3.6.1/error.html)
- [SIPp statistics](https://sipp.readthedocs.io/en/latest/statistics.html)
- [PJSUA2 Call documentation](https://docs.pjsip.org/en/2.12.1/pjsua2/call.html)
