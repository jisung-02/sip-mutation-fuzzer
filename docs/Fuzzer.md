---

## 1. 퍼저의 정의

> **퍼즈 테스팅**(Fuzz testing) 또는 **퍼징**(fuzzing)은 (종종 자동화 또는 반자동화된) [소프트웨어 테스트](https://ko.wikipedia.org/wiki/%EC%86%8C%ED%94%84%ED%8A%B8%EC%9B%A8%EC%96%B4_%ED%85%8C%EC%8A%A4%ED%8A%B8) 기법으로서, 컴퓨터 프로그램에 유효한, 예상치 않은 또는 [무작위](https://ko.wikipedia.org/wiki/%EB%AC%B4%EC%9E%91%EC%9C%84) 데이터를 입력하는 것이다. 이후 프로그램은 [충돌](https://ko.wikipedia.org/wiki/%EC%B6%A9%EB%8F%8C_(%EC%BB%B4%ED%93%A8%ED%8C%85))이나 빌트인 코드 검증의 실패, 잠재적인 [메모리 누수](https://ko.wikipedia.org/wiki/%EB%A9%94%EB%AA%A8%EB%A6%AC_%EB%88%84%EC%88%98) 발견 등 같은 예외에 대한 감시가 이루어진다. 퍼징은 주로 소프트웨어나 컴퓨터 시스템들의 보안 문제를 테스트하기 위해 사용된다. 이것은 하드웨어나 소프트웨어 테스트를 위한 [무작위 테스팅](https://ko.wikipedia.org/wiki/%EB%AC%B4%EC%9E%91%EC%9C%84_%ED%85%8C%EC%8A%A4%ED%8C%85?action=edit&redlink=1) 형식이다.
- wikipedia
> 

> 소프트웨어나 프로토콜 구현체에 **의도적으로 비정상·반정상 입력을 주입**하여 취약점, 버그, 충돌(crash)을 자동으로 발견하는 보안 테스트 도구
> 

퍼저는 세 가지 핵심 구성 요소로 이루어짐

```
Poet (입력 생성기) → Courier (전달자) → Oracle (판정기)
```

| 구성 요소 | 역할 | 이 프로젝트에서의 대응 |
| --- | --- | --- |
| **Poet** | 변이/생성된 테스트 케이스 제작 | `generator` + `mutator` |
| **Courier** | 대상 시스템에 테스트 케이스 전달 | `sender` |
| **Oracle** | 응답·프로세스 상태를 분석해 이상 판정 | `oracle` |

---

## 2. 퍼저의 종류

### 2.1 입력 생성 전략 기준

| 유형 | 설명 | 장점 | 단점 |
| --- | --- | --- | --- |
| **생성 기반 (Generation-based)** | 프로토콜 사양/문법을 기반으로 입력을 처음부터 생성 | 구조적으로 유효한 입력, 깊은 코드 경로 도달 | 사양 모델링 비용 높음 |
| **변이 기반 (Mutation-based)** | 유효한 시드 입력에 변이를 가해 새 입력 생성 | 구현 간단, 실존 트래픽 재사용 가능 | 시드 품질에 의존 |
| **커버리지 유도 (Coverage-guided)** | 코드 커버리지 피드백으로 새로운 경로를 탐색 | 체계적 탐색 (AFL, libFuzzer) | 대상 계측(instrumentation) 필요 |
- 이 프로젝트는 **변이 기반**에 해당
- SIP 카탈로그에서 유효한 패킷을 생성한 뒤, 다수의 변이 전략을 적용

### 2.2 상태(Statefulness) 기준

| 유형 | 설명 |
| --- | --- |
| **Stateless** | 각 패킷을 독립적으로 전송. 빠르지만 dialog 내부 메시지 도달 불가 |
| **Stateful** | 프로토콜 상태 기계(state machine)를 추적하며 메시지 시퀀스를 구성. SIP INVITE→PRACK→BYE 같은 dialog 내 메시지 테스트 가능 |
- SIP/VoLTE 퍼징에서 stateful 접근은 필요 → SIP는 메시지의 상태를 기반하기 때문
- INTERSTATE, KiF 같은 선행 연구가 stateful SIP 퍼저의 필요성을 입증

---

## 3. 퍼저가 갖춰야 하는 핵심 기능

![image.png](attachment:e1a71e04-afd9-4de9-85ef-60ea2d2b5e89:image.png)

### 3.1 입력 생성 (Poet)

퍼저가 대상에 보낼 패킷을 만드는 모듈, 세 가지 레이어에서 변이 전략을 적용

- **model-layer**: 프로토콜 필드 단위에서 값을 교체하거나 필드를 삭제·추가
    - ex) "SIP의 Via 헤더를 날려버리면 어떻게 반응하는가?”
- **wire-layer**: 헤더 순서를 바꾸거나 경계값을 주입
    - 파서가 순서에 의존하거나 경계를 잘못 처리하는 버그를 노림
    - ex) Content-Length를 실제보다 크게
- **byte-layer**:
    - 비트 플립, 랜덤 바이트 삽입 등 가장 무차별적인 방식
    - 프로토콜 의미를 모르는 파서 버그를 찾는 데 특화

퍼징은 재현성이 중요, 동일한 시드와 전략에서는 동일한 패킷이 나와야 버그의 재현이 가능

→ 이때 시드의 예시? ~~~~~

### 3.2 전달 (Courier)

생성된 패킷을 실제로 대상에게 보내는 모듈

Courier 계층은 아래 네 가지 기능을 지원해야함

- **프로토콜 정확성**: 변이가 전송 계층을 깨지 않아야 함. UDP/TCP 위에서 정상 소켓 통신
- **응답 수집**: 대상의 응답(SIP 상태코드, 본문)을 캡처해 오라클에 전달
- **타임아웃 처리**: 응답 없음(drop, crash)을 정해진 시간 내에 판정
- **쿨다운(Cooldown)**: 연속 전송 시 대상 과부하 방지 및 타이밍 경합 회피

### 3.3 오라클 (Oracle)

대상에게 패킷이 전달 되었는지, 어떤 결과가 나왔는지를 탐지하는 모듈

**오라클의 두 가지 축**

1. **Socket Oracle**: 응답 코드 + 응답 시간 기반 판정
2. **Process Oracle**: 프로세스 생존 여부로 crash 확정
- 두 가지 오라클을 결합해 프로토콜 상태, 대상 프로세스 상태를 모두 확인해야함

**오라클이 탐지해야 하는 이상(anomaly) 유형**

| 판정(Verdict) | 의미 | 탐지 방법 |
| --- | --- | --- |
| `crash` | 대상 프로세스가 종료됨 | 프로세스 생존 확인 (`pgrep`) |
| `timeout` | 응답 없음 (패킷 drop 또는 hang) | 소켓 타임아웃 |
| `suspicious` | 비정상 응답 (5xx/6xx, 파싱 실패, 비정상 지연) | SIP 상태코드 + 응답 시간 분석 |
| `stack_failure` | 스택 트레이스 감지 | stderr/로그 패턴 매칭 |
| `normal` | 정상 동작 | 위 조건 미해당 |
| `unknown` | 인프라 오류로 판정 불가 | 전송 자체 실패 |

### 3.4 캠페인 (Campaign)

다수의 케이스를 자동으로 돌리는 루프 관리자 역할의 모듈

각 케이스는 `method / layer / strategy / seed` 조합으로 정의되어 재현이 가능해야함

- **자동화된 루프**: 수백~수천 케이스를 사람 개입 없이 실행
- **케이스 명세(Spec)**: 각 케이스는 method/layer/strategy/seed의 조합으로 정의. 재현 가능해야 함
- **결과 저장 (Crash-safe)**: 캠페인 중 크래시가 나도 이미 수집된 결과가 보존되어야 함. JSONL 형식이 적합 (append-only) → 캠페인 중간에 크래시가 나도 이미 수집된 결과는 보존
- **재현 명령 생성**: 각 케이스마다 동일 입력을 재현하는 CLI 명령을 저장

### 3.5 분석 및 보고 (Report)

캠페인이 끝난 후 결과를 정리

- **집계 요약**: total/normal/suspicious/timeout/crash 건수
- **필터링**: suspicious, crash만 추출해 우선 분석
- **재실행(Replay)**: 특정 케이스 ID로 동일 패킷 재전송 → 재현성 검증

---

## **4. SIP 프로토콜 퍼저 고려 사항**

### **4.1 상태 기계 (State Machine)**

SIP는 stateful 프로토콜

- INVITE 이후에는 PRACK, UPDATE, BYE가 와야 하며, dialog-ID(Call-ID, From-tag, To-tag)가 일치해야 함
- Stateless 퍼저는 이 대화(dialog) 내부로 진입하지 못함

![image.png](attachment:c0367c06-c976-4dc3-bdfb-b62430ea4326:image.png)

### 4.2 결정론 vs 랜덤성

퍼징을 위해서는 아래 변조 전략 관점에서 크게 두 가지 분류로 나눌 수 있음

1. **랜덤 퍼저**: 빠르게 넓은 공간을 탐색. 재현성 없음
    - 매 실행마다 다른 패킷을 만들기 때문에 넓은 공간을 빠르게 훑을 수 있음
    - 버그를 발견해도 어떤 패킷인지 재현이 어려움
2. **결정론적 퍼저**: 동일 시드 → 동일 변이. 버그 보고 및 회귀 테스트에 필수
    - 결정론적 퍼저는 seed값 하나에서 전체 변이 시퀀스가 수학적으로 검증
    - 같은 seed를 줄 경우 동일한 패킷이 생성
    - 버그 재현, 패치 검증, 회귀 테스트 가능
- 이 프로젝트는 **결정론적**: `seed` 값 하나로 전체 변이 시퀀스 재현 가능

### **4.3 실행 속도의 근본적 한계**

- AFL같은 in-process 퍼저는 실제 프로세스의 함수를 호출하므로 네트워크를 왕복하는 비용이 발생하지 않음
- 반면 현재 구현하고 있음 SIP 퍼저는 실제 네트워크 소켓을 쓰기 때문에 매 케이스마다 네트워크를 통과하는 RTT가 붙게됨
    - INTERSTATE 연구에서 측정하니 초당 5회 미만이 나옴
- 연속으로 패킷을 쏠 경우 아래와 같은 문제점이 생길 수 있음
    - 연속으로 패킷을 쏘면 UDP 특성상 서버가 과부하되거나 패킷이 드롭될 수 있음
    - 서버가 이전 요청을 처리하는 시간을 확보해주어야 함(플러딩 공격 제외)

⇒ 즉, 퍼저 구현 시 패킷 전송 사이 쿨다운(패킷 사이 시간 갭)을 주어야 함

### **4.4 공격면 분류**

- SIP 프로토콜의 표준 패킷을 분석한 결과  1. 요청과 응답 / 2. dialog 필요 여부 / 3. 역할의 성격의 총 세 가지 축으로 분류가 가능했음

#### 1. 요청 평면

변이된 요청을 대상 단말에 생성하여 전송, 이후 단말의 응답을 Oracle로 탐지

dialog 필요 여부, 역할의 성격에 따라 5개의 그룹으로 분류

1. 그룹 A - dialog 없이 혼자 보낼 수 있는 메서드(세션 개시)
    - `INVITE` `REGISTER` `OPTIONS` `MESSAGE` `PUBLISH` `SUBSCRIBE`
        - 통화나 세션을 시작하자고 제안하는 메서드 - `INVITE`
        - UA(전화기, 소프트폰 등)가 자신의 현재 위치를 SIP 서버에 등록하는 메서드 - `REGISTER`
        - 상대방이 어떤 기능을 지원하는지 물어보는 메서드 - `OPTIONS`
        - SIP 위에서 텍스트 메시지를 보내는 메서드 - `MESSAGE`
        - UA가 자신의 현재 상태(presence)를 서버에 올리는 메서드 - `PUBLISH`
        - 특정 이벤트를 구독하는 메서드 - `SUBSCRIBE`
    - dialog 없이 단독으로 전송 가능, 세션을 개시하는 역할, stateless 퍼징 가능
    - 서버 입장에서는 이전 컨텍스트가 없는 첫 요청, 즉 파서가 모든 필드를 처음부터 처리해야 하고, 그만큼 파싱 버그가 많이 숨어있을 것으로 추정
2. 그룹 B - 이미 진행 중인 특정 트랜잭션에 묶여있는 메시지
    - `CANCEL` `ACK`
        - 아직 최종 응답이 오지 않은 진행 중인 요청을 취소하는 메서드 - `CANCEL`
        - INVITE에 대한 200 OK를 받았다는 확인 - `ACK`
    - 진행 중인 특정 트랜잭션의 Call-ID, CSeq에 묶이는 패킷
        - 즉, stateless하게 트랜젝션 상태를 고려하지 않고 전송할 경우 대부분 단말에서 드랍할 것으로 추정
    - 아래 두 가지 경우로 다룰 수 있음
        1. 트랜젝션을 나타내는 필드(Call-ID, CSeq)는 정상적으로 두고, 기타 필드를 변조
        2. 그룹 A와 같이 stateless하게 퍼징
3. 그룹 C - dialog 내부 세션 제어
    - `BYE` `UPDATE` `REFER`
        - BYE는 통화 종료, UPDATE는 세션 파라미터 재협상(SDP 변경), REFER는 통화 전달(콜 트랜스퍼) 역할 수행
    - INVITE → 200 OK → ACK 흐름이 완료되어 dialog가 열린 상태에서만 유효
    - stateful 퍼저가 Call-ID, From-tag, To-tag를 유지한 채로 진입해야 드랍되지 않음
    - stateless fuzzer로는 찾지 못한 영역이므로 탐구 가치가 있다고 판단
4. 그룹 D - 신뢰성 보조
    - `PRACK`
        - 1xx provisional 응답에 대한 확인 메시지
    - RFC 3262를 구현한 서버에서만 의미가 있고, 구현 여부가 벤더마다 다름 - Optional하게 구현되는 경우가 많은 것으로 추정
    - dialog 수립 전후에 모두 나타낼 수 있는 것으로 보임
5. 그룹 E - 이벤트 / 알림
    - `NOTIFY` `INFO`
        - SUBSCRIBE로 구독을 신청한 후 서버가 보내는 알림이 NOTIFY
        - 세션 중 DTMF 같은 부가 정보를 실어 나르는 게 INFO
    - 이벤트 패키지(presence, message-summary, refer 등)마다 바디 구조가 달라서 파서 다양성이 가장 높음
    - 잘못된 이벤트 패키지명이나 바디 포맷 변이로 예상치 못한 버그를 유발할 수 있을 것으로 추정

#### 2. 응답 평면

단말의 정상적인 요청을 퍼저가 탐지(Oracle X), 일종의 프록시 역할을 맡아 상대 단말에 응답을 변조하여 전송

1. 그룹 F - 상태 전이 유발
    - `100 Trying` `180 Ringing` `183 Session Progress`
        - `100 Trying` — 프록시나 서버가 요청을 받아서 처리하기 시작했다는 신호.
        - `180 Ringing` — 상대방 전화가 울리고 있다는 의미. UA가 이걸 받으면 내부적으로 "early dialog" 상태로 전이
        - `183 Session Progress` — 링백 톤이나 early media(통화 연결 전 음성)를 협상할 때 사용, SDP 바디가 붙기도 함
    - 요청을 받은 상대가 처리 중임을 알리는 임시 응답
    - 해당 응답 이후에는 최종 응답이 아니므로 트랜잭션이 닫히지 않음
    - 
2. 그룹 G — dialog 수립
    - `200 OK` `202 Accepted`
        - `200 OK` — 요청이 성공했다는 최종 확인
        - `202 Accepted` — 요청을 받아들였지만 아직 처리가 완료되지 않았다는 의미
    - 이 응답을 받는 순간 트랜잭션이 끝나고 dialog가 열림
3. 그룹 H — 재시도 / 우회
    - `301` `302` `305` `380` `408` `480` `503`
        - `301 Moved Permanently` — 이 주소는 영구적으로 바뀌었다는 뜻, Contact 헤더에 새 주소가 담김
        - `302 Moved Temporarily` — 일시적으로 다른 주소로 리다이렉트
        - `305 Use Proxy` — 특정 프록시를 경유해서 재시도
        - `380 Alternative Service` — 대안 서비스로 연결
        - `408 Request Timeout` — 서버가 제시간에 최종 응답을 못 했다는 의미, UA는 일정 시간 후 재시도하게 됨
        - `480 Temporarily Unavailable` — 현재 서비스 사용 불간
        - `503 Service Unavailable` — 서버 과부하 또는 에러 상태를 의미. `Retry-After` 헤더가 붙으면 그 시간 후 재시도
    - UA가 이 응답을 받으면 같은 요청을 다른 방식이나 다른 주소로 다시 시도
4. 그룹 I — 인증 협상
    - `401 Unauthorized` `407 Proxy Authentication Required` `494 Security Agreement Required`
        - `401 Unauthorized` — 서버가 직접 인증을 요구. `WWW-Authenticate` 헤더에 realm, nonce, algorithm이 담김
        - `407 Proxy Authentication Required` — 프록시가 인증을 요구. `Proxy-Authenticate` 헤더를 사용. 구조는 401과 같지만 처리 경로가 다름
        - `494 Security Agreement Required` — SIPS(TLS 기반 SIP)에서 보안 협상을 먼저 하라는 요구
    - 단순 거절이 아닌 credentials를 가져와서 다시 요청하라는 의미
    - UA가 헤더를 파싱해서 digest를 계산하고 Authorization 헤더를 붙여 재전송
5. 그룹 J — 거절 / 단순 종료
    - `403` `404` `405` `415` `486` `487` `500` `501`
        - `403 Forbidden` — 권한 없음
        - `404 Not Found` — 해당 사용자나 리소스가 존재하지 않음
        - `405 Method Not Allowed` — 이 메서드는 지원하지 않는다는 의미, `Allow` 헤더에 지원 목록이 붙음
        - `415 Unsupported Media Type` — SDP나 바디의 미디어 타입을 처리할 수 없다는 의미
        - `486 Busy Here` — 지금 통화 중이라 받을 수 없다는 뜻
        - `487 Request Terminated` — CANCEL을 받아서 요청이 취소됐다는 뜻
        - `500 Internal Server Error` — 서버 내부 오류
        - `501 Not Implemented` — 해당 기능이 구현되어 있지 않다는 뜻
    - 이 트랜잭션은 끝났다는 최종 거절, 재시도는 없음
6. 그룹 K — 전역 종료
    - `600 Busy Everywhere` `603 Decline` `604 Does Not Exist Anywhere` `606 Not Acceptable`
        - `600 Busy Everywhere` — 이 사용자의 모든 단말이 전부 통화 중이다. 486과 달리 "어디서도 안 됨"입니다.
        - `603 Decline` — 사용자가 명시적으로 거절했다. "받기 싫다"는 의사 표시입니다.
        - `604 Does Not Exist Anywhere` — 이 사용자는 어디에도 등록되어 있지 않다. 404가 로컬 서버 기준이라면 604는 전역 기준입니다.
        - `606 Not Acceptable` — 제안한 세션 파라미터(코덱, 대역폭 등)를 어떤 단말에서도 수락할 수 없다.
    - 6xx의 특수성은 "이 사용자 전체를 포기하라"는 전파 범위에 있습니다. 프록시가 여러 UA에 병렬로 fork해서 보낸 요청들을 전부 한꺼번에 취소시킵니다.

---

## 5. 기타 용어 정리

1. dialog : 두 UA 사이의 지속적인 peer-to-peer 관계, 한 번의 메시지 교환이 끝나도 계속 유지되는 연결 
    - `Call-ID` + `From-tag` + `To-tag`  태그의 조합으로 식별
    - **트랜잭션**은 요청 하나와 그에 대한 응답들의 묶음 - 즉 하나의 dialog안에서 여러 트랜젝션이 존재
    - `CSeq: 번호`  형태로 하나의 dialog안에서 요청의 순서를 보장
        - 응답의 CSeq는 대응되는 요청의 CSeq와 동일
            - 즉, 응답이 올 떄 CSeq를 보면 어떤 요청에 대한 응답인지 확인 가능
        - 일반적으로 요청끼리는 CSeq가 같으면 안됨 - 그러나 CANCEL은 예외, 취소하려는 INVITE와 CSeq가 동일해야함
    - `RSeq: 번호` provisional 응답인 경우 요청에 RSeq를 붙이면 응답 RAck에 동일한 RSeq가 첨부
2. digest 계산
    - **비밀번호를 네트워크에 직접 보내지 않는 것을 아이디어로 하는 인증 방식, 비밀번호로 해시를 생성**
        1. 서버가 401을 보낼 때 `nonce`라는 일회용 랜덤값을 함께 줌
        2. UA는 이 nonce와 자신의 비밀번호를 섞어서 해시를 만들고, 그 결과값만 서버에 돌려보냄
        3. 서버는 자기가 가진 비밀번호로 똑같이 계산해서 값이 일치하면 인증을 통과시킴
    - 아래 단계로 계산
        1. HA1 = MD5(username : realm : password)
        2. HA2 = MD5(SIP메서드 : Request-URI)
        3. response = MD5(HA1 : nonce : HA2)
    - `HA1`은 사용자가 이 도메인에서 이 비밀번호를 가졌다는 증명
    - `HA2`는 요청의 종류와 대상입니다. 둘을 nonce로 묶어서 최종 response를 만듬
    - nonce가 매번 바뀌기 때문에 같은 비밀번호라도 response 값이 매번 달라짐 → 재전송 공격을 막는 원리
3. Authentication and Key Agreement(AKA 인증)
    
    ![image.png](attachment:ba618419-5636-48a5-8d71-509bf393ed0b:image.png)
    
    - Digest 인증의 확장판, 주로 모바일 네트워크(3GPP, IMS)에서 SIP를 쓸 때 사용
    - SIM 카드 안의 비밀키를 기반으로 nonce를 만들고 동시에 세션 암호화 키까지 생성하는 방식
    - Digest와의 차이점
        - 일반 Digest에서 nonce는 서버가 임의로 만든 랜덤값인 반면, AKA에서 nonce는 `RAND + AUTN` 두 값의 조합
        - **비밀키가 SIM 밖으로 나가지 않음 →** 비밀키 K는 SIM 칩과 HSS(이동통신사 인증 서버) 두 곳에만 존재
        - **세션 암호화 키를 동시에 생성 →** 인증 과정에서 CK(Cipher Key)와 IK(Integrity Key)가 함께 생성, 이 키로 이후 SIP 트래픽을 IPSec으로 암호화

---

## 5. 참고 자료

1. [Fuzzing - Wikipedia](https://en.wikipedia.org/wiki/Fuzzing)
2. [What is Fuzzing: The Poet, the Courier, and the Oracle (Black Duck)](https://www.blackduck.com/content/dam/black-duck/en-us/whitepapers/what-is-fuzzing.pdf)
3. [Mutation-Based Fuzzing - The Fuzzing Book](https://www.fuzzingbook.org/html/MutationFuzzer.html)
4. [A Survey of Network Protocol Fuzzing: Model, Techniques and Directions](https://arxiv.org/html/2402.17394v1)
5. [A Survey of Protocol Fuzzing (ACM CSUR 2024)](https://wcventure.github.io/FuzzingPaper/Paper/ACM_CSUR24_Protocol_Fuzzing.pdf)
6. [INTERSTATE: A Stateful Protocol Fuzzer for SIP (DEF CON 15)](https://www.defcon.org/images/defcon-15/dc15-presentations/dc-15-harris.pdf)
7. [ProFuzzBench: A Benchmark for Stateful Protocol Fuzzing](https://arxiv.org/pdf/2101.05102)
8. [Telecom 4G/VoLTE/5G Security & Fuzzing (Fuzzing Labs)](https://fuzzinglabs.com/telecom-4g-volte-5g-security-fuzzing/)
9. [IoTFuzzSentry: Protocol Guided Mutation Based Fuzzer](https://arxiv.org/abs/2509.09158)