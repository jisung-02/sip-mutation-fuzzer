---
title: SIP 프로토콜 연구 종합
created: 2026-03-23
tags:
  - sip
  - protocol
  - research
  - iana
  - volte
  - ims
  - fuzzing
  - attack-surface
aliases:
  - SIP 연구 보고서
  - SIP Research
---

# SIP 프로토콜 연구 종합

> [!abstract] 핵심 결론
> SIP는 단순한 텍스트 프로토콜이 아니라, **request/response 종류 + transaction/dialog 상태 + capability negotiation + IMS private extension + 대량의 IANA registry**가 겹쳐진 **다층 상태 프로토콜**이다. 단말 지향 퍼징은 이 전체 표면 중 무엇을 우선적으로 흔들지 정하는 문제다.

이 문서는 프로젝트의 SIP 프로토콜 조사 결과 전체를 **하나의 독립 문서**로 통합한 것이다. 외부 참조 없이 이 문서만으로 조사 범위, 프로토콜 구조, IANA 전수조사 데이터, 공격면 분석을 모두 확인할 수 있다.

공식 기준: IANA SIP Parameters Registry (스냅샷 2026-03-18), 관련 RFC 계열

---

# Part I. 연구 범위와 프로토콜 구조

## 1. IANA 레지스트리 전수조사 현황

| 조사 대상 | 규모 | 의미 |
|-----------|-----:|------|
| Request Method | **14** | IANA 등록 요청 전체 |
| Response Code | **75** | IANA 등록 응답 전체 |
| Header Field | **134** | SIP 헤더 레지스트리 전체 |
| Header Parameter / Value | **201** | 헤더 내부 파라미터/값 표면 |
| SIP/SIPS URI Parameter | **35** | URI 기반 제어 표면 |
| Option Tag | **36** | capability/extension 협상 표면 |
| 값 중심 registry row | **89** | Warning, Privacy, Transport, PNS 등 |
| 기능 식별자 registry row | **71** | Identity, Feature-Caps, Info Package, UUI 등 |
| Resource-Priority namespace | **48** | 우선순위 네임스페이스 |
| Resource-Priority child value | **463** | namespace별 실제 priority 토큰 |

> [!success] 조사 완료도
> 프로젝트는 더 이상 "SIP가 어떤 필드를 가지는가"를 모르는 상태가 아니다. 향후 실패는 조사 부족보다 **우선순위 설정 실패**, **상태 모델링 실패**, 또는 **실험 환경 부족**에서 날 가능성이 높다.

## 2. SIP 프로토콜 구조 이해

### 2.1 SIP는 메시지 목록이 아니라 상태 기계다

SIP를 단순 request/response 집합으로만 보면 중요한 부분을 놓친다. 조사 문서들이 공통으로 보여주는 SIP의 본질은 **네 층**이다.

```
┌─────────────────────────────────────────────────────┐
│  Layer 4: 환경 / 사설 확장 층                         │
│  IMS/3GPP private header, Resource-Priority,        │
│  Feature-Caps, push, charging                       │
├─────────────────────────────────────────────────────┤
│  Layer 3: 의미 / 확장 층                              │
│  Event, Subscription-State, Recv-Info,              │
│  Info-Package, Security-*, Identity, Privacy        │
├─────────────────────────────────────────────────────┤
│  Layer 2: 상관관계 층                                 │
│  Via, Call-ID, CSeq, From tag, To tag,              │
│  Contact, Route, Record-Route                       │
├─────────────────────────────────────────────────────┤
│  Layer 1: 메시지 종류 층                              │
│  14 Methods + 75 Response Codes                     │
└─────────────────────────────────────────────────────┘
```

> [!important] 핵심 인사이트
> SIP는 "헤더 몇 개를 채운 문자열"이 아니라, **상태 전이가 헤더와 응답 코드에 분산된 프로토콜**이다.

### 2.2 패킷 구조

#### Request 패킷

```sip
METHOD SP Request-URI SP SIP/2.0 CRLF
Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776
Max-Forwards: 70
From: "Alice" <sip:alice@example.com>;tag=1928301774
To: <sip:bob@example.com>
Call-ID: a84b4c76e66710@pc33.example.com
CSeq: 314159 INVITE
Contact: <sip:alice@pc33.example.com>
Content-Type: application/sdp
Content-Length: 142

[Body]
```

#### Response 패킷

```sip
SIP/2.0 SP 200 SP OK CRLF
Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776
From: "Alice" <sip:alice@example.com>;tag=1928301774
To: <sip:bob@example.com>;tag=a6c85cf
Call-ID: a84b4c76e66710@pc33.example.com
CSeq: 314159 INVITE
Contact: <sip:bob@192.0.2.4>
Content-Type: application/sdp
Content-Length: 131

[Body]
```

### 2.3 필드 표면 분석

패킷 필드 비교 매트릭스 기준:

| 분류 | 개수 | 성격 |
|------|-----:|------|
| **공통 필드** | 28 | 상관관계 유지용 (Via, From, To, Call-ID, CSeq 등) |
| **요청 전용 필드** | 22 | 동작 의도/대상 제어 (Method, Request-URI, Max-Forwards, Route 등) |
| **응답 전용 필드** | 19 | 실패 원인/협상 결과/정책 설명 (Status-Code, Retry-After, WWW-Authenticate 등) |
| **합계** | **69** | |

**공통 필드 28개**: Accept, Accept-Encoding, Accept-Language, Allow, Allow-Events, Body, CSeq, Call-ID, Call-Info, Contact, Content-Disposition, Content-Encoding, Content-Language, Content-Length, Content-Type, Expires, From, Min-SE, Path, Reason, Record-Route, Recv-Info, Require, SIP-Version, Session-Expires, Supported, To, Via

**요청 전용 필드 22개**: Alert-Info, Event, Info-Package, Max-Forwards, Method, Organization, P-Asserted-Identity, Priority, Privacy, Proxy-Require, RAck, Refer-Sub, Refer-To, Referred-By, Replaces, Request-URI, Route, SIP-If-Match, Subject, Subscription-State, Target-Dialog, User-Agent

**응답 전용 필드 19개**: AlertMsg-Error, Authentication-Info, Error-Info, Geolocation-Error, Min-Expires, Permission-Missing, Proxy-Authenticate, RSeq, Reason-Phrase, Retry-After, SIP-ETag, Security-Server, Server, Service-Route, Status-Code, Timestamp, Unsupported, WWW-Authenticate, Warning

> [!note] 퍼징 함의
> SIP 퍼징은 아무 필드나 무작정 깨는 게 아니라:
> 1. **상관관계 필드**는 유지할지 깨뜨릴지 의도적으로 선택하고
> 2. **조건부 필드**는 "맞는 문맥에서만" 삽입 또는 삭제하고
> 3. **실패 응답을 유도하는 negotiation 필드**를 우선적으로 흔들어야 한다

### 2.4 Request보다 failure path가 더 넓다

응답 코드 전수조사에서 가장 눈에 띄는 점은 `4xx`가 `46개`로 가장 많다는 것이다. 이는:

- SIP 구현은 성공 경로보다 **실패 경로 분기가 더 많다**.
- 퍼징 우선순위도 `200 OK`를 잘 받는지보다, **실패 분기에서 구현체가 얼마나 일관되게 무너지지 않는지** 보는 쪽이 더 중요하다.
- 단말 구현체의 취약점은 파싱 성공 후의 **"상태 거절 처리"**에서 날 가능성이 높다.

실제로 `401`, `407`, `420`, `421`, `422`, `423`, `469`, `489`, `494` 같은 코드는 인증, 확장 협상, session timer, event framework, security agreement와 직접 연결된다.

---

# Part II. IANA 전수조사 데이터

## 3. SIP 메서드 — 14개 전수

| Method | Reference(s) |
|--------|-------------|
| ACK | RFC 3261 |
| BYE | RFC 3261 |
| CANCEL | RFC 3261 |
| INFO | RFC 6086 |
| INVITE | RFC 3261, RFC 6026 |
| MESSAGE | RFC 3428 |
| NOTIFY | RFC 6665 |
| OPTIONS | RFC 3261 |
| PRACK | RFC 3262 |
| PUBLISH | RFC 3903 |
| REFER | RFC 3515 |
| REGISTER | RFC 3261 |
| SUBSCRIBE | RFC 6665 |
| UPDATE | RFC 3311 |

### 3.1 단말(UE) 관점 수신 분류

#### 핵심 직접 수신 (5개)

| Method | RFC | 의미 | 전제조건 |
|--------|-----|------|---------|
| `INVITE` | RFC 3261 | 세션 생성/수정 (re-INVITE) | 없음 (re-INVITE는 dialog 필요) |
| `ACK` | RFC 3261 | INVITE 최종 응답 확인 | 선행 INVITE 트랜잭션 |
| `BYE` | RFC 3261 | 세션 종료 | 확정된 dialog |
| `CANCEL` | RFC 3261 | 미완료 INVITE 취소 | 진행중 INVITE 서버 트랜잭션 |
| `OPTIONS` | RFC 3261 | 기능/지원 능력 조회 | 없음 |

#### 조건부 수신 (7개)

| Method | RFC | 의미 | 전제조건 |
|--------|-----|------|---------|
| `PRACK` | RFC 3262 | reliable provisional response 확인 | 선행 reliable 1xx |
| `UPDATE` | RFC 3311 | 세션 파라미터 갱신 | early/confirmed dialog |
| `INFO` | RFC 6086 | mid-dialog 정보 전달 | 기존 dialog + Info-Package 협상 |
| `MESSAGE` | RFC 3428 | pager-mode 인스턴트 메시지 | in/out-of-dialog |
| `NOTIFY` | RFC 6665 | 이벤트 상태 통지 | 활성 subscription |
| `REFER` | RFC 3515 | 제3자 접촉 지시 (호 전환) | 주로 dialog 내 |
| `SUBSCRIBE` | RFC 6665 | 이벤트 상태 구독 | Event Package 지원 |

#### 비전형 수신 (2개)

| Method | RFC | 의미 | 비고 |
|--------|-----|------|------|
| `REGISTER` | RFC 3261 | AoR-Contact 바인딩 등록 | UE는 보통 UAC (발신자) |
| `PUBLISH` | RFC 3903 | 이벤트 상태 게시 | UE가 publication server인 경우만 |

---

## 4. SIP 응답 코드 — 75개 전수

### 4.1 클래스별 분포

```
1xx Informational  :   6개  ████
2xx Success        :   3개  ██
3xx Redirection    :   5개  ███
4xx Client Error   :  46개  ██████████████████████████████████████
5xx Server Error   :   9개  ██████
6xx Global Failure :   6개  ████
                      ─────
                      75개
```

### 4.2 전체 응답 코드 테이블

| Code | Reason Phrase | Class | Reference |
|------|--------------|-------|-----------|
| 100 | Trying | 1xx | RFC 3261 |
| 180 | Ringing | 1xx | RFC 3261 |
| 181 | Call Is Being Forwarded | 1xx | RFC 3261 |
| 182 | Queued | 1xx | RFC 3261 |
| 183 | Session Progress | 1xx | RFC 3261 |
| 199 | Early Dialog Terminated | 1xx | RFC 6228 |
| 200 | OK | 2xx | RFC 3261 |
| 202 | Accepted (Deprecated) | 2xx | RFC 6665 |
| 204 | No Notification | 2xx | RFC 5839 |
| 300 | Multiple Choices | 3xx | RFC 3261 |
| 301 | Moved Permanently | 3xx | RFC 3261 |
| 302 | Moved Temporarily | 3xx | RFC 3261 |
| 305 | Use Proxy | 3xx | RFC 3261 |
| 380 | Alternative Service | 3xx | RFC 3261 |
| 400 | Bad Request | 4xx | RFC 3261 |
| 401 | Unauthorized | 4xx | RFC 3261 |
| 402 | Payment Required | 4xx | RFC 3261 |
| 403 | Forbidden | 4xx | RFC 3261 |
| 404 | Not Found | 4xx | RFC 3261 |
| 405 | Method Not Allowed | 4xx | RFC 3261 |
| 406 | Not Acceptable | 4xx | RFC 3261 |
| 407 | Proxy Authentication Required | 4xx | RFC 3261 |
| 408 | Request Timeout | 4xx | RFC 3261 |
| 410 | Gone | 4xx | RFC 3261 |
| 412 | Conditional Request Failed | 4xx | RFC 3903 |
| 413 | Request Entity Too Large | 4xx | RFC 3261 |
| 414 | Request-URI Too Long | 4xx | RFC 3261 |
| 415 | Unsupported Media Type | 4xx | RFC 3261 |
| 416 | Unsupported URI Scheme | 4xx | RFC 3261 |
| 417 | Unknown Resource-Priority | 4xx | RFC 4412 |
| 420 | Bad Extension | 4xx | RFC 3261 |
| 421 | Extension Required | 4xx | RFC 3261 |
| 422 | Session Interval Too Small | 4xx | RFC 4028 |
| 423 | Interval Too Brief | 4xx | RFC 3261 |
| 424 | Bad Location Information | 4xx | RFC 6442 |
| 425 | Bad Alert Message | 4xx | RFC 8876 |
| 428 | Use Identity Header | 4xx | RFC 8224 |
| 429 | Provide Referrer Identity | 4xx | RFC 3892 |
| 430 | Flow Failed | 4xx | RFC 5626 |
| 433 | Anonymity Disallowed | 4xx | RFC 5079 |
| 436 | Bad Identity Info | 4xx | RFC 8224 |
| 437 | Unsupported Credential | 4xx | RFC 8224 |
| 438 | Invalid Identity Header | 4xx | RFC 8224 |
| 439 | First Hop Lacks Outbound Support | 4xx | RFC 5626 |
| 440 | Max-Breadth Exceeded | 4xx | RFC 5393 |
| 469 | Bad Info Package | 4xx | RFC 6086 |
| 470 | Consent Needed | 4xx | RFC 5360 |
| 480 | Temporarily Unavailable | 4xx | RFC 3261 |
| 481 | Call/Transaction Does Not Exist | 4xx | RFC 3261 |
| 482 | Loop Detected | 4xx | RFC 3261 |
| 483 | Too Many Hops | 4xx | RFC 3261 |
| 484 | Address Incomplete | 4xx | RFC 3261 |
| 485 | Ambiguous | 4xx | RFC 3261 |
| 486 | Busy Here | 4xx | RFC 3261 |
| 487 | Request Terminated | 4xx | RFC 3261 |
| 488 | Not Acceptable Here | 4xx | RFC 3261 |
| 489 | Bad Event | 4xx | RFC 6665 |
| 491 | Request Pending | 4xx | RFC 3261 |
| 493 | Undecipherable | 4xx | RFC 3261 |
| 494 | Security Agreement Required | 4xx | RFC 3329 |
| 500 | Server Internal Error | 5xx | RFC 3261 |
| 501 | Not Implemented | 5xx | RFC 3261 |
| 502 | Bad Gateway | 5xx | RFC 3261 |
| 503 | Service Unavailable | 5xx | RFC 3261 |
| 504 | Server Time-out | 5xx | RFC 3261 |
| 505 | Version Not Supported | 5xx | RFC 3261 |
| 513 | Message Too Large | 5xx | RFC 3261 |
| 555 | Push Notification Service Not Supported | 5xx | RFC 8599 |
| 580 | Precondition Failure | 5xx | RFC 3312 |
| 600 | Busy Everywhere | 6xx | RFC 3261 |
| 603 | Decline | 6xx | RFC 3261 |
| 604 | Does Not Exist Anywhere | 6xx | RFC 3261 |
| 606 | Not Acceptable | 6xx | RFC 3261 |
| 607 | Unwanted | 6xx | RFC 8197 |
| 608 | Rejected | 6xx | RFC 8688 |

### 4.3 단말 관점 주요 4xx 그룹핑

**범용 오류 (RFC 3261 Core)**: 400, 402, 403, 404, 405, 406, 408, 410, 413, 414, 415, 416, 480, 481, 482, 483, 484, 485, 486, 487, 488, 491, 493

**인증/보안**: 401, 407, 494

**확장/협상**: 417, 420, 421, 422, 423

**Identity/Privacy**: 428, 429, 433, 436, 437, 438

**특화 확장**: 412, 424, 425, 430, 439, 440, 469, 470, 489

---

## 5. SIP 헤더 필드 — 134개 전수

### 5.1 Slice A–H

| Header | Compact | Reference(s) | Meaning / Role | Flags |
|--------|:-------:|-------------|----------------|-------|
| `Accept` | — | RFC 3261 | 수용 가능한 media/body 포맷 선언 | |
| `Accept-Contact` | `a` | RFC 3841 | contact 선택 preference | |
| `Accept-Encoding` | — | RFC 3261 | 수용 가능한 content encoding | |
| `Accept-Language` | — | RFC 3261 | 수용 가능한 자연어 | |
| `Accept-Resource-Priority` | — | RFC 4412 | 수용 가능한 resource-priority namespace/값 | |
| `Additional-Identity` | — | 3GPP TS 24.229 v16.7.0 | 추가 asserted identity | 3GPP/IMS |
| `Alert-Info` | — | RFC 3261 | 수신자 알림 방식 보조 정보 | |
| `AlertMsg-Error` | — | RFC 8876 | alert-message 처리 오류 정보 | |
| `Allow` | — | RFC 3261 | 지원하는 SIP 메서드 목록 | |
| `Allow-Events` | `u` | RFC 6665 | 지원하는 이벤트 패키지 목록 | |
| `Answer-Mode` | — | RFC 5373 | 응답 처리 선호/요구 모드 | |
| `Attestation-Info` | — | 3GPP TS 24.229 v15.11.0 | attestation 관련 identity 정보 | 3GPP/IMS |
| `Authentication-Info` | — | RFC 3261 | 인증 교환 관련 파라미터 반환 | |
| `Authorization` | — | RFC 3261 | 클라이언트 인증 자격증명 | |
| `Call-ID` | `i` | RFC 3261 | dialog/call 인스턴스 전역 식별 | |
| `Call-Info` | — | RFC 3261 | 발신자/통화 추가 정보 (URI 참조) | |
| `Cellular-Network-Info` | — | 3GPP TS 24.229 v13.9.0 | 셀룰러 접근 네트워크/라디오 컨텍스트 | 3GPP/IMS |
| `Contact` | `m` | RFC 3261 | 직접 도달 가능한 URI 광고 | |
| `Content-Disposition` | — | RFC 3261 | 메시지 본문 해석/처리 방법 | |
| `Content-Encoding` | `e` | RFC 3261 | 본문 적용 인코딩 식별 | |
| `Content-ID` | — | RFC 8262 | 본문 파트/콘텐츠 객체 식별자 | |
| `Content-Language` | — | RFC 3261 | 본문 콘텐츠 언어 식별 | |
| `Content-Length` | `l` | RFC 3261 | 메시지 본문 길이 | |
| `Content-Type` | `c` | RFC 3261 | 메시지 본문 미디어 타입 | |
| `CSeq` | — | RFC 3261 | 순번 + method (transaction/dialog 순서) | |
| `Date` | — | RFC 3261 | SIP 메시지 타임스탬프 | |
| `DC-Info` | — | 3GPP TS 24.229 v19.4.1 | device/client 컨텍스트 정보 | 3GPP/IMS |
| `Encryption` | — | RFC 3261 | (Deprecated) 암호화 표시 | Deprecated |
| `Error-Info` | — | RFC 3261 | 오류 응답 추가 정보 (URI 참조) | |
| `Event` | `o` | RFC 6665, RFC 6446 | 구독/통지의 이벤트 패키지 식별 | |
| `Expires` | — | RFC 3261 | 등록/시간 제한 상태의 수명 | |
| `Feature-Caps` | — | RFC 6809 | 기능 능력 지표 광고 | |
| `Flow-Timer` | — | RFC 5626 | outbound 연결 flow keepalive 타이밍 | |
| `From` | `f` | RFC 3261 | 논리적 발신자/원점 식별 | |
| `Geolocation` | — | RFC 6442 | 위치 정보 전달/참조 | |
| `Geolocation-Error` | — | RFC 6442 | 위치 정보 전달/사용 오류 보고 | |
| `Geolocation-Routing` | — | RFC 6442 | 위치 정보 관련 라우팅 처리 표시 | |
| `Hide` | — | RFC 3261 | (Deprecated) 프라이버시 관련 | Deprecated |
| `History-Info` | — | RFC 7044 | 요청 라우팅 중 retargeting/diversion 이력 | |

### 5.2 Slice I–P

| Header | Compact | Reference(s) | Meaning / Role | Flags |
|--------|:-------:|-------------|----------------|-------|
| `Identity` | `y` | RFC 8224 | STIR 서명 발신자 identity assertion | |
| `Identity-Info` | — | RFC 8224 | (Deprecated by RFC 8224) identity 처리 정보 | Deprecated |
| `Info-Package` | — | RFC 6086 | INFO 요청의 패키지 시맨틱 식별 | |
| `In-Reply-To` | — | RFC 3261 | 이전 통신과의 상관관계 | |
| `Join` | — | RFC 3911 | 기존 dialog/call leg 합류 요청 | |
| `Max-Breadth` | — | RFC 5393 | 재귀/참조 작업의 fan-out 폭 제한 | |
| `Max-Forwards` | — | RFC 3261 | 요청 hop 수 제한 (루프 방지) | |
| `MIME-Version` | — | RFC 3261 | MIME 버전 컨텍스트 | |
| `Min-Expires` | — | RFC 3261 | 최소 허용 만료 간격 광고 | |
| `Min-SE` | — | RFC 4028 | 세션 타이머 최소 허용 간격 | |
| `Organization` | — | RFC 3261 | 발신자 조직 식별 (사람 읽기용) | |
| `Origination-Id` | — | 3GPP TS 24.229 v15.11.0 | IMS 절차 내 발신 관련 identity/correlation | 3GPP/IMS |
| `P-Access-Network-Info` | — | RFC 7315 | 사용자/디바이스 접근 네트워크 정보 | IMS |
| `P-Answer-State` | — | RFC 4964 | 통화 처리 로직용 응답 상태 정보 | |
| `P-Asserted-Identity` | — | RFC 3325 | 신뢰 네트워크 내 사용자 identity assertion | IMS |
| `P-Asserted-Service` | — | RFC 6050 | 서비스 중인 통신 서비스 assertion | IMS |
| `P-Associated-URI` | — | RFC 7315 | 서비스 사용자 연관 URI 목록 | IMS |
| `P-Called-Party-ID` | — | RFC 7315 | 피호출자 식별 (네트워크 보존) | IMS |
| `P-Charge-Info` | — | RFC 8496 | 과금 관련 정보 | IMS |
| `P-Charging-Function-Addresses` | — | RFC 7315 | 과금 기능 주소 | IMS |
| `P-Charging-Vector` | — | RFC 7315 | IMS 과금 기록용 상관관계 벡터 | IMS |
| `P-DCS-Trace-Party-ID` | — | RFC 5503 | DCS trace party 식별 | |
| `P-DCS-OSPS` | — | RFC 5503 | DCS operator-service 스타일 처리 | |
| `P-DCS-Billing-Info` | — | RFC 5503 | DCS 과금 정보 | |
| `P-DCS-LAES` | — | RFC 5503 | DCS 합법적 감청/감시 컨텍스트 | |
| `P-DCS-Redirect` | — | RFC 5503 | DCS 리다이렉트 관련 | |
| `P-Early-Media` | — | RFC 5009 | early-media 인가/처리 제어 | |
| `P-Media-Authorization` | — | RFC 3313 | 미디어 인가 토큰/자격증명 | |
| `P-Preferred-Identity` | — | RFC 3325 | 사용자 선호 identity (신뢰 네트워크 assertion용) | IMS |
| `P-Preferred-Service` | — | RFC 6050 | 선호 IMS 서비스 표현 | IMS |
| `P-Private-Network-Indication` | — | RFC 7316 | 사설 네트워크 사용/소속 표시 | |
| `P-Profile-Key` | — | RFC 5002 | 사용자/서비스 프로필 키 식별 | |
| `P-Refused-URI-List` | — | RFC 5318 | 요청 처리 중 거부된 URI 목록 | |
| `P-Served-User` | — | RFC 5502, RFC 8498 | IMS 서비스 로직 내 서비스 사용자 식별 | IMS |
| `P-User-Database` | — | RFC 4457 | 사용자 데이터베이스/HSS 소스 식별 | IMS |
| `P-Visited-Network-ID` | — | RFC 7315 | 방문 네트워크 식별 | IMS |
| `Path` | — | RFC 3327 | 등록 라우팅용 프록시 경로 정보 기록 | |
| `Permission-Missing` | — | RFC 5360 | 필요한 permission 정보 부재 신호 | |
| `Policy-Contact` | — | RFC 6794 | 정책 authority/서버 연락처 정보 | |
| `Policy-ID` | — | RFC 6794 | 정책 또는 정책 규칙 컨텍스트 식별 | |
| `Priority` | — | RFC 3261 | 요청 우선순위 수준 전달 | |
| `Priority-Share` | — | 3GPP TS 24.229 v13.16.0 | IMS 우선순위 공유 정보 | 3GPP/IMS |
| `Priority-Verstat` | — | 3GPP TS 24.229 | 우선순위 처리 관련 검증 상태 | 3GPP/IMS |
| `Priv-Answer-Mode` | — | RFC 5373 | 통화 처리 선호의 private 형태 | |
| `Privacy` | — | RFC 3323 | SIP identity 및 관련 정보 프라이버시 서비스 요청 | |
| `Proxy-Authenticate` | — | RFC 3261 | SIP 프록시가 생성한 인증 challenge | |
| `Proxy-Authorization` | — | RFC 3261 | 프록시 인증 challenge에 대한 자격증명 | |
| `Proxy-Require` | — | RFC 3261 | 프록시가 반드시 이해해야 하는 SIP 확장 선언 | |

### 5.3 Slice Q–Z

| Header | Compact | Reference(s) | Meaning / Role | Flags |
|--------|:-------:|-------------|----------------|-------|
| `RAck` | — | RFC 3262 | provisional response 신뢰성 확인 | |
| `Reason` | — | RFC 3326 | 요청/응답 생성 이유 (프로토콜별 cause) | |
| `Reason-Phrase` | — | Reserved | (Reserved) 일반 헤더가 아닌 예약된 이름 | Reserved |
| `Record-Route` | — | RFC 3261 | 프록시가 dialog 경로에 남기 위한 기록 | |
| `Recv-Info` | — | RFC 6086 | 수용할 INFO 패키지 본문 선언 | |
| `Refer-Events-At` | — | RFC 7614 | REFER 관련 이벤트 구독 방향 제어 | |
| `Refer-Sub` | — | RFC 4488 | REFER 요청의 implicit subscription 생성 여부 | |
| `Refer-To` | `r` | RFC 3515 | REFER가 수신자에게 접촉 요청하는 대상 리소스 | |
| `Referred-By` | `b` | RFC 3892 | referral을 시작/인가한 당사자 식별 | |
| `Reject-Contact` | `j` | RFC 3841 | 매칭되면 안 되는 contact feature preference | |
| `Relayed-Charge` | — | 3GPP TS 24.229 v12.14.0 | IMS 서비스 컨텍스트 과금 관련 | 3GPP/IMS |
| `Replaces` | — | RFC 3891 | 새 INVITE로 대체할 기존 dialog 식별 | |
| `Reply-To` | — | RFC 3261 | 답장/후속 통신 선호 주소 | |
| `Request-Disposition` | `d` | RFC 3841 | 요청 라우팅/처리 방법에 대한 caller preference | |
| `Require` | — | RFC 3261 | 요청 처리에 반드시 이해되어야 하는 option tag | |
| `Resource-Priority` | — | RFC 4412 | 우선 통신/선점 정책용 resource-priority 값 | |
| `Resource-Share` | — | 3GPP TS 24.229 v13.7.0 | IMS 리소스 공유 | 3GPP/IMS |
| `Response-Key` | — | RFC 3261 | (Deprecated) 초기 SIP 보안 작업의 응답 키잉 | Deprecated |
| `Response-Source` | — | 3GPP TS 24.229 v15.11.0 | SIP 응답의 소스 컨텍스트 식별 | 3GPP/IMS |
| `Restoration-Info` | — | 3GPP TS 24.229 v12.14.0 | IMS 서비스/세션 복원 처리 정보 | 3GPP/IMS |
| `Retry-After` | — | RFC 3261 | 일시적 실패/리다이렉션 후 재시도 시점 표시 | |
| `Route` | — | RFC 3261 | 특정 SIP 중개자를 통한 라우팅 경로 집합 | |
| `RSeq` | — | RFC 3262 | 신뢰성 있게 전송되는 provisional response 순서번호 | |
| `Security-Client` | — | RFC 3329 | 클라이언트가 지원하는 보안 메커니즘 목록 | |
| `Security-Server` | — | RFC 3329 | 서버가 제공하는 보안 메커니즘 목록 | |
| `Security-Verify` | — | RFC 3329 | 협상된 보안 메커니즘 에코/확인 | |
| `Server` | — | RFC 3261 | SIP 메시지 처리 소프트웨어 서버 식별 | |
| `Service-Interact-Info` | — | 3GPP TS 24.229 v13.18.0 | IMS 서비스 상호작용 조정 | 3GPP/IMS |
| `Service-Route` | — | RFC 3608 | 등록 시 학습한 향후 요청용 경로 집합 | |
| `Session-Expires` | `x` | RFC 4028 | SIP 세션 유지용 세션 타이머 간격 선언 | |
| `Session-ID` | — | RFC 7989 | 디바이스/중개자 간 SIP 세션 상관관계 식별자 | |
| `SIP-ETag` | — | RFC 3903 | SIP 이벤트 상태 publication 버전 태그 | |
| `SIP-If-Match` | — | RFC 3903 | SIP 이벤트 상태 publication 조건부 매칭 | |
| `Subject` | `s` | RFC 3261 | 세션/요청의 사람 읽기용 주제 텍스트 | |
| `Subscription-State` | — | RFC 6665 | SIP 이벤트 구독 현재 상태 보고 | |
| `Supported` | `k` | RFC 3261 | 발신자가 지원하지만 요구하지 않는 option tag | |
| `Suppress-If-Match` | — | RFC 5839 | SIP 이벤트 publication 조건부 억제 | |
| `Target-Dialog` | — | RFC 4538 | REFER 등 요청이 대상으로 하는 dialog 식별 | |
| `Timestamp` | — | RFC 3261 | 지연 측정/메시지 타이밍 진단용 타이밍 정보 | |
| `To` | `t` | RFC 3261 | 논리적 수신자 식별 | |
| `Trigger-Consent` | — | RFC 5360 | 위치 관련 정책 동의 처리 트리거 | |
| `Unsupported` | — | RFC 3261 | 수신자가 이해하지 못하는 option tag 목록 | |
| `User-Agent` | — | RFC 3261 | 발신 user agent 소프트웨어 식별 | |
| `User-to-User` | — | RFC 7433 | 애플리케이션 레벨 user-to-user 정보 end-to-end 전달 | |
| `Via` | `v` | RFC 3261, RFC 7118 | 응답이 중개자를 통해 되돌아갈 transport 경로 기록 | |
| `Warning` | — | RFC 3261 | 메시지 처리/상태에 대한 추가 경고 텍스트/코드 | |
| `WWW-Authenticate` | — | RFC 3261 | UAS의 인증 challenge 전달 | |

### 5.4 Compact Form 보유 헤더 (19개)

| Compact | Full Name |
|---------|-----------|
| `a` | Accept-Contact |
| `b` | Referred-By |
| `c` | Content-Type |
| `d` | Request-Disposition |
| `e` | Content-Encoding |
| `f` | From |
| `i` | Call-ID |
| `j` | Reject-Contact |
| `k` | Supported |
| `l` | Content-Length |
| `m` | Contact |
| `o` | Event |
| `r` | Refer-To |
| `s` | Subject |
| `t` | To |
| `u` | Allow-Events |
| `v` | Via |
| `x` | Session-Expires |
| `y` | Identity |

---

## 6. SIP/SIPS URI 파라미터 — 35개 전수

| URI Parameter | Predefined | Reference(s) | Short Meaning | Grouping |
|---------------|:----------:|-------------|---------------|----------|
| `aai` | No | RFC 5552 | 애플리케이션별 식별자/마커 | service-specific |
| `bnc` | No | RFC 6140 | flow/연결 마커 토큰 | routing / outbound |
| `cause` | Yes | RFC 4458, RFC 8119 | 원인/이유 표시자 | signaling |
| `ccxml` | No | RFC 5552 | CCXML 관련 서비스 파라미터 | service-specific |
| `comp` | Yes | RFC 3486 | 압축 처리 표시자 | transport / compression |
| `content-type` | No | RFC 4240 | URI 시맨틱 내 content type 표시자 | service-specific |
| `delay` | No | RFC 4240 | 지연/타이밍 제어 값 | media |
| `duration` | No | RFC 4240 | 재생 길이 값 | media |
| `extension` | No | RFC 4240 | 범용 확장 마커/값 | generic |
| `gr` | No | RFC 5627 | GRUU 관련 인스턴스 마커 | GRUU |
| `iotl` | Yes | RFC 7549 | IoT/위치 관련 토큰 | service-specific |
| `locale` | No | RFC 4240 | locale / 언어-지역 힌트 | service-specific |
| `lr` | No | RFC 3261 | loose routing 플래그 | routing |
| `m` | Yes | RFC 6910 | 메시지/메서드 관련 짧은 토큰 | service-specific |
| `maddr` | No | RFC 3261 | 멀티캐스트/메시지 목적지 주소 | routing / transport |
| `maxage` | No | RFC 5552 | 최대 나이 제약 | caching |
| `maxstale` | No | RFC 5552 | 최대 낡음 제약 | caching |
| `method` | Yes | RFC 3261, RFC 5552 | 메서드 선택기 | routing |
| `ob` | No | RFC 5626 | outbound 마커 | routing / outbound |
| `param[n]` | No | RFC 4240 | 번호 매긴 범용 파라미터 슬롯 | generic |
| `play` | No | RFC 4240 | 재생 제어 표시자 | media |
| `pn-param` | No | RFC 8599 | push notification 파라미터 페이로드 | push |
| `pn-prid` | No | RFC 8599 | push 등록 식별자 | push |
| `pn-provider` | No | RFC 8599 | push 공급자 식별자 | push |
| `pn-purr` | No | RFC 8599 | push 관련 라우팅/등록 토큰 | push |
| `postbody` | No | RFC 5552 | POST-body 표시자/콘텐츠 훅 | service-specific |
| `repeat` | No | RFC 4240 | 반복/재생 횟수 또는 플래그 | media |
| `sg` | No | RFC 6140 | 서비스/그룹 마커 토큰 | service-specific |
| `sigcomp-id` | No | RFC 5049 | SigComp 식별자 | transport / compression |
| `target` | No | RFC 4458 | 명시적 대상 지정자 | routing |
| `transport` | Yes | RFC 3261, RFC 7118 | transport 프로토콜 선택기 | transport |
| `ttl` | No | RFC 3261 | time-to-live 값 | transport / routing |
| `user` | Yes | RFC 3261, RFC 4967 | user-part 해석 선택기 | user-identification |
| `voicexml` | No | RFC 4240 | VoiceXML 관련 서비스 파라미터 | service-specific |

---

## 7. 헤더 필드 파라미터 — 201개 (주요 그룹)

43개 헤더 그룹에 분포된 201개 파라미터. 고밀도 영역만 발췌:

### 7.1 Authorization / Proxy-Authorization (11개)

`algorithm`, `auts`, `cnonce`, `nc`, `nonce`, `opaque`, `qop`, `realm`, `response`, `uri`, `username`

### 7.2 WWW-Authenticate / Proxy-Authenticate (7개)

`algorithm`, `domain`, `nonce`, `opaque`, `qop`, `realm`, `stale`

### 7.3 Authentication-Info (5개)

`cnonce`, `nc`, `nextnonce`, `qop`, `rspauth`

### 7.4 Security-Client / Security-Server / Security-Verify (7개)

`alg`, `ealg`, `mod`, `port1`, `port2`, `prot`, `spi`

### 7.5 Via (11개)

`branch`, `comp`, `keep`, `maddr`, `oc`, `oc-algo`, `oc-seq`, `oc-validity`, `received`, `rport`, `ttl`

> `sigcomp-id`도 Via에서 사용되나 URI parameter로 분류됨

### 7.6 Contact (9개)

`expires`, `mp`, `np`, `pub-gruu`, `q`, `rc`, `reg-id`, `temp-gruu`, `temp-gruu-cookie`

### 7.7 Event (15개)

`adaptive-min-rate`, `body`, `call-id`, `effective-by`, `from-tag`, `id`, `include-session-description`, `max-rate`, `min-rate`, `model`, `profile-type`, `shared`, `to-tag`, `vendor`, `version`

### 7.8 Subscription-State (3개)

`expires`, `reason`, `retry-after`

### 7.9 Reason (4개)

`cause`, `location`, `ppi`, `text`

### 7.10 Call-Info (5개)

`call-reason`, `integrity`, `m`, `purpose`, `verified`

### 7.11 From / To (1개 each)

`tag`

---

## 8. Option Tag — 36개 전수

| Option Tag | Reference | 카테고리 |
|-----------|-----------|---------|
| `100rel` | RFC 3262 | Provisional response reliability |
| `199` | RFC 6228 | Provisional response signaling |
| `answermode` | RFC 5373 | Call handling |
| `early-session` | RFC 3959 | Early media/session |
| `eventlist` | RFC 4662 | Event subscription |
| `explicitsub` | RFC 7614 | REFER/subscription control |
| `from-change` | RFC 4916 | Identity/dialog update |
| `geolocation-http` | RFC 6442 | Geolocation |
| `geolocation-sip` | RFC 6442 | Geolocation |
| `gin` | RFC 6140 | Registration |
| `gruu` | RFC 5627 | Registration/routing |
| `histinfo` | RFC 7044 | Request history |
| `ice` | RFC 5768 | NAT traversal/media |
| `join` | RFC 3911 | Dialog control |
| `multiple-refer` | RFC 5368 | REFER/resource lists |
| `norefersub` | RFC 4488 | REFER/subscription control |
| `nosub` | RFC 7614 | REFER/subscription control |
| `outbound` | RFC 5626 | Registration/connectivity |
| `path` | RFC 3327 | Registration/routing |
| `policy` | RFC 6794 | Policy control |
| `precondition` | RFC 3312 | Session preconditions |
| `pref` | RFC 3840 | Caller preferences |
| `privacy` | RFC 3323 | Privacy |
| `recipient-list-invite` | RFC 5366 | Recipient lists |
| `recipient-list-message` | RFC 5365 | Recipient lists |
| `recipient-list-subscribe` | RFC 5367 | Recipient lists |
| `record-aware` | RFC 7866 | Recording awareness |
| `replaces` | RFC 3891 | Dialog control |
| `resource-priority` | RFC 4412 | Priority/resource control |
| `sdp-anat` | RFC 4092 | SDP/media negotiation |
| `sec-agree` | RFC 3329 | Security |
| `siprec` | RFC 7866 | Session recording |
| `tdialog` | RFC 4538 | Dialog targeting |
| `timer` | RFC 4028 | Session maintenance |
| `trickle-ice` | RFC 8840 | NAT traversal/media |
| `uui` | RFC 7433 | User information |

---

## 9. 값 레지스트리 — 89행 (12개 registry)

### 9.1 Reason Protocol (22개)

| Value | Description | Reference |
|-------|------------|-----------|
| SIP | Status code | RFC 3261 |
| Q.850 | Cause value in decimal | ITU-T Q.850 |
| Preemption | Cause value in decimal | RFC 4411 |
| EMM | 3GPP EPS mobility management cause | 3GPP TS 24.301 |
| ESM | 3GPP EPS session management cause | 3GPP TS 24.301 |
| S1AP-RNL | Radio network layer cause | 3GPP TS 36.413 |
| S1AP-TL | Transport layer cause | 3GPP TS 36.413 |
| S1AP-NAS | Non-access stratum cause | 3GPP TS 36.413 |
| S1AP-MISC | Miscellaneous cause | 3GPP TS 36.413 |
| S1AP-PROT | S1 protocol cause | 3GPP TS 36.413 |
| DIAMETER | GTP-C WLAN protocol failure cause | 3GPP TS 29.274 |
| IKEV2 | IKEV2 untrusted WLAN cause | 3GPP TS 29.274 |
| RELEASE_CAUSE | cause 1~7: user end/RTP timeout/bearer loss/SIP timeout/setup timeout/redirect failure | 3GPP TS 24.229 |
| FAILURE_CAUSE | cause 1~3: bearer/QoS loss/signalling bearer release/failed resource allocation | 3GPP TS 24.229 |
| STIR | STIR error code | RFC 8224 |
| 5GMM | 5G mobility management cause | 3GPP TS 24.501 |
| 5GSM | 5G session management cause | 3GPP TS 24.501 |
| NGAP-RNL | Radio network layer cause | 3GPP TS 38.413 |
| NGAP-TL | Transport layer cause | 3GPP TS 38.413 |
| NGAP-NAS | Non-access stratum cause | 3GPP TS 38.413 |
| NGAP-MISC | Miscellaneous cause | 3GPP TS 38.413 |
| NGAP-PROT | NGAP protocol cause | 3GPP TS 38.413 |

### 9.2 Warning Code (15개)

| Code | Description |
|------|------------|
| 300 | Incompatible network protocol |
| 301 | Incompatible network address formats |
| 302 | Incompatible transport protocol |
| 303 | Incompatible bandwidth units |
| 304 | Media type not available |
| 305 | Incompatible media format |
| 306 | Attribute not understood |
| 307 | Session description parameter not understood |
| 308 | Incompatible language specification |
| 330 | Multicast not available |
| 331 | Unicast not available |
| 370 | Insufficient bandwidth |
| 380 | SIPS Not Allowed |
| 381 | SIPS Required |
| 399 | Miscellaneous warning |

### 9.3 Privacy 값 (7개)

| Value | Description |
|-------|------------|
| user | 사용자 수준 프라이버시 |
| header | Contact/Via 등 헤더 수정 요청 |
| session | 세션 미디어 프라이버시 |
| none | 프라이버시 적용 금지 |
| critical | 지정 서비스 수행 또는 요청 실패 |
| id | Third-Party Asserted Identity 프라이버시 |
| history | History-Info 헤더 프라이버시 |

### 9.4 Security Mechanism (5개)

`digest`, `tls`, `ipsec-ike`, `ipsec-man`, `ipsec-3gpp`

### 9.5 Compression Scheme (1개)

`sigcomp`

### 9.6 URI Purpose (7개)

`participation`, `streaming`, `event`, `recording`, `web-page`, `ccmp`, `grouptextchat`

### 9.7 Geolocation-Error Code (5개)

| Code | Description |
|------|------------|
| 100 | Cannot Process Location |
| 200 | Permission to Use Location Information |
| 201 | Permission to Retransmit Location Information to a Third Party |
| 202 | Permission to Route Based on Location Information |
| 300 | Deference Failure |

### 9.8 Reason Code (8개)

`deactivated`, `probation`, `rejected`, `timeout`, `giveup`, `noresource`, `invariant`, `badfilter`

### 9.9 Priority 값 (5개)

`non-urgent`, `normal`, `urgent`, `emergency`, `psap-callback`

### 9.10 SIP Transport (7개)

`UDP`, `TCP`, `TLS`, `SCTP`, `TLS-SCTP`, `WS`, `WSS`

### 9.11 Push Notification Service (3개)

| Value | Description |
|-------|------------|
| apns | Apple Push Notification service |
| fcm | Firebase Cloud Messaging |
| webpush | Generic Event Delivery Using HTTP Push |

### 9.12 AlertMsg-Error Code (4개)

| Code | Description |
|------|------------|
| 100 | Cannot process the alert payload |
| 101 | Alert payload was not present or could not be found |
| 102 | Not enough information to determine the purpose of the alert |
| 103 | Alert payload was corrupted |

---

## 10. 기능 식별자 레지스트리 — 71행 (12개 registry)

### 10.1 Identity Parameter (2개)

`alg`, `info`

### 10.2 Identity-Info Algorithm (2개)

`rsa-sha1`, `rsa-sha256`

### 10.3 SIP Forum UA Configuration Parameter (5개)

`sfua-id`, `sfua-user`, `sfua-vendor`, `sfua-model`, `sfua-revision`

### 10.4 Service-ID / Application-ID Label (2개)

`3gpp-service`, `3gpp-application`

### 10.5 Info Package (13개)

| Value | Reference |
|-------|-----------|
| g.3gpp.access-transfer-events | 3GPP TS 24.237 |
| g.3gpp.mid-call | 3GPP TS 24.237 |
| g.3gpp.ussd | 3GPP TS 24.390 |
| g.3gpp.state-and-event | 3GPP 24.237 |
| EmergencyCallData.eCall.MSD | RFC 8147 |
| EmergencyCallData.VEDS | RFC 8148 |
| infoDtmf | 3GPP 24.229 |
| g.3gpp.mcptt-floor-request | 3GPP 24.379 |
| g.3gpp.mcptt-info | 3GPP 24.379 |
| g.3gpp.mcdata-com-release | 3GPP TS 24.282 |
| trickle-ice | RFC 8840 |
| g.3gpp.mcvideo-info | 3GPP TS 24.281 |
| g.3gpp.current-location-discovery | 3GPP TS 24.229 |

### 10.6 SIP Configuration Profile Type (3개)

`local-network`, `device`, `user`

### 10.7 Feature-Capability Indicator Tree (2개)

`g.` (Global), `sip.` (SIP)

### 10.8 Global Feature-Capability Indicator (33개)

`g.3gpp.iut-focus`, `g.3gpp.mid-call`, `g.3gpp.atcf`, `g.3gpp.srvcc-alerting`, `g.3gpp.atcf-mgmt-uri`, `g.3gpp.srvcc`, `g.3gpp.atcf-path`, `g.3gpp.cs2ps-srvcc`, `g.3gpp.ti`, `g.3gpp.loopback`, `g.3gpp.trf`, `g.3gpp.home-visited`, `g.3gpp.mrb`, `g.3gpp.icsi-ref`, `g.3gpp.drvcc-alerting`, `g.3gpp.dynamic-stn`, `g.3gpp.ps2cs-drvcc-orig-pre-alerting`, `g.3gpp.ps2cs-srvcc-orig-pre-alerting`, `g.3gpp.cs2ps-drvcc-alerting`, `g.3gpp.cs2ps-drvcc-orig-pre-alerting`, `g.3gpp.ics`, `g.3gpp.registration-token`, `g.3gpp.verstat`, `g.3gpp.mcvideo.ambient-viewing-call-release`, `g.3gpp.mcptt.ambient-listening-call-release`, `g.3gpp.dynamic-e-stn-drvcc`, `g.3gpp.ps2cs-srvcc-term-pre-alerting`, `g.3gpp.priority-share`, `g.3gpp.thig-path`, `g.3gpp.anbr`, `g.3gpp.in-call-access-update`, `g.3gpp.datachannel`, `g.3gpp.dc-mux`

### 10.9 SIP Feature-Capability Indicator (6개)

| Value | Description |
|-------|------------|
| sip.607 | 서버가 607 (Unwanted) 응답 코드를 지원/처리함 |
| sip.pns | SIP push 메커니즘 및 push 서비스 타입 지원 |
| sip.vapid | VAPID 메커니즘 지원 (push subscription 제한용 공개키) |
| sip.pnsreg | binding-refresh REGISTER 수신 기대 |
| sip.pnspurr | mid-dialog 요청과 binding 정보 연관 저장 |
| sip.608 | 608 응답 코드의 Call-Info 정보 전달 책임 |

### 10.10 UUI (3개)

- **UUI Package**: `isdn-uui`
- **UUI Content**: `isdn-uui`
- **UUI Encoding**: `hex`

---

## 11. Resource-Priority — 48 namespace, 463 child value

### 11.1 Namespace 전수 (48개)

| Namespace | Levels | Algorithm | Reference |
|-----------|-------:|-----------|-----------|
| dsn | 5 | preemption | RFC 4412 |
| drsn | 6 | preemption | RFC 4412 |
| q735 | 5 | preemption | RFC 4412 |
| ets | 5 | queue | RFC 4412 |
| wps | 5 | queue | RFC 4412 |
| dsn-000000 ~ dsn-000009 | 10 each | preemption | RFC 5478 |
| drsn-000000 ~ drsn-000009 | 10 each | preemption | RFC 5478 |
| rts-000000 ~ rts-000009 | 10 each | preemption | RFC 5478 |
| crts-000000 ~ crts-000009 | 10 each | preemption | RFC 5478 |
| esnet | 5 | queue | RFC 7135 |
| mcpttp | 16 | preemption | RFC 8101 |
| mcpttq | 16 | queue | RFC 8101 |

### 11.2 Priority Value 분포

| 그룹 | Namespace 수 | Values/namespace | Total values |
|------|------------:|----------------:|-------------:|
| dsn | 1 | 5 | 5 |
| drsn | 1 | 6 | 6 |
| q735 | 1 | 5 | 5 |
| ets | 1 | 5 | 5 |
| wps | 1 | 5 | 5 |
| dsn-00000x | 10 | 10 | 100 |
| drsn-00000x | 10 | 10 | 100 |
| rts-00000x | 10 | 10 | 100 |
| crts-00000x | 10 | 10 | 100 |
| esnet | 1 | 5 | 5 |
| mcpttp | 1 | 16 | 16 |
| mcpttq | 1 | 16 | 16 |
| **합계** | **48** | | **463** |

---

## 12. IANA 레지스트리 커버리지 매트릭스

| Registry ID | Registry Title | Count | 본 문서 섹션 |
|-------------|---------------|------:|------------|
| sip-parameters-2 | Header Fields | 134 | §5 |
| sip-parameters-3 | Reason Protocols | 22 | §9.1 |
| sip-parameters-4 | Option Tags | 36 | §8 |
| sip-parameters-5 | Warning Codes | 15 | §9.2 |
| sip-parameters-6 | Methods and Response Codes | 14 | §3 |
| sip-parameters-7 | Response Codes | 75 | §4 |
| sip-parameters-8 | Privacy Header Field Values | 7 | §9.3 |
| sip-parameters-9 | Security Mechanism Names | 5 | §9.4 |
| sip-parameters-10 | Compression Schemes | 1 | §9.5 |
| sip-parameters-11 | SIP/SIPS URI Parameters | 35 | §6 |
| sip-parameters-12 | Header Field Parameters and Parameter Values | 201 | §7 |
| sip-parameters-13 | URI Purposes | 7 | §9.6 |
| sip-parameters-14 | Resource-Priority Namespaces | 48 | §11.1 |
| sip-parameters-15 | Resource-Priority Priority-values | 463 | §11.2 |
| sip-parameters-61 | Identity Parameters | 2 | §10.1 |
| sip-parameters-62 | Identity-Info Algorithm Values | 2 | §10.2 |
| sip-parameters-64 | SIP Forum UA Configuration Parameters | 5 | §10.3 |
| sip-parameters-65 | Service-ID/Application-ID Labels | 2 | §10.4 |
| sip-parameters-66 | Info Packages Registry | 13 | §10.5 |
| sip-parameters-67 | SIP Configuration Profile Types | 3 | §10.6 |
| sip-parameters-68 | Geolocation-Error Codes | 5 | §9.7 |
| sip-parameters-69 | Reason Codes | 8 | §9.8 |
| sip-parameters-70 | Feature-Capability Indicator Trees | 2 | §10.7 |
| sip-parameters-71 | Global Feature-Capability Indicators | 33 | §10.8 |
| sip-parameters-72 | SIP Feature-Capability Indicators | 6 | §10.9 |
| sip-parameters-73 | Priority Header Field Values | 5 | §9.9 |
| sip-transport | SIP Transport | 7 | §9.10 |
| uui-packages | UUI Packages | 1 | §10.10 |
| uui-content | UUI Content Parameters | 1 | §10.10 |
| uui-encoding | UUI Encoding Parameters | 1 | §10.10 |
| sip-pns | Push Notification Service | 3 | §9.11 |
| sip-alertmsg-error-codes | AlertMsg-Error Codes | 4 | §9.12 |

---

# Part III. 공격면 분석

## 13. Tier 구조

퍼징 관점에서 SIP 표면의 우선순위를 4계층으로 분류:

### Tier 1 — 핵심 상태 불변식

> [!danger] 가장 먼저 흔들어야 할 축

| 필드 | 역할 | 변조 방향 |
|------|------|----------|
| `Via.branch` | 트랜잭션 식별 | 상관관계 붕괴 |
| `Call-ID` | dialog/call 식별 | 상태 기계 혼란 |
| `CSeq` | 순서 + method | 순서 위반/method 불일치 |
| `From tag` / `To tag` | dialog 식별 | tag 불일치/누락 |
| `Contact` | 직접 도달 URI | URI 변조/누락 |

두 갈래 변조 전략:
1. **일관성 유지형** — 값만 경계 조건으로 흔들기
2. **상태 붕괴형** — 상관관계를 깨서 state machine 혼란

> [!tip] 단말 스택은 서버보다 방어적이지 않을 수 있다
> 서버는 불완전한 상관관계를 자주 보므로 방어적으로 작성되지만, 단말 스택은 그 정도로 강건하지 않을 수 있다.

### Tier 2 — 실패 분기 유도 표면

| 필드 그룹 | 유도 가능한 4xx |
|----------|----------------|
| `Supported`, `Require`, `Proxy-Require` | 420, 421 |
| `Allow`, `Allow-Events` | 405, 489 |
| `Unsupported` | 420 |
| `Security-*` | 494 |
| 인증 challenge/response | 401, 407 |

### Tier 3 — 상태 의존 확장

| 필드 | 관련 상태 기계 |
|------|--------------|
| `Event` | event framework |
| `Subscription-State` | subscription lifetime |
| `Info-Package` / `Recv-Info` | INFO package negotiation |
| `RAck` / `RSeq` | provisional reliability |
| `SIP-ETag` / `SIP-If-Match` | publication conditional update |

> [!note] 특성
> "문자열 형식은 맞지만 상태가 어긋난 메시지"를 만들기 좋은 영역

### Tier 4 — IMS/VoLTE 특화 표면

| 영역 | 헤더 |
|------|------|
| Identity | `P-Asserted-Identity`, `P-Preferred-Identity` |
| Network Info | `P-Access-Network-Info`, `P-Visited-Network-ID` |
| Charging | `P-Charging-Vector`, `P-Charging-Function-Addresses`, `P-Charge-Info` |
| Capability | `Feature-Caps`, `Resource-Priority` |
| Routing | `Path`, `Service-Route` |

> [!important] 차별점
> 단말 지향 퍼저의 핵심 차별점은 이 **IMS/3GPP private surface를 정면으로 다룬다**는 것이다. generic SIP만으로는 상용 VoLTE 단말의 실제 코드 경로를 충분히 자극하지 못한다.

## 14. Rare but High-Value 표면

메시지 빈도는 낮지만 구현체 분기 수가 큰 영역:

- **Resource-Priority** — 48개 namespace + 463개 값
- **Feature-Caps** — 39개 indicator
- **Push Notification** — `sip.pns`, `pn-*` 파라미터
- **에러 코드** — `Warning` (15), `Reason` (22 protocol + 8 code), `Geolocation-Error` (5), `AlertMsg-Error` (4)
- **UUI** — `User-to-User` 파라미터/인코딩

> [!quote] 드물지만 별도 코드 경로를 타는 메시지가 취약점 탐색 효율이 높을 수 있다

## 15. 실험 우선순위 (Softphone-First)

### 15.1 Tier 1 — 즉시 실험

| 영역 | 이유 | 필요 타깃 |
|------|------|----------|
| INVITE provisional/final response | dialog 형성, 상태 전이가 크고 분기 수가 많다 | softphone |
| MESSAGE success/error | non-dialog baseline 검증에 좋다 | softphone |
| REGISTER 성공 응답 | Contact, Path, Service-Route 반영 | softphone 또는 registrar test double |
| SUBSCRIBE/NOTIFY/PUBLISH | 상태성 필드 집중 | programmable softphone |

### 15.2 Tier 2 — IMS/확장 상태

| 영역 | 이유 |
|------|------|
| PRACK, UPDATE | early dialog + precondition 흐름 |
| INFO, Info-Package | mid-dialog feature negotiation |
| Security-*, WWW-Authenticate | IMS/AKA + security agreement |

### 15.3 Tier 3 — IMS private / carrier-specific

| 영역 | 필요 타깃 |
|------|----------|
| P-Asserted-Identity, P-Access-Network-Info, P-Charging-* | real-ue/pcscf |
| Feature-Caps, Resource-Priority | controlled IMS peer |
| Path, Service-Route | real-ue/pcscf |

### 15.4 Tier 4 — Parser robustness / byte damage

| 영역 | 이유 |
|------|------|
| header 삭제/중복/순서 변경 | parser robustness |
| Content-Length mismatch | framing robustness |
| delimiter damage / byte truncation | low-level parser stress |

### 15.5 실험 순서

```
1. OPTIONS / MESSAGE baseline  → send/receive 경로 안정화
2. INVITE 1xx/2xx              → provisional/final response 수집 검증
3. SUBSCRIBE/NOTIFY/PUBLISH    → 상태성 필드 실험
4. wire/byte mutation artifact → parser robustness
5. real-ue/pcscf/direct        → 같은 우선순위 체계 재사용
```

---

# Part IV. 구현 연결 및 결론

## 16. Generator/Mutator/Sender 함의

### 16.1 Generator

- 정상 baseline은 "문법적으로 맞는 메시지" 이상이어야 한다
- method/code별 필수 필드와 문맥 필드 보존 필수
- wire text가 아니라 **구조화된 Pydantic 모델**이 기준 산출물

### 16.2 Mutator

| 계층 | 적합한 변조 대상 |
|------|----------------|
| **model** | 상태 필드, 의미 필드 (Tier 1~3) |
| **wire** | 헤더 삭제/중복/순서 변경, Content-Length 불일치 (Tier 4) |
| **byte** | parser robustness, delimiter damage (Tier 4) |

> [!success] 설계 적합성
> 프로젝트의 `model → wire → byte` 3계층 변조 분리는 SIP 특성상 **필요한 분리**이며, 과도한 설계가 아니다.

### 16.3 Sender/Reactor

SIP는 "응답이 없으면 실패"로 단순 판정할 수 없다. 최소 관측 계층:

```
1. socket response         → 직접 SIP 응답
2. network trace           → 패킷 도달 여부
3. device-side observer    → 크래시/ANR/재부팅 탐지
```

## 17. 최종 결론

### 17.1 조사 범위

SIP 표면 조사는 이미 충분히 깊다. 지금 필요한 것은 더 많은 인벤토리보다는, 그 인벤토리 중 어떤 부분이 단말 퍼징에 가장 큰 효용을 가지는지 **우선순위를 정하는 일**이다.

### 17.2 프로토콜 이해

SIP는 본질적으로 **상태 기계**다. parser만 흔드는 퍼저는 충분하지 않다. transaction, dialog, capability negotiation, event framework, security agreement를 함께 흔들어야 한다.

### 17.3 VoLTE/IMS

단말 지향 SIP 퍼징의 핵심 차별점은 **IMS/3GPP private surface를 정면으로 다룬다**는 점이다. generic SIP만으로는 상용 VoLTE 단말의 실제 코드 경로를 충분히 자극하지 못할 수 있다.

### 17.4 공통 필드는 적고 조건부 규칙이 많다

- 공통 필드는 상관관계 유지에 쓰인다
- 요청 전용 필드는 동작 의도와 대상 제어에 가깝다
- 응답 전용 필드는 실패 원인, 협상 결과, 정책 설명에 가깝다

### 17.5 프로젝트 실행

현재 프로젝트의 가장 큰 공백은 조사 문서가 아니라, **Sender/Reactor와 실험 환경 결정**이다. 따라서 다음 단계의 중심은 "추가 조사"보다 **"우선순위가 접힌 실행 설계와 구현"**이어야 한다.

---

## 참조 RFC 목록

| RFC | 제목 | 핵심 내용 |
|-----|------|----------|
| RFC 3261 | SIP: Session Initiation Protocol | Core SIP |
| RFC 3262 | Reliability of Provisional Responses | PRACK, RSeq, RAck |
| RFC 3310 | HTTP Digest Authentication Using AKA | AKA auts parameter |
| RFC 3311 | SIP UPDATE Method | UPDATE |
| RFC 3312 | Integration of Resource Management and SIP | Precondition |
| RFC 3313 | Private SIP Extensions for Media Authorization | P-Media-Authorization |
| RFC 3323 | A Privacy Mechanism for SIP | Privacy |
| RFC 3325 | Private Extensions for Asserted Identity | P-Asserted/Preferred-Identity |
| RFC 3326 | The Reason Header Field | Reason |
| RFC 3327 | SIP Extension Header for Registering Non-Adjacent Contacts | Path |
| RFC 3329 | Security Mechanism Agreement for SIP | Security-Client/Server/Verify |
| RFC 3428 | SIP Extension for Instant Messaging | MESSAGE |
| RFC 3486 | Compressing the SIP | comp, sigcomp |
| RFC 3515 | The SIP Refer Method | REFER |
| RFC 3608 | SIP Extension for Service Route Discovery | Service-Route |
| RFC 3840 | Indicating UA Capabilities in SIP | pref |
| RFC 3841 | Caller Preferences for SIP | Accept-Contact, Reject-Contact |
| RFC 3891 | The SIP "Replaces" Header | Replaces |
| RFC 3892 | The SIP Referred-By Mechanism | Referred-By |
| RFC 3903 | SIP Extension for Event State Publication | PUBLISH, SIP-ETag |
| RFC 3911 | The SIP "Join" Header | Join |
| RFC 4028 | Session Timers in SIP | Session-Expires, Min-SE |
| RFC 4092 | Usage of the SDP ANAT Semantics | sdp-anat |
| RFC 4240 | Basic Network Media Services with SIP | URI media params |
| RFC 4411 | Extending the SIP Reason Header for Preemption Events | Preemption reason |
| RFC 4412 | Communications Resource Priority for SIP | Resource-Priority |
| RFC 4458 | SIP URIs for Applications such as Voicemail and IVR | cause, target URI params |
| RFC 4488 | Suppression of Session Initiation Protocol REFER Implicit Subscription | Refer-Sub, norefersub |
| RFC 4538 | Request Authorization through Dialog Identification | Target-Dialog |
| RFC 4662 | A SIP Event Notification Extension for Resource Lists | eventlist |
| RFC 4916 | Connected Identity in SIP | from-change |
| RFC 4964 | The P-Answer-State Header Extension to SIP | P-Answer-State |
| RFC 5002 | The SIP P-Profile-Key Private Header | P-Profile-Key |
| RFC 5009 | Private Header for the P-Early-Media Authorization | P-Early-Media |
| RFC 5049 | Applying Signaling Compression to SIP | sigcomp-id |
| RFC 5079 | Rejecting Anonymous Requests in SIP | 433 |
| RFC 5318 | The SIP P-Refused-URI-List Private Header | P-Refused-URI-List |
| RFC 5360 | A Framework for Consent-Based Communications | Permission-Missing |
| RFC 5373 | Requesting Answering Modes for SIP | Answer-Mode |
| RFC 5393 | Addressing an Amplification Vulnerability | Max-Breadth |
| RFC 5478 | IANA Registration of New Session Initiation Protocol Resource-Priority Namespaces | dsn/drsn/rts/crts extended |
| RFC 5502 | The SIP P-Served-User Private Header | P-Served-User |
| RFC 5503 | Private SIP Proxy-to-Proxy Extensions (DCS) | P-DCS-* |
| RFC 5552 | SIP Interface to VoiceXML Media Services | URI service params |
| RFC 5626 | Managing Client-Initiated Connections | Flow-Timer, outbound, ob |
| RFC 5627 | Obtaining and Using GRUUs in SIP | GRUU, gr, pub-gruu |
| RFC 5630 | The Use of the SIPS URI Scheme in SIP | Warning 380/381 |
| RFC 5839 | An Extension to SIP Events for Conditional Subscriptions | Suppress-If-Match, 204 |
| RFC 5989 | A SIP Event Package for Subscribing to Changes to an HTTP Resource | Event body param |
| RFC 6011 | SIP UA Configuration | sfua-* params |
| RFC 6026 | Correct Transaction Handling for 2xx Responses to SIP INVITE | INVITE 2xx handling |
| RFC 6050 | A SIP Extension for the Identification of Services | P-*-Service |
| RFC 6080 | A Framework for SIP UA Profile Delivery | Event profile params |
| RFC 6086 | SIP INFO Method and Package Framework | INFO, Info-Package |
| RFC 6140 | Registration for Multiple Phone Numbers in SIP | gin, bnc, sg |
| RFC 6228 | Response Code for Indication of Terminated Dialog | 199 |
| RFC 6442 | Location Conveyance for SIP | Geolocation |
| RFC 6446 | Session Initiation Protocol Event Package for Throttle Control | Event rate params |
| RFC 6665 | SIP-Specific Event Notification | SUBSCRIBE, NOTIFY |
| RFC 6794 | A Framework for Session Policy in SIP | Policy-Contact/ID |
| RFC 6809 | Mechanism to Indicate Support of Features | Feature-Caps |
| RFC 6878 | IANA Registry for the SIP Priority Header Field | Priority values |
| RFC 6910 | Completion of Calls for SIP | m param |
| RFC 7044 | An Extension to SIP for Request History Information | History-Info |
| RFC 7082 | Indication of Conference Focus Support for SIP | ccmp URI purpose |
| RFC 7118 | The WebSocket Protocol as a Transport for SIP | WS/WSS transport |
| RFC 7134 | The Management Policy of the Resource Priority Header IANA Registry | RP policy update |
| RFC 7135 | Registering a SIP Resource Priority Header Field Namespace for Local Emergency Communications | esnet |
| RFC 7315 | Private Header Extensions to SIP for 3GPP | P-Charging-*, P-Access-* |
| RFC 7316 | The Session Initiation Protocol P-Private-Network-Indication | P-Private-Network-Indication |
| RFC 7433 | A Mechanism for Transporting UUI Data in SIP | User-to-User |
| RFC 7434 | Interworking ISDN Call Control User Information with SIP | isdn-uui |
| RFC 7463 | Shared Appearances of a SIP AOR | appearance, shared params |
| RFC 7549 | 3GPP SIP URI Inter-Operator Traffic Leg Parameter | iotl |
| RFC 7614 | Explicit Subscriptions for the REFER Method | explicitsub, nosub |
| RFC 7852 | Marking SIP Messages to Be Logged | Call-Info purpose |
| RFC 7866 | Session Recording Protocol | record-aware, siprec |
| RFC 7989 | End-to-End Session Identification in IP Communications | Session-ID |
| RFC 8101 | IANA Registration of New SIP RP Namespaces for MCPTT | mcpttp, mcpttq |
| RFC 8147 | Next-Generation Pan-European eCall | EmergencyCallData.eCall.MSD |
| RFC 8148 | Next-Generation Vehicle-Initiated Emergency Calls | EmergencyCallData.VEDS |
| RFC 8197 | A SIP Response Code for Unwanted Calls | 607 |
| RFC 8224 | Authenticated Identity Management in SIP | Identity |
| RFC 8262 | Content-ID Header Field in SIP | Content-ID |
| RFC 8373 | Negotiating Human Language in Real-Time Communications | Warning 308 |
| RFC 8496 | P-Charge-Info | P-Charge-Info |
| RFC 8498 | A P-Served-User Header Field Parameter for an Originating CDIV | P-Served-User update |
| RFC 8599 | Push Notification with SIP | 555, PNS, sip.pns |
| RFC 8688 | A SIP Response Code for Rejected Calls | 608 |
| RFC 8840 | A SIP Usage for Trickle ICE | trickle-ice |
| RFC 8876 | Non-Interactive Emergency Calls | AlertMsg-Error |

---

> [!info] 공식 출처
> - [IANA Session Initiation Protocol (SIP) Parameters](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml)
> - [IANA XML export](https://www.iana.org/assignments/sip-parameters/sip-parameters.xml)
> - IANA XML 스냅샷: `.omx/research/sip-iana-full-20260318/sip-parameters.xml`
