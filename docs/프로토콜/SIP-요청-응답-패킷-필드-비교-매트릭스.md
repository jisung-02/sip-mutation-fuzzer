# SIP 요청/응답 패킷 필드 비교 매트릭스

기준 일자: 2026-03-19

## 1. 문서 목적
이 문서는 지금까지의 RFC/IANA 리서치와 현재 프로젝트 catalog/model 정의를 기준으로, SIP 요청 패킷과 응답 패킷의 field surface를 누락 없이 비교해 읽기 좋은 형태로 정리한 문서다.

비교 기준:
- source of truth 1: `docs/프로토콜/SIP-요청-응답-오피셜-필드-리서치.md`의 의미/규칙 설명
- source of truth 2: `src/volte_mutation_fuzzer/sip/requests.py`의 14개 request definition
- source of truth 3: `src/volte_mutation_fuzzer/sip/responses.py`의 75개 response definition

이 문서가 커버하는 surface는 다음과 같다.
- request definitions: `14`
- response definitions: `75`
- union field count: `69`
- shared fields: `28`
- request-only fields: `22`
- response-only fields: `19`

## 2. 한눈에 보는 패킷 구조
### 2.1 Request packet
```text
METHOD SP Request-URI SP SIP/2.0
Via: ...
Max-Forwards: ...
From: ...
To: ...
Call-ID: ...
CSeq: ...
[기타 헤더들]

[Body]
```

### 2.2 Response packet
```text
SIP/2.0 SP Status-Code SP Reason-Phrase
Via: ...
From: ...
To: ...
Call-ID: ...
CSeq: ...
[기타 헤더들]

[Body]
```

## 3. 핵심 차이 요약
| Aspect | Request packet | Response packet | Why it matters |
| --- | --- | --- | --- |
| Request start-line | Method + Request-URI + SIP-Version | - | 요청은 동작과 대상을 start-line에서 직접 선언한다. |
| Response start-line | - | SIP-Version + Status-Code + Reason-Phrase | 응답은 결과 코드를 start-line에서 직접 선언한다. |
| Universal transaction/dialog core | Via, From, To, Call-ID, CSeq | Via, From, To, Call-ID, CSeq | 양쪽 모두 상관관계와 routing을 유지하는 공통 핵심이다. |
| Request-only universal field | Max-Forwards | - | hop limit은 요청에서만 감소하며 루프를 막는다. |
| Response-only universal nuance | - | To tag rule (except 100) | 응답은 dialog 식별을 위해 To tag 규칙이 추가된다. |

## 4. Field family summary
- Shared fields `28`: `Accept, Accept-Encoding, Accept-Language, Allow, Allow-Events, Body, CSeq, Call-ID, Call-Info, Contact, Content-Disposition, Content-Encoding, Content-Language, Content-Length, Content-Type, Expires, From, Min-SE, Path, Reason, Record-Route, Recv-Info, Require, SIP-Version, Session-Expires, Supported, To, Via`
- Request-only fields `22`: `Alert-Info, Event, Info-Package, Max-Forwards, Method, Organization, P-Asserted-Identity, Priority, Privacy, Proxy-Require, RAck, Refer-Sub, Refer-To, Referred-By, Replaces, Request-URI, Route, SIP-If-Match, Subject, Subscription-State, Target-Dialog, User-Agent`
- Response-only fields `19`: `AlertMsg-Error, Authentication-Info, Error-Info, Geolocation-Error, Min-Expires, Permission-Missing, Proxy-Authenticate, RSeq, Reason-Phrase, Retry-After, SIP-ETag, Security-Server, Server, Service-Route, Status-Code, Timestamp, Unsupported, WWW-Authenticate, Warning`

## 5. 전체 필드 비교 매트릭스
표 읽는 법:
- `모든 요청/응답에서 핵심`은 현재 definition 전체에서 공통 핵심으로 취급되는 필드다.
- `일부 요청/응답에서 필수`는 특정 method/code에서만 강하게 요구되는 필드다.
- `조건부 규칙 있음`은 아래 Appendix의 RFC 조건을 반드시 함께 봐야 하는 필드다.
- `선택 가능`은 현재 surface에 존재하지만 모든 메시지에서 필수는 아닌 필드다.
- `선택 가능: METHOD...`처럼 보이면, 그 method subset에서만 surface가 열려 있다는 뜻이다.

### 5.1 Start-Line
| Field | Location | Request side | Response side | Meaning | Comparison point |
| --- | --- | --- | --- | --- | --- |
| Method | Start-Line | 모든 요청에서 핵심 | 없음 | 요청의 동작 종류를 나타내는 start-line 토큰 | 요청에만 존재하는 시작줄 토큰이다. |
| Reason-Phrase | Start-Line | 없음 | 모든 응답에서 핵심 | 상태 코드의 사람이 읽는 설명 | 응답 상태를 사람이 읽는 텍스트로 보강한다. |
| Request-URI | Start-Line | 모든 요청에서 핵심 | 없음 | 요청이 향하는 논리적 대상 URI | 요청의 대상 URI이며 응답에는 대응 필드가 없다. |
| SIP-Version | Start-Line | 모든 요청에서 핵심 | 모든 응답에서 핵심 | 프로토콜 버전 표기 | 양쪽 모두 `SIP/2.0`이지만 요청과 응답의 시작줄 위치가 같다. |
| Status-Code | Start-Line | 없음 | 모든 응답에서 핵심 | 응답의 숫자 결과 코드 | 응답에만 존재하는 결과 코드다. |

### 5.2 Routing / Transaction
| Field | Location | Request side | Response side | Meaning | Comparison point |
| --- | --- | --- | --- | --- | --- |
| CSeq | Header | 모든 요청에서 핵심 | 모든 응답에서 핵심 | 순번 + method 조합 | 양쪽 surface 차이는 하단 조건부 규칙 표를 함께 봐야 정확하다. |
| Call-ID | Header | 모든 요청에서 핵심 | 모든 응답에서 핵심 | 전체 call/dialog/transaction 계열을 식별하는 고유 ID | 양쪽 surface 차이는 하단 조건부 규칙 표를 함께 봐야 정확하다. |
| Contact | Header | 일부 요청에서 필수: INVITE, NOTIFY, REFER, SUBSCRIBE, UPDATE; 조건부 규칙 있음 | 일부 응답에서 필수: 300, 301, 302, 305; 조건부 규칙 있음 | 해당 UA에게 직접 도달할 수 있는 URI | 양쪽 모두 중요하지만 요청은 자신을 광고하고 응답은 remote target/redirect target을 돌려준다. |
| From | Header | 모든 요청에서 핵심 | 모든 응답에서 핵심 | 논리적 발신자 식별 | 양쪽 surface 차이는 하단 조건부 규칙 표를 함께 봐야 정확하다. |
| Max-Forwards | Header | 모든 요청에서 핵심 | 없음 | 요청이 거칠 수 있는 최대 hop 수 | 해당 방향의 전용 필드다. |
| Path | Header | 선택 가능: REGISTER | 조건부 규칙 있음 | registration path vector | 요청은 REGISTER path 벡터를 싣고, 응답은 성공 REGISTER에서 이를 반영할 수 있다. |
| Record-Route | Header | 선택 가능 | 조건부 규칙 있음 | 프록시가 이후 dialog path에 남기 위한 기록 | 요청과 응답 모두 가능하지만 dialog-establishing 응답에서 복사 규칙이 특히 중요하다. |
| Route | Header | 조건부 규칙 있음 | 없음 | 미리 정해진 라우팅 경로 | 실질적으로 요청 쪽 라우팅 제어에만 쓰인다. |
| Service-Route | Header | 없음 | 조건부 규칙 있음 | 등록 후 사용할 서비스 경로 | 응답, 특히 REGISTER 성공 응답에서 미래 요청 경로를 돌려줄 때 중요하다. |
| To | Header | 모든 요청에서 핵심 | 모든 응답에서 핵심 | 논리적 수신자 식별 | 양쪽 모두 핵심이며, 응답은 `100 Trying`을 제외하면 To tag 규칙이 추가된다. |
| Via | Header | 모든 요청에서 핵심 | 모든 응답에서 핵심 | 응답이 되돌아갈 transport 경로와 branch를 담는 헤더 | 양쪽 모두 핵심이지만 요청은 경로를 쌓고 응답은 그 경로를 되짚는다. |

### 5.3 Capability / Negotiation
| Field | Location | Request side | Response side | Meaning | Comparison point |
| --- | --- | --- | --- | --- | --- |
| Accept | Header | 선택 가능 | 선택 가능 | 허용 가능한 media type 목록 | 양쪽 surface 차이는 하단 조건부 규칙 표를 함께 봐야 정확하다. |
| Accept-Encoding | Header | 선택 가능 | 선택 가능 | 허용 가능한 content encoding 목록 | 양쪽 surface 차이는 하단 조건부 규칙 표를 함께 봐야 정확하다. |
| Accept-Language | Header | 선택 가능 | 선택 가능 | 허용 가능한 자연어 목록 | 양쪽 surface 차이는 하단 조건부 규칙 표를 함께 봐야 정확하다. |
| Allow | Header | 선택 가능 | 일부 응답에서 필수: 405 | 해당 UA가 처리 가능한 method 목록 | 요청과 응답 모두 실을 수 있지만 405 응답에서 필수 규칙이 있다. |
| Allow-Events | Header | 선택 가능 | 조건부 규칙 있음 | 지원하는 event package 목록 | 양쪽 surface 차이는 하단 조건부 규칙 표를 함께 봐야 정확하다. |
| Info-Package | Header | INFO에서만; 조건부 규칙 있음 | 없음 | 해당 INFO request의 package 이름 | 실질적으로 INFO request에서만 의미가 있다. |
| Min-Expires | Header | 없음 | 일부 응답에서 필수: 423 | 허용 가능한 최소 expires 값 | 사실상 423 응답 설명용 필드다. |
| Min-SE | Header | 선택 가능: INVITE, UPDATE | 일부 응답에서 필수: 422 | 최소 session timer 값 | 요청과 응답 모두 가능하지만 422 응답에서 특히 강한 규칙이 있다. |
| Proxy-Require | Header | 선택 가능 | 없음 | 경로 상의 proxy가 이해해야 하는 option tag 목록 | 해당 방향의 전용 필드다. |
| Recv-Info | Header | INVITE, PRACK, REGISTER, UPDATE에서만; 조건부 규칙 있음 | 일부 응답에서 필수: 469; 조건부 규칙 있음 | 수신자가 받을 수 있는 INFO package 목록 | 요청은 지원 package 광고, 응답은 INFO framework 연계 시 반사/협상 정보 역할이 강하다. |
| Require | Header | 선택 가능 | 일부 응답에서 필수: 421, 494; 조건부 규칙 있음 | 수신자가 반드시 이해해야 하는 option tag 목록 | 양쪽 surface 차이는 하단 조건부 규칙 표를 함께 봐야 정확하다. |
| Session-Expires | Header | 선택 가능: INVITE, UPDATE | 선택 가능 | session timer 만료 시간 | 양쪽 surface 차이는 하단 조건부 규칙 표를 함께 봐야 정확하다. |
| Supported | Header | 선택 가능 | 조건부 규칙 있음 | 발신자가 지원하는 option tag 목록 | 양쪽 surface 차이는 하단 조건부 규칙 표를 함께 봐야 정확하다. |
| Unsupported | Header | 없음 | 일부 응답에서 필수: 420 | 이해하지 못한 option tag 목록 | 해당 방향의 전용 필드다. |

### 5.4 Body / Payload
| Field | Location | Request side | Response side | Meaning | Comparison point |
| --- | --- | --- | --- | --- | --- |
| Body | Body | 조건부 규칙 있음 | 조건부 규칙 있음 | 메시지 본문 | 양쪽 surface 차이는 하단 조건부 규칙 표를 함께 봐야 정확하다. |
| Content-Disposition | Header | 선택 가능 | 선택 가능 | body 처리 방식 | 양쪽 surface 차이는 하단 조건부 규칙 표를 함께 봐야 정확하다. |
| Content-Encoding | Header | 선택 가능 | 선택 가능 | body에 적용된 content coding | 양쪽 surface 차이는 하단 조건부 규칙 표를 함께 봐야 정확하다. |
| Content-Language | Header | 선택 가능 | 선택 가능 | body 자연어 | 양쪽 surface 차이는 하단 조건부 규칙 표를 함께 봐야 정확하다. |
| Content-Length | Header | 선택 가능 | 선택 가능 | body 바이트 길이 | 양쪽 surface 차이는 하단 조건부 규칙 표를 함께 봐야 정확하다. |
| Content-Type | Header | 선택 가능 | 선택 가능 | body media type | 양쪽 surface 차이는 하단 조건부 규칙 표를 함께 봐야 정확하다. |

### 5.5 Presentation / UI
| Field | Location | Request side | Response side | Meaning | Comparison point |
| --- | --- | --- | --- | --- | --- |
| Alert-Info | Header | 선택 가능 | 없음 | 호출 시 사용자 단말의 alerting style에 대한 정보 | 해당 방향의 전용 필드다. |
| Call-Info | Header | 선택 가능 | 조건부 규칙 있음 | call/resource 관련 추가 정보 URI | 양쪽 surface 차이는 하단 조건부 규칙 표를 함께 봐야 정확하다. |
| Organization | Header | 선택 가능 | 없음 | 발신 조직 이름 | 해당 방향의 전용 필드다. |
| Priority | Header | 선택 가능 | 없음 | 요청 우선순위 | 해당 방향의 전용 필드다. |
| Server | Header | 없음 | 선택 가능 | 서버 소프트웨어 식별 문자열 | 해당 방향의 전용 필드다. |
| Subject | Header | 선택 가능 | 없음 | 사람이 읽는 세션 주제 | 해당 방향의 전용 필드다. |
| Timestamp | Header | 없음 | 선택 가능 | timestamp 측정값 | 해당 방향의 전용 필드다. |
| User-Agent | Header | 선택 가능 | 없음 | UA 소프트웨어 식별 문자열 | 해당 방향의 전용 필드다. |

### 5.6 Event / Publication
| Field | Location | Request side | Response side | Meaning | Comparison point |
| --- | --- | --- | --- | --- | --- |
| Event | Header | 일부 요청에서 필수: NOTIFY, PUBLISH, SUBSCRIBE; 조건부 규칙 있음 | 없음 | event package 이름 | 이벤트 계열 요청에서만 직접 쓰인다. |
| Expires | Header | 조건부 규칙 있음 | 조건부 규칙 있음 | 등록/구독/발행 lifetime | 요청은 등록/구독/발행 lifetime 제안, 응답은 실제 grant 값 통지로 의미가 달라진다. |
| SIP-ETag | Header | 없음 | 선택 가능 | publication state의 entity tag | 응답의 publication state 버전 식별자다. |
| SIP-If-Match | Header | PUBLISH에서만; 조건부 규칙 있음 | 없음 | 기존 entity tag와 매칭되는 경우에만 갱신 | 요청의 conditional PUBLISH 갱신용 필드다. |
| Subscription-State | Header | 일부 요청에서 필수: NOTIFY; 조건부 규칙 있음 | 없음 | subscription의 현재 상태 | NOTIFY request 전용 상태 필드다. |

### 5.7 Dialog Control / Transfer
| Field | Location | Request side | Response side | Meaning | Comparison point |
| --- | --- | --- | --- | --- | --- |
| RAck | Header | 일부 요청에서 필수: PRACK | 없음 | reliable provisional response를 지목하는 ack 정보 | PRACK request 전용 매칭 필드다. |
| RSeq | Header | 없음 | 조건부 규칙 있음 | reliable provisional response sequence 번호 | reliable provisional response 쪽 번호 필드다. |
| Refer-Sub | Header | 선택 가능: REFER | 없음 | REFER에 implicit subscription을 둘지 여부 | 해당 방향의 전용 필드다. |
| Refer-To | Header | 일부 요청에서 필수: REFER | 없음 | REFER가 지시하는 새로운 대상 URI | REFER request 전용 핵심 대상 지정 필드다. |
| Referred-By | Header | 선택 가능: REFER | 없음 | referral을 일으킨 주체 정보 | REFER provenance를 요청 쪽에서만 싣는다. |
| Replaces | Header | 선택 가능: REFER | 없음 | 기존 dialog를 교체할 dialog 식별 | REFER/transfer 계열 요청에서 dialog 교체 대상을 지정한다. |
| Target-Dialog | Header | 선택 가능: REFER | 없음 | 특정 dialog를 지목하는 식별자 | 해당 방향의 전용 필드다. |

### 5.8 Security / Identity
| Field | Location | Request side | Response side | Meaning | Comparison point |
| --- | --- | --- | --- | --- | --- |
| Authentication-Info | Header | 없음 | 선택 가능 | 인증 성공 후 전달되는 추가 auth metadata | 인증 성공 후 응답에서만 의미가 있다. |
| P-Asserted-Identity | Header | 선택 가능: INVITE | 없음 | trusted network가 보증하는 사용자 identity | trusted network identity를 요청에서 운반하는 IMS 성격이 강하다. |
| Privacy | Header | 선택 가능: INVITE | 없음 | privacy 처리 요청/표시 | 현재 surface에서는 INVITE request 쪽 privacy 요구에 배치된다. |
| Proxy-Authenticate | Header | 없음 | 일부 응답에서 필수: 407; 조건부 규칙 있음 | proxy의 인증 challenge | 407 및 일부 security-agreement 맥락 응답에서 중요하다. |
| Reason | Header | 조건부 규칙 있음 | 조건부 규칙 있음 | 메시지 종료/취소/거절 원인 표기 | 요청에서는 CANCEL 같은 종료 사유 전달, 응답에서는 199 등 종료 맥락 설명에 쓰인다. |
| Security-Server | Header | 없음 | 일부 응답에서 필수: 494 | 서버가 제안하는 security mechanism 목록 | 494 응답에서 핵심이다. |
| WWW-Authenticate | Header | 없음 | 일부 응답에서 필수: 401 | UAS/origin server의 인증 challenge | 401 응답 쪽 challenge 필드다. |

### 5.9 Error / Policy
| Field | Location | Request side | Response side | Meaning | Comparison point |
| --- | --- | --- | --- | --- | --- |
| AlertMsg-Error | Header | 없음 | 일부 응답에서 필수: 425 | alerting information 오류 값 | 425 Bad Alert Message 응답 설명용이다. |
| Error-Info | Header | 없음 | 선택 가능 | 추가 오류 설명 URI | 응답의 추가 오류 참조 URI다. |
| Geolocation-Error | Header | 없음 | 일부 응답에서 필수: 424 | geolocation 관련 오류 코드/설명 | 424 Bad Location Information 응답 설명용이다. |
| Permission-Missing | Header | 없음 | 조건부 규칙 있음 | consent가 없는 target URI 목록 | 470 Consent Needed 응답 쪽 보조 정보다. |
| Retry-After | Header | 없음 | 조건부 규칙 있음 | 재시도 가능 시점 또는 대기 시간 | 응답에서 재시도 시점을 알려준다. |
| Warning | Header | 없음 | 선택 가능 | 추가 경고 정보 | 응답에서 부가 경고를 주는 진단 필드다. |

## 6. Request-side conditional rules appendix
같은 조건이 반복되는 경우 method 목록을 한 행으로 묶어 가독성을 높였다.

| Field | Affected request methods | Condition | Note |
| --- | --- | --- | --- |
| Body | NOTIFY | If a body is present, its format must be acceptable to the subscriber; many event packages send a body, but empty NOTIFY is possible for some terminal states. | - |
| Body | PUBLISH | Initial PUBLISH requests MUST carry the publication state in the message body. | - |
| Body | MESSAGE | MESSAGE usually carries an instant-message payload, but the model keeps the body optional for RFC-tolerant parsing/fuzzing. | - |
| Body | INVITE | Often carries SDP offer/answer, but offerless INVITE is also valid. | - |
| Body | UPDATE | Required when the UPDATE carries SDP or another message body. | - |
| Contact | REGISTER | Needed for normal binding add/update flows; omitted or specialized in query variants. | - |
| Event | NOTIFY | The NOTIFY Event package must match the subscription or implicit REFER subscription it is reporting on. | - |
| Expires | SUBSCRIBE | SUBSCRIBE requests SHOULD include Expires; Expires: 0 is used to fetch or terminate a subscription depending on context. | - |
| Expires | PUBLISH | Typically supplied to define publication lifetime. | - |
| Info-Package | INFO | Required when the INFO package framework is used for a named package. | - |
| Reason | CANCEL | Include when cancellation cause should be conveyed explicitly. | Reason is not mandatory in base RFC3261 but is common in modern deployments. |
| Recv-Info | INVITE | Include in an initial INVITE when advertising supported INFO packages; an empty Recv-Info value is valid. | - |
| Recv-Info | REGISTER | May be included to advertise INFO-package support as allowed by RFC6086. | - |
| Recv-Info | PRACK | May be included when the UA advertises support for INFO packages during dialog establishment. | - |
| Recv-Info | UPDATE | May be included when the UA refreshes advertised INFO-package support in-dialog. | - |
| Route | CANCEL | If the original request established a route set, CANCEL follows the same route set. | - |
| Route | ACK | Populate when the INVITE dialog established a route set. | - |
| SIP-If-Match | PUBLISH | Used for refresh/modify/remove of an existing publication and MUST NOT appear on an initial PUBLISH. | - |
| Subscription-State | NOTIFY | Subscription-State drives whether expires is required (active/pending) or forbidden (terminated). | - |

## 7. Response-side conditional rules appendix
같은 조건이 반복되는 경우 response code 목록을 한 행으로 묶어 가독성을 높였다.

| Field | Affected response codes | Condition | Note |
| --- | --- | --- | --- |
| Allow-Events | 489 | Strongly recommended when advertising supported event packages after 489 Bad Event. | - |
| Body | 200 | A 2xx response to MESSAGE MUST NOT include a message body. | - |
| Body | 380 | Alternative services are described in the message body rather than by redirect Contact targets. | - |
| Call-Info | 608 | Include a Call-Info URI when policy wants to provide a human- or machine-readable explanation for 608 Rejected. | - |
| Contact | 200 | 2xx responses to INVITE require Contact so the remote target for the established dialog is known. | - |
| Contact | 200 | A 2xx response to MESSAGE MUST NOT include Contact because MESSAGE does not establish a dialog. | - |
| Contact | 180, 181, 182, 183 | For non-100 provisional responses to INVITE that establish an early dialog, Contact is mandatory so the remote target is known. | - |
| Contact | 200 | Successful REGISTER responses MUST return the current contact bindings known to the registrar. | - |
| Contact | 300, 301, 302, 305 | Typically carries one or more alternative targets for the redirection decision. | - |
| Expires | 204 | 204 No Notification responses to SUBSCRIBE MUST include Expires to communicate the granted subscription duration. | - |
| Expires | 200 | A 200-class response to SUBSCRIBE MUST include Expires to indicate the actual subscription duration granted by the notifier. | - |
| Path | 200 | When the Path extension is in use, a successful REGISTER response copies the Path header field values from the request. | - |
| Permission-Missing | 470 | SHOULD be included when the rejecting entity can identify which target URIs are missing consent. | - |
| Proxy-Authenticate | 494 | When the chosen security mechanism needs challenge material such as HTTP Digest, include the corresponding authentication challenge headers as well. | - |
| RSeq | 180, 181, 182, 183, 199 | Include RSeq when the provisional response is sent reliably with 100rel. | RSeq is not mandatory for ordinary provisional responses, only for reliable ones. |
| Reason | 199 | A 199 Early Dialog Terminated response MUST include a Reason header indicating which final outcome terminated the dialog. | - |
| Record-Route | 200 | If the INVITE request contained Record-Route, copy it into the dialog-establishing 2xx response. | - |
| Record-Route | 180, 181, 182, 183 | If the INVITE request contained Record-Route, copy it into the dialog-establishing provisional response. | - |
| Recv-Info | 180, 181, 182, 183, 200 | When the associated request used the INFO package framework and carried Recv-Info, reliable 18x/2xx responses include Recv-Info as well, even if empty. | - |
| Require | 494 | Include the sec-agree option tag when the response instructs the UE to negotiate a security agreement before retrying. | The Require header should contain the 'sec-agree' option tag when applicable. |
| Retry-After | 503 | Recommended when the server can indicate when the UE should retry. | - |
| Service-Route | 200 | A successful REGISTER response may include Service-Route values that the UA must use for future requests in the registered context. | - |
| Supported | 199 | 199 is only meaningful when the UAC indicated support for the '199' option-tag. | - |
| To | 180, 181, 182, 183, 199, 200, 202, 204, 300, 301, 302, 305, 380, 400, 401, 402, 403, 404, 405, 406, 407, 408, 410, 412, 413, 414, 415, 416, 417, 420, 421, 422, 423, 424, 425, 428, 429, 430, 433, 436, 437, 438, 439, 440, 469, 470, 480, 481, 482, 483, 484, 485, 486, 487, 488, 489, 491, 493, 494, 500, 501, 502, 503, 504, 505, 513, 555, 580, 600, 603, 604, 606, 607, 608 | Except for 100 Trying, if the request lacked a To tag the response MUST add one. | - |

## 8. 문서 해석 주의
- 이 매트릭스는 `field surface`를 누락 없이 비교하기 위한 문서다.
- 어떤 field가 response model surface 전체에 존재한다고 해서, 모든 응답 코드에서 의미 있게 쓰인다는 뜻은 아니다.
- 따라서 실제 사용 강도는 `Request side` / `Response side`의 분류와 Appendix의 조건부 규칙을 함께 읽어야 정확하다.
- request/response별 대표 packet text는 `요청-패킷-예시.md`, `응답-패킷-예시.md`를 같이 보면 가장 이해가 빠르다.

## 공식 출처
- [IANA Session Initiation Protocol (SIP) Parameters](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml)
- [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261)
- [RFC 3262](https://www.rfc-editor.org/rfc/rfc3262)
- [RFC 3311](https://www.rfc-editor.org/rfc/rfc3311)
- [RFC 3323](https://www.rfc-editor.org/rfc/rfc3323)
- [RFC 3325](https://www.rfc-editor.org/rfc/rfc3325)
- [RFC 3326](https://www.rfc-editor.org/rfc/rfc3326)
- [RFC 3327](https://www.rfc-editor.org/rfc/rfc3327)
- [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329)
- [RFC 3428](https://www.rfc-editor.org/rfc/rfc3428)
- [RFC 3515](https://www.rfc-editor.org/rfc/rfc3515)
- [RFC 3608](https://www.rfc-editor.org/rfc/rfc3608)
- [RFC 3891](https://www.rfc-editor.org/rfc/rfc3891)
- [RFC 3892](https://www.rfc-editor.org/rfc/rfc3892)
- [RFC 3903](https://www.rfc-editor.org/rfc/rfc3903)
- [RFC 4028](https://www.rfc-editor.org/rfc/rfc4028)
- [RFC 4412](https://www.rfc-editor.org/rfc/rfc4412)
- [RFC 4488](https://www.rfc-editor.org/rfc/rfc4488)
- [RFC 4538](https://www.rfc-editor.org/rfc/rfc4538)
- [RFC 5079](https://www.rfc-editor.org/rfc/rfc5079)
- [RFC 5360](https://www.rfc-editor.org/rfc/rfc5360)
- [RFC 5393](https://www.rfc-editor.org/rfc/rfc5393)
- [RFC 5626](https://www.rfc-editor.org/rfc/rfc5626)
- [RFC 5839](https://www.rfc-editor.org/rfc/rfc5839)
- [RFC 6026](https://www.rfc-editor.org/rfc/rfc6026)
- [RFC 6086](https://www.rfc-editor.org/rfc/rfc6086)
- [RFC 6228](https://www.rfc-editor.org/rfc/rfc6228)
- [RFC 6442](https://www.rfc-editor.org/rfc/rfc6442)
- [RFC 6665](https://www.rfc-editor.org/rfc/rfc6665)
- [RFC 8197](https://www.rfc-editor.org/rfc/rfc8197)
- [RFC 8224](https://www.rfc-editor.org/rfc/rfc8224)
- [RFC 8599](https://www.rfc-editor.org/rfc/rfc8599)
- [RFC 8688](https://www.rfc-editor.org/rfc/rfc8688)
- [RFC 8876](https://www.rfc-editor.org/rfc/rfc8876)
