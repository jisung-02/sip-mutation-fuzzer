# SIP 요청/응답 오피셜 필드 리서치

기준 일자: 2026-03-18

## 1. 문서 목적
이 문서는 **단말(UE) 기준으로 수신할 수 있는 SIP 요청과 응답 전체**를, 가능한 한 공식 자료만을 기준으로 정리한 연구 문서다.

정리 대상:
- IANA SIP Parameters에 등록된 request method 중 본 프로젝트 범위의 14개
- IANA / RFC 기반으로 현재 프로젝트가 채택한 UE 수신 response code 75개
- 각 메시지의 용도
- 필수 필드
- 선택 필드
- 조건부 필드
- 필드 의미
- 공식 출처

이 문서는 구현 문서가 아니라 **RFC/IANA 기준 프로토콜 조사 문서**다.

## 2. 문서 범위와 읽는 법
### 2.1 범위
이번 문서는 “UE가 받는 SIP”에 맞춰 정리했다.

- `incoming request`
  - 네트워크, 프록시, 상대 단말이 UE에게 보내는 요청
- `incoming response`
  - UE가 먼저 보낸 요청에 대해 네트워크/상대가 UE로 돌려보내는 응답

즉, SIP 전체 표준 가운데서도 **UE 관점에서 의미 있는 request/response 범위**를 정리한 문서다.

### 2.2 필수/선택/조건부 표기 기준
- `필수 필드`
  - 해당 메시지 유형에서 RFC 상 사실상 반드시 있어야 하는 핵심 필드
- `선택 필드`
  - 메시지 의미를 보강하거나 특정 시나리오에서만 쓰이는 필드
- `조건부 필드`
  - 특정 RFC 확장, 특정 응답 코드, 특정 다이얼로그 상태에서 사실상 요구되거나 강하게 권장되는 필드
- `금지/부적합 필드`
  - 특정 메시지에 실으면 안 되거나, 의미가 맞지 않는 필드

### 2.3 중요한 주의
SIP는 “모든 메시지에 완전히 동일한 필드 규칙”이 적용되는 프로토콜이 아니다.
실제 의미는 아래 셋이 같이 결정한다.

1. 기본 SIP RFC 3261
2. 확장 RFC
3. 현재 메시지가 놓인 상태
   - transaction
   - dialog
   - registration
   - subscription

따라서 이 문서는 **기본 규칙 + 확장 규칙 + 대표적인 조건부 규칙**을 함께 정리한다.

## 3. 이번 문서의 공식 출처
### 3.1 최상위 공식 레지스트리
- [IANA Session Initiation Protocol (SIP) Parameters](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml)
  - Header Fields
  - Methods and Response Codes
  - Response Codes

### 3.2 핵심 RFC
- [RFC 3261 - SIP: Session Initiation Protocol](https://www.rfc-editor.org/rfc/rfc3261)
- [RFC 3262 - Reliability of Provisional Responses in SIP](https://www.rfc-editor.org/rfc/rfc3262)
- [RFC 3311 - The UPDATE Method](https://www.rfc-editor.org/rfc/rfc3311)
- [RFC 3323 - A Privacy Mechanism for SIP](https://www.rfc-editor.org/rfc/rfc3323)
- [RFC 3325 - Private Extensions to SIP for Asserted Identity](https://www.rfc-editor.org/rfc/rfc3325)
- [RFC 3326 - The Reason Header Field for SIP](https://www.rfc-editor.org/rfc/rfc3326)
- [RFC 3327 - SIP Extension Header Field for Registering Non-Adjacent Contacts (Path)](https://www.rfc-editor.org/rfc/rfc3327)
- [RFC 3329 - Security Mechanism Agreement for SIP](https://www.rfc-editor.org/rfc/rfc3329)
- [RFC 3428 - SIP Extension for Instant Messaging](https://www.rfc-editor.org/rfc/rfc3428)
- [RFC 3515 - The SIP Refer Method](https://www.rfc-editor.org/rfc/rfc3515)
- [RFC 3608 - Session Initiation Protocol (SIP) Extension Header Field for Service Route Discovery During Registration](https://www.rfc-editor.org/rfc/rfc3608)
- [RFC 3891 - The Session Initiation Protocol (SIP) "Replaces" Header](https://www.rfc-editor.org/rfc/rfc3891)
- [RFC 3892 - The Session Initiation Protocol (SIP) Referred-By Mechanism](https://www.rfc-editor.org/rfc/rfc3892)
- [RFC 3903 - Session Initiation Protocol (SIP) Extension for Event State Publication](https://www.rfc-editor.org/rfc/rfc3903)
- [RFC 4028 - Session Timers in the Session Initiation Protocol (SIP)](https://www.rfc-editor.org/rfc/rfc4028)
- [RFC 4412 - Communications Resource Priority for the Session Initiation Protocol (SIP)](https://www.rfc-editor.org/rfc/rfc4412)
- [RFC 4488 - Suppressing Refer Messages](https://www.rfc-editor.org/rfc/rfc4488)
- [RFC 4538 - Request Authorization Through Dialog Identification in the Session Initiation Protocol (SIP)](https://www.rfc-editor.org/rfc/rfc4538)
- [RFC 5079 - Rejecting Anonymous Requests in the Session Initiation Protocol (SIP)](https://www.rfc-editor.org/rfc/rfc5079)
- [RFC 5360 - Consent Framework for SIP](https://www.rfc-editor.org/rfc/rfc5360)
- [RFC 5393 - Addressing an Amplification Vulnerability in SIP Forking Proxies](https://www.rfc-editor.org/rfc/rfc5393)
- [RFC 5626 - Managing Client-Initiated Connections in SIP (Outbound)](https://www.rfc-editor.org/rfc/rfc5626)
- [RFC 5839 - An Extension to SIP for Event Notification Without Subscription](https://www.rfc-editor.org/rfc/rfc5839)
- [RFC 6026 - Correct Transaction Handling for 2xx Responses to SIP INVITE Requests](https://www.rfc-editor.org/rfc/rfc6026)
- [RFC 6086 - INFO Method and Package Framework in SIP](https://www.rfc-editor.org/rfc/rfc6086)
- [RFC 6228 - Response Code for Indication of Terminated Early Dialog](https://www.rfc-editor.org/rfc/rfc6228)
- [RFC 3312 - Integration of Resource Management and Session Initiation Protocol (SIP)](https://www.rfc-editor.org/rfc/rfc3312)
- [RFC 6442 - Location Conveyance for SIP](https://www.rfc-editor.org/rfc/rfc6442)
- [RFC 6665 - SIP-Specific Event Notification](https://www.rfc-editor.org/rfc/rfc6665)
- [RFC 7647 - Clarifications, Corrections, and Updates for the Usage of the SIP 202 Accepted Response Code](https://www.rfc-editor.org/rfc/rfc7647)
- [RFC 8197 - A SIP Response Code for Unwanted Calls](https://www.rfc-editor.org/rfc/rfc8197)
- [RFC 8224 - Authenticated Identity Management in SIP](https://www.rfc-editor.org/rfc/rfc8224)
- [RFC 8599 - Push Notification with SIP](https://www.rfc-editor.org/rfc/rfc8599)
- [RFC 8688 - A Session Initiation Protocol (SIP) Response Code for Rejected Calls](https://www.rfc-editor.org/rfc/rfc8688)
- [RFC 8876 - A SIP Response Code for Rejected Alert-Info](https://www.rfc-editor.org/rfc/rfc8876)

### 3.3 작성 방식에 대한 정직한 설명
이번 문서의 “요청/응답별 필드 매트릭스”는 위 공식 문서를 기준으로 읽고, **현재 프로젝트의 RFC/IANA 기반 catalog와 교차검증하여 누락을 줄이는 방식**으로 정리했다.

즉, 출처의 진실성은 RFC/IANA에 있고, 정리의 일관성은 catalog를 통해 확보했다.

중요:
- 이 문서는 **RFC/IANA 기준의 공식 규칙 설명 문서**다.
- 현재 저장소의 `metadata`와 `validator`는 이 규칙들을 상당 부분 반영하지만, 모든 RFC MUST/SHOULD를 완전하게 강제하는 것은 아니다.
- 따라서 아래 표의 설명은 먼저 **표준 기준**으로 읽고, 필요한 경우 “현재 repo가 실제로 어디까지 강제하는가”와는 별도로 봐야 한다.

## 4. SIP 메시지의 공통 구조
## 4.1 Request 공통 골격
```text
METHOD SP Request-URI SP SIP/2.0
Via: ...
Max-Forwards: ...
From: ...
To: ...
Call-ID: ...
CSeq: ...
[기타 헤더들]

[메시지 바디]
```

### 기본적으로 항상 보는 request 핵심 요소
- `Method`
- `Request-URI`
- `SIP-Version`
- `Via`
- `Max-Forwards`
- `From`
- `To`
- `Call-ID`
- `CSeq`

## 4.2 Response 공통 골격
```text
SIP/2.0 SP Status-Code SP Reason-Phrase
Via: ...
From: ...
To: ...
Call-ID: ...
CSeq: ...
[기타 헤더들]

[메시지 바디]
```

### 기본적으로 항상 보는 response 핵심 요소
- `Status-Code`
- `Reason-Phrase`
- `SIP-Version`
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### response 공통 조건부 규칙
- `To` tag
  - `100 Trying`을 제외한 응답은, 원래 요청에 `To` tag가 없었다면 응답에서 이를 추가해야 한다.
  - 이 규칙은 INVITE만의 특수 규칙이 아니라 response 전반의 기본 규칙이다.

## 5. 필드 용어집
필드 의미를 한 번에 볼 수 있도록 공통 용어집을 먼저 둔다.
아래 표의 “출처”는 해당 필드의 주요 정의를 담고 있는 대표 공식 문서다.

## 5.1 Start-Line / Body 계열
| 필드 | 의미 | 대표 용도 | 공식 출처 |
| --- | --- | --- | --- |
| `Method` | 요청의 동작 종류를 나타내는 start-line 토큰 | `INVITE`, `REGISTER`, `BYE` 등 | RFC3261, IANA Methods and Response Codes |
| `Request-URI` | 요청이 향하는 논리적 대상 URI | 사용자, 서비스, registrar, event resource 식별 | RFC3261 |
| `Status-Code` | 응답의 숫자 결과 코드 | `1xx`, `2xx`, `4xx`, `5xx`, `6xx` | RFC3261, IANA Response Codes |
| `Reason-Phrase` | 상태 코드의 사람이 읽는 설명 | `OK`, `Busy Here`, `Unauthorized` 등 | RFC3261 |
| `SIP-Version` | 프로토콜 버전 표기 | 현재 실질적으로 `SIP/2.0` | RFC3261 |
| `Body` | 메시지 본문 | SDP, instant message, PIDF/XML, 기타 payload | RFC3261 및 개별 payload RFC |

## 5.2 Transaction / Dialog 핵심 필드
| 필드 | 의미 | 대표 용도 | 공식 출처 |
| --- | --- | --- | --- |
| `Via` | 응답이 되돌아갈 transport 경로와 branch를 담는 헤더 | transaction 식별, 응답 라우팅, transport 정보 | RFC3261 |
| `Max-Forwards` | 요청이 거칠 수 있는 최대 hop 수 | 루프 방지 | RFC3261 |
| `From` | 논리적 발신자 식별 | dialog의 한 쪽 participant 식별 | RFC3261 |
| `To` | 논리적 수신자 식별 | dialog의 반대편 participant 식별. 응답에서는 일반적으로 `To` tag가 dialog 식별의 핵심이 되며, `100 Trying`을 제외한 응답은 요청에 tag가 없었다면 이를 추가한다. | RFC3261 |
| `Call-ID` | 전체 call/dialog/transaction 계열을 식별하는 고유 ID | 상관관계 추적, dialog 식별 | RFC3261 |
| `CSeq` | 순번 + method 조합 | 요청 순서 관리, 요청/응답 매칭 | RFC3261 |
| `Contact` | 해당 UA에게 직접 도달할 수 있는 URI | registration binding, dialog remote target 학습 | RFC3261 |
| `Route` | 미리 정해진 라우팅 경로 | dialog route set 적용 | RFC3261 |
| `Record-Route` | 프록시가 이후 dialog path에 남기 위한 기록 | 이후 `Route` 집합 생성 | RFC3261 |

## 5.3 Capability / Negotiation 계열
| 필드 | 의미 | 대표 용도 | 공식 출처 |
| --- | --- | --- | --- |
| `Supported` | 발신자가 지원하는 option tag 목록 | 확장 지원 광고 | RFC3261 |
| `Require` | 수신자가 반드시 이해해야 하는 option tag 목록 | 확장 기능 강제 | RFC3261 |
| `Proxy-Require` | 경로 상의 proxy가 이해해야 하는 option tag 목록 | proxy 확장 강제 | RFC3261 |
| `Allow` | 해당 UA가 처리 가능한 method 목록 | 405 응답, 기능 광고 | RFC3261 |
| `Accept` | 허용 가능한 media type 목록 | content negotiation | RFC3261 |
| `Accept-Encoding` | 허용 가능한 content encoding 목록 | 압축/인코딩 협상 | RFC3261 |
| `Accept-Language` | 허용 가능한 자연어 목록 | 언어 협상 | RFC3261 |
| `Allow-Events` | 지원하는 event package 목록 | 489 이후 capability 광고 | RFC6665, IANA Header Fields |
| `Recv-Info` | 수신자가 받을 수 있는 INFO package 목록 | INFO framework capability | RFC6086 |
| `Info-Package` | 해당 INFO request의 package 이름 | INFO semantics 명시 | RFC6086 |

## 5.4 Content / Payload 계열
| 필드 | 의미 | 대표 용도 | 공식 출처 |
| --- | --- | --- | --- |
| `Content-Type` | body media type | SDP, text/plain, application/pidf+xml 등 | RFC3261 |
| `Content-Disposition` | body 처리 방식 | session, render, alert 등 | RFC3261 |
| `Content-Encoding` | body에 적용된 content coding | gzip류 인코딩 | RFC3261 |
| `Content-Language` | body 자연어 | 다국어 payload 표기 | RFC3261 |
| `Content-Length` | body 바이트 길이 | framing, parser 동작 | RFC3261 |
| `Session-Expires` | session timer 만료 시간 | 세션 유지/refresh 제어 | RFC4028 |
| `Min-SE` | 최소 session timer 값 | 너무 짧은 session timer 방지 | RFC4028 |
| `Min-Expires` | 허용 가능한 최소 expires 값 | `423 Interval Too Brief`에서 재시도 기준 제시 | RFC3261 |

전역 규칙:
- body가 비어 있지 않다면 `Content-Type`이 필요하다.

## 5.5 Event / Presence / Publication 계열
| 필드 | 의미 | 대표 용도 | 공식 출처 |
| --- | --- | --- | --- |
| `Event` | event package 이름 | `SUBSCRIBE`, `NOTIFY`, `PUBLISH` | RFC6665, RFC3903 |
| `Subscription-State` | subscription의 현재 상태 | `NOTIFY`에서 active/pending/terminated 전달 | RFC6665 |
| `Expires` | 등록/구독/발행 lifetime | `REGISTER`, `SUBSCRIBE`, `PUBLISH`, 일부 response | RFC3261, RFC3903, RFC6665 |
| `SIP-ETag` | publication state의 entity tag | publication 버전 식별 | RFC3903 |
| `SIP-If-Match` | 기존 entity tag와 매칭되는 경우에만 갱신 | conditional PUBLISH | RFC3903 |
| `Path` | registration path vector | REGISTER request의 경로 벡터를 유지하고, Path extension 사용 시 성공적인 REGISTER response에도 반영될 수 있음 | RFC3327 |

## 5.6 Call Transfer / Dialog Targeting 계열
| 필드 | 의미 | 대표 용도 | 공식 출처 |
| --- | --- | --- | --- |
| `Refer-To` | REFER가 지시하는 새로운 대상 URI | call transfer, referral | RFC3515 |
| `Referred-By` | referral을 일으킨 주체 정보 | referral provenance | RFC3892 |
| `Refer-Sub` | REFER에 implicit subscription을 둘지 여부 | REFER 후 NOTIFY 구독 제어 | RFC4488 |
| `Target-Dialog` | 특정 dialog를 지목하는 식별자 | dialog-targeted requests | RFC4538 |
| `Replaces` | 기존 dialog를 교체할 dialog 식별 | attended transfer 계열 | RFC3891 |
| `RAck` | reliable provisional response를 지목하는 ack 정보 | `PRACK`에서 `RSeq`/`CSeq` 매칭 | RFC3262 |
| `RSeq` | reliable provisional response sequence 번호 | `100rel` provisional 응답 | RFC3262 |

## 5.7 Security / Authentication / Identity 계열
| 필드 | 의미 | 대표 용도 | 공식 출처 |
| --- | --- | --- | --- |
| `WWW-Authenticate` | UAS/origin server의 인증 challenge | `401 Unauthorized` | RFC3261 |
| `Proxy-Authenticate` | proxy의 인증 challenge | `407 Proxy Authentication Required` | RFC3261 |
| `Authentication-Info` | 인증 성공 후 전달되는 추가 auth metadata | digest-auth 후속 정보 | RFC3261 |
| `Security-Server` | 서버가 제안하는 security mechanism 목록 | `494 Security Agreement Required` | RFC3329 |
| `Identity` | PASSporT 기반 신원 보증 정보를 담는 헤더 | STIR/SHAKEN 계열 identity verification | RFC8224 |
| `Identity-Info` | `Identity` 검증에 필요한 보조 정보/참조 | RFC 8224 identity chain 보조 | RFC8224 |
| `Privacy` | privacy 처리 요청/표시 | asserted identity 은닉 | RFC3323 |
| `P-Asserted-Identity` | trusted network가 보증하는 사용자 identity | IMS / trusted domain identity | RFC3325 |
| `Reason` | 메시지 종료/취소/거절 원인 표기 | `CANCEL`, `BYE`, 일부 응답 | RFC3326 |

## 5.8 Error / Diagnostic / Policy 계열
| 필드 | 의미 | 대표 용도 | 공식 출처 |
| --- | --- | --- | --- |
| `Warning` | 추가 경고 정보 | 경로/서비스 문제 설명 | RFC3261 |
| `Retry-After` | 재시도 가능 시점 또는 대기 시간 | `503 Service Unavailable` 등 | RFC3261 |
| `Unsupported` | 이해하지 못한 option tag 목록 | `420 Bad Extension` | RFC3261 |
| `Error-Info` | 추가 오류 설명 URI | 에러 상세 참조 | RFC3261 |
| `Permission-Missing` | consent가 없는 target URI 목록 | `470 Consent Needed` | RFC5360 |
| `Geolocation-Error` | geolocation 관련 오류 코드/설명 | `424 Bad Location Information` | RFC6442 |
| `AlertMsg-Error` | alerting information 오류 값 | `425 Bad Alert Message` | RFC8876 |
| `Call-Info` | call/resource 관련 추가 정보 URI | call metadata, policy explanation, `608 Rejected` 부가정보 | RFC3261, RFC8688 |
| `Alert-Info` | 호출 시 사용자 단말의 alerting style에 대한 정보 | ringtone/alerting 힌트 | RFC3261 |
| `Timestamp` | timestamp 측정값 | 지연/왕복시간 추정 | RFC3261 |
| `Server` | 서버 소프트웨어 식별 문자열 | 응답 생성자 표시 | RFC3261 |

## 5.9 Misc 메타데이터 계열
| 필드 | 의미 | 대표 용도 | 공식 출처 |
| --- | --- | --- | --- |
| `Subject` | 사람이 읽는 세션 주제 | call subject | RFC3261 |
| `Organization` | 발신 조직 이름 | informational metadata | RFC3261 |
| `Priority` | 요청 우선순위 | 긴급도 표시 | RFC3261 |
| `User-Agent` | UA 소프트웨어 식별 문자열 | 발신 단말/스택 식별 | RFC3261 |
| `Service-Route` | 등록 후 사용할 서비스 경로 | registered UA의 향후 route set | RFC3608 |

## 6. Request Method 전체 조사
## 6.1 공통 request 필수 필드 세트
아래 필드 세트는 본 프로젝트 범위의 request 14개 전반에서 공통적인 핵심 세트다.

- `Method`
- `Request-URI`
- `SIP-Version`
- `Via`
- `Max-Forwards`
- `From`
- `To`
- `Call-ID`
- `CSeq`

출처:
- RFC3261

## 6.2 공통 request 선택 필드 풀
다음 필드들은 다수의 request에서 공통적으로 선택적으로 보일 수 있다.

- `Contact`
- `Route`
- `Record-Route`
- `Supported`
- `Require`
- `Proxy-Require`
- `Allow`
- `Allow-Events`
- `Accept`
- `Accept-Encoding`
- `Accept-Language`
- `Alert-Info`
- `Call-Info`
- `Event`
- `Expires`
- `Subject`
- `Organization`
- `Priority`
- `User-Agent`
- `Content-Type`
- `Content-Disposition`
- `Content-Encoding`
- `Content-Language`
- `Content-Length`
- `Body`

주의:
- `Record-Route`는 다수의 dialog-forming request에서 의미가 있지만, `REGISTER`에는 의미가 없고, `PUBLISH`에서는 수신자가 이를 무시한다.
- 즉 “공통 선택 필드 풀”은 전부가 모든 method에서 의미 있다는 뜻이 아니라, 여러 request에서 반복적으로 등장하는 후보 목록이라는 뜻이다.

아래 method별 섹션에서는 이 공통 풀에 더해지는 **추가 필수 필드**, **조건부 필드**, **금지 필드**를 중심으로 정리한다.

## 6.3 Method별 정리
### ACK
- `무엇에 쓰는가`
  - INVITE final response를 확인하는 요청이다.
- `주요 사용 상황`
  - UE가 INVITE의 UAS 역할을 했고 final response를 보낸 뒤 ACK를 받음
- `필수 필드`
  - 공통 request 필수 필드 세트
- `선택 필드`
  - 공통 request 선택 필드 풀
- `조건부 필드`
  - `Route`: INVITE dialog가 route set을 만든 경우
- `공식 출처`
  - RFC3261

### BYE
- `무엇에 쓰는가`
  - 이미 성립된 dialog/session을 종료한다.
- `필수 필드`
  - 공통 request 필수 필드 세트
- `선택 필드`
  - 공통 request 선택 필드 풀
- `공식 출처`
  - RFC3261

### CANCEL
- `무엇에 쓰는가`
  - 아직 final response가 오지 않은 INVITE transaction을 취소한다.
- `필수 필드`
  - 공통 request 필수 필드 세트
- `선택 필드`
  - 공통 request 선택 필드 풀
  - `Reason`
- `조건부 필드`
  - `Route`: 원래 요청이 route set을 만들었다면 같은 route set을 따라간다
  - `Reason`: 취소 사유를 명시하고 싶을 때
- `금지/부적합 필드`
  - `Require`
  - `Proxy-Require`
- `공식 출처`
  - RFC3261
  - RFC3326

### INFO
- `무엇에 쓰는가`
  - dialog 안에서 application information을 운반한다.
- `필수 필드`
  - 공통 request 필수 필드 세트
- `선택 필드`
  - 공통 request 선택 필드 풀
  - `Info-Package`
- `조건부 필드`
  - `Info-Package`: INFO package framework를 쓰는 INFO 요청에서는 의미상 필요하다
- `금지/부적합 필드`
  - `Recv-Info`: RFC 6086 기준 `Recv-Info`는 INFO request 자체가 아니라, 다른 메시지에서 INFO package capability를 광고하는 데 쓰인다
- `공식 출처`
  - RFC6086

### INVITE
- `무엇에 쓰는가`
  - 새 세션을 만들거나, 기존 dialog를 재협상한다.
- `필수 필드`
  - 공통 request 필수 필드 세트
  - `Contact`
- `선택 필드`
  - 공통 request 선택 필드 풀
  - `Recv-Info`
  - `Session-Expires`
  - `Min-SE`
  - `Privacy`
  - `P-Asserted-Identity`
- `조건부 필드`
  - `Body`: 일반적으로 SDP offer/answer가 실림
  - `Recv-Info`: INFO package framework를 사용하는 초기 INVITE에서는 capability 광고를 위해 중요하며, 빈 값도 유효하다
- `공식 출처`
  - RFC3261
  - RFC6026
  - RFC4028
  - RFC6086
  - RFC3323
  - RFC3325

### MESSAGE
- `무엇에 쓰는가`
  - pager-mode instant message를 운반한다.
- `필수 필드`
  - 공통 request 필수 필드 세트
- `선택 필드`
  - 공통 request 선택 필드 풀
- `조건부 필드`
  - `Body`: 보통 텍스트나 작은 signalling payload를 담음
- `금지/부적합 필드`
  - `Contact`: RFC 3428 기준 `MESSAGE`는 dialog를 만들지 않으므로 UAC가 `Contact`를 넣으면 안 된다
- `공식 출처`
  - RFC3428

### NOTIFY
- `무엇에 쓰는가`
  - subscription 상태 변화나 REFER 진행 상황을 통지한다.
- `필수 필드`
  - 공통 request 필수 필드 세트
  - `Contact`
  - `Event`
  - `Subscription-State`
- `선택 필드`
  - 공통 request 선택 필드 풀
- `조건부 필드`
  - `Subscription-State.expires`: `active`/`pending` 상태의 NOTIFY에서는 필요하고, `terminated`에서는 넣지 않는다
  - `Event`: 기존 SUBSCRIBE(또는 implicit REFER subscription)와 같은 event package를 가리켜야 한다
  - `Body`: event package에 따라 흔하지만, 종료 상태에서는 비어 있을 수도 있음
  - `Body`가 있을 때: subscriber가 `Accept`로 허용한 형식과 일치해야 한다
- `공식 출처`
  - RFC6665

### OPTIONS
- `무엇에 쓰는가`
  - 상대의 기능과 reachability를 질의한다.
- `필수 필드`
  - 공통 request 필수 필드 세트
- `선택 필드`
  - 공통 request 선택 필드 풀
- `공식 출처`
  - RFC3261

### PRACK
- `무엇에 쓰는가`
  - reliable provisional response(100rel)를 확인한다.
- `필수 필드`
  - 공통 request 필수 필드 세트
  - `RAck`
- `선택 필드`
  - 공통 request 선택 필드 풀
  - `Recv-Info`
- `조건부 필드`
  - `Recv-Info`: 초기 dialog 성립 시 INFO capability 광고용
- `공식 출처`
  - RFC3262
  - RFC6086

### PUBLISH
- `무엇에 쓰는가`
  - event state를 compositor/상태 저장자에게 publish한다.
- `필수 필드`
  - 공통 request 필수 필드 세트
  - `Event`
- `선택 필드`
  - 공통 request 선택 필드 풀
  - `SIP-If-Match`
- `조건부 필드`
  - `Expires`: publication lifetime을 지정할 때
  - `Body`: 초기 `PUBLISH`에서는 publication state를 담는 body가 필요하다
  - `SIP-If-Match`: 기존 publication refresh/modify/remove에서 쓰이며, 초기 `PUBLISH`에는 들어가면 안 된다
- `비핵심/무시되는 필드`
  - `Record-Route`: RFC 3903 기준 receiver가 무시하며, 응답에 복사하지도 않는다
  - `Contact`: RFC 3903 기준 receiver가 의미 있는 routing state로 사용하지 않는다
- `현재 repo 구현 메모`
  - 현재 validator는 초기 `PUBLISH`의 body requirement는 검사하지만, `SIP-If-Match` 금지/허용 매트릭스 전체를 완전히 강제하는 것은 아니다
- `공식 출처`
  - RFC3903

### REFER
- `무엇에 쓰는가`
  - 상대에게 제3자와 접촉하도록 지시한다. 주로 call transfer에 사용된다.
- `필수 필드`
  - 공통 request 필수 필드 세트
  - `Contact`
  - `Refer-To`
- `선택 필드`
  - 공통 request 선택 필드 풀
  - `Referred-By`
  - `Refer-Sub`
  - `Target-Dialog`
  - `Replaces`
- `공식 출처`
  - RFC3515
  - RFC3892
  - RFC4488
  - RFC4538
  - RFC3891

### REGISTER
- `무엇에 쓰는가`
  - AOR binding을 등록/갱신/질의한다.
- `필수 필드`
  - 공통 request 필수 필드 세트
- `선택 필드`
  - 공통 request 선택 필드 풀
  - `Contact`
  - `Path`
  - `Recv-Info`
- `조건부 필드`
  - `Contact`: 일반 binding add/update 시 필요, 특정 query/특수 흐름에서는 생략 가능
  - `Recv-Info`: INFO package capability 광고 시
- `공식 출처`
  - RFC3261
  - RFC3327
  - RFC6086

### SUBSCRIBE
- `무엇에 쓰는가`
  - event package에 대한 subscription을 생성/갱신한다.
- `필수 필드`
  - 공통 request 필수 필드 세트
  - `Contact`
  - `Event`
- `선택 필드`
  - 공통 request 선택 필드 풀
- `조건부 필드`
  - `Expires`: RFC 6665 기준 `SHOULD` 포함한다. `Expires: 0`은 fetch 또는 unsubscribe 의미로 쓰일 수 있다
- `공식 출처`
  - RFC6665

### UPDATE
- `무엇에 쓰는가`
  - dialog를 새로 만들지 않고 session parameter를 업데이트한다.
- `필수 필드`
  - 공통 request 필수 필드 세트
  - `Contact`
- `선택 필드`
  - 공통 request 선택 필드 풀
  - `Recv-Info`
  - `Session-Expires`
  - `Min-SE`
- `조건부 필드`
  - `Body`: SDP 등 payload를 실을 때
  - `Recv-Info`: dialog 중 INFO capability refresh 시
- `공식 출처`
  - RFC3311
  - RFC4028
  - RFC6086

## 7. Response Code 전체 조사
## 7.1 공통 response 필수 필드 세트
본 프로젝트 범위의 response 75개는 기본적으로 아래 핵심 세트를 공유한다.

- `Status-Code`
- `Reason-Phrase`
- `SIP-Version`
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

출처:
- RFC3261

## 7.2 공통 response 선택 필드 풀
아래 필드들은 다수의 response에서 선택적으로 나타날 수 있다.

- `Contact`
- `Record-Route`
- `Allow`
- `Allow-Events`
- `Supported`
- `Require`
- `Unsupported`
- `Accept`
- `Accept-Encoding`
- `Accept-Language`
- `Call-Info`
- `Warning`
- `Retry-After`
- `Proxy-Authenticate`
- `WWW-Authenticate`
- `Authentication-Info`
- `Expires`
- `Session-Expires`
- `Min-Expires`
- `Min-SE`
- `Recv-Info`
- `RSeq`
- `SIP-ETag`
- `Path`
- `Security-Server`
- `Service-Route`
- `Error-Info`
- `Geolocation-Error`
- `AlertMsg-Error`
- `Permission-Missing`
- `Timestamp`
- `Server`
- `Reason`
- `Content-Type`
- `Content-Disposition`
- `Content-Encoding`
- `Content-Language`
- `Content-Length`
- `Body`

아래 class별 표에서는 이 공통 선택 풀에 더해지는 **코드별 필수/조건부 포인트**를 적는다.

## 7.3 1xx Informational
| 코드 | 무엇에 쓰는가 | 주 사용 메서드 | 코드별 필드 포인트 | 공식 출처 |
| --- | --- | --- | --- | --- |
| `100 Trying` | 요청 처리가 시작되었음을 알림 | 거의 모든 요청 | 공통 response 필수/선택 세트 | RFC3261 |
| `180 Ringing` | 피호출자가 벨 울림 상태임을 알림 | `INVITE` | reliable provisional이면 `RSeq`와 `Require: 100rel`이 함께 중요하다. `100`이 아닌 응답이므로 `To` tag가 중요하며, early dialog를 만들었다면 `Contact`는 필수이고 요청의 `Record-Route`를 반영해야 한다. 원래 요청이 `Recv-Info`를 사용한 Info Package negotiation이면, provisional response가 reliable할 때 응답도 `Recv-Info`를 반영한다. | RFC3261, RFC3262, RFC6086 |
| `181 Call Is Being Forwarded` | 호출이 다른 곳으로 전달 중임을 알림 | `INVITE` | reliable provisional이면 `RSeq`와 `Require: 100rel`이 함께 중요하다. `To` tag가 중요하며, early dialog를 만들었다면 `Contact`는 필수이고 요청의 `Record-Route`를 반영해야 한다. 원래 요청이 `Recv-Info`를 사용한 경우, provisional response가 reliable할 때 응답도 이를 반영한다. | RFC3261, RFC3262, RFC6086 |
| `182 Queued` | 요청이 큐에 들어갔음을 알림 | `INVITE` | reliable provisional이면 `RSeq`와 `Require: 100rel`이 함께 중요하다. `To` tag가 중요하며, early dialog를 만들었다면 `Contact`는 필수이고 요청의 `Record-Route`를 반영해야 한다. 원래 요청이 `Recv-Info`를 사용한 경우, provisional response가 reliable할 때 응답도 이를 반영한다. | RFC3261, RFC3262, RFC6086 |
| `183 Session Progress` | early session progress / early media 정보를 알림 | `INVITE` | reliable provisional이면 `RSeq`와 `Require: 100rel`이 함께 중요하다. `To` tag가 중요하며, early dialog를 만들었다면 `Contact`는 필수이고 요청의 `Record-Route`를 반영해야 한다. 종종 `Body(SDP)`가 실리며, 원래 요청이 `Recv-Info`를 사용한 경우 reliable provisional 응답은 이를 반영한다. | RFC3261, RFC3262, RFC6086 |
| `199 Early Dialog Terminated` | early dialog가 종료되었음을 알림 | `INVITE` | `To` tag와 `Reason` 헤더가 중요하다. 이 응답은 UAC가 `199` option-tag를 이해하는 상황에서 의미가 있으며, reliable provisional 흐름과 함께 쓰였다면 `RSeq`와 `Require: 100rel`이 관여할 수 있다. 현재 repo validator는 이 조건 중 `To` tag만 직접 강제하고, `Reason`/`199` support 전제는 metadata/doc 수준에서 설명한다. | RFC6228, RFC3262, RFC3261 |

## 7.4 2xx Success
| 코드 | 무엇에 쓰는가 | 주 사용 메서드 | 코드별 필드 포인트 | 공식 출처 |
| --- | --- | --- | --- | --- |
| `200 OK` | 요청 성공 | 거의 모든 요청 | `2xx to INVITE`에서 dialog를 성립시키면 `Contact`는 필수이고 요청의 `Record-Route`를 반영해야 한다. `MESSAGE`에 대한 `2xx`는 `Contact`와 `Body`를 실으면 안 된다. `SUBSCRIBE` 성공에서는 `Expires`가 필수적으로 실제 구독 기간을 알려주며, 일반적으로 즉시 `NOTIFY`가 이어진다. `REGISTER` 성공에서는 현재 binding 전체를 `Contact`로 돌려주고, 환경에 따라 `Path`/`Service-Route`가 함께 중요해질 수 있다. Info Package negotiation이 걸린 경우 `Recv-Info`도 응답에 반영될 수 있다. | RFC3261, RFC3428, RFC6665, RFC3327, RFC3608, RFC6086 |
| `202 Accepted` | 접수는 했으나 처리가 아직 비동기적으로 끝나지 않음 | 현재 프로젝트 scope에서는 `MESSAGE` | 현재 프로젝트 카탈로그는 `202`를 `MESSAGE` 중심으로만 취급한다. `SUBSCRIBE`는 RFC6665에서 deprecated되었고, `REFER`는 RFC7647 이후 새 구현에서 `202`가 아니라 `200`을 사용해야 한다. | RFC3261, RFC3428, RFC6665, RFC7647 |
| `204 No Notification` | SUBSCRIBE는 성공했지만 즉시 NOTIFY를 보내지 않음 | `SUBSCRIBE` | `SUBSCRIBE` refresh 수락에서 쓰이며, 일반적인 `200-class SUBSCRIBE`와 달리 immediate NOTIFY를 생략한다. RFC 6665/5839 기준 `Expires`를 포함해 실제 구독 기간을 전달해야 한다. | RFC5839, RFC6665 |

## 7.5 3xx Redirection
| 코드 | 무엇에 쓰는가 | 주 사용 메서드 | 코드별 필드 포인트 | 공식 출처 |
| --- | --- | --- | --- | --- |
| `300 Multiple Choices` | 여러 대체 target 제시 | `INVITE`, `OPTIONS`, `REGISTER` | redirection target 목록을 위해 `Contact`가 핵심이다. | RFC3261 |
| `301 Moved Permanently` | 영구 이동 | `INVITE`, `OPTIONS`, `REGISTER` | 새 영구 target을 제시하기 위해 `Contact`가 핵심이다. | RFC3261 |
| `302 Moved Temporarily` | 임시 이동 | `INVITE`, `OPTIONS`, `REGISTER` | 새 임시 target을 제시하기 위해 `Contact`가 핵심이다. | RFC3261 |
| `305 Use Proxy` | 지정 프록시를 사용해야 함 | `INVITE`, `OPTIONS`, `REGISTER` | 클라이언트가 사용해야 할 proxy URI를 주기 위해 `Contact`가 핵심이다. | RFC3261 |
| `380 Alternative Service` | 다른 대체 서비스를 제안함 | `INVITE` | 대체 서비스 설명은 주로 `response body`에 실린다. `305`처럼 proxy `Contact`를 주는 redirection과는 다르다. | RFC3261 |

## 7.6 4xx Client Error / Request Failure
| 코드 | 무엇에 쓰는가 | 주 사용 메서드 | 코드별 필드 포인트 | 공식 출처 |
| --- | --- | --- | --- | --- |
| `400 Bad Request` | 문법/프레이밍 오류 | 광범위 | 공통 세트 | RFC3261 |
| `401 Unauthorized` | origin server 인증 요구 | 대부분의 요청(`ACK`, `CANCEL` 제외가 전형적) | `WWW-Authenticate`가 필요하다. | RFC3261 |
| `402 Payment Required` | 결제 관련 예약 코드 | 광범위 | 현재 실사용 드묾 | RFC3261 |
| `403 Forbidden` | 정책/권한 거부 | 광범위 | 공통 세트 | RFC3261 |
| `404 Not Found` | 사용자/리소스 부재 | 광범위 | 공통 세트 | RFC3261 |
| `405 Method Not Allowed` | 해당 target이 method를 허용하지 않음 | 광범위 | RFC 3261 기준 `Allow`가 필수다. 수신자는 어떤 method가 허용되는지 알아야 한다. | RFC3261 |
| `406 Not Acceptable` | Accept 계열 조건 불만족 | 광범위 | 공통 세트 | RFC3261 |
| `407 Proxy Authentication Required` | proxy 인증 요구 | 대부분의 요청(`ACK`, `CANCEL` 제외가 전형적) | `Proxy-Authenticate`가 필요하다. | RFC3261 |
| `408 Request Timeout` | 요청 처리 시간 초과 | 광범위 | 공통 세트 | RFC3261 |
| `410 Gone` | 리소스가 영구적으로 사라짐 | 광범위 | 공통 세트 | RFC3261 |
| `412 Conditional Request Failed` | conditional publication 실패 | `PUBLISH` | publication 조건 불일치 | RFC3903 |
| `413 Request Entity Too Large` | body/headers가 너무 큼 | 광범위 | 공통 세트 | RFC3261 |
| `414 Request-URI Too Long` | Request-URI가 너무 김 | 광범위 | 공통 세트 | RFC3261 |
| `415 Unsupported Media Type` | body media type 미지원 | 광범위 | `Content-Type`이 직접 문제의 원인이며, 수신자는 필요에 따라 `Accept`, `Accept-Encoding`, `Accept-Language`로 어떤 형식을 받을 수 있는지 추가 힌트를 줄 수 있다. | RFC3261 |
| `416 Unsupported URI Scheme` | URI scheme 미지원 | 광범위 | Request-URI scheme 문제 | RFC3261 |
| `417 Unknown Resource-Priority` | Resource-Priority namespace/value 미지원 | 광범위 | Resource-Priority extension 맥락 | RFC4412 |
| `420 Bad Extension` | 필수 option tag 미지원 | 광범위 | RFC 3261 기준 `Unsupported`가 필수다. 어떤 extension을 이해하지 못했는지 알려야 한다. | RFC3261 |
| `421 Extension Required` | 상대가 특정 확장을 쓰라고 요구 | 광범위 | RFC 3261 기준 `Require`가 필수다. 어떤 option tag를 반드시 써야 하는지 제시해야 한다. | RFC3261 |
| `422 Session Interval Too Small` | session timer가 너무 짧음 | `INVITE`, `UPDATE` | RFC 4028 기준 `Min-SE`가 필수다. 허용 가능한 최소 session interval을 알려야 한다. | RFC4028 |
| `423 Interval Too Brief` | expires가 너무 짧음 | `REGISTER`, `PUBLISH`, `SUBSCRIBE` | RFC 기준 `Min-Expires`가 필수다. 허용 가능한 최소 expires를 알려야 한다. | RFC3261, RFC6665 |
| `424 Bad Location Information` | geolocation 정보 오류 | 광범위 | RFC 6442 기준 `Geolocation-Error`가 필요하다. 오류의 세부 원인을 구조적으로 알려준다. | RFC6442 |
| `425 Bad Alert Message` | alerting info 오류 | 광범위 | RFC 8876 기준 `AlertMsg-Error`가 필요하다. 어떤 alerting 정보가 잘못됐는지 알려준다. | RFC8876 |
| `428 Use Identity Header` | Identity 헤더 요구 | 광범위 | identity extension 맥락 | RFC8224 |
| `429 Provide Referrer Identity` | REFER에 referrer identity 필요 | `REFER` | referral identity 맥락 | RFC3892 |
| `430 Flow Failed` | SIP outbound flow 실패 | `REGISTER` | outbound extension 맥락 | RFC5626 |
| `433 Anonymity Disallowed` | 익명성 정책 위반 | 광범위 | privacy/identity 정책 | RFC5079 |
| `436 Bad Identity Info` | identity info 무효 | 광범위 | identity verification 실패 | RFC8224 |
| `437 Unsupported Credential` | credential type 미지원 | 광범위 | identity/auth credential 불가 | RFC8224 |
| `438 Invalid Identity Header` | Identity 헤더 자체가 잘못됨 | 광범위 | identity extension 맥락 | RFC8224 |
| `439 First Hop Lacks Outbound Support` | first-hop proxy가 outbound 미지원 | `REGISTER` | outbound extension 맥락 | RFC5626 |
| `440 Max-Breadth Exceeded` | REFER recursion breadth 초과 | `REFER` | Max-Breadth extension 맥락 | RFC5393 |
| `469 Bad Info Package` | INFO package 오류 | `INFO` | RFC 6086 기준 `Recv-Info`가 필요하다. 수신 가능한 Info Package 집합을 알려준다. | RFC6086 |
| `470 Consent Needed` | explicit consent 필요 | 광범위 | 가능하면 `Permission-Missing` | RFC5360 |
| `480 Temporarily Unavailable` | 일시적으로 도달 불가 | 광범위 | 공통 세트 | RFC3261 |
| `481 Call/Transaction Does Not Exist` | dialog/transaction 상태 없음 | 광범위 | 상관관계 필드(`Call-ID`, `CSeq`, `Via`) 중요 | RFC3261 |
| `482 Loop Detected` | 라우팅 루프 감지 | 광범위 | 공통 세트 | RFC3261 |
| `483 Too Many Hops` | hop limit 소진 | 광범위 | `Max-Forwards` 맥락 | RFC3261 |
| `484 Address Incomplete` | 주소 정보 불완전 | 광범위 | Request-URI user/address 맥락 | RFC3261 |
| `485 Ambiguous` | target 식별이 애매함 | 광범위 | 공통 세트 | RFC3261 |
| `486 Busy Here` | 해당 target이 busy | 광범위, 특히 `INVITE` | 공통 세트 | RFC3261 |
| `487 Request Terminated` | 요청이 중간에 종료됨 | 광범위, 특히 `INVITE` | CANCEL 후 INVITE 종료에서 대표적 | RFC3261 |
| `488 Not Acceptable Here` | 제안된 session/body가 여기서는 불가 | 광범위 | SDP/offer 조건 문제 | RFC3261 |
| `489 Bad Event` | event package 미지원/부적합 | `SUBSCRIBE`, `NOTIFY`, `PUBLISH` | `Allow-Events`가 강하게 권장되며, `PUBLISH`에서도 Event가 없거나 미지원일 때 쓰인다. | RFC6665, RFC3903 |
| `491 Request Pending` | 겹치는 요청이 이미 진행 중 | 광범위 | re-INVITE/UPDATE collision 대표적 | RFC3261 |
| `493 Undecipherable` | security 처리 후 해독 불가 | 광범위 | 보안 처리 맥락 | RFC3261 |
| `494 Security Agreement Required` | sec-agree 협상 필요 | `REGISTER`, `INVITE` | `Security-Server`가 필요하고, `Require: sec-agree`도 핵심 규칙으로 다뤄야 한다. 선택한 보안 메커니즘이 challenge material을 요구하면 그 정보(예: `Proxy-Authenticate`)도 함께 필요해질 수 있다. | RFC3329 |

## 7.7 5xx Server Error / Server Failure
| 코드 | 무엇에 쓰는가 | 주 사용 메서드 | 코드별 필드 포인트 | 공식 출처 |
| --- | --- | --- | --- | --- |
| `500 Server Internal Error` | 서버 내부 오류 | 광범위 | 공통 세트 | RFC3261 |
| `501 Not Implemented` | method/기능 미구현 | 광범위 | 공통 세트 | RFC3261 |
| `502 Bad Gateway` | 다른 네트워크 요소 때문에 처리 실패 | 광범위 | 공통 세트 | RFC3261 |
| `503 Service Unavailable` | 서비스 일시 불가 | 광범위 | 가능하면 `Retry-After` | RFC3261 |
| `504 Server Time-out` | 다른 요소를 기다리다 timeout | 광범위 | 공통 세트 | RFC3261 |
| `505 Version Not Supported` | SIP version 미지원 | 광범위 | `SIP-Version` 맥락 | RFC3261 |
| `513 Message Too Large` | 메시지 전체가 너무 큼 | 광범위 | body+headers 전체 크기 문제 | RFC3261 |
| `555 Push Notification Service Not Supported` | push notification extension 미지원 | `REGISTER` | push notification extension 맥락 | RFC8599 |
| `580 Precondition Failure` | session preconditions 불만족 | `INVITE`, `UPDATE` | preconditions/session negotiation 맥락 | RFC3312 |

## 7.8 6xx Global Failure / Global Failures
| 코드 | 무엇에 쓰는가 | 주 사용 메서드 | 코드별 필드 포인트 | 공식 출처 |
| --- | --- | --- | --- | --- |
| `600 Busy Everywhere` | 어디에도 수락 가능한 target이 없음, 모두 busy | `INVITE` | global busy | RFC3261 |
| `603 Decline` | 명시적 거절 | `INVITE` | 공통 세트 | RFC3261 |
| `604 Does Not Exist Anywhere` | 대상이 어디에도 존재하지 않음 | `INVITE` | global not found | RFC3261 |
| `606 Not Acceptable` | 제안된 세션이 전역적으로 불가 | `INVITE` | global unacceptable session | RFC3261 |
| `607 Unwanted` | unwanted communication으로 분류 | `INVITE`, `MESSAGE`, `SUBSCRIBE` | unwanted calls/messages 정책 | RFC8197 |
| `608 Rejected` | 정책/기능 이유로 거절 | `INVITE`, `MESSAGE`, `SUBSCRIBE` | 경우에 따라 `Call-Info`가 설명 URI로 유용 | RFC8688 |

## 8. 요청/응답 전체를 보는 실무적 요약
## 8.1 UE가 받는 Request에서 특히 중요한 축
- dialog를 만드는가: `INVITE`
- dialog 안에서 상태를 바꾸는가: `BYE`, `INFO`, `UPDATE`, `REFER`
- event framework인가: `SUBSCRIBE`, `NOTIFY`, `PUBLISH`
- transaction 제어인가: `ACK`, `CANCEL`, `PRACK`
- registration/capability인가: `REGISTER`, `OPTIONS`
- out-of-dialog instant message인가: `MESSAGE`

## 8.2 UE가 받는 Response에서 특히 중요한 축
- provisional인가: `100`, `180`, `183`, `199`
- success인가: `200`, `204`
- redirection인가: `300`, `301`, `302`, `305`, `380`
- authentication / security / identity 관련 실패인가:
  - `401`, `407`, `428`, `436`, `437`, `438`, `494`
- session / body / event 확장 관련 실패인가:
  - `415`, `422`, `424`, `425`, `469`, `489`, `580`
- routing / dialog / transaction 실패인가:
  - `408`, `481`, `482`, `483`, `487`

## 8.3 퍼징 관점에서 중요한 이유
이 문서를 기준으로 보면, Sender/Mutator/Oracle은 아래를 특히 신경 써야 한다.

- `transaction 상관관계 필드`
  - `Via.branch`
  - `Call-ID`
  - `CSeq`
- `dialog 상태 필드`
  - `From` tag
  - `To` tag
  - `Contact`
  - `Route` / `Record-Route`
- `body 처리 필드`
  - `Content-Type`
  - `Content-Length`
  - `Body`
- `확장 필드`
  - `Event`
  - `Subscription-State`
  - `RAck` / `RSeq`
  - `Security-Server`
  - `Info-Package` / `Recv-Info`

즉, SIP 퍼징은 단순히 “헤더를 많이 바꾼다”가 아니라, **메시지 종류별로 어떤 필드가 transaction/dialog/state semantics를 지배하는지 이해한 뒤 변조해야 의미가 있다.**

## 9. 빠른 참고용 체크리스트
### Request를 볼 때
- 이 method는 dialog 밖에서 오는가, 안에서 오는가?
- `Contact`가 필수인가?
- `Event`나 `Subscription-State`가 필요한가?
- `Body`가 실리는 것이 자연스러운가?
- `Route` set이 필요한가?

### Response를 볼 때
- 이 응답은 어떤 method에 대한 것인가?
- authentication/security extension인가?
- redirection이면 `Contact`가 필요한가?
- reliable provisional이면 `RSeq`가 필요한가?
- event/publication/session timer 확장이라면 관련 필드가 필요한가?

## 10. 이 문서와 함께 보면 좋은 공식 참고 순서
1. IANA SIP Parameters
2. RFC3261
3. 메시지별 확장 RFC
   - PRACK: RFC3262
   - UPDATE: RFC3311
   - MESSAGE: RFC3428
   - REFER: RFC3515
   - PUBLISH: RFC3903
   - Session-Timer: RFC4028
   - INFO framework: RFC6086
   - Event framework: RFC6665
   - Location: RFC6442
   - Security agreement: RFC3329
   - Identity: RFC8224
