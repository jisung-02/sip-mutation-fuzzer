# 단말 기준 SIP 메시지 전체 분류 및 정의

> 검증 기준: IANA SIP Parameters Registry(Methods / Response Codes)와 관련 RFC를 **2026-03-07** 기준으로 확인했다.

## 1. 문서 목적
이 문서는 **단말(UE) 기준으로 수신 가능한 SIP 메시지 전체 목록**을 분류하고, 각 메시지의 의미·전제조건·단말 관점의 현실적 수신 양상을 정리한다. 이 문서는 Phase 1의 **정의/분류 기준 문서**이며, 구현 계획이나 개발 일정은 별도 계획 문서에서 관리한다.

## 2. 기준 및 분류 원칙
### 2.1 기준 문서
- IANA 등록 Request Method 수: **14개**
- IANA 등록 Response Code 수: **75개**
- IANA 표에 별도 RFC가 비어 있는 Response Code는 기본적으로 **RFC3261의 기본 SIP 코드**로 본다.
- 이 문서는 **메시지 종류(method / status code) 분류 문서**이며, 헤더 필드/option tag/URI parameter 전체 분류 문서는 아니다.

### 2.2 단말 기준 방향 정의
- **Incoming Request**: 네트워크/프록시/다른 단말이 UE로 보내는 요청. 이때 UE는 주로 **UAS** 역할이다.
- **Incoming Response**: UE가 먼저 보낸 요청에 대해 네트워크/프록시/다른 단말이 UE로 반환하는 응답. 이때 UE는 주로 **UAC** 역할이다.

### 2.3 실무상 해석 주의
- IANA에 등록된 모든 Method는 **표준상 존재하는 SIP Request 종류**이지만, 그중 일부는 **일반 핸드셋 UE가 실무에서 직접 수신하는 시나리오가 매우 드물다**. 대표적으로 `REGISTER`, `PUBLISH`는 일반 UE보다 registrar / publication server 쪽 의미가 강하다.
- Response Code는 특정 Method에 완전히 고정되지 않는다. 다만 각 코드마다 **대표적으로 자주 연결되는 요청/확장**이 있다.
- 구현 계획, 개발 일정, 테스트 커버리지 계획은 이 문서가 아니라 **PRD 또는 별도 실행 계획 문서**에서 관리하는 것이 적절하다.

## 3. Incoming SIP Requests 전체 분류

| Method | 기준 RFC | 표준 의미 | UE가 수신하는 전형적 상황 | 주요 전제조건 | 단말 관점 수신 가능성 |
| --- | --- | --- | --- | --- | --- |
| `ACK` | `[RFC3261]` | INVITE에 대한 최종 응답(특히 2xx)을 확인하여 트랜잭션/대화 진행을 확정한다. | UE가 INVITE 수신자(UAS)였고 최종 응답을 이미 보낸 뒤, 상대가 그 응답을 확인할 때 | 선행 INVITE 트랜잭션 존재, 특히 2xx 응답 이후 | 직접 수신(일반적) |
| `BYE` | `[RFC3261]` | 이미 성립한 세션(dialog)을 종료한다. | 통화/세션이 성립된 뒤 상대가 종료를 요청할 때 | 확정된 dialog 존재 | 직접 수신(일반적) |
| `CANCEL` | `[RFC3261]` | 아직 완료되지 않은 INVITE 트랜잭션을 취소한다. | 상대가 보낸 INVITE를 UE가 아직 최종 처리하지 않았을 때 상대가 취소를 보내는 경우 | 진행 중인 INVITE 서버 트랜잭션 존재, 최종 응답 전 | 직접 수신(일반적) |
| `INFO` | `[RFC6086]` | dialog 중 애플리케이션 레벨 추가 정보를 전달한다. RFC 6086에서는 Info Package 체계를 정의한다. | 통화 중 DTMF/부가정보 등 mid-dialog 정보 전달이 필요한 경우 | 기존 dialog 존재, 필요 시 Info-Package 협상/지원 | 조건부 수신(기능 의존) |
| `INVITE` | `[RFC3261][RFC6026]` | 새 세션을 생성하거나 기존 dialog의 세션 특성을 수정(re-INVITE)한다. | 수신 통화/세션 시작 또는 세션 재협상이 필요한 경우 | 초기 INVITE는 별도 전제조건 없음, re-INVITE는 기존 dialog 필요 | 직접 수신(핵심) |
| `MESSAGE` | `[RFC3428]` | pager-mode 인스턴트 메시지를 전달한다. | 상대가 SIP MESSAGE 기반 텍스트/신호성 메시지를 UE로 보낼 때 | out-of-dialog 또는 in-dialog 모두 가능 | 조건부 수신(서비스 의존) |
| `NOTIFY` | `[RFC6665]` | 구독 상태(Event Package) 또는 REFER 진행 상태를 통지한다. | UE가 앞서 SUBSCRIBE를 보냈거나 REFER로 인해 implicit subscription이 생긴 경우 | 활성 subscription 또는 REFER 기반 implicit subscription | 조건부 수신(이벤트/REFER 의존) |
| `OPTIONS` | `[RFC3261]` | 상대 단말/서버의 기능과 지원 능력을 조회한다. | 네트워크 또는 상대가 UE capability를 확인하려 할 때 | 별도 dialog 불필요 | 직접 수신(일반적) |
| `PRACK` | `[RFC3262]` | 신뢰성 있는 provisional response(100rel)를 확인한다. | UE가 reliable provisional response를 보낸 뒤 상대가 이를 확인할 때 | 선행 reliable provisional response(예: 183 + 100rel) 존재 | 조건부 수신(100rel 의존) |
| `PUBLISH` | `[RFC3903]` | 이벤트 상태를 event state compositor에 게시한다. | UE가 publication server 역할을 제공하는 특수 환경에서만 실질적으로 가능 | UE가 publication 대상 서버/서비스 역할을 가져야 함 | 희소/비전형(단말 일반 용도와 거리 있음) |
| `REFER` | `[RFC3515]` | 수신자에게 제3자와 접촉하도록 지시하여 전환/호전달 등을 유도한다. | 호 전환, call transfer, click-to-dial 류 시나리오에서 | 일반적으로 dialog 존재가 흔하나, 구현에 따라 out-of-dialog도 가능 | 조건부 수신(서비스/기능 의존) |
| `REGISTER` | `[RFC3261]` | Address-of-Record와 Contact 바인딩을 registrar에 등록/갱신한다. | 일반적인 핸드셋 UE는 송신자(UAC)이며, 수신 측 registrar 역할은 드묾 | UE가 registrar 또는 동등한 서비스 역할을 제공해야 의미가 생김 | 희소/비전형(핸드셋 UE에는 보통 부적합) |
| `SUBSCRIBE` | `[RFC6665]` | 특정 이벤트 패키지에 대한 상태 통지를 구독한다. | 상대가 UE의 상태(예: presence, dialog event 등)를 구독하려 할 때 | UE가 해당 Event Package를 지원해야 함 | 조건부 수신(이벤트 프레임워크 의존) |
| `UPDATE` | `[RFC3311]` | 최종 INVITE 응답 이전 또는 dialog 중 세션 파라미터를 갱신한다. | 세션 협상(SDP 등)을 조정하되 새로운 dialog를 만들지 않을 때 | early dialog 또는 confirmed dialog 존재 | 조건부 수신(세션 제어 의존) |

### 3.1 Request 분류 요약
- **핵심적으로 직접 수신되는 요청**: `INVITE`, `ACK`, `BYE`, `CANCEL`, `OPTIONS`
- **기능/상태에 따라 조건부로 수신되는 요청**: `PRACK`, `UPDATE`, `INFO`, `MESSAGE`, `NOTIFY`, `REFER`, `SUBSCRIBE`
- **표준상 존재하지만 일반 핸드셋 UE에는 비전형적인 요청**: `REGISTER`, `PUBLISH`

## 4. Incoming SIP Responses 전체 분류

### 4.1 Response Class 의미
| Class | 의미 | UE가 이 응답을 받는 전형적 상황 |
| --- | --- | --- |
| `1xx` | 최종 응답 전 진행 상태를 알리는 provisional response | UE가 요청을 보낸 뒤 상대가 처리 중임을 알릴 때 |
| `2xx` | 요청이 성공적으로 처리됨 | UE의 요청이 수락/완료되었을 때 |
| `3xx` | 다른 대상/서비스로 재시도하라는 redirection | 요청 대상이 다른 위치나 대안 서비스로 옮겨졌을 때 |
| `4xx` | UE가 보낸 요청 또는 현재 상태에 문제가 있음 | 문법 오류, 인증 요구, 상태 불일치, 확장 미지원 등 |
| `5xx` | 상대 서버/네트워크 측 처리 실패 | 서버 내부 오류, 다음 홉 실패, 서비스 불가 등 |
| `6xx` | 전역(global) 수준에서 요청이 거부됨 | 특정 대상이 아니라 전체적으로 수용 불가로 판단될 때 |

### 4.2 Response 해석 규칙
- UE가 Response를 수신하려면 **반드시 선행 Request를 UE가 먼저 송신**했어야 한다.
- 동일한 Response Code라도 **요청 Method, dialog 상태, extension 사용 여부**에 따라 의미가 조금 달라질 수 있다.
- `Reason-Phrase`는 구현에 따라 달라질 수 있으므로, 구현상 핵심 식별자는 **정수 Status Code 자체**다.

### 1xx Informational

| Code | Reason Phrase | 기준 RFC | 대표 연관 요청/시나리오 | 해석 메모 |
| --- | --- | --- | --- | --- |
| `100` | `Trying` | `[RFC3261]` | INVITE, OPTIONS, REGISTER, SUBSCRIBE 등 거의 모든 요청 | 상대 측이 요청 처리를 시작했음을 알림. 거의 모든 요청에서 가능. |
| `180` | `Ringing` | `[RFC3261]` | INVITE | 피호출 측이 벨을 울리는 중임을 알리는 전형적 INVITE 응답. |
| `181` | `Call Is Being Forwarded` | `[RFC3261]` | INVITE | 호가 다른 대상으로 전달되고 있음을 알림. 주로 INVITE. |
| `182` | `Queued` | `[RFC3261]` | INVITE | 요청이 대기열에 들어갔음을 알림. 주로 INVITE. |
| `183` | `Session Progress` | `[RFC3261]` | INVITE | 최종 응답 전 세션 진행 상태(early media 포함 가능)를 전달. 주로 INVITE. |
| `199` | `Early Dialog Terminated` | `[RFC6228]` | INVITE(early dialog) | 생성되었던 early dialog가 더 이상 유효하지 않음을 알림. INVITE early dialog 확장. |

### 2xx Success

| Code | Reason Phrase | 기준 RFC | 대표 연관 요청/시나리오 | 해석 메모 |
| --- | --- | --- | --- | --- |
| `200` | `OK` | `[RFC3261]` | 모든 요청 | 요청이 성공적으로 완료됨. 모든 요청에서 가장 핵심적인 성공 응답. |
| `202` | `Accepted (Deprecated)` | `[RFC6665]` | SUBSCRIBE 등 이벤트 요청 | 요청이 수락되었으나 즉시 완료 의미는 아니며, IANA상 Deprecated. 이벤트 계열에서 주로 관찰. |
| `204` | `No Notification` | `[RFC5839]` | 이벤트 알림 확장 | 성공은 했지만 추가 Notification을 보내지 않음을 의미하는 이벤트 확장 응답. |

### 3xx Redirection

| Code | Reason Phrase | 기준 RFC | 대표 연관 요청/시나리오 | 해석 메모 |
| --- | --- | --- | --- | --- |
| `300` | `Multiple Choices` | `[RFC3261]` | INVITE, OPTIONS, REGISTER 등 | 다수의 가능한 대상이 있어 재선택이 필요함. |
| `301` | `Moved Permanently` | `[RFC3261]` | INVITE, OPTIONS, REGISTER 등 | 요청 대상이 영구적으로 다른 위치로 이동했음을 알림. |
| `302` | `Moved Temporarily` | `[RFC3261]` | INVITE, OPTIONS, REGISTER 등 | 요청 대상이 일시적으로 다른 위치로 이동했음을 알림. |
| `305` | `Use Proxy` | `[RFC3261]` | 리다이렉션 계열 요청 | 특정 프록시를 통해 요청하라는 의미의 비교적 드문 리다이렉션. |
| `380` | `Alternative Service` | `[RFC3261]` | INVITE 중심 | 대체 서비스 사용을 제안하는 리다이렉션 성격의 응답. |

### 4xx Client Error

| Code | Reason Phrase | 기준 RFC | 대표 연관 요청/시나리오 | 해석 메모 |
| --- | --- | --- | --- | --- |
| `400` | `Bad Request` | `[RFC3261]` | 대부분의 요청 | 문법/구성 오류 등으로 요청을 해석할 수 없음을 의미. |
| `401` | `Unauthorized` | `[RFC3261]` | REGISTER, INVITE, MESSAGE, SUBSCRIBE 등 | 대상 서버가 인증을 요구함. REGISTER/INVITE 등에서 매우 중요. |
| `402` | `Payment Required` | `[RFC3261]` | 대부분의 요청 | SIP에서는 거의 쓰이지 않는 예약성 코드로 실무에서는 드묾. |
| `403` | `Forbidden` | `[RFC3261]` | 대부분의 요청 | 인증 여부와 별개로 요청이 정책적으로 거부됨. |
| `404` | `Not Found` | `[RFC3261]` | 대부분의 요청 | 대상 사용자/리소스를 찾을 수 없음. |
| `405` | `Method Not Allowed` | `[RFC3261]` | 대부분의 요청 | 해당 대상이 그 Method를 허용하지 않음. |
| `406` | `Not Acceptable` | `[RFC3261]` | 대부분의 요청 | Accept류 조건을 만족하지 못해 수용 불가. |
| `407` | `Proxy Authentication Required` | `[RFC3261]` | REGISTER, INVITE, MESSAGE, SUBSCRIBE 등 | 프록시가 인증을 요구함. IMS/Proxy 환경에서 중요. |
| `408` | `Request Timeout` | `[RFC3261]` | 대부분의 요청 | 응답 대기 중 시간 초과. |
| `410` | `Gone` | `[RFC3261]` | 대부분의 요청 | 대상이 더 이상 존재하지 않음. |
| `412` | `Conditional Request Failed` | `[RFC3903]` | PUBLISH | 조건부 요청 조건이 맞지 않음. 주로 PUBLISH와 연계. |
| `413` | `Request Entity Too Large` | `[RFC3261]` | 대부분의 요청 | 메시지 본문/헤더가 너무 큼. |
| `414` | `Request-URI Too Long` | `[RFC3261]` | 대부분의 요청 | Request-URI가 너무 김. |
| `415` | `Unsupported Media Type` | `[RFC3261]` | 대부분의 요청 | 지원하지 않는 미디어 타입. |
| `416` | `Unsupported URI Scheme` | `[RFC3261]` | 대부분의 요청 | 지원하지 않는 URI Scheme. |
| `417` | `Unknown Resource-Priority` | `[RFC4412]` | Resource-Priority 사용 요청 | Resource-Priority 확장을 이해하지 못하거나 허용하지 않음. |
| `420` | `Bad Extension` | `[RFC3261]` | 대부분의 요청 | 필수 확장/option tag가 지원되지 않음. |
| `421` | `Extension Required` | `[RFC3261]` | 대부분의 요청 | 요청 처리를 위해 특정 확장을 반드시 요구함. |
| `422` | `Session Interval Too Small` | `[RFC4028]` | INVITE, UPDATE | Session-Timer 제안이 너무 작음. 주로 INVITE/UPDATE. |
| `423` | `Interval Too Brief` | `[RFC3261]` | REGISTER, PUBLISH | Expires 계열 값이 너무 짧음. REGISTER/PUBLISH에서 자주 연결. |
| `424` | `Bad Location Information` | `[RFC6442]` | Geolocation 포함 요청 | 위치 정보(Geolocation) 관련 값이 잘못됨. |
| `425` | `Bad Alert Message` | `[RFC8876]` | Alert-Info/Alert 확장 요청 | Alert 메시지/알림 확장 값이 잘못됨. |
| `428` | `Use Identity Header` | `[RFC8224]` | Identity 헤더 사용 요청 | Identity 헤더 사용을 요구함. |
| `429` | `Provide Referrer Identity` | `[RFC3892]` | REFER 계열 | Referrer Identity 제공을 요구함. REFER 계열 확장. |
| `430` | `Flow Failed` | `[RFC5626]` | REGISTER / outbound 사용 요청 | Outbound flow가 실패했음을 의미. |
| `433` | `Anonymity Disallowed` | `[RFC5079]` | Privacy/Identity 관련 요청 | 익명성 정책상 요청이 허용되지 않음. |
| `436` | `Bad Identity Info` | `[RFC8224]` | Identity 사용 요청 | Identity 정보가 잘못되었거나 검증 불가. |
| `437` | `Unsupported Credential` | `[RFC8224]` | Identity 사용 요청 | 제공된 자격증명/credential 형식을 지원하지 않음. |
| `438` | `Invalid Identity Header` | `[RFC8224]` | Identity 사용 요청 | Identity 헤더 값 자체가 유효하지 않음. |
| `439` | `First Hop Lacks Outbound Support` | `[RFC5626]` | REGISTER / outbound 사용 요청 | 첫 홉이 SIP Outbound를 지원하지 않음. |
| `440` | `Max-Breadth Exceeded` | `[RFC5393]` | REFER | REFER 확장에서 재귀 탐색 폭이 한도를 넘음. |
| `469` | `Bad Info Package` | `[RFC6086]` | INFO | INFO 패키지가 잘못되었거나 지원되지 않음. |
| `470` | `Consent Needed` | `[RFC5360]` | Consent framework 사용 요청 | 상대가 요청 처리 전에 명시적 consent를 요구함. |
| `480` | `Temporarily Unavailable` | `[RFC3261]` | 대부분의 요청 | 상대가 현재 일시적으로 이용 불가. |
| `481` | `Call/Transaction Does Not Exist` | `[RFC3261]` | 대부분의 요청 | 대응되는 call/dialog/transaction 상태를 찾을 수 없음. |
| `482` | `Loop Detected` | `[RFC3261]` | 대부분의 요청 | 라우팅 루프 감지. |
| `483` | `Too Many Hops` | `[RFC3261]` | 대부분의 요청 | 홉 수 초과. |
| `484` | `Address Incomplete` | `[RFC3261]` | 대부분의 요청 | 주소 정보가 불완전함. |
| `485` | `Ambiguous` | `[RFC3261]` | 대부분의 요청 | 지정한 대상이 모호함. |
| `486` | `Busy Here` | `[RFC3261]` | 대부분의 요청 | 상대가 통화 중(busy)임. |
| `487` | `Request Terminated` | `[RFC3261]` | 대부분의 요청 | 요청이 취소 또는 다른 이유로 종료됨. CANCEL 후 INVITE에 흔함. |
| `488` | `Not Acceptable Here` | `[RFC3261]` | 대부분의 요청 | 현재 제안/세션 조건을 수용할 수 없음. SDP 협상 실패 등에 중요. |
| `489` | `Bad Event` | `[RFC6665]` | SUBSCRIBE, NOTIFY | 이벤트 패키지가 잘못되었거나 지원되지 않음. |
| `491` | `Request Pending` | `[RFC3261]` | 대부분의 요청 | 동시 재협상 충돌 등으로 요청을 잠시 처리할 수 없음. |
| `493` | `Undecipherable` | `[RFC3261]` | 대부분의 요청 | 보안 처리를 통해 해독할 수 없는 요청임. |
| `494` | `Security Agreement Required` | `[RFC3329]` | REGISTER, INVITE | 보안 메커니즘 합의가 필요함. IMS 계열에서 중요할 수 있음. |

### 5xx Server Error

| Code | Reason Phrase | 기준 RFC | 대표 연관 요청/시나리오 | 해석 메모 |
| --- | --- | --- | --- | --- |
| `500` | `Server Internal Error` | `[RFC3261]` | 대부분의 요청 | 상대 서버 내부 처리 오류. |
| `501` | `Not Implemented` | `[RFC3261]` | 대부분의 요청 | 상대가 해당 기능/Method를 구현하지 않음. |
| `502` | `Bad Gateway` | `[RFC3261]` | 대부분의 요청 | 게이트웨이/중간 서버 오류. |
| `503` | `Service Unavailable` | `[RFC3261]` | 대부분의 요청 | 서비스 일시 불가. |
| `504` | `Server Time-out` | `[RFC3261]` | 대부분의 요청 | 상위 서버/다음 홉 응답 시간 초과. |
| `505` | `Version Not Supported` | `[RFC3261]` | 대부분의 요청 | 지원하지 않는 SIP 버전. |
| `513` | `Message Too Large` | `[RFC3261]` | 대부분의 요청 | 메시지가 너무 커서 처리할 수 없음. |
| `555` | `Push Notification Service Not Supported` | `[RFC8599]` | Push Notification 확장 요청 | Push Notification Service 확장을 지원하지 않음. |
| `580` | `Precondition Failure` | `[RFC3312]` | INVITE, UPDATE | 세션 precondition을 만족하지 못함. INVITE/UPDATE에서 중요. |

### 6xx Global Failure

| Code | Reason Phrase | 기준 RFC | 대표 연관 요청/시나리오 | 해석 메모 |
| --- | --- | --- | --- | --- |
| `600` | `Busy Everywhere` | `[RFC3261]` | 주로 INVITE | 어느 대상에서도 busy 상태로 간주되는 전역 실패. |
| `603` | `Decline` | `[RFC3261]` | 주로 INVITE | 요청이 명시적으로 거절됨. INVITE류에서 흔한 최종 실패. |
| `604` | `Does Not Exist Anywhere` | `[RFC3261]` | 주로 INVITE | 대상이 어느 위치에도 존재하지 않음. |
| `606` | `Not Acceptable` | `[RFC3261]` | 주로 INVITE | 세션 특성상 전혀 수용 불가. |
| `607` | `Unwanted` | `[RFC8197]` | INVITE, MESSAGE | 상대가 원치 않는(unwanted) 통신으로 분류해 거절함. |
| `608` | `Rejected` | `[RFC8688]` | INVITE, REFER 계열 | 정책/기능상의 이유로 요청이 거절됨(확장 정의). |

## 5. 문서 활용 원칙
1. 이 문서는 **정의 문서**이므로, 무엇이 존재하고 어떤 의미를 가지는지를 정리하는 데 집중한다.
2. 구현 계획, 개발 일정, 테스트 커버리지 계획은 **PRD 또는 별도 실행 계획 문서**에서 관리한다.
3. Request 쪽 스키마에는 최소한 `method`, `direction`, `ue_role`, `semantic_relevance`, `preconditions`, `reference_rfcs` 필드가 필요하다.
4. Response 쪽 스키마에는 최소한 `status_code`, `status_class`, `reason_phrase`, `direction`, `ue_role`, `related_methods`, `reference_rfcs` 필드가 필요하다.
5. `REGISTER`, `PUBLISH` 같은 비전형 Request도 이 문서에서는 빠지지 않아야 한다. 정의 문서의 역할은 흔한 것만 남기는 것이 아니라 **존재하는 범주를 빠짐없이 기록하는 것**이기 때문이다.

## 6. 출처
- IANA SIP Parameters Registry: https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml
- RFC 3261 (Session Initiation Protocol): https://www.rfc-editor.org/info/rfc3261
- RFC 3262 (Reliability of Provisional Responses in SIP): https://www.rfc-editor.org/info/rfc3262
- RFC 3311 (The SIP UPDATE Method): https://www.rfc-editor.org/info/rfc3311
- RFC 3428 (SIP Extension for Instant Messaging): https://www.rfc-editor.org/info/rfc3428
- RFC 3515 (The SIP Refer Method): https://www.rfc-editor.org/info/rfc3515
- RFC 3903 (SIP Extension for Event State Publication): https://www.rfc-editor.org/info/rfc3903
- RFC 6086 (Session Initiation Protocol (SIP) INFO Method and Package Framework): https://www.rfc-editor.org/info/rfc6086
- RFC 6665 (SIP-Specific Event Notification): https://www.rfc-editor.org/info/rfc6665

---
이 문서는 **2026-03-07 기준 IANA registry snapshot**을 바탕으로 정리했으며, 이후 IANA 등록 값이 바뀌면 다시 검증해야 한다.
