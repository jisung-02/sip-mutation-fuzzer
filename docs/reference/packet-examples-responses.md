# SIP 응답 패킷 예시

> 이 문서는 `scripts/generate_packet_docs.py` 로 생성된다.
> 이 문서는 각 SIP 응답을 **실제 SIP 텍스트 패킷 형태**로 이해하기 위한 설명 문서이다.
> 예시 패킷은 대표 예시이며, 응답 코드별 핵심 헤더만 우선 보여준다.

## 공통 응답 골격

```text
SIP/2.0 200 OK
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-generic
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: generic-response@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

공통 필수 헤더:
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

## 100 Trying

- 설명: Provisional response indicating request processing has started.
- 대표 상황: UE sent a request and the next hop has begun processing it.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 100 Trying
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-100-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 100-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

## 180 Ringing

- 설명: Indicates the callee is alerting.
- 대표 상황: UE receives 180 after sending INVITE for an outbound call.
- 관련 메서드: INVITE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 180 Ringing
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-180-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 180-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Require: 100rel
RSeq: 1
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- `Require`
- `Rseq`

### 조건부 규칙
- `Rseq`: Include RSeq when the provisional response is sent reliably with 100rel. — RSeq is not mandatory for ordinary provisional responses, only for reliable ones.
- `Contact`: For non-100 provisional responses to INVITE that establish an early dialog, Contact is mandatory so the remote target is known.
- `Record-Route`: If the INVITE request contained Record-Route, copy it into the dialog-establishing provisional response.
- `Recv-Info`: When the associated request used the INFO package framework and carried Recv-Info, reliable 18x/2xx responses include Recv-Info as well, even if empty.
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 181 Call Is Being Forwarded

- 설명: Indicates the called party is being forwarded elsewhere.
- 대표 상황: Outbound INVITE is being redirected during early dialog handling.
- 관련 메서드: INVITE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 181 Call Is Being Forwarded
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-181-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 181-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Contact: <sip:network@ims.mnc001.mcc001.3gppnetwork.org>
Require: 100rel
RSeq: 1
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- `Require`
- `Rseq`
- `Contact`

### 조건부 규칙
- `Rseq`: Include RSeq when the provisional response is sent reliably with 100rel. — RSeq is not mandatory for ordinary provisional responses, only for reliable ones.
- `Contact`: For non-100 provisional responses to INVITE that establish an early dialog, Contact is mandatory so the remote target is known.
- `Record-Route`: If the INVITE request contained Record-Route, copy it into the dialog-establishing provisional response.
- `Recv-Info`: When the associated request used the INFO package framework and carried Recv-Info, reliable 18x/2xx responses include Recv-Info as well, even if empty.
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 182 Queued

- 설명: Indicates the request has been placed in a queue.
- 대표 상황: Outbound INVITE waits in a queue at the far end.
- 관련 메서드: INVITE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 182 Queued
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-182-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 182-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Require: 100rel
RSeq: 1
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- `Require`
- `Rseq`

### 조건부 규칙
- `Rseq`: Include RSeq when the provisional response is sent reliably with 100rel. — RSeq is not mandatory for ordinary provisional responses, only for reliable ones.
- `Contact`: For non-100 provisional responses to INVITE that establish an early dialog, Contact is mandatory so the remote target is known.
- `Record-Route`: If the INVITE request contained Record-Route, copy it into the dialog-establishing provisional response.
- `Recv-Info`: When the associated request used the INFO package framework and carried Recv-Info, reliable 18x/2xx responses include Recv-Info as well, even if empty.
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 183 Session Progress

- 설명: Provides early session progress, often with early media information.
- 대표 상황: Outbound INVITE receives early media/session setup details before final answer.
- 관련 메서드: INVITE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 183 Session Progress
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-183-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 183-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Require: 100rel
RSeq: 1
Content-Type: application/sdp
Content-Length: 94

v=0
o=- 0 0 IN IP4 172.22.0.20
s=-
c=IN IP4 198.51.100.20
t=0 0
m=audio 50000 RTP/AVP 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- `Require`
- `Rseq`
- `Content-Type`

### 조건부 규칙
- `Rseq`: Include RSeq when the provisional response is sent reliably with 100rel. — RSeq is not mandatory for ordinary provisional responses, only for reliable ones.
- `Contact`: For non-100 provisional responses to INVITE that establish an early dialog, Contact is mandatory so the remote target is known.
- `Record-Route`: If the INVITE request contained Record-Route, copy it into the dialog-establishing provisional response.
- `Recv-Info`: When the associated request used the INFO package framework and carried Recv-Info, reliable 18x/2xx responses include Recv-Info as well, even if empty.
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 199 Early Dialog Terminated

- 설명: Signals that an established early dialog has terminated.
- 대표 상황: One branch of a forked INVITE early dialog is ended before final answer.
- 관련 메서드: INVITE
- RFC: RFC6228

### 대표 SIP 패킷 예시

```text
SIP/2.0 199 Early Dialog Terminated
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-199-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 199-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Require: 100rel
RSeq: 1
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- `Require`
- `Rseq`

### 조건부 규칙
- `Rseq`: Include RSeq when the provisional response is sent reliably with 100rel. — RSeq is not mandatory for ordinary provisional responses, only for reliable ones.
- `Reason`: A 199 Early Dialog Terminated response MUST include a Reason header indicating which final outcome terminated the dialog.
- `Supported`: 199 is only meaningful when the UAC indicated support for the '199' option-tag.
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 200 OK

- 설명: Generic success response for SIP requests.
- 대표 상황: UE request completed successfully.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 200 OK
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-200-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 200-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Contact: <sip:network@ims.mnc001.mcc001.3gppnetwork.org>
Content-Type: application/sdp
Content-Length: 94

v=0
o=- 0 0 IN IP4 172.22.0.20
s=-
c=IN IP4 198.51.100.20
t=0 0
m=audio 50002 RTP/AVP 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- `Contact`
- `Content-Type`

### 조건부 규칙
- `Contact`: 2xx responses to INVITE require Contact so the remote target for the established dialog is known.
- `Record-Route`: If the INVITE request contained Record-Route, copy it into the dialog-establishing 2xx response.
- `Expires`: A 200-class response to SUBSCRIBE MUST include Expires to indicate the actual subscription duration granted by the notifier.
- `Contact`: A 2xx response to MESSAGE MUST NOT include Contact because MESSAGE does not establish a dialog.
- `Body`: A 2xx response to MESSAGE MUST NOT include a message body.
- `Recv-Info`: When the associated request used the INFO package framework and carried Recv-Info, reliable 18x/2xx responses include Recv-Info as well, even if empty.
- `Contact`: Successful REGISTER responses MUST return the current contact bindings known to the registrar.
- `Path`: When the Path extension is in use, a successful REGISTER response copies the Path header field values from the request.
- `Service-Route`: A successful REGISTER response may include Service-Route values that the UA must use for future requests in the registered context.
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 202 Accepted (Deprecated)

- 설명: Accepted but not yet fully completed; explicitly allowed for MESSAGE asynchronous gateway delivery (RFC 3428). Not mentioned by RFC 6665 for SUBSCRIBE (200 OK is the expected response). Forbidden for REFER by RFC 7647 (MUST NOT send 202).
- 대표 상황: Asynchronous MESSAGE processing via a store-and-forward gateway.
- 관련 메서드: MESSAGE
- RFC: RFC3261, RFC3428, RFC6665, RFC7647

### 대표 SIP 패킷 예시

```text
SIP/2.0 202 Accepted (Deprecated)
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-202-message
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 202-message@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 MESSAGE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 204 No Notification

- 설명: Successful SUBSCRIBE processing without sending a follow-up NOTIFY.
- 대표 상황: In-dialog SUBSCRIBE refresh is accepted and the notifier suppresses an immediate NOTIFY.
- 관련 메서드: SUBSCRIBE
- RFC: RFC5839

### 대표 SIP 패킷 예시

```text
SIP/2.0 204 No Notification
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-204-subscribe
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 204-subscribe@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 SUBSCRIBE
Expires: 300
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- `Expires`

### 조건부 규칙
- `Expires`: 204 No Notification responses to SUBSCRIBE MUST include Expires to communicate the granted subscription duration.
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 300 Multiple Choices

- 설명: Indicates several possible targets are available.
- 대표 상황: UE must choose between alternative redirect contacts.
- 관련 메서드: INVITE, OPTIONS, REGISTER
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 300 Multiple Choices
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-300-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 300-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Contact: <sip:network@ims.mnc001.mcc001.3gppnetwork.org>
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`
- `Contact`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `Contact`: Typically carries one or more alternative targets for the redirection decision.
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 301 Moved Permanently

- 설명: Indicates the target has moved permanently.
- 대표 상황: UE should update routing based on permanent redirection.
- 관련 메서드: INVITE, OPTIONS, REGISTER
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 301 Moved Permanently
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-301-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 301-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Contact: <sip:network@ims.mnc001.mcc001.3gppnetwork.org>
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`
- `Contact`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `Contact`: Typically carries one or more alternative targets for the redirection decision.
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 302 Moved Temporarily

- 설명: Indicates the target has moved temporarily.
- 대표 상황: UE retries the request using a temporary alternate target.
- 관련 메서드: INVITE, OPTIONS, REGISTER
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 302 Moved Temporarily
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-302-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 302-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Contact: <sip:network@ims.mnc001.mcc001.3gppnetwork.org>
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`
- `Contact`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `Contact`: Typically carries one or more alternative targets for the redirection decision.
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 305 Use Proxy

- 설명: Requires the client to use a specified proxy.
- 대표 상황: UE must reattempt the request through a designated proxy.
- 관련 메서드: INVITE, OPTIONS, REGISTER
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 305 Use Proxy
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-305-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 305-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Contact: <sip:network@ims.mnc001.mcc001.3gppnetwork.org>
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`
- `Contact`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `Contact`: Typically carries one or more alternative targets for the redirection decision.
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 380 Alternative Service

- 설명: Suggests an alternative service for the request.
- 대표 상황: Outbound INVITE is redirected to a different service handling model.
- 관련 메서드: INVITE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 380 Alternative Service
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-380-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 380-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Type: text/plain
Content-Length: 81

Alternative service available via sip:service@ims.mnc001.mcc001.3gppnetwork.org
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- `Content-Type`

### 조건부 규칙
- `Body`: Alternative services are described in the message body rather than by redirect Contact targets.
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 400 Bad Request

- 설명: The request could not be understood because of syntax or framing problems.
- 대표 상황: Malformed or inconsistent request was rejected.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 400 Bad Request
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-400-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 400-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 401 Unauthorized

- 설명: Origin server demands client authentication.
- 대표 상황: UE must resend with Authorization credentials.
- 관련 메서드: BYE, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 401 Unauthorized
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-401-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 401-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
WWW-Authenticate: Digest realm="ims.mnc001.mcc001.3gppnetwork.org", nonce="nonce-1"
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`
- `WWW-Authenticate`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 402 Payment Required

- 설명: Reserved or rarely used payment-related rejection.
- 대표 상황: Mostly theoretical SIP status code with little deployment use.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 402 Payment Required
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-402-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 402-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 403 Forbidden

- 설명: Policy or authorization rejected the request.
- 대표 상황: Server understood the request but refuses to fulfill it.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 403 Forbidden
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-403-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 403-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 404 Not Found

- 설명: Requested user or resource was not found.
- 대표 상황: Outbound request targets an unknown user or resource.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 404 Not Found
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-404-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 404-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 405 Method Not Allowed

- 설명: Target does not allow the request method.
- 대표 상황: UE used a method unsupported at the destination URI.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 405 Method Not Allowed
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-405-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 405-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, INFO, MESSAGE, NOTIFY, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`
- `Allow`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 406 Not Acceptable

- 설명: Request could not be fulfilled due to Accept-related constraints.
- 대표 상황: Negotiated media or content preferences could not be satisfied.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 406 Not Acceptable
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-406-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 406-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 407 Proxy Authentication Required

- 설명: Proxy demands client authentication.
- 대표 상황: UE must resend via proxy with Proxy-Authorization credentials.
- 관련 메서드: BYE, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 407 Proxy Authentication Required
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-407-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 407-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Proxy-Authenticate: Digest realm="ims.mnc001.mcc001.3gppnetwork.org", nonce="nonce-1"
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`
- `Proxy-Authenticate`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 408 Request Timeout

- 설명: Request timed out before it could be completed.
- 대표 상황: UE receives timeout for an outstanding SIP transaction.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 408 Request Timeout
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-408-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 408-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 410 Gone

- 설명: Target resource no longer exists.
- 대표 상황: Requested user/resource was known but has permanently disappeared.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 410 Gone
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-410-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 410-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 412 Conditional Request Failed

- 설명: Conditional publication or similar precondition failed.
- 대표 상황: PUBLISH state version no longer matches current entity tag.
- 관련 메서드: PUBLISH
- RFC: RFC3903

### 대표 SIP 패킷 예시

```text
SIP/2.0 412 Conditional Request Failed
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-412-publish
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 412-publish@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 PUBLISH
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 413 Request Entity Too Large

- 설명: Request body or headers are too large to process.
- 대표 상황: UE sent a request payload that exceeds remote limits.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 413 Request Entity Too Large
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-413-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 413-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 414 Request-URI Too Long

- 설명: Request-URI exceeded remote processing limits.
- 대표 상황: Generated Request-URI is too long for the far end.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 414 Request-URI Too Long
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-414-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 414-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 415 Unsupported Media Type

- 설명: Message body media type is not supported.
- 대표 상황: Remote endpoint rejects an SDP or payload content type.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 415 Unsupported Media Type
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-415-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 415-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 416 Unsupported URI Scheme

- 설명: URI scheme is unsupported by the receiver.
- 대표 상황: Request targeted a URI scheme the remote side cannot process.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 416 Unsupported URI Scheme
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-416-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 416-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 417 Unknown Resource-Priority

- 설명: Resource-Priority namespace or value is unknown.
- 대표 상황: Resource-Priority extension is present but unsupported.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC4412

### 대표 SIP 패킷 예시

```text
SIP/2.0 417 Unknown Resource-Priority
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-417-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 417-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 420 Bad Extension

- 설명: Mandatory option tags are unsupported.
- 대표 상황: UE required extensions that the far end does not support.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 420 Bad Extension
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-420-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 420-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Unsupported: foo-ext
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`
- `Unsupported`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 421 Extension Required

- 설명: Remote endpoint requires an extension the UE did not use.
- 대표 상황: UE must add the listed Require option tags and retry.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 421 Extension Required
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-421-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 421-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Require: timer
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`
- `Require`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 422 Session Interval Too Small

- 설명: Session timer interval is smaller than acceptable.
- 대표 상황: INVITE/UPDATE session timer negotiation failed due to too-small interval.
- 관련 메서드: INVITE, UPDATE
- RFC: RFC4028

### 대표 SIP 패킷 예시

```text
SIP/2.0 422 Session Interval Too Small
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-422-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 422-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Min-SE: 90
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`
- `Min-SE`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 423 Interval Too Brief

- 설명: Expires interval is shorter than allowed.
- 대표 상황: REGISTER or PUBLISH requested an expiry that is too short.
- 관련 메서드: REGISTER, PUBLISH, SUBSCRIBE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 423 Interval Too Brief
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-423-register
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 423-register@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 REGISTER
Min-Expires: 600
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`
- `Min-Expires`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 424 Bad Location Information

- 설명: Geolocation or location-format information is invalid.
- 대표 상황: Request carrying geolocation information was rejected.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC6442

### 대표 SIP 패킷 예시

```text
SIP/2.0 424 Bad Location Information
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-424-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 424-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Geolocation-Error: 100 locationValueError
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`
- `Geolocation-Error`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 425 Bad Alert Message

- 설명: Alerting information extension was malformed or unacceptable.
- 대표 상황: Alert-Info or alerting extension parameters were rejected.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC8876

### 대표 SIP 패킷 예시

```text
SIP/2.0 425 Bad Alert Message
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-425-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 425-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
AlertMsg-Error: 300 unsupported-alerting
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`
- `AlertMsg-Error`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 428 Use Identity Header

- 설명: Receiver insists on use of an Identity header.
- 대표 상황: Identity assertion is required before request can proceed.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC8224

### 대표 SIP 패킷 예시

```text
SIP/2.0 428 Use Identity Header
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-428-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 428-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 429 Provide Referrer Identity

- 설명: REFER handling requires referrer identity information.
- 대표 상황: REFER request lacks the identity information demanded by policy.
- 관련 메서드: REFER
- RFC: RFC3892

### 대표 SIP 패킷 예시

```text
SIP/2.0 429 Provide Referrer Identity
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-429-refer
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 429-refer@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 REFER
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 430 Flow Failed

- 설명: Previously established outbound flow failed.
- 대표 상황: UE's SIP Outbound registration flow is no longer usable.
- 관련 메서드: REGISTER
- RFC: RFC5626

### 대표 SIP 패킷 예시

```text
SIP/2.0 430 Flow Failed
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-430-register
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 430-register@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 REGISTER
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 433 Anonymity Disallowed

- 설명: Policy forbids the requested anonymous identity behavior.
- 대표 상황: Privacy or identity policy rejects anonymous signaling.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC5079

### 대표 SIP 패킷 예시

```text
SIP/2.0 433 Anonymity Disallowed
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-433-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 433-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 436 Bad Identity Info

- 설명: Identity information is invalid or unverifiable.
- 대표 상황: Remote verifier cannot validate identity assertion metadata.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC8224

### 대표 SIP 패킷 예시

```text
SIP/2.0 436 Bad Identity Info
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-436-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 436-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 437 Unsupported Credential

- 설명: Credential type is unsupported.
- 대표 상황: Identity credentials are present but not supported by the verifier.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC8224

### 대표 SIP 패킷 예시

```text
SIP/2.0 437 Unsupported Credential
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-437-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 437-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 438 Invalid Identity Header

- 설명: Identity header itself is syntactically or semantically invalid.
- 대표 상황: Identity header value does not validate.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC8224

### 대표 SIP 패킷 예시

```text
SIP/2.0 438 Invalid Identity Header
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-438-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 438-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 439 First Hop Lacks Outbound Support

- 설명: First-hop proxy does not support SIP Outbound.
- 대표 상황: UE attempted an outbound-specific request through a non-outbound first hop.
- 관련 메서드: REGISTER
- RFC: RFC5626

### 대표 SIP 패킷 예시

```text
SIP/2.0 439 First Hop Lacks Outbound Support
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-439-register
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 439-register@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 REGISTER
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 440 Max-Breadth Exceeded

- 설명: Maximum recursion breadth was exceeded in REFER processing.
- 대표 상황: REFER triggered recursive operations beyond configured breadth.
- 관련 메서드: REFER
- RFC: RFC5393

### 대표 SIP 패킷 예시

```text
SIP/2.0 440 Max-Breadth Exceeded
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-440-refer
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 440-refer@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 REFER
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 469 Bad Info Package

- 설명: INFO package is unsupported or malformed.
- 대표 상황: INFO request used an unsupported Info Package token.
- 관련 메서드: INFO
- RFC: RFC6086

### 대표 SIP 패킷 예시

```text
SIP/2.0 469 Bad Info Package
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-469-info
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 469-info@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INFO
Recv-Info: dtmf
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`
- `Recv-Info`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 470 Consent Needed

- 설명: Explicit user or policy consent is required before processing.
- 대표 상황: Consent framework blocks request until recipient grants permission.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC5360

### 대표 SIP 패킷 예시

```text
SIP/2.0 470 Consent Needed
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-470-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 470-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Permission-Missing: <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- `Permission-Missing`

### 조건부 규칙
- `Permission-Missing`: SHOULD be included when the rejecting entity can identify which target URIs are missing consent.
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 480 Temporarily Unavailable

- 설명: Target is temporarily unavailable.
- 대표 상황: Called party or resource is not currently reachable.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 480 Temporarily Unavailable
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-480-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 480-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 481 Call/Transaction Does Not Exist

- 설명: Matching dialog, call leg, or transaction could not be found.
- 대표 상황: In-dialog request references state that no longer exists remotely.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 481 Call/Transaction Does Not Exist
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-481-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 481-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 482 Loop Detected

- 설명: Routing loop was detected.
- 대표 상황: Proxy routing causes the request to revisit a previous hop.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 482 Loop Detected
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-482-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 482-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 483 Too Many Hops

- 설명: Max-Forwards reached zero before successful routing.
- 대표 상황: Request exceeded routing hop limit.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 483 Too Many Hops
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-483-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 483-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 484 Address Incomplete

- 설명: Address or dial string is incomplete.
- 대표 상황: Request URI/user part lacks enough information to route.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 484 Address Incomplete
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-484-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 484-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 485 Ambiguous

- 설명: Target address resolves ambiguously to multiple resources.
- 대표 상황: Far end cannot uniquely identify intended target.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 485 Ambiguous
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-485-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 485-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 486 Busy Here

- 설명: The callee's end system was contacted successfully but the callee is currently not willing or able to take additional calls at this end system (RFC 3261 §21.4.23). Semantically INVITE-specific: 'callee' and 'calls' terminology applies exclusively to session-establishment requests.
- 대표 상황: Remote user rejects INVITE because they are busy at this location.
- 관련 메서드: INVITE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 486 Busy Here
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-486-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 486-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 487 Request Terminated

- 설명: Request was terminated before completion.
- 대표 상황: INVITE receives 487 after a CANCEL was processed.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 487 Request Terminated
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-487-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 487-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 488 Not Acceptable Here

- 설명: Proposed session description or conditions are unacceptable here.
- 대표 상황: Local SDP or session offer cannot be accepted by the remote side.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 488 Not Acceptable Here
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-488-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 488-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 489 Bad Event

- 설명: Event package is unsupported or invalid.
- 대표 상황: SUBSCRIBE or NOTIFY references an unknown event package.
- 관련 메서드: SUBSCRIBE, NOTIFY, PUBLISH
- RFC: RFC6665

### 대표 SIP 패킷 예시

```text
SIP/2.0 489 Bad Event
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-489-subscribe
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 489-subscribe@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 SUBSCRIBE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `Allow-Events`: Strongly recommended when advertising supported event packages after 489 Bad Event.
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 491 Request Pending

- 설명: Another conflicting request is already in progress.
- 대표 상황: Concurrent re-INVITE or UPDATE collision occurs.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 491 Request Pending
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-491-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 491-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 493 Undecipherable

- 설명: Request could not be deciphered after security processing.
- 대표 상황: Encrypted or integrity-protected SIP content cannot be interpreted.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 493 Undecipherable
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-493-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 493-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 494 Security Agreement Required

- 설명: Security mechanism agreement is required before proceeding.
- 대표 상황: IMS-style security negotiation must complete before REGISTER/INVITE proceeds.
- 관련 메서드: REGISTER, INVITE
- RFC: RFC3329

### 대표 SIP 패킷 예시

```text
SIP/2.0 494 Security Agreement Required
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-494-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 494-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Require: sec-agree
Security-Server: ipsec-3gpp;alg=hmac-md5-96;prot=esp;mod=trans
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`
- `Require`
- `Security-Server`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `Require`: Include the sec-agree option tag when the response instructs the UE to negotiate a security agreement before retrying. — The Require header should contain the 'sec-agree' option tag when applicable.
- `Proxy-Authenticate`: When the chosen security mechanism needs challenge material such as HTTP Digest, include the corresponding authentication challenge headers as well.
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 500 Server Internal Error

- 설명: Server hit an internal failure while processing the request.
- 대표 상황: Remote SIP element encountered an unexpected processing error.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 500 Server Internal Error
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-500-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 500-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 501 Not Implemented

- 설명: Requested method or functionality is not implemented.
- 대표 상황: Remote side does not implement the method or extension UE attempted to use.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 501 Not Implemented
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-501-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 501-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 502 Bad Gateway

- 설명: Upstream or downstream gateway processing failed.
- 대표 상황: Intermediary cannot complete the request because of another network element.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 502 Bad Gateway
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-502-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 502-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 503 Service Unavailable

- 설명: Service is temporarily unavailable.
- 대표 상황: Remote service is overloaded or intentionally unavailable for a period.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 503 Service Unavailable
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-503-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 503-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Retry-After: 120
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- `Retry-After`

### 조건부 규칙
- `Retry-After`: Recommended when the server can indicate when the UE should retry.
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 504 Server Time-out

- 설명: Server timed out waiting on another element.
- 대표 상황: Downstream element failed to answer in time.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 504 Server Time-out
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-504-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 504-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 505 Version Not Supported

- 설명: SIP version in request is unsupported.
- 대표 상황: Far end cannot process the request's SIP version.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 505 Version Not Supported
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-505-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 505-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 513 Message Too Large

- 설명: Entire SIP message is too large to process or forward.
- 대표 상황: Headers and/or body exceeded transport or implementation limits.
- 관련 메서드: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 513 Message Too Large
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-513-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 513-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 555 Push Notification Service Not Supported

- 설명: Push notification service extension is not supported.
- 대표 상황: REGISTER request depends on a SIP push notification capability absent at the remote side.
- 관련 메서드: REGISTER
- RFC: RFC8599

### 대표 SIP 패킷 예시

```text
SIP/2.0 555 Push Notification Service Not Supported
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-555-register
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 555-register@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 REGISTER
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 580 Precondition Failure

- 설명: Requested session preconditions could not be met.
- 대표 상황: INVITE or UPDATE preconditions fail during session setup.
- 관련 메서드: INVITE, UPDATE
- RFC: RFC3312

### 대표 SIP 패킷 예시

```text
SIP/2.0 580 Precondition Failure
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-580-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 580-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 600 Busy Everywhere

- 설명: All known contacts are busy.
- 대표 상황: Forked INVITE failed because every reachable target is busy.
- 관련 메서드: INVITE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 600 Busy Everywhere
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-600-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 600-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 603 Decline

- 설명: Request is explicitly declined.
- 대표 상황: Remote user explicitly rejects the INVITE or similar contact attempt.
- 관련 메서드: INVITE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 603 Decline
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-603-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 603-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 604 Does Not Exist Anywhere

- 설명: Target does not exist at any location.
- 대표 상황: Global lookup determines no valid destination exists.
- 관련 메서드: INVITE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 604 Does Not Exist Anywhere
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-604-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 604-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 606 Not Acceptable

- 설명: Session proposal is globally unacceptable.
- 대표 상황: No reachable destination can accept the offered session characteristics.
- 관련 메서드: INVITE
- RFC: RFC3261

### 대표 SIP 패킷 예시

```text
SIP/2.0 606 Not Acceptable
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-606-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 606-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 607 Unwanted

- 설명: Request is classified as unwanted communication.
- 대표 상황: Remote policy blocks unwanted INVITE, MESSAGE, or SUBSCRIBE attempts.
- 관련 메서드: INVITE, MESSAGE, SUBSCRIBE
- RFC: RFC8197

### 대표 SIP 패킷 예시

```text
SIP/2.0 607 Unwanted
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-607-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 607-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- 없음

### 조건부 규칙
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 608 Rejected

- 설명: Request is rejected for policy or feature-specific reasons.
- 대표 상황: Feature-specific rejection of an INVITE, MESSAGE, or other out-of-dialog request.
- 관련 메서드: INVITE, MESSAGE, SUBSCRIBE
- RFC: RFC8688

### 대표 SIP 패킷 예시

```text
SIP/2.0 608 Rejected
Via: SIP/2.0/UDP pcscf.ims.mnc001.mcc001.3gppnetwork.org;branch=z9hG4bK-608-invite
From: "UE" <sip:111111@ue.ims.mnc001.mcc001.3gppnetwork.org>;tag=ue-tag
To: "Network" <sip:network@ims.mnc001.mcc001.3gppnetwork.org>;tag=net-tag
Call-ID: 608-invite@pcscf.ims.mnc001.mcc001.3gppnetwork.org
CSeq: 1 INVITE
Call-Info: <https://pcscf.ims.mnc001.mcc001.3gppnetwork.org/call-info>;purpose=info
Content-Length: 0
```

### 필수 헤더
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`

### 대표 선택/조건부 헤더
- `Call-Info`

### 조건부 규칙
- `Call-Info`: Include a Call-Info URI when policy wants to provide a human- or machine-readable explanation for 608 Rejected.
- `To`: Except for 100 Trying, if the request lacked a To tag the response MUST add one.

## 참고 RFC

- [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261)
- [RFC 3262](https://www.rfc-editor.org/rfc/rfc3262)
- [RFC 3311](https://www.rfc-editor.org/rfc/rfc3311)
- [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329)
- [RFC 3428](https://www.rfc-editor.org/rfc/rfc3428)
- [RFC 3515](https://www.rfc-editor.org/rfc/rfc3515)
- [RFC 3903](https://www.rfc-editor.org/rfc/rfc3903)
- [RFC 5360](https://www.rfc-editor.org/rfc/rfc5360)
- [RFC 5839](https://www.rfc-editor.org/rfc/rfc5839)
- [RFC 6086](https://www.rfc-editor.org/rfc/rfc6086)
- [RFC 6442](https://www.rfc-editor.org/rfc/rfc6442)
- [RFC 6665](https://www.rfc-editor.org/rfc/rfc6665)
- [RFC 7647](https://www.rfc-editor.org/rfc/rfc7647)
- [RFC 8197](https://www.rfc-editor.org/rfc/rfc8197)
- [RFC 8599](https://www.rfc-editor.org/rfc/rfc8599)
- [RFC 8688](https://www.rfc-editor.org/rfc/rfc8688)
- [RFC 8876](https://www.rfc-editor.org/rfc/rfc8876)
