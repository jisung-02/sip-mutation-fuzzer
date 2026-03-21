# SIP IANA 전체 필드 전수조사

기준 일자: 2026-03-18

## 1. 문서 목적
이 문서는 **IANA SIP Parameters Registry**를 기준으로, 현재 등록된 SIP Header Fields 전체를 빠짐없이 정리한 전수조사 문서다.

이번 문서의 중심 대상은:
- IANA `Header Fields` registry의 **전체 134개 header field**

그리고 부록 수준으로 함께 다루는 대상은:
- SIP/SIPS URI Parameters
- Header Field Parameters and Parameter Values
- Identity Parameters
- Identity-Info Algorithm Parameter Values
- Info Packages Registry
- Geolocation-Error Codes
- Reason Codes
- Priority Header Field Values
- SIP Transport

즉, 이 문서는 앞서 만든 **UE 퍼징 범위 중심 문서**가 아니라, **IANA Header Fields registry 전체를 전수 inventory하고, 선택된 인접 registries를 함께 정리하는 문서**다.

## 2. 조사 원칙
### 2.1 공식 기준
이번 문서의 1차 기준은 IANA registry 자체다.

사용한 원문:
- [IANA Session Initiation Protocol (SIP) Parameters](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml)
- IANA XML export: `sip-parameters.xml`

워크스페이스에 저장한 조사 원본:
- `.omx/research/sip-iana-full-20260318/sip-parameters.xml`
- `.omx/research/sip-iana-full-20260318/sip-parameters.xhtml`

### 2.2 이번 문서에서의 “의미” 수준
아래 표의 “meaning / role”은 **registry-level short meaning**이다.

즉:
- field name
- compact form
- reference
- field 이름과 reference 맥락에서 읽히는 1차적 역할

를 요약한 것이다.

이 문서는 전수조사 문서이므로 **누락 없이 inventory를 잡는 것**을 우선한다.
각 헤더의 완전한 normative semantics는 최종적으로 해당 RFC 본문을 따라야 한다.

중요:
- `Header Fields 134개`는 **전수**로 다룬다.
- 하지만 `Adjacent IANA Registries`는 **선택된 관련 registry 요약**이다.
- 즉, 모든 비-header SIP registry를 같은 깊이로 전수한 문서는 아니다.

### 2.3 3GPP / IMS 헤더 처리 원칙
IANA Header Fields registry에는 3GPP TS 24.229 등 **3GPP/IMS 쪽 참조**를 가진 헤더도 다수 들어 있다.
이들은 일반 SIP core header와 동일하게 “등록된 SIP header”이지만, 의미는 IMS/3GPP 환경에 강하게 묶여 있을 수 있다.

이번 문서에서는 이런 항목에:
- `3GPP-specific`
- `IMS-specific`

같은 플래그를 붙여 구분한다.

## 3. 레지스트리 스냅샷
IANA XML 기준 확인된 주요 개수:

- Header Fields: `134`
- Methods and Response Codes: `14`
- Response Codes: `75`
- SIP/SIPS URI Parameters: `35`
- Header Field Parameters and Parameter Values: `201`
- Identity Parameters: `2`
- Identity-Info Algorithm Parameter Values: `2`
- Info Packages Registry: `13`
- Geolocation-Error Codes: `5`
- Reason Codes: `8`
- Priority Header Field Values: `5`
- SIP Transport: `7`

## 4. Header Fields 전체 Inventory
## 4.1 Slice A-H

| Header | Compact | Reference(s) | Registry-level meaning / role | Flags |
|---|---:|---|---|---|
| `Accept` | none | `RFC 3261` | Declares which media/body formats a SIP entity can accept in message content. | |
| `Accept-Contact` | `a` | `RFC 3841` | Carries contact-selection preferences, indicating what kinds of contacts/UAs are acceptable for routing. | |
| `Accept-Encoding` | none | `RFC 3261` | Declares acceptable content encodings for SIP message bodies. | |
| `Accept-Language` | none | `RFC 3261` | Declares acceptable natural languages for content or human-facing indications. | |
| `Accept-Resource-Priority` | none | `RFC 4412` | Indicates acceptable resource-priority namespaces/values for prioritized communications. | |
| `Additional-Identity` | none | `3GPP TS 24.229 v16.7.0` | Appears to carry an additional asserted identity beyond the primary SIP identity. | `3GPP-specific`; appears `IMS-specific` |
| `Alert-Info` | none | `RFC 3261` | Provides supplementary information about how the recipient should be alerted. | |
| `AlertMsg-Error` | none | `RFC 8876` | Conveys error information tied to alert-message handling. | |
| `Allow` | none | `RFC 3261` | Lists SIP methods supported by the UA or server. | |
| `Allow-Events` | `u` | `RFC 6665` | Lists supported event packages for SIP events/subscriptions. | |
| `Answer-Mode` | none | `RFC 5373` | Indicates answering preferences or requested handling mode for call setup. | |
| `Attestation-Info` | none | `3GPP TS 24.229 v15.11.0` | Appears to carry attestation-related identity information in SIP signaling. | `3GPP-specific`; appears `IMS-specific` |
| `Authentication-Info` | none | `RFC 3261` | Returns authentication-related parameters associated with SIP digest/auth exchanges. | |
| `Authorization` | none | `RFC 3261` | Carries client authorization credentials for SIP authentication. | |
| `Call-ID` | `i` | `RFC 3261` | Globally identifies a SIP dialog/call instance. | |
| `Call-Info` | none | `RFC 3261` | Provides additional information about the caller or call, typically by reference/URI. | |
| `Cellular-Network-Info` | none | `3GPP TS 24.229 v13.9.0` | Appears to convey cellular access-network or radio/network context in SIP signaling. | `3GPP-specific`; appears `IMS-specific` |
| `Contact` | `m` | `RFC 3261` | Advertises a direct URI where the sender can be reached for this dialog/registration. | |
| `Content-Disposition` | none | `RFC 3261` | Describes how the message body should be interpreted or handled. | |
| `Content-Encoding` | `e` | `RFC 3261` | Identifies any encoding applied to the body. | |
| `Content-ID` | none | `RFC 8262` | Identifies a body part or message content object by content identifier. | |
| `Content-Language` | none | `RFC 3261` | Identifies the language of the message body content. | |
| `Content-Length` | `l` | `RFC 3261` | States the length of the message body. | |
| `Content-Type` | `c` | `RFC 3261` | Identifies the media type of the message body. | |
| `CSeq` | none | `RFC 3261` | Carries the command sequence number and method for transaction/dialog ordering. | |
| `Date` | none | `RFC 3261` | Conveys a timestamp for the SIP message. | |
| `DC-Info` | none | `3GPP TS 24.229 v19.4.1` | Appears to carry device/client context information; exact semantics are 3GPP-defined rather than general SIP-core. | `3GPP-specific`; appears `IMS-specific` |
| `Encryption (Deprecated)` | none | `RFC 3261` | Historical header related to encryption indication. | `Deprecated` |
| `Error-Info` | none | `RFC 3261` | Provides additional information about an error response, often by reference/URI. | |
| `Event` | `o` | `RFC 6665`, `RFC 6446` | Identifies the event package associated with a SIP subscription/notification. | |
| `Expires` | none | `RFC 3261` | Indicates lifetime/expiry for registrations or other time-bounded SIP state. | |
| `Feature-Caps` | none | `RFC 6809` | Advertises feature-capability indicators associated with the SIP entity or request context. | |
| `Flow-Timer` | none | `RFC 5626` | Conveys flow keepalive or flow lifetime timing for outbound SIP connections. | |
| `From` | `f` | `RFC 3261` | Identifies the logical initiator/originator of the SIP request. | |
| `Geolocation` | none | `RFC 6442` | Carries or references location information associated with the request. | |
| `Geolocation-Error` | none | `RFC 6442` | Reports errors related to geolocation conveyance or usage. | |
| `Geolocation-Routing` | none | `RFC 6442` | Indicates routing treatment related to geolocation information. | |
| `Hide (Deprecated)` | none | `RFC 3261` | Historical privacy-related header. | `Deprecated` |
| `History-Info` | none | `RFC 7044` | Captures retargeting/diversion history as a request is routed through SIP. | |

### A-H Notes
- 이 slice 안의 3GPP 참조 헤더는 `IMS-specific` 가능성이 높다.
- registry가 이름에 직접 `Deprecated`를 붙인 항목은 그대로 표시했다.

## 4.2 Slice I-P

| Header | Compact | Reference(s) | Registry-level meaning / role | Flags |
|---|---:|---|---|---|
| `Identity` | `y` | `RFC 8224` | SIP identity assertion header for STIR-style signed calling identity. | |
| `Identity-Info (deprecated by [RFC8224])` | none | `RFC 8224` | Carries information related to SIP identity handling. | `Deprecated` |
| `Info-Package` | none | `RFC 6086` | Identifies the INFO-package semantics for a SIP `INFO` request. | |
| `In-Reply-To` | none | `RFC 3261` | Correlates a SIP message with an earlier communication, by name indicating reply linkage. | |
| `Join` | none | `RFC 3911` | Requests joining an existing dialog/call leg to another session. | |
| `Max-Breadth` | none | `RFC 5393` | Limits the breadth/fan-out of SIP request processing in recursive or referred operations. | |
| `Max-Forwards` | none | `RFC 3261` | Hop-count limiter for SIP requests to prevent looping. | |
| `MIME-Version` | none | `RFC 3261` | Declares MIME versioning context for SIP bodies. | |
| `Min-Expires` | none | `RFC 3261` | Advertises the minimum acceptable expiration interval. | |
| `Min-SE` | none | `RFC 4028` | Minimum allowed session timer interval for session refreshes. | |
| `Organization` | none | `RFC 3261` | Human-readable organizational identity of the sender/originating domain. | |
| `Origination-Id` | none | `3GPP TS 24.229 v15.11.0` | Header for origination-related identity/correlation within IMS procedures. | `3GPP-specific`; `IMS-specific` |
| `P-Access-Network-Info` | none | `RFC 7315` | Private header conveying access-network information associated with the user/device. | `IMS-specific` |
| `P-Answer-State` | none | `RFC 4964` | Private header indicating answer-state information for call handling logic. | |
| `P-Asserted-Identity` | none | `RFC 3325` | Private trusted-network header asserting the user identity. Common in IMS/trusted SIP domains. | `IMS-specific` |
| `P-Asserted-Service` | none | `RFC 6050` | Private header asserting the served communication service. | `IMS-specific` |
| `P-Associated-URI` | none | `RFC 7315` | Private header listing URIs associated with the served user. | `IMS-specific` |
| `P-Called-Party-ID` | none | `RFC 7315` | Private header identifying the called party as received/retained in the network. | `IMS-specific` |
| `P-Charge-Info` | none | `RFC 8496` | Private charging-related information used for charging correlation. | `IMS-specific` |
| `P-Charging-Function-Addresses` | none | `RFC 7315` | Private header carrying charging function addresses. | `IMS-specific` |
| `P-Charging-Vector` | none | `RFC 7315` | Private charging correlation vector for IMS charging records. | `IMS-specific` |
| `P-DCS-Trace-Party-ID` | none | `RFC 5503` | Private header for trace party identification in the DCS family. | |
| `P-DCS-OSPS` | none | `RFC 5503` | Private DCS header related to operator-service style processing. | |
| `P-DCS-Billing-Info` | none | `RFC 5503` | Private DCS billing information header. | |
| `P-DCS-LAES` | none | `RFC 5503` | Private DCS lawful intercept / surveillance-related header context. | |
| `P-DCS-Redirect` | none | `RFC 5503` | Private DCS redirect-related header. | |
| `P-Early-Media` | none | `RFC 5009` | Private header governing early-media authorization/handling. | |
| `P-Media-Authorization` | none | `RFC 3313` | Private header carrying media authorization tokens/credentials. | |
| `P-Preferred-Identity` | none | `RFC 3325` | Private header expressing the user’s preferred identity for trusted-network assertion. | `IMS-specific` |
| `P-Preferred-Service` | none | `RFC 6050` | Private header expressing the preferred IMS service. | `IMS-specific` |
| `P-Private-Network-Indication` | none | `RFC 7316` | Private header indicating use of or affiliation with a private network. | |
| `P-Profile-Key` | none | `RFC 5002` | Private header identifying a user/service profile key. | |
| `P-Refused-URI-List` | none | `RFC 5318` | Private header listing URIs refused during request handling. | |
| `P-Served-User` | none | `RFC 5502, RFC 8498` | Private header identifying the served user in IMS service logic. | `IMS-specific` |
| `P-User-Database` | none | `RFC 4457` | Private header identifying the user database / HSS-like source. | `IMS-specific` |
| `P-Visited-Network-ID` | none | `RFC 7315` | Private header identifying the visited network. | `IMS-specific` |
| `Path` | none | `RFC 3327` | Records SIP proxy path information for later requests, especially registration routing. | |
| `Permission-Missing` | none | `RFC 5360` | Signals that required permission information is absent. | |
| `Policy-Contact` | none | `RFC 6794` | Provides contact information for a policy authority/server. | |
| `Policy-ID` | none | `RFC 6794` | Identifies the policy or policy rule context being referenced. | |
| `Priority` | none | `RFC 3261` | Conveys the request priority level. | |
| `Priority-Share` | none | `3GPP TS 24.229 v13.16.0` | Header tied to sharing priority-related information in IMS procedures. | `3GPP-specific`; `IMS-specific` |
| `Priority-Verstat` | none | `3GPP TS 24.229` | Header for carrying verification-status information associated with priority handling. | `3GPP-specific`; `IMS-specific` |
| `Priv-Answer-Mode` | none | `RFC 5373` | Private form of answer-mode indication for call treatment preferences. | |
| `Privacy` | none | `RFC 3323` | Requests privacy services for SIP identity and related information. | |
| `Proxy-Authenticate` | none | `RFC 3261` | Authentication challenge generated by a SIP proxy. | |
| `Proxy-Authorization` | none | `RFC 3261` | Credentials supplied in response to a proxy authentication challenge. | |
| `Proxy-Require` | none | `RFC 3261` | Declares SIP extensions that proxies must understand to process the request. | |

### I-P Notes
- Deprecated in this slice: `Identity-Info`
- 3GPP/IMS 헤더가 가장 밀집한 구간이다.

## 4.3 Slice Q-Z

| Header | Compact | Reference(s) | Registry-level meaning / role | Flags |
|---|---:|---|---|---|
| `RAck` | none | RFC 3262 | Reliability acknowledgement header for provisional response handling. | |
| `Reason` | none | RFC 3326 | Carries a protocol-specific reason/cause explaining why a SIP request or response was generated. | |
| `Reason-Phrase` | none | Adam Roach note; reserved to avoid conflict with RFC 6873 | Reserved header-field name; not a normal active SIP header definition. | Reserved |
| `Record-Route` | none | RFC 3261 | Route-recording header used by proxies to stay on the signaling path for subsequent requests in a dialog. | |
| `Recv-Info` | none | RFC 6086 | Declares INFO package bodies the receiver is prepared to accept. | |
| `Refer-Events-At` | none | RFC 7614 | Controls where REFER-related event subscriptions are directed. | |
| `Refer-Sub` | none | RFC 4488 | Indicates whether a REFER request should create an implicit subscription. | |
| `Refer-To` | `r` | RFC 3515 | Names the target resource a REFER asks the recipient to contact. | |
| `Referred-By` | `b` | RFC 3892 | Identifies the party that initiated or authorized a referral. | |
| `Reject-Contact` | `j` | RFC 3841 | Expresses contact feature preferences that must not be matched. | |
| `Relayed-Charge` | none | 3GPP TS 24.229 v12.14.0 | Charging-related header used in 3GPP/IMS service contexts, apparently for relayed charging information. | 3GPP-specific, IMS-specific |
| `Replaces` | none | RFC 3891 | Identifies an existing dialog to be replaced by a new INVITE. | |
| `Reply-To` | none | RFC 3261 | Supplies a preferred address for replies or follow-up communication. | |
| `Request-Disposition` | `d` | RFC 3841 | Conveys caller preferences about how a request should be routed or handled. | |
| `Require` | none | RFC 3261 | Lists option tags that must be understood for the request to be processed. | |
| `Resource-Priority` | none | RFC 4412 | Carries resource-priority values for priority communications and preemption policy. | |
| `Resource-Share` | none | 3GPP TS 24.229 v13.7.0 | 3GPP/IMS resource-sharing header, apparently for sharing resource-priority or related service state across IMS entities. | 3GPP-specific, IMS-specific |
| `Response-Key (Deprecated)` | none | RFC 3261 | Historical response-keying header from early SIP security work. | Deprecated |
| `Response-Source` | none | 3GPP TS 24.229 v15.11.0 | 3GPP/IMS header that appears to identify the source context of a SIP response. | 3GPP-specific, IMS-specific |
| `Restoration-Info` | none | 3GPP TS 24.229 v12.14.0 | 3GPP/IMS restoration-state header, apparently used to carry information for service/session restoration handling. | 3GPP-specific, IMS-specific |
| `Retry-After` | none | RFC 3261 | Indicates when the requester should retry after a temporary failure or redirection. | |
| `Route` | none | RFC 3261 | Carries the route set that directs a request through specific SIP intermediaries. | |
| `RSeq` | none | RFC 3262 | Sequence number for reliably transmitted provisional responses. | |
| `Security-Client` | none | RFC 3329 | Lists security mechanisms the client supports for SIP security agreement. | |
| `Security-Server` | none | RFC 3329 | Lists security mechanisms the server offers for SIP security agreement. | |
| `Security-Verify` | none | RFC 3329 | Echoes/verifies the negotiated security mechanisms to confirm agreement. | |
| `Server` | none | RFC 3261 | Identifies the software server handling the SIP message. | |
| `Service-Interact-Info` | none | 3GPP TS 24.229 v13.18.0 | 3GPP/IMS service-interaction header, apparently used to coordinate interacting IMS services/application servers. | 3GPP-specific, IMS-specific |
| `Service-Route` | none | RFC 3608 | Supplies a route set learned at registration for future requests. | |
| `Session-Expires` | `x` | RFC 4028 | Declares the session timer interval for keeping a SIP session alive. | |
| `Session-ID` | none | RFC 7989 | Provides an identifier for correlating the SIP session across devices and intermediaries. | |
| `SIP-ETag` | none | RFC 3903 | Entity tag used for SIP event state publication versioning. | |
| `SIP-If-Match` | none | RFC 3903 | Conditional-match header used with SIP event state publication updates. | |
| `Subject` | `s` | RFC 3261 | Carries human-readable subject text for the session or request. | |
| `Subscription-State` | none | RFC 6665 | Reports the current state of a SIP event subscription. | |
| `Supported` | `k` | RFC 3261 | Lists option tags the sender supports but does not require. | |
| `Suppress-If-Match` | none | RFC 5839 | Conditional suppression header used in SIP event publication logic. | |
| `Target-Dialog` | none | RFC 4538 | Identifies the dialog targeted by a request such as REFER. | |
| `Timestamp` | none | RFC 3261 | Carries timing information for latency measurement and message timing diagnostics. | |
| `To` | `t` | RFC 3261 | Identifies the logical recipient of the SIP request or response. | |
| `Trigger-Consent` | none | RFC 5360 | Triggers user-consent processing for location-related policy actions. | |
| `Unsupported` | none | RFC 3261 | Lists option tags not understood by the recipient. | |
| `User-Agent` | none | RFC 3261 | Identifies the originating user agent software. | |
| `User-to-User` | none | RFC 7433 | Carries application-level user-to-user information end-to-end in SIP. | |
| `Via` | `v` | RFC 3261, RFC 7118 | Records transport path information so responses can traverse back through intermediaries; RFC 7118 extends WebSocket transport context. | |
| `Warning` | none | RFC 3261 | Conveys additional warning text or codes about message processing or status. | |
| `WWW-Authenticate` | none | RFC 3261 | Carries authentication challenges from a UAS. | |

### Q-Z Notes
- Deprecated in this slice: `Response-Key (Deprecated)`
- `Reason-Phrase`는 active header가 아니라 reserved name으로 보는 것이 맞다.

## 5. Adjacent IANA Registries
Header field inventory를 넘어, “SIP field surface”를 넓게 보려면 아래 registry들도 중요하다.

### 5.1 SIP/SIPS URI Parameters
- Count: `35`
- 핵심 예시:
  - routing/targeting: `transport`, `user`, `method`, `ttl`, `maddr`, `lr`
  - outbound/GRUU/push: `comp`, `sigcomp-id`, `ob`, `gr`, `pn-provider`, `pn-prid`, `pn-param`, `pn-purr`
  - service/application: `cause`, `content-type`, `target`, `locale`, `aai`, `bnc`
- 의미:
  - header 밖에서 URI 자체의 동작을 바꾸는 field surface다.

### 5.2 Header Field Parameters and Parameter Values
- Count: `201`
- 핵심 예시:
  - `Via`: `branch`, `maddr`, `received`, `rport`, `ttl`, `comp`
  - `Contact`: `expires`, `q`, `reg-id`, `pub-gruu`, `temp-gruu`
  - `From` / `To`: `tag`
  - `WWW-Authenticate` / `Proxy-Authenticate` / `Authorization`: `algorithm`, `nonce`, `opaque`, `qop`, `realm`, `username`, `uri`, `response`
  - `Event`: `id`, `call-id`, `from-tag`, `to-tag`, `body`, `vendor`, `version`
  - `Subscription-State`: `reason`, `expires`, `retry-after`
  - `Reason`: `cause`, `text`, `location`, `ppi`
  - `Security-*`: `alg`, `ealg`, `prot`, `mod`, `spi`, `port1`, `port2`
- 의미:
  - header 이름만 보는 것보다, 실제 구문 해석과 상호운용성 검토에서는 parameter 공간도 매우 중요하다.

### 5.3 Identity Parameters
- Count: `2`
- 항목:
  - `alg`
  - `info`

### 5.4 Identity-Info Algorithm Parameter Values
- Count: `2`
- 항목:
  - `rsa-sha1`
  - `rsa-sha256`

### 5.5 Info Packages Registry
- Count: `13`
- 핵심 예시:
  - `infoDtmf`
  - `trickle-ice`
  - `EmergencyCallData.eCall.MSD`
  - 다수의 `g.3gpp.*` package

### 5.6 Geolocation-Error Codes
- Count: `5`
- 항목 예시:
  - `100` Cannot Process Location
  - `200` Permission to Use Location Information
  - `201` Permission to Retransmit Location Information to a Third Party
  - `202` Permission to Route Based on Location Information
  - `300` Deference Failure

### 5.7 Reason Codes
- Count: `8`
- 항목 예시:
  - `deactivated`
  - `probation`
  - `rejected`
  - `timeout`
  - `giveup`
  - `noresource`
  - `invariant`
  - `badfilter`

### 5.8 Priority Header Field Values
- Count: `5`
- 항목:
  - `non-urgent`
  - `normal`
  - `urgent`
  - `emergency`
  - `psap-callback`

### 5.9 SIP Transport
- Count: `7`
- 항목:
  - `UDP`
  - `TCP`
  - `TLS`
  - `SCTP`
  - `TLS-SCTP`
  - `WS`
  - `WSS`

### 5.10 이번 부록에서 별도 전개하지 않은 다른 IANA SIP registries
이번 문서는 Header Fields를 중심으로 썼기 때문에, 아래 registry들은 존재만 언급하고 표 전체를 별도로 풀어쓰지는 않았다.

- Option Tags
- Warning Codes (warn-codes)
- SIP Privacy Header Field Values
- Security Mechanism Names
- Compression Schemes
- URI Purposes
- Resource-Priority Namespaces
- Resource-Priority Priority-values
- Service-ID/Application-ID Labels
- UUI Packages
- UUI Content Parameters
- UUI Encoding Parameters
- Push Notification Service (PNS)
- SIP AlertMsg-Error Codes

## 6. 이 문서를 읽는 실무 팁
- `Header field inventory`는 전체 표면을 보는 데 유용하다.
- `Compact form`은 parser/mutator/sender에서 short form fuzzing 포인트가 된다.
- `3GPP/IMS-specific` 필드는 일반 SIP 스택과 상용 IMS stack을 구분하는 포인트다.
- `Deprecated` 또는 `Reserved` 표시는 parser robustness 테스트에서 특히 중요하다.

## 7. 공식 출처
- [IANA Session Initiation Protocol (SIP) Parameters](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml)
- [IANA XML export](https://www.iana.org/assignments/sip-parameters/sip-parameters.xml)

추가 로컬 작업 산출물:
- `.omx/research/sip-iana-full-20260318/header-fields.json`
- `.omx/research/sip-iana-full-20260318/sip-parameters-11.json`
- `.omx/research/sip-iana-full-20260318/sip-parameters-12.json`
- `.omx/research/sip-iana-full-20260318/sip-parameters-61.json`
- `.omx/research/sip-iana-full-20260318/sip-parameters-62.json`
- `.omx/research/sip-iana-full-20260318/sip-parameters-66.json`
- `.omx/research/sip-iana-full-20260318/sip-parameters-68.json`
- `.omx/research/sip-iana-full-20260318/sip-parameters-69.json`
- `.omx/research/sip-iana-full-20260318/sip-parameters-73.json`
- `.omx/research/sip-iana-full-20260318/sip-transport.json`
