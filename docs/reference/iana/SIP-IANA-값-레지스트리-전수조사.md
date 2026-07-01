# SIP IANA 값 레지스트리 전수조사

기준 일자: 2026-03-18

## 1. 문서 목적
이 문서는 IANA SIP Parameters 중 값 중심 top-level registry 일부를 묶어 전수 inventory한 문서다. Header field 이름이나 header parameter 이름이 아니라, 실제 메시지 안에 들어가는 token/code/value vocabulary 중 이 문서 범위에 속하는 registry를 빠짐없이 정리하는 데 목적이 있다.

## 2. 공식 기준
- IANA registry: `Session Initiation Protocol (SIP) Parameters`
- IANA page last updated: `2026-01-07`
- IANA XML source: `.omx/research/sip-iana-full-20260318/sip-parameters.xml`

## 3. 문서 범위
- Covered registries: `12`
- Total rows covered: `89`
- Covered registry ids: `sip-parameters-3, sip-parameters-5, sip-parameters-8, sip-parameters-9, sip-parameters-10, sip-parameters-13, sip-parameters-68, sip-parameters-69, sip-parameters-73, sip-transport, sip-pns, sip-alertmsg-error-codes`
- Note: Methods/Response Codes, Identity/Info Package/UUI 계열, Resource-Priority child registries는 별도 전수 문서에서 다룬다. 전체 커버리지는 `SIP-IANA-기타-레지스트리-survey.md`를 기준으로 본다.

## 1. Reason Protocols (`sip-parameters-3`)
- Total rows: `22`
- Registry reference(s): `rfc3326`
- Why it matters: Reason header의 protocol token 공간을 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| SIP | Status code | rfc3261 |
| Q.850 | Cause value in decimal representation | ITU-T Q.850 |
| Preemption | Cause value in decimal | rfc4411 |
| EMM | Cause value in decimal representation | 3GPP TS 24.301 subclause 9.9.3.9, Table 9.9.3.9.1, _3GPP |
| ESM | Cause value in decimal representation | 3GPP TS 24.301 subclause 9.9.4.4, Table 9.9.4.4.1, _3GPP |
| S1AP-RNL | Radio network layer cause value in decimal representation | 3GPP TS 36.413, _3GPP |
| S1AP-TL | Radio network layer cause value in decimal representation | 3GPP TS 36.413 subclause 9.2.1.3, 4, _3GPP |
| S1AP-NAS | Non-access stratum cause value in decimal representation | 3GPP TS 36.413 subclause 9.2.1.3, 4, _3GPP |
| S1AP-MISC | Miscellaneous cause value in decimal representation | 3GPP TS 36.413 subclause 9.2.1.3, 4, _3GPP |
| S1AP-PROT | S1 Protocol cause value in decimal representation | 3GPP TS 36.413 subclause 9.2.1.3, 4, _3GPP |
| DIAMETER | Cause for protocol failure of GTP-C supporting WLAN, as a representation in decimal digits of the received binary value. | 3GPP TS 29.274 subclause 8.103, 5, _3GPP |
| IKEV2 | Cause for protocol failure of IKEV2 supporting untrusted WLAN, as a representation in decimal digits of the received binary value. | 3GPP TS 29.274 subclause 8.103, 6, _3GPP |
| RELEASE_CAUSE | cause value 1: User ends call cause value 2: RTP/RTCP time-out cause value 3: Media bearer loss cause value 4: SIP timeout - no ACK cause value 5: SIP response time-out cause value 6: Call-setup time-out cause value 7: Redirection failure | 3GPP TS 24.229 |
| FAILURE_CAUSE | cause value 1: Media bearer or QoS lost cause value 2: Release of signalling bearer cause value 3: Indication of failed resources allocation | 3GPP TS 24.229 v14.4.0, Dongwook_Kim |
| STIR | STIR Error code | rfc8224 |
| 5GMM | Cause value in decimal representation | 3GPP TS 24.501 subclause 9.11.3.2, _3GPP |
| 5GSM | Cause value in decimal representation | 3GPP TS 24.501 subclause 9.11.4.2, _3GPP |
| NGAP-RNL | Radio network layer cause value in decimal representation | 3GPP TS 38.413 subclause 9.3.1.2, _3GPP |
| NGAP-TL | Radio network layer cause value in decimal representation | 3GPP TS 38.413 subclause 9.3.1.2, _3GPP |
| NGAP-NAS | Non-access stratum cause value in decimal representation | 3GPP TS 38.413 subclause 9.3.1.2, _3GPP |
| NGAP-MISC | Miscellaneous cause value in decimal representation | 3GPP TS 38.413 subclause 9.3.1.2, _3GPP |
| NGAP-PROT | S1 Protocol cause value in decimal representation | 3GPP TS 38.413 subclause 9.3.1.2, _3GPP |

## 2. Warning Codes (warn-codes) (`sip-parameters-5`)
- Total rows: `15`
- Registry reference(s): `rfc3261, Section 27.2`
- Why it matters: Warning header의 numeric warn-code 공간을 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| 300 | Incompatible network protocol: One or more network protocols contained in the session description are not available. | rfc3261 |
| 301 | Incompatible network address formats: One or more network address formats contained in the session description are not available. | rfc3261 |
| 302 | Incompatible transport protocol: One or more transport protocols described in the session description are not available. | rfc3261 |
| 303 | Incompatible bandwidth units: One or more bandwidth measurement units contained in the session description were not understood. | rfc3261 |
| 304 | Media type not available: One or more media types contained in the session description are not available. | rfc3261 |
| 305 | Incompatible media format: One or more media formats contained in the session description are not available. | rfc3261 |
| 306 | Attribute not understood: One or more of the media attributes in the session description are not supported. | rfc3261 |
| 307 | Session description parameter not understood: A parameter other than those listed above was not understood. | rfc3261 |
| 308 | Incompatible language specification: Requested languages not supported. Supported languages and media are: [list of supported languages and media]. | rfc8373 |
| 330 | Multicast not available: The site where the user is located does not support multicast. | rfc3261 |
| 331 | Unicast not available: The site where the user is located does not support unicast communication (usually due to the presence of a firewall). | rfc3261 |
| 370 | Insufficient bandwidth: The bandwidth specified in the session description or defined by the media exceeds that known to be available. | rfc3261 |
| 380 | SIPS Not Allowed: The UAS or proxy cannot process the request because the SIPS scheme is not allowed (e.g., because there are currently no registered SIPS Contacts). | rfc5630 |
| 381 | SIPS Required: The UAS or proxy cannot process the request because the SIPS scheme is required. | rfc5630 |
| 399 | Miscellaneous warning: The warning text can include arbitrary information to be presented to a human user or logged. A system receiving this warning MUST NOT take any automated action. | rfc3261 |

## 3. SIP Privacy Header Field Values (`sip-parameters-8`)
- Total rows: `7`
- Registry reference(s): `rfc3323`
- Why it matters: Privacy header에서 사용할 수 있는 값 토큰을 정의한다.

| Value | Description | Reference(s) | Registrant |
| --- | --- | --- | --- |
| user | Request that privacy services provide a user-level privacy function | rfc3323 |  |
| header | Request that privacy services modify headers that cannot be set arbitrarily by the user (Contact/Via). | rfc3323 |  |
| session | Request that privacy services provide privacy for session media | rfc3323 |  |
| none | Privacy services must not perform any privacy function | rfc3323 |  |
| critical | Privacy service must perform the specified services or fail the request | rfc3323 |  |
| id | Privacy requsted for Third-Party Asserted Identity | rfc3325 |  |
| history | Privacy requested for History-Info header field(s) | rfc7044 |  |

## 4. Security Mechanism Names (`sip-parameters-9`)
- Total rows: `5`
- Registry reference(s): `rfc3329`
- Why it matters: Security-Client/Server/Verify 등에서 쓰이는 security mechanism 이름을 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| digest | Registered token/value. | rfc3329 |
| tls | Registered token/value. | rfc3329 |
| ipsec-ike | Registered token/value. | rfc3329 |
| ipsec-man | Registered token/value. | rfc3329 |
| ipsec-3gpp | Registered token/value. | rfc3329 |

## 5. Compression Schemes (`sip-parameters-10`)
- Total rows: `1`
- Registry reference(s): `rfc3486`
- Why it matters: SIP signaling compression scheme 값을 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| sigcomp | Signaling Compression | rfc3486 |

## 6. URI Purposes (`sip-parameters-13`)
- Total rows: `7`
- Registry reference(s): `rfc4575`
- Why it matters: URI에 붙는 purpose 계열 값의 등록 공간을 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| participation | The URI can be used to join the conference | rfc4575 |
| streaming | The URI can be used to access the streamed conference data | rfc4575 |
| event | The URI can be used to subscribe to the conference event package | rfc4575 |
| recording | The URI can be used to access the recorded conference data | rfc4575 |
| web-page | The URI can be used to access a web page that contains additional information of the conference | rfc4575 |
| ccmp | The URI can be used to indicate that the conference focus supports CCMP. | rfc7082 |
| grouptextchat | The URI can be used to join a multi-user chat directly associated with the conference | rfc7106 |

## 7. Geolocation-Error Codes (`sip-parameters-68`)
- Total rows: `5`
- Registry reference(s): `rfc6442`
- Why it matters: Geolocation-Error header의 코드 값을 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| 100 | "Cannot Process Location" | rfc6442 |
| 200 | "Permission to Use Location Information" | rfc6442 |
| 201 | "Permission to Retransmit Location Information to a Third Party" | rfc6442 |
| 202 | "Permission to Route Based on Location Information" | rfc6442 |
| 300 | "Deference Failure" | rfc6442 |

## 8. Reason Codes (`sip-parameters-69`)
- Total rows: `8`
- Registry reference(s): `rfc6665`
- Why it matters: Reason 계열 symbolic code token을 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| deactivated | Registered token/value. | rfc6665 |
| probation | Registered token/value. | rfc6665 |
| rejected | Registered token/value. | rfc6665 |
| timeout | Registered token/value. | rfc6665 |
| giveup | Registered token/value. | rfc6665 |
| noresource | Registered token/value. | rfc6665 |
| invariant | Registered token/value. | rfc6665 |
| badfilter | Registered token/value. | rfc4660 |

## 9. Priority Header Field Values (`sip-parameters-73`)
- Total rows: `5`
- Registry reference(s): `rfc6878`
- Why it matters: Priority header의 값 공간을 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| non-urgent | Registered token/value. | rfc3261 |
| normal | Registered token/value. | rfc3261 |
| urgent | Registered token/value. | rfc3261 |
| emergency | Registered token/value. | rfc3261 |
| psap-callback | Registered token/value. | rfc7090 |

## 10. SIP Transport (`sip-transport`)
- Total rows: `7`
- Registry reference(s): `rfc7118`
- Why it matters: sip:/sips: URI와 routing/transport 처리에 쓰이는 transport token을 정의한다.

| Transport Token | Description | Reference(s) |
| --- | --- | --- |
| UDP | Registered SIP transport token. | rfc3261 |
| TCP | Registered SIP transport token. | rfc3261 |
| TLS | Registered SIP transport token. | rfc3261 |
| SCTP | Registered SIP transport token. | rfc3261, rfc4168 |
| TLS-SCTP | Registered SIP transport token. | rfc4168 |
| WS | Registered SIP transport token. | rfc7118 |
| WSS | Registered SIP transport token. | rfc7118 |

## 11. Push Notification Service (PNS) (`sip-pns`)
- Total rows: `3`
- Registry reference(s): `rfc8599`
- Why it matters: SIP push mechanism에서 쓰는 push notification service 식별자를 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| apns | Apple Push Notification service | rfc8599 |
| fcm | Firebase Cloud Messaging | rfc8599 |
| webpush | Generic Event Delivery Using HTTP Push | rfc8599 |

## 12. SIP AlertMsg-Error Codes (`sip-alertmsg-error-codes`)
- Total rows: `4`
- Registry reference(s): `rfc8876`
- Why it matters: Alert-Message 처리 실패용 특수 에러 코드를 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| 100 | "Cannot process the alert payload" | rfc8876 |
| 101 | "Alert payload was not present or could not be found" | rfc8876 |
| 102 | "Not enough information to determine the purpose of the alert" | rfc8876 |
| 103 | "Alert payload was corrupted" | rfc8876 |

## 공식 출처
- [IANA Session Initiation Protocol (SIP) Parameters](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml)
- [IANA XML export](https://www.iana.org/assignments/sip-parameters/sip-parameters.xml)
