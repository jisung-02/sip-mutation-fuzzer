# SIP Header Field Parameters and Parameter Values 전수조사

기준 일자: 2026-03-18

## 1. 문서 목적
이 문서는 IANA SIP Parameters Registry의 `Header Field Parameters and Parameter Values` 레지스트리를 기준으로, 현재 등록된 `201개` 파라미터/값 항목을 전수 정리한 문서다.

이번 문서의 중심 대상은 다음 한 개의 IANA 레지스트리다.

- `Header Field Parameters and Parameter Values` (`201` records)

이 문서는 앞서 작성한 `Header Fields 134개 전수조사`의 확장판으로, “헤더 이름”이 아니라 **헤더 내부 parameter/value 표면**을 다룬다.

## 2. 공식 기준
- IANA XML source: `.omx/research/sip-iana-full-20260318/sip-parameters.xml`
- Local extraction: `.omx/research/sip-iana-full-20260318/header-field-parameters-detailed.json`
- Grouped working set: `.omx/research/sip-iana-full-20260318/header-field-parameters-grouped.json`

## 3. 읽는 법
- `Header Field`: parameter가 속한 헤더 이름
- `Parameter/Value Token`: IANA에 등록된 token
- `Predefined`: IANA의 predefined 여부
- `Reference(s)`: IANA row에 연결된 공식 reference
- `Short Meaning`: token 이름과 header 맥락을 기준으로 한 짧은 역할 설명이다. 최종 normative semantics는 reference RFC 본문을 따라야 한다.

중요: 이 문서는 `registry-level inventory` 문서다. 일부 token은 이름만으로도 의미를 쉽게 추정할 수 있지만, `mp`, `np`, `rc`처럼 약어성 token은 reference RFC를 함께 읽어야 정확하다.

## 4. 레지스트리 스냅샷
- Distinct `header_field` groups: `43`
- Total parameter/value rows: `201`

## 5. Header Field별 전수 Inventory
### Accept

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `q` | `No` | `rfc3261` | Preference/priority weight. |

### Accept-Encoding

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `q` | `No` | `rfc3261` | Preference/priority weight. |

### Accept-Language

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `q` | `No` | `rfc3261` | Preference/priority weight. |

### Alert-Info

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `appearance` | `No` | `rfc7463` | Appearance or presentation hint. |

### AlertMsg-Error

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `code` | `no` | `rfc8876` | Structured code value for the header context. |

### Answer-Mode

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `require` | `No` | `rfc5373` | Indicates the associated behavior is required rather than optional. |

### Authentication-Info

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `cnonce` | `No` | `rfc3261` | Client-generated nonce contribution. |
| `nc` | `No` | `rfc3261` | Nonce use counter. |
| `nextnonce` | `No` | `rfc3261` | Next nonce value suggested for subsequent use. |
| `qop` | `Yes` | `rfc3261` | Quality-of-protection mode. |
| `rspauth` | `No` | `rfc3261` | Response-authentication value returned by the server. |

### Authorization
- 요약: Digest/AKA authorization parameter set.

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `algorithm` | `Yes` | `rfc3261, rfc3310` | Algorithm identifier used by the header mechanism. |
| `auts` | `No` | `rfc3310` | AKA/IMS synchronization token for resynchronization flows. |
| `cnonce` | `No` | `rfc3261` | Client-generated nonce contribution. |
| `nc` | `No` | `rfc3261` | Nonce use counter. |
| `nonce` | `No` | `rfc3261` | Challenge nonce value. |
| `opaque` | `No` | `rfc3261` | Opaque state blob echoed unchanged. |
| `qop` | `Yes` | `rfc3261` | Quality-of-protection mode. |
| `realm` | `No` | `rfc3261` | Protection or authentication domain. |
| `response` | `No` | `rfc3261` | Computed authentication response value. |
| `uri` | `No` | `rfc3261` | Request URI covered by or associated with the parameter set. |
| `username` | `No` | `rfc3261` | User identity for authentication. |

### Call-Info

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `call-reason` | `No` | `rfc9796` | Reason associated with the call context. |
| `integrity` | `No` | `rfc9796` | Integrity-related qualifier. |
| `m` | `Yes` | `rfc6910` | Parameter token used within `Call-Info`; see reference RFC for exact semantics. |
| `purpose` | `Yes` | `rfc3261, rfc5367, rfc6910, rfc6993, rfc7082, rfc7852, rfc8688, rfc9248, rfc9796` | Semantic purpose of the associated value or URI. |
| `verified` | `Yes` | `rfc9796` | Verification indicator. |

### Contact
- 요약: Contact binding and GRUU-related parameters.

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `expires` | `No` | `rfc3261` | Lifetime or remaining validity interval. |
| `mp` | `No` | `rfc7044` | Header-specific flag/qualifier defined by its reference RFC. |
| `np` | `No` | `rfc7044` | Header-specific flag/qualifier defined by its reference RFC. |
| `pub-gruu` | `No` | `rfc5627` | Public GRUU associated with the contact. |
| `q` | `No` | `rfc3261` | Preference/priority weight. |
| `rc` | `No` | `rfc7044` | Header-specific code/qualifier defined by its reference RFC. |
| `reg-id` | `No` | `rfc5626` | Registration flow or instance identifier. |
| `temp-gruu` | `No` | `rfc5627` | Temporary GRUU associated with the contact. |
| `temp-gruu-cookie` | `No` | `rfc6140` | Cookie/token bound to a temporary GRUU. |

### Content-Disposition

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `handling` | `Yes` | `rfc3204, rfc3261, rfc3459, rfc5621` | Parameter token used within `Content-Disposition`; see reference RFC for exact semantics. |

### Event
- 요약: Event-package and subscription-correlation parameters.

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `adaptive-min-rate` | `No` | `rfc6446` | Adaptive lower-bound rate control hint. |
| `body` | `Yes` | `rfc5989` | Body-related behavior selector. |
| `call-id` | `No` | `rfc4235` | Call-ID correlation parameter. |
| `effective-by` | `No` | `rfc6080` | Effective-until time indicator. |
| `from-tag` | `No` | `rfc4235` | From-tag correlation parameter. |
| `id` | `No` | `rfc6665` | Identifier value for the header context. |
| `include-session-description` | `No` | `rfc4235` | Requests or signals inclusion of session description content. |
| `max-rate` | `No` | `rfc6446` | Maximum allowed rate. |
| `min-rate` | `No` | `rfc6446` | Minimum allowed rate. |
| `model` | `No` | `rfc6080` | Model/type selector. |
| `profile-type` | `Yes` | `rfc6080` | Profile or profile-family selector. |
| `shared` | `No` | `rfc7463` | Marks shared/common state. |
| `to-tag` | `No` | `rfc4235` | To-tag correlation parameter. |
| `vendor` | `No` | `rfc6080` | Vendor-specific qualifier. |
| `version` | `No` | `rfc6080` | Version indicator. |

### Feature-Caps

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `fcap-name ` | `No` | `rfc6809` | Parameter token used within `Feature-Caps`; see reference RFC for exact semantics. |

### From

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `tag` | `No` | `rfc3261` | Dialog-identifying tag value. |

### Geolocation

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `loc-src` | `No` | `rfc8787` | Source of location information. |

### Geolocation-Error

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `code` | `Yes` | `rfc6442` | Structured code value for the header context. |

### History-Info

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `mp` | `No` | `rfc7044` | Header-specific flag/qualifier defined by its reference RFC. |
| `np` | `No` | `rfc7044` | Header-specific flag/qualifier defined by its reference RFC. |
| `rc` | `No` | `rfc7044` | Header-specific code/qualifier defined by its reference RFC. |

### P-Access-Network-Info

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `cgi-3gpp` | `No` | `rfc7315` | 3GPP cell global identity. |
| `ci-3gpp2` | `No` | `rfc7315` | 3GPP2 cell identity. |
| `ci-3gpp2-femto` | `No` | `rfc7315` | 3GPP2 femtocell identity. |
| `dsl-location` | `No` | `rfc7315` | DSL access location indicator. |
| `dvb-rcs2-node-id` | `No` | `rfc7315` | DVB-RCS2 node identifier. |
| `eth-location` | `No` | `rfc7315` | Ethernet attachment/location indicator. |
| `fiber-location` | `No` | `rfc7315` | Fiber attachment/location indicator. |
| `gstn-location` | `No` | `rfc7315` | GSTN or legacy telephony location indicator. |
| `i-wlan-node-id` | `No` | `rfc7315` | Interworking WLAN node identifier. |
| `local-time-zone` | `No` | `rfc7315` | Local time zone indicator. |
| `operator-specific-GI` | `No` | `rfc7315` | Operator-specific geographic/network identifier. |
| `utran-cell-id-3gpp` | `No` | `rfc7315` | UTRAN cell identifier. |
| `utran-sai-3gpp` | `No` | `rfc7315` | UTRAN service area identity. |

### P-Charging-Function-Addresses

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `ccf` | `No` | `rfc7315` | Charging Collection Function address. |
| `ccf-2` | `No` | `rfc7315` | Secondary Charging Collection Function address. |
| `ecf` | `No` | `rfc7315` | Event Charging Function address. |
| `ecf-2` | `No` | `rfc7315` | Secondary Event Charging Function address. |

### P-Charging-Vector

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `icid-value` | `No` | `rfc7315` | Inter-operator charging identifier value. |
| `icid-generated-at` | `No` | `rfc7315` | Originator of the charging identifier. |
| `orig-ioi` | `No` | `rfc7315` | Originating inter-operator identifier. |
| `related-icid` | `No` | `rfc7315` | Related charging identifier. |
| `related-icid-generated-at` | `No` | `rfc7315` | Originator of the related charging identifier. |
| `term-ioi` | `No` | `rfc7315` | Terminating inter-operator identifier. |
| `transit-ioi` | `No` | `rfc7315` | Transit inter-operator identifier. |

### P-DCS-Billing-Info

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `called` | `No` | `rfc5503` | Called-party value. |
| `calling` | `No` | `rfc5503` | Calling-party value. |
| `charge` | `No` | `rfc5503` | Charging indicator/value. |
| `jip` | `No` | `rfc5503` | Jurisdiction/routing-related parameter. |
| `locroute` | `No` | `rfc5503` | Local routing indicator. |
| `rksgroup` | `No` | `rfc5503` | Rate/route group identifier. |
| `routing` | `No` | `rfc5503` | Routing-related parameter. |

### P-DCS-LAES

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `bcid` | `No` | `rfc5503` | Bearer/content correlation identifier. |
| `cccid` | `No` | `rfc5503` | Call-control/case correlation identifier. |
| `content` | `No` | `rfc5503` | Content kind or payload semantic selector. |
| `key (OBSOLETED)` | `No` | `rfc3603, rfc5503` | Obsoleted key/reference parameter. |

### P-DCS-Redirect

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `count` | `No` | `rfc5503` | Count value. |
| `redirector-uri` | `No` | `rfc5503` | URI of the redirecting entity. |

### P-DCS-Trace-Party-ID

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `timestamp` | `No` | `rfc5503` | Timestamp value. |

### P-Refused-URI-List

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `members` | `No` | `rfc5318` | Member count or member-list metadata. |

### P-Served-User

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `sescase` | `Yes` | `rfc5502` | Session case indicator. |
| `regstate` | `Yes` | `rfc5502` | Registration-state indicator. |
| `orig-cdiv` | `No` | `rfc8498` | Originating call-diversion indicator. |

### Policy-Contact

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `non-cacheable` | `Yes` | `rfc6794` | Indicates the associated policy/contact data should not be cached. |

### Priv-Answer-Mode

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `require` | `No` | `rfc5373` | Indicates the associated behavior is required rather than optional. |

### Proxy-Authenticate
- 요약: Proxy authentication challenge parameter set.

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `algorithm` | `Yes` | `rfc3261, rfc3310` | Algorithm identifier used by the header mechanism. |
| `authz_server` | `No` | `rfc8898` | Authorization server identifier or hint. |
| `domain` | `No` | `rfc3261` | Domain or URI scope where the parameter applies. |
| `error` | `No` | `rfc8898` | Error indicator/details. |
| `nonce` | `No` | `rfc3261` | Challenge nonce value. |
| `opaque` | `No` | `rfc3261` | Opaque state blob echoed unchanged. |
| `qop` | `Yes` | `rfc3261` | Quality-of-protection mode. |
| `realm` | `No` | `rfc3261` | Protection or authentication domain. |
| `scope` | `No` | `rfc8898` | Scope or extent of applicability. |
| `stale` | `Yes` | `rfc3261` | Indicates that credentials may be retried with a fresh nonce. |

### Proxy-Authorization
- 요약: Proxy authentication credential parameter set.

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `algorithm` | `Yes` | `rfc3261, rfc3310` | Algorithm identifier used by the header mechanism. |
| `auts` | `No` | `rfc3310` | AKA/IMS synchronization token for resynchronization flows. |
| `cnonce` | `No` | `rfc3261` | Client-generated nonce contribution. |
| `nc` | `No` | `rfc3261` | Nonce use counter. |
| `nonce` | `No` | `rfc3261` | Challenge nonce value. |
| `opaque` | `No` | `rfc3261` | Opaque state blob echoed unchanged. |
| `qop` | `Yes` | `rfc3261` | Quality-of-protection mode. |
| `realm` | `No` | `rfc3261` | Protection or authentication domain. |
| `response` | `No` | `rfc3261` | Computed authentication response value. |
| `uri` | `No` | `rfc3261` | Request URI covered by or associated with the parameter set. |
| `username` | `No` | `rfc3261` | User identity for authentication. |

### Reason

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `cause` | `Yes` | `rfc3326` | Cause code for the header context. |
| `location` | `Yes` | `rfc8606` | Location/origin information for the header context. |
| `ppi` | `No` | `rfc9410` | Additional policy/protocol indicator. |
| `text` | `No` | `rfc3326` | Human-readable explanatory text. |

### Retry-After

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `duration` | `No` | `rfc3261` | Parameter token used within `Retry-After`; see reference RFC for exact semantics. |

### Security-Client
- 요약: Client-advertised security-agreement parameter set.

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `alg` | `Yes` | `rfc3329` | Security algorithm identifier. |
| `ealg` | `Yes` | `rfc3329` | Encryption algorithm identifier. |
| `d-alg` | `Yes` | `rfc3329` | Digest/integrity algorithm identifier. |
| `d-qop` | `Yes` | `rfc3329` | Digest quality-of-protection mode. |
| `d-ver` | `No` | `rfc3329` | Digest or security version indicator. |
| `mod` | `Yes` | `rfc3329` | Security mechanism mode or profile. |
| `port1` | `No` | `rfc3329` | First negotiated port value. |
| `port2` | `No` | `rfc3329` | Second negotiated port value. |
| `prot` | `Yes` | `rfc3329` | Protocol identifier. |
| `q` | `No` | `rfc3329` | Preference/priority weight. |
| `spi` | `No` | `rfc3329` | Security Parameters Index / security association identifier. |

### Security-Server
- 요약: Server-advertised security-agreement parameter set.

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `alg` | `Yes` | `rfc3329` | Security algorithm identifier. |
| `ealg` | `Yes` | `rfc3329` | Encryption algorithm identifier. |
| `d-alg` | `Yes` | `rfc3329` | Digest/integrity algorithm identifier. |
| `d-qop` | `Yes` | `rfc3329` | Digest quality-of-protection mode. |
| `d-ver` | `No` | `rfc3329` | Digest or security version indicator. |
| `mod` | `Yes` | `rfc3329` | Security mechanism mode or profile. |
| `port1` | `No` | `rfc3329` | First negotiated port value. |
| `port2` | `No` | `rfc3329` | Second negotiated port value. |
| `prot` | `Yes` | `rfc3329` | Protocol identifier. |
| `q` | `No` | `rfc3329` | Preference/priority weight. |
| `spi` | `No` | `rfc3329` | Security Parameters Index / security association identifier. |

### Security-Verify
- 요약: Security-agreement verification parameter set.

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `alg` | `Yes` | `rfc3329` | Security algorithm identifier. |
| `ealg` | `Yes` | `rfc3329` | Encryption algorithm identifier. |
| `d-alg` | `Yes` | `rfc3329` | Digest/integrity algorithm identifier. |
| `d-qop` | `Yes` | `rfc3329` | Digest quality-of-protection mode. |
| `d-ver` | `No` | `rfc3329` | Digest or security version indicator. |
| `mod` | `Yes` | `rfc3329` | Security mechanism mode or profile. |
| `port1` | `No` | `rfc3329` | First negotiated port value. |
| `port2` | `No` | `rfc3329` | Second negotiated port value. |
| `prot` | `Yes` | `rfc3329` | Protocol identifier. |
| `q` | `No` | `rfc3329` | Preference/priority weight. |
| `spi` | `No` | `rfc3329` | Security Parameters Index / security association identifier. |

### Session-ID

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `logme` | `No (no values are allowed)` | `rfc8497` | Parameter token used within `Session-ID`; see reference RFC for exact semantics. |
| `remote` | `No` | `rfc7989` | Parameter token used within `Session-ID`; see reference RFC for exact semantics. |

### Subscription-State
- 요약: Subscription-state control parameters.

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `adaptive-min-rate` | `No` | `rfc6446` | Adaptive lower-bound rate control hint. |
| `expires` | `No` | `rfc6665` | Lifetime or remaining validity interval. |
| `max-rate` | `No` | `rfc6446` | Maximum allowed rate. |
| `min-rate` | `No` | `rfc6446` | Minimum allowed rate. |
| `reason` | `Yes` | `rfc6665` | Parameter token used within `Subscription-State`; see reference RFC for exact semantics. |
| `retry-after` | `No` | `rfc6665` | Delay before retrying. |

### Target-Dialog

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `local-tag` | `No` | `rfc4538` | Local dialog tag used to identify the targeted dialog. |
| `remote-tag` | `No` | `rfc4538` | Remote dialog tag used to identify the targeted dialog. |

### To

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `tag` | `No` | `rfc3261` | Dialog-identifying tag value. |

### Trigger-Consent

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `target-uri` | `No` | `rfc5360` | Target URI involved in the consent trigger. |

### User-to-User

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `content` | `No` | `rfc7433` | Content kind or payload semantic selector. |
| `encoding` | `Yes` | `rfc7433` | Encoding format applied to the payload. |
| `purpose` | `No` | `rfc7433` | Semantic purpose of the associated value or URI. |

### Via
- 요약: Transport-path and transaction parameters.

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `alias` | `No` | `rfc5923` | Parameter token used within `Via`; see reference RFC for exact semantics. |
| `branch` | `No` | `rfc3261` | Transaction branch identifier. |
| `comp` | `Yes` | `rfc3486` | Compression indicator. |
| `keep` | `No` | `rfc6223` | Keepalive-related flag/hint. |
| `maddr` | `No` | `rfc3261` | Multicast or address override. |
| `oc` | `Yes` | `rfc7339` | Overload-control value. |
| `oc-algo` | `Yes` | `rfc7339, rfc7415` | Overload-control algorithm identifier. |
| `oc-seq` | `Yes` | `rfc7339` | Overload-control sequencing value. |
| `oc-validity` | `Yes` | `rfc7339` | Validity period for overload-control data. |
| `received` | `No` | `rfc3261, rfc7118` | Actual source address seen by the receiver. |
| `received-realm` | `No` | `rfc8055` | Realm associated with the received source info. |
| `rport` | `No` | `rfc3581` | Source-port reflection/symmetric response hint. |
| `sigcomp-id` | `No` | `rfc5049` | SigComp compartment/instance identifier. |
| `ttl` | `No` | `rfc3261` | Time-to-live value. |

### WWW-Authenticate
- 요약: UAS/server authentication challenge parameter set.

| Parameter/Value Token | Predefined | Reference(s) | Short Meaning |
| --- | --- | --- | --- |
| `algorithm` | `Yes` | `rfc3261, rfc3310` | Algorithm identifier used by the header mechanism. |
| `authz_server` | `No` | `rfc8898` | Authorization server identifier or hint. |
| `domain` | `Yes` | `rfc3261` | Domain or URI scope where the parameter applies. |
| `error` | `No` | `rfc8898` | Error indicator/details. |
| `nonce` | `No` | `rfc3261` | Challenge nonce value. |
| `opaque` | `No` | `rfc3261` | Opaque state blob echoed unchanged. |
| `qop` | `Yes` | `rfc3261` | Quality-of-protection mode. |
| `realm` | `No` | `rfc3261` | Protection or authentication domain. |
| `scope` | `No` | `rfc8898` | Scope or extent of applicability. |
| `stale` | `Yes` | `rfc3261` | Indicates that credentials may be retried with a fresh nonce. |

## 6. 빠른 정리 포인트
- 가장 row가 많은 header groups: `Event(15)`, `Via(14)`, `P-Access-Network-Info(13)`, `Authorization/Proxy-Authorization/Security-*` 계열
- 인증/보안 파라미터는 `Authorization`, `Proxy-Authenticate`, `Proxy-Authorization`, `WWW-Authenticate`, `Security-*`에 집중된다.
- IMS/3GPP-specific 파라미터는 `P-Access-Network-Info`, `P-Charging-*`, `P-Served-User` 등 private header에 많이 몰린다.
- `Header Field Parameters and Parameter Values`는 parser/fuzzer 입장에서 매우 중요하다. 헤더 이름은 같아도 parameter 조합에서 상호운용성 문제가 자주 생긴다.

## 7. 공식 출처
- [IANA Session Initiation Protocol (SIP) Parameters](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml)
- [IANA XML export](https://www.iana.org/assignments/sip-parameters/sip-parameters.xml)
