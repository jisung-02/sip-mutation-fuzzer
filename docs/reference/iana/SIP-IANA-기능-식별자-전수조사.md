# SIP IANA 기능 식별자 전수조사

기준 일자: 2026-03-18

## 1. 문서 목적
이 문서는 IANA SIP Parameters 중 capability, identity, configuration, package, UUI 같은 구조화된 식별자 registry를 전수 inventory한 문서다. Feature-Caps, Identity, Info-Package, User-to-User처럼 단순 헤더 이름만으로는 파악되지 않는 value surface를 빠짐없이 정리하는 데 목적이 있다.

## 2. 공식 기준
- IANA registry: `Session Initiation Protocol (SIP) Parameters`
- IANA page last updated: `2026-01-07`
- IANA XML source: `.omx/research/sip-iana-full-20260318/sip-parameters.xml`

## 3. 문서 범위
- Covered registries: `12`
- Total rows covered: `71`
- Covered registry ids: `sip-parameters-61, sip-parameters-62, sip-parameters-64, sip-parameters-65, sip-parameters-66, sip-parameters-67, sip-parameters-70, sip-parameters-71, sip-parameters-72, uui-packages, uui-content, uui-encoding`

## 1. Identity Parameters (`sip-parameters-61`)
- Total rows: `2`
- Registry reference(s): `rfc8224`
- Why it matters: SIP Identity 관련 parameter name을 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| alg | Registered token/value. | rfc8224 |
| info | Registered token/value. | rfc8224 |

## 2. Identity-Info Algorithm Parameter Values (`sip-parameters-62`)
- Total rows: `2`
- Registry reference(s): `rfc8224`
- Why it matters: Identity-Info의 alg parameter value를 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| rsa-sha1 | Registered token/value. | rfc4474 |
| rsa-sha256 | Registered token/value. | rfc6072 |

## 3. SIP Forum User Agent Configuration Parameters (`sip-parameters-64`)
- Total rows: `5`
- Registry reference(s): `rfc6011`
- Why it matters: SIP Forum UA configuration request parameter name을 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| sfua-id | The URN identifying the User Agent, constructed as specified in section 4.1 of "Managing Client-Initiated Connections in the Session Initiation Protocol (SIP)". Since the procedure defined by allows any UA to construct a value for this parameter, the sfua-id parameter MUST always be included. If the UA implements , and includes the '+sip.instance' Contact header field parameter in any request, when requesting configuration it MUST use the same value for the sfua-id parameter. | rfc6011 |
| sfua-user | An identifier for a user associated with the configuration. Note that this might be different than any SIP 'user' in the UA configuration: it could, for example, be the login name of an account on the service provider web site. The syntax of this parameter is that of the 'userid'. See Section 2.4.1, "Configuration Data Request Authentication" for how this parameter relates to authentication of the configuration data request. | rfc6011 |
| sfua-vendor | An identifier that specifies the vendor of the User Agent. The syntax of the value of this parameter is that of a DNS domain. The domain value MUST be that of a domain owned by the vendor. | rfc6011 |
| sfua-model | An identifier that further specifies the User Agent from among those produced by the vendor. The syntax of the value of this parameter is the same as the 'token'. Values for this parameter are selected by the vendor. | rfc6011 |
| sfua-revision | An identifier that further specifies the User Agent from among those produced by the vendor. The syntax of the value of this parameter is the same as the 'token'. Values for this parameter are selected by the vendor. | rfc6011 |

## 4. Service-ID/Application-ID Labels (`sip-parameters-65`)
- Total rows: `2`
- Registry reference(s): `rfc6050`
- Why it matters: Service-ID / Application-ID의 최상위 label 값을 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| 3gpp-service | Communication services defined by 3GPP for use by the IM CN subsystem and its attached UAs. This value in itself does not define a service and requires subsequent labels to define the service. | rfc6050 |
| 3gpp-application | Applications defined by 3GPP for use by UAs attached to the IM CN subsystem. This value in itself does not define a service and requires subsequent labels to define the service. | rfc6050 |

## 5. Info Packages Registry (`sip-parameters-66`)
- Total rows: `13`
- Registry reference(s): `rfc6086`
- Why it matters: Info-Package header에서 쓰는 package name을 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| g.3gpp.access-transfer-events | Registered token/value. | 3GPP TS 24.237 v11.14.0, Dongwook_Kim |
| g.3gpp.mid-call | Registered token/value. | 3GPP TS 24.237 v10.19.0, Dongwook_Kim |
| g.3gpp.ussd | Registered token/value. | 3GPP TS 24.390 v11.5.0, Dongwook_Kim |
| g.3gpp.state-and-event | Registered token/value. | 3GPP 24.237 Rel-10, Dongwook_Kim |
| EmergencyCallData.eCall.MSD | Registered token/value. | rfc8147 |
| EmergencyCallData.VEDS | Registered token/value. | rfc8148 |
| infoDtmf | Registered token/value. | 3GPP 24.229 v12.16.0, Dongwook_Kim |
| g.3gpp.mcptt-floor-request | Registered token/value. | 3GPP 24.379 v13.7.0, Section J.1.2, Dongwook_Kim |
| g.3gpp.mcptt-info | Registered token/value. | 3GPP 24.379 v13.7.0, Section J.2.2, Dongwook_Kim |
| g.3gpp.mcdata-com-release | Registered token/value. | 3GPP TS 24.282 14.3.0, Dongwook_Kim |
| trickle-ice | Registered token/value. | rfc8840 |
| g.3gpp.mcvideo-info | Registered token/value. | 3GPP TS 24.281 14.3.0, Dongwook_Kim |
| g.3gpp.current-location-discovery | Registered token/value. | 3GPP TS 24.229, Lionel_Morand |

## 6. SIP Configuration Profile Types (`sip-parameters-67`)
- Total rows: `3`
- Registry reference(s): `rfc6080`
- Why it matters: SIP configuration profile type 값을 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| local-network | Registered token/value. | rfc6080 |
| device | Registered token/value. | rfc6080 |
| user | Registered token/value. | rfc6080 |

## 7. Proxy-Feature Feature-Capability Indicator Trees (`sip-parameters-70`)
- Total rows: `2`
- Registry reference(s): `rfc6809`
- Why it matters: Feature-Caps indicator tree의 최상위 namespace를 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| g. | Global Feature Capability Indicator Tree | rfc6809 |
| sip. | SIP Feature Capability Indicator Tree | rfc6809 |

## 8. Global Feature-Capability Indicator Registration Tree (`sip-parameters-71`)
- Total rows: `33`
- Registry reference(s): `rfc6809`
- Why it matters: Feature-Caps의 global g. indicator 값을 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| g.3gpp.iut-focus | This feature-capability indicator when used in a Feature-Caps header field of a SIP request or a SIP response indicates that the function which inserted the Feature-Caps header field supports anchoring an IUT session. | 3GPP TS 24.337 10.7.0 |
| g.3gpp.mid-call | This feature-capability indicator when used in a Feature-Caps header field of a SIP request or a SIP response indicates that: 1. the functional entity including the feature-capability indicator in the SIP message supports the MSC server assisted mid-call feature; and 2. all entities of which the functional entity including the feature-capability indicator in the SIP message is aware of being requested to support the feature do support the MSC server assisted mid-call feature. | 3GPP TS 24.237 10.10.0 |
| g.3gpp.atcf | This feature-capability indicator when included in a Feature-Caps header field as specified in IETF in a SIP REGISTER request or a SIP response to the SIP REGISTER request indicates presence and support of a resource which is an Access Transfer Control Function (ATCF) and also the session transfer number allocated to the ATCF. | 3GPP TS 24.237 10.10.0 |
| g.3gpp.srvcc-alerting | This feature-capability indicator when used in a Feature-Caps header field of a SIP request or a SIP response indicates that: 1. the functional entity including the feature-capability indicator in the SIP message supports access transfer for calls in alerting phase; and 2. all entities of which the functional entity including the feature-capability indicator in the SIP message is aware of being requested to support the feature do support access transfer for calls in alerting phase. | 3GPP TS 24.237 10.10.0 |
| g.3gpp.atcf-mgmt-uri | This feature-capability indicator when used in a Feature-Caps header field as specified in IETF [60] in SIP REGISTER request indicates presence and support of performing as a UAS for SIP requests for ATCF management received at this URI. | 3GPP TS 24.237 10.10.0 |
| g.3gpp.srvcc | This feature-capability indicator when included in a Feature-Caps header field as specified in IETF of: - a SIP INVITE request; or - a SIP INVITE response; indicates presence and support of a resource capable of performing the SRVCC access transfer procedure as specified in 3GPP TS 24.237. | 3GPP TS 24.237 10.10.0 |
| g.3gpp.atcf-path | This feature-capability indicator when used in a Feature-Caps header field as specified in IETF in SIP REGISTER request indicates capability of identifying the registration path and binding SRVCC related information to it. | 3GPP TS 24.237 10.10.0 |
| g.3gpp.cs2ps-srvcc | This feature-capability indicator when included in Feature-Caps header field as specified in IETF [60] indicates support of the CS to PS single radio voice call continuity as specified in 3GPP TS 24.237. | 3GPP TS 24.237 11.10.0, Dongwook_Kim |
| g.3gpp.ti | This feature-capability indicator when used in a Feature-Caps header field as specified in IETF in SIP INVITE request or SIP response to the SIP INVITE request indicates the capability of associating a CS call with dialog created by the SIP INVITE request. | 3GPP TS 24.237 11.10.0, Dongwook_Kim |
| g.3gpp.loopback | This feature-capability indicator, when included in a Feature-Caps header field as specified in in a SIP INVITE request, indicates the support of the roaming architecture for voice over IMS with local breakout. | 3GPP TS 24.229, Dongwook_Kim |
| g.3gpp.trf | This feature-capability indicator, when included in a Feature-Caps header field as specified in in a SIP INVITE request, indicates that in a roaming scenario, the visited network supports a transit and roaming functionality in order to allow loopback of session requests to the visited network from the home network. When used, it may indicate the URI of the transit and roaming functionality. | 3GPP TS 24.229 11.11.0, Dongwook_Kim |
| g.3gpp.home-visited | This feature-capability indicator, when included in a Feature-Caps header field as specified in in a SIP INVITE request, indicates that the home network supports loopback to the identified visited network for this session. The loopback is expected to be applied at some subsequent entity to the insertion point. The feature-capability indicator carries a parameter value which indicates the visited network. | 3GPP TS 24.229, Dongwook_Kim |
| g.3gpp.mrb | This feature-capability indicator when included in a Feature-Caps header field as specified in in a SIP INVITE request indicates that in a roaming scenario, the visited network supports media resource broker functionality for the allocation of multimedia resources in the visited network. When used, it indicates the URI of the visited network MRB. | 3GPP TS 24.229 11.11.0, Dongwook_Kim |
| g.3gpp.icsi-ref | Each value of the Service Reference feature-capability indicator indicates the software applications supported by the entity. The values for this feature-capability indicator equal the IMS communication Service Identifier (ICSI) values supported by the entity. Multiple feature-capability indicator values can be included in the Service Reference feature-capability indicators. When included in the Feature-Caps header field, according to , the value of this feature-capability indicator contains the IMS communication service identifier (ICSI) of the IMS communication service supported for use 1) in the standalone transaction (if included in a request for a standalone transaction or a response associated with it) or 2) in the dialog (if included in an initial request for dialog or a response associated with it) by the entity which included the Feature-Caps header field. | 3GPP TS 24.229 11.12.0, Dongwook_Kim |
| g.3gpp.drvcc-alerting | This feature-capability indicator when included in a Feature-Caps header field as specified in IETF in a SIP INVITE request or a SIP response to the SIP INVITE request indicates support of PS to CS dual radio access transfer for calls in alerting phase. | 3GPP TS 24.237 12.8.0, Dongwook_Kim |
| g.3gpp.dynamic-stn | This feature-capability indicator g.3gpp.dynamic-stn, when included in a Feature-Caps header field as specified in IETF in a SIP INVITE request or a SIP response to the SIP INVITE request, indicates support to transfer the session to the circuit switched (CS) domain using the dynamic STN (session transfer number) digit string. | 3GPP TS 24.237 12.8.0, Dongwook_Kim |
| g.3gpp.ps2cs-drvcc-orig-pre-alerting | This feature-capability indicator g.3gpp.ps2cs-srvcc-orig-pre-alerting when used in a Feature-Caps header field of a SIP request or a SIP response indicates that: 1. the functional entity including the feature-capability indicator in the SIP message supports the PS to CS SRVCC for originating calls in pre-alerting phase; and 2. all entities of which the functional entity including the feature-capability indicator in the SIP message is aware of being requested to support the feature do support the PS to CS SRVCC for originating calls in pre-alerting phase. | 3GPP TS 24.237 12.8.0, Dongwook_Kim |
| g.3gpp.ps2cs-srvcc-orig-pre-alerting | This feature-capability indicator g.3gpp.ps2cs-srvcc-orig-pre-alerting when used in a Feature-Caps header field of a SIP request or a SIP response indicates that: 1. the functional entity including the feature-capability indicator in the SIP message supports the PS to CS SRVCC for originating calls in pre-alerting phase; and 2. all entities of which the functional entity including the feature-capability indicator in the SIP message is aware of being requested to support the feature do support the PS to CS SRVCC for originating calls in pre-alerting phase. | 3GPP TS 24.237 12.8.0, Dongwook_Kim |
| g.3gpp.cs2ps-drvcc-alerting | This feature-capability indicator, when included in a Feature-Caps header field as specified in IETF in a SIP request or a SIP response to the SIP request, indicates support of CS to PS dual radio access transfer for calls in alerting phase. | 3GPP TS 24.237 12.9.0, Dongwook_Kim |
| g.3gpp.cs2ps-drvcc-orig-pre-alerting | This feature-capability indicator when included in a Feature-Caps header field as specified in IETF in a SIP request or a SIP response to the SIP request indicates support of CS to PS dual radio access transfer for originating calls in pre-alerting phase. | 3GPP TS 24.237 12.9.0, Dongwook_Kim |
| g.3gpp.ics | This feature-capability indicator when included in a Feature-Caps header field as specified in IETF in a SIP initial request for dialog or a response associated with the SIP initial request indicates support of IMS Centralized Services (ICS). | 3GPP TS 24.292 12.8.0, Dongwook_Kim |
| g.3gpp.registration-token | This feature-capability indicator, when included in a Feature-Caps header field as specified in [190] in a SIP REGISTER request, indicates the support of using a token to identify the registration used for the request. This feature-capability indicator can be included in an originating initial INVITE request to identify which registration was used for this request by setting the indicator to the same value as in the +g.3gpp.registration-token media feature tag in the Contact header field of the REGISTER request. This feature-capability indicator can be included in any response to a terminating INVITE request to identify which registration was used for the response by setting the indicator to the same value as in the +g.3gpp.registration-token media feature tag in the Contact header field of the REGISTER request. | 3GPP TS 24.229 12.16.0, Dongwook_Kim |
| g.3gpp.verstat | This feature-capability indicator, when included in a Feature-Caps header field as specified in in a 200 (OK) response to a REGISTER request, indicates that the home network supports calling party number verification, as described in . | 3GPP TS 24.229 v14.7.0, Dongwook_Kim |
| g.3gpp.mcvideo.ambient-viewing-call-release | This feature-capability indicator when included in a Feature-Caps header field as specified in IETF in a SIP INVITE request or a SIP 200 (OK) response to a SIP INVITE request indicates that the MCVideo server is capable of receiving a SIP BYE from an MCVideo client to release an ambient-viewing call. | 3GPP TS 24.281 Rel-15, Dongwook_Kim |
| g.3gpp.mcptt.ambient-listening-call-release | This feature-capability indicator when included in a Feature-Caps header field as specified in IETF in a SIP INVITE request or a SIP 200 (OK) response to a SIP INVITE request indicates that the MCPTT server is capable of receiving a SIP BYE from an MCPTT client to release an ambient-listening call. | 3GPP TS 24.379 v14.5.0, Dongwook_Kim |
| g.3gpp.dynamic-e-stn-drvcc | This feature-capability indicator, when included in a Feature-Caps header field as specified in IETF in a SIP response to a SIP INVITE request, indicates support to transfer the session to the circuit switched (CS) domain using the Emergency Session Transfer Number for DRVCC digit string. | 3GPP TS 24.237, Dongwook_Kim |
| g.3gpp.ps2cs-srvcc-term-pre-alerting | This feature-capability indicator when used in a Feature-Caps header field of a SIP request or a SIP response indicates that: 1. the functional entity including the feature-capability indicator in the SIP message supports the PS to CS SRVCC for terminating calls in pre-alerting phase; and 2. all entities of which the functional entity including the feature-capability indicator in the SIP message is aware of being requested to support the feature do support the PS to CS SRVCC for terminating calls in pre-alerting phase. | 3GPP TS 24.237, Dongwook_Kim |
| g.3gpp.priority-share | When included in a Feature-Caps header field in SIP requests or SIP responses, the sender indicates that priority sharing is supported. | 3GPP TS 24.229 13.16.0, Dongwook_Kim |
| g.3gpp.thig-path | This feature-capability indicator when included in a Feature-Caps header field as specified in in a 200 (OK) response to the REGISTER request indicates that in a roaming scenario, the visited network IBCF supports topology hiding of a Path header field. | 3GPP TS 24.229 |
| g.3gpp.anbr | This feature-capability indicator, when included in a Feature-Caps header field as specified in in a 200 (OK) response to a REGISTER request, indicates that the network supports ANBR as specified in 3GPP TS 26.114. | 3GPP TS 24.229 |
| g.3gpp.in-call-access-update | This feature-capability indicator, when included in a Feature-Caps header field as specified in in a SIP INVITE request or a response to a SIP INVITE, indicates that the entity supports in-call access update procedure specified in 3GPP TS 24.229. The value of this feature capability indicator is a SIP URI to where the entity can be reached. | 3GPP TS 24.229 |
| g.3gpp.datachannel | This feature-capability indicator indicates the support of data channel capability in the network, and can be included in a Feature-Caps header field as specified in in a 200 (OK) response to the REGISTER request. | 3GPP TS 24.186 |
| g.3gpp.dc-mux | This feature-capability indicator indicates the support of IMS data channel multiplexing capability in the network, and can be included in a Feature-Caps header field as specified in in SIP request and response. | 3GPP TS 24.186 |

## 9. SIP Feature-Capability Indicator Registration Tree (`sip-parameters-72`)
- Total rows: `6`
- Registry reference(s): `rfc6809`
- Why it matters: Feature-Caps의 sip. indicator 값을 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| sip.607 | This feature-capability indicator, when included in a Feature-Caps header field of a REGISTER response, indicates that the server supports, and will process, the 607 (Unwanted) response code. | rfc8197 |
| sip.pns | This feature-capability indicator, when inserted in a Feature-Caps header field of a SIP REGISTER request or a SIP 2xx response to a REGISTER request, denotes that the entity associated with the indicator supports the SIP push mechanism and the type of push notification service conveyed by the indicator value. | rfc8599 |
| sip.vapid | This feature-capability indicator, when inserted in a SIP 2xx response to a SIP REGISTER request, denotes that the entity associated with the indicator supports the Voluntary Application Server Identification (VAPID) mechanism when the entity requests that a push notification be sent to a SIP UA. The indicator value is a public key identifying the entity, which can be used by a SIP UA to restrict subscriptions to that entity. | rfc8599 |
| sip.pnsreg | This feature-capability indicator, when inserted in a SIP 2xx response to a SIP REGISTER request, denotes that the entity associated with the indicator expects to receive binding-refresh REGISTER requests for the binding from the SIP UA associated with the binding before the binding expires, even if the entity does not request that a push notification be sent to the SIP UA in order to trigger the binding-refresh REGISTER requests. The indicator value conveys the minimum time (given in seconds) prior to the binding expiration when the UA MUST send the REGISTER request. | rfc8599 |
| sip.pnspurr | This feature-capability indicator, when inserted in a SIP 2xx response to a SIP REGISTER request, conveys that the entity associated with the indicator will store information that can be used to associate a mid-dialog SIP request with the binding information in the REGISTER request. The indicator value is an identifier that can be used as a key to retrieve the binding information. | rfc8599 |
| sip.608 | This feature-capability indicator, when included in a Feature-Caps header field of an INVITE request, indicates that the entity associated with the indicator will be responsible for indicating to the caller any information contained in the 608 SIP response code, specifically, the value referenced by the Call-Info header. | rfc8688 |

## 10. UUI Packages (`uui-packages`)
- Total rows: `1`
- Registry reference(s): `rfc7433`
- Why it matters: User-to-User header의 package namespace를 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| isdn-uui | The associated application is being used with constraints suitable for interworking with the ISDN User-to-User service, and therefore can be interworked at ISDN gateways. | rfc7434 |

## 11. UUI Content Parameters (`uui-content`)
- Total rows: `1`
- Registry reference(s): `rfc7433`
- Why it matters: User-to-User header의 content parameter 값을 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| isdn-uui | The associated contents conforms to the content associated with the ISDN User-to-User service. In the presence of the "purpose" header field parameter set to "isdn-uui" (or the absence of any "purpose" header field parameter) this is the default meaning and therefore need not be included in this case. | rfc7434 |

## 12. UUI Encoding Parameters (`uui-encoding`)
- Total rows: `1`
- Registry reference(s): `rfc7433`
- Why it matters: User-to-User header의 encoding parameter 값을 정의한다.

| Value | Description | Reference(s) |
| --- | --- | --- |
| hex | The UUI data is encoded using hexadecimal | rfc7433 |

## 공식 출처
- [IANA Session Initiation Protocol (SIP) Parameters](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml)
- [IANA XML export](https://www.iana.org/assignments/sip-parameters/sip-parameters.xml)
