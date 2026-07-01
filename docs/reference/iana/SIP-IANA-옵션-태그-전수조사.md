# SIP Option Tags 전수조사

기준 일자: 2026-03-18

## 1. 문서 목적
이 문서는 IANA SIP Parameters Registry의 `Option Tags` 레지스트리를 기준으로, 현재 등록된 `36개` option tag를 전수 정리한 문서다.

## 2. 공식 기준
- IANA XML source: `.omx/research/sip-iana-full-20260318/sip-parameters.xml`
- Local extraction: `.omx/research/sip-iana-full-20260318/option-tags-detailed.json`

## 3. Registry Snapshot
- Registry title: `Option Tags`
- Total rows: `36`

## 4. Option Tag Inventory
| Option Tag | Description | Reference(s) | Category |
| --- | --- | --- | --- |
| `100rel` | This option tag is for reliability of provisional responses. When present in a Supported header, it indicates that the UA can send or receive reliable provisional responses. When present in a Require header in a request it indicates that the UAS MUST send all provisional responses reliably. When present in a Require header in a reliable provisional response, it indicates that the response is to be sent reliably. | `rfc3262` | Provisional response reliability |
| `199` | This option-tag is for indicating support of the 199 Early Dialog Terminated provisional response code. When present in a Supported header of a request, it indicates that the UAC supports the 199 response code. When present in a Require or Proxy-Require header field of a request, it indicates that the UAS, or proxies, MUST support the 199 response code. It does not require the UAS, or proxies, to actually send 199 responses. | `rfc6228` | Provisional response signaling |
| `answermode` | This option tag is for support of the Answer-Mode and Priv-Answer-Mode extensions used to negotiate automatic or manual answering of a request. | `rfc5373` | Call handling |
| `early-session` | A UA adding the early-session option tag to a message indicates that it understands the early-session content disposition. | `rfc3959` | Early media/session |
| `eventlist` | Extension to allow subscriptions to lists of resources | `rfc4662` | Event subscription |
| `explicitsub` | This option tag identifies an extension to REFER to suppress the implicit subscription and provide a URI for an explicit subscription. | `rfc7614` | REFER/subscription control |
| `from-change` | This option tag is used to indicate that a UA supports changes to URIs in From and To header fields during a dialog. | `rfc4916` | Identity/dialog update |
| `geolocation-http` | The "geolocation-http" option tag signals support for acquiring location information via an HTTP . A location recipient who supports this option can request location with an HTTP GET and parse a resulting 200 response containing a PIDF-LO object. The URI schemes supported by this option include "http" and "https". | `rfc6442` | Geolocation |
| `geolocation-sip` | The "geolocation-sip" option tag signals support for acquiring location information via the presence event package of SIP . A location recipient who supports this option can send a SUBSCRIBE request and parse a resulting NOTIFY containing a PIDF-LO object. The URI schemes supported by this option include "sip", "sips", and "pres". | `rfc6442` | Geolocation |
| `gin` | This option tag is used to identify the extension that provides Registration for Multiple Phone Numbers in SIP. When present in a Require or Proxy-Require header field of a REGISTER request, it indicates that support for this extension is required of registrars and proxies, respectively, that are a party to the registration transaction. | `rfc6140` | Registration |
| `gruu` | This option tag is used to identify the Globally Routable User Agent URI (GRUU) extension. When used in a Supported header, it indicates that a User Agent understands the extension. When used in a Require header field of a REGISTER request, it indicates that the registrar is not expected to process the registration unless it supports the GRUU extension. | `rfc5627` | Registration/routing |
| `histinfo` | When used with the Supported header field, this option tag indicates the UAC supports the History Information to be captured for requests and returned in subsequent responses. This tag is not used in a Proxy-Require or Require header field, since support of History-Info is optional. | `rfc7044` | Request history |
| `ice` | This option tag is used to identify the Interactive Connectivity Establishment (ICE) extension. When present in a Require header field, it indicates that ICE is required by an agent. | `rfc5768` | NAT traversal/media |
| `join` | Support for the SIP Join Header | `rfc3911` | Dialog control |
| `multiple-refer` | This option tag indicates support for REFER requests that contain a resource list document describing multiple REFER targets. | `rfc5368` | REFER/resource lists |
| `norefersub` | This option tag specifies a User Agent ability of accepting a REFER request without establishing an implicit subscription (compared to the default case defined in . | `rfc4488` | REFER/subscription control |
| `nosub` | This option tag identifies an extension to REFER to suppress the implicit subscription and indicate that no explicit subscription is forthcoming. | `rfc7614` | REFER/subscription control |
| `outbound` | This option-tag is used to identify UAs and Registrars which support extensions for Client Initiated Connections. A UA places this option in a Supported header to communicate its support for this extension. A Registrar places this option-tag in a Require header to indicate to the registering User Agent that the Registrar used registrations using the binding rules defined in this extension. | `rfc5626` | Registration/connectivity |
| `path` | A SIP UA that supports the Path extension header field includes this option tag as a header field value in a Supported header field in all requests generated by that UA. Intermediate proxies may use the presence of this option tag in a REGISTER request to determine whether to offer Path service for for that request. If an intermediate proxy requires that the registrar support Path for a request, then it includes this option tag as a header field value in a Requires header field in that request. | `rfc3327` | Registration/routing |
| `policy` | This option tag is used to indicate that a UA can process policy server URIs for and subscribe to session-specific policies. | `rfc6794` | Policy control |
| `precondition` | An offerer MUST include this tag in the Require header field if the offer contains one or more "mandatory" strength-tags. If all the strength-tags in the description are "optional" or "none" the offerer MUST include this tag either in a Supported header field or in a Require header field. | `rfc3312` | Session preconditions |
| `pref` | This option tag is used to ensure that a server understands the callee capabilities parameters used in the request. | `rfc3840` | Caller preferences |
| `privacy` | This option tag indicates support for the Privacy mechanism. When used in the Proxy-Require header, it indicates that proxy servers do not forward the request unless they can provide the requested privacy service. This tag is not used in the Require or Supported headers. Proxies remove this option tag before forwarding the request if the desired privacy function has been performed. | `rfc3323` | Privacy |
| `recipient-list-invite` | The body contains a list of URIs that indicates the recipients of the SIP INVITE request | `rfc5366` | Recipient lists |
| `recipient-list-message` | The body contains a list of URIs that indicates the recipients of the SIP MESSAGE request | `rfc5365` | Recipient lists |
| `recipient-list-subscribe` | This option tag is used to ensure that a server can process the recipient-list body used in a SUBSCRIBE request. | `rfc5367` | Recipient lists |
| `record-aware` | This option tag is to indicate the ability of the UA to receive recording indicators in media-level or session-level SDP. When present in a Supported header, it indicates that the UA can receive recording indicators in media-level or session-level SDP. | `rfc7866` | Recording awareness |
| `replaces` | This option tag indicates support for the SIP Replaces header. | `rfc3891` | Dialog control |
| `resource-priority` | Indicates or requests support for the resource priority mechanism. | `rfc4412` | Priority/resource control |
| `sdp-anat` | The option-tag sdp-anat is defined for use in the Require and Supported SIP header fields. SIP user agents that place this option-tag in a Supported header field understand the ANAT semantics as defined in . | `rfc4092` | SDP/media negotiation |
| `sec-agree` | This option tag indicates support for the Security Agreement mechanism. When used in the Require, or Proxy-Require headers, it indicates that proxy servers are required to use the Security Agreement mechanism. When used in the Supported header, it indicates that the User Agent Client supports the Security Agreement mechanism. When used in the Require header in the 494 (Security Agreement Required) or 421 (Extension Required) responses, it indicates that the User Agent Client must use the Security Agreement Mechanism. | `rfc3329` | Security |
| `siprec` | This option tag is for identifying that the SIP session is for the purpose of an RS. This is typically not used in a Supported header. When present in a Require header in a request, it indicates that the UA is either an SRC or SRS capable of handling a recording session. | `rfc7866` | Session recording |
| `tdialog` | This option tag is used to identify the target dialog header field extension. When used in a Require header field, it implies that the recipient needs to support the Target-Dialog header field. When used in a Supported header field, it implies that the sender of the message supports it. | `rfc4538` | Dialog targeting |
| `timer` | This option tag is for support of the session timer extension. Inclusion in a Supported header field in a request or response indicates that the UA is capable of performing refreshes according to that specification. Inclusion in a Require header in a request means that the UAS must understand the session timer extension to process the request. Inclusion in a Require header field in a response indicates that the UAC must look for the Session-Expires header field in the response, and process accordingly. | `rfc4028` | Session maintenance |
| `trickle-ice` | This option tag is used to indicate that a UA supports and understands Trickle ICE. | `rfc8840` | NAT traversal/media |
| `uui` | This option tag is used to indicate that a UA supports and understands the User-to-User header field. | `rfc7433` | User information |

## 5. 읽는 법
- option tag는 주로 `Supported`, `Require`, `Proxy-Require`, 일부 response의 `Unsupported` 등에서 의미를 갖는다.
- 즉 헤더 이름이 아니라 SIP capability/extension negotiation surface다.

## 6. 공식 출처
- [IANA Session Initiation Protocol (SIP) Parameters](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml)
- [IANA XML export](https://www.iana.org/assignments/sip-parameters/sip-parameters.xml)
