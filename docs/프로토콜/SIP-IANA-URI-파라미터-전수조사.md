# SIP/SIPS URI Parameters 전수조사

기준 일자: 2026-03-18

## 1. 문서 목적
이 문서는 IANA SIP Parameters Registry의 `SIP/SIPS URI Parameters` 레지스트리를 기준으로, 현재 등록된 `35개` URI parameter token을 전수 정리한 문서다.

## 2. 공식 기준
- IANA XML source: `.omx/research/sip-iana-full-20260318/sip-parameters.xml`
- Local extraction: `.omx/research/sip-iana-full-20260318/sip-sips-uri-parameters-detailed.json`

## 3. Registry Snapshot
- Registry title: `SIP/SIPS URI Parameters`
- Total rows: `35`

## 4. URI Parameter Inventory
| URI Parameter | Predefined | Reference(s) | Short Meaning | Grouping |
| --- | --- | --- | --- | --- |
| `aai` | `No` | `rfc5552` | Application-specific identifier/marker. | service-specific |
| `bnc` | `No` | `rfc6140` | Flow/connection marker token. | routing / outbound |
| `cause` | `Yes` | `rfc4458, rfc8119` | Cause or reason indicator. | signaling / service-specific |
| `ccxml` | `No` | `rfc5552` | CCXML-related service parameter. | service-specific |
| `comp` | `Yes` | `rfc3486` | Compression handling indicator. | transport / compression |
| `content-type` | `No` | `rfc4240` | Content type indicator embedded in URI semantics. | message-body / service-specific |
| `delay` | `No` | `rfc4240` | Delay or timing control value. | media / service-specific |
| `duration` | `No` | `rfc4240` | Duration or playback length value. | media / service-specific |
| `extension` | `No` | `rfc4240` | Generic extension marker/value. | generic / extension |
| `gr` | `No` | `rfc5627` | GRUU-related instance marker. | GRUU |
| `iotl` | `Yes` | `rfc7549` | IoT/location-related token. | service-specific |
| `locale` | `No` | `rfc4240` | Locale / language-region hint. | service-specific |
| `lr` | `No` | `rfc3261` | Loose routing flag. | routing |
| `m` | `Yes` | `rfc6910` | Message / method-related short token. | service-specific |
| `maddr` | `No` | `rfc3261` | Multicast / message destination address. | routing / transport |
| `maxage` | `No` | `rfc5552` | Maximum age constraint. | caching / service-specific |
| `maxstale` | `No` | `rfc5552` | Maximum staleness constraint. | caching / service-specific |
| `method` | `"get" / "post"` | `rfc5552` | Method selector. | routing / request handling |
| `method` | `Yes` | `rfc3261` | Method selector. | routing / request handling |
| `ob` | `No` | `rfc5626` | Outbound marker. | routing / outbound |
| `param[n]` | `No` | `rfc4240` | Numbered generic parameter slot. | generic / extension |
| `play` | `No` | `rfc4240` | Playback control indicator. | media / service-specific |
| `pn-param` | `No` | `rfc8599` | Push notification parameter payload. | push |
| `pn-prid` | `No` | `rfc8599` | Push registration identifier. | push |
| `pn-provider` | `No` | `rfc8599` | Push provider identifier. | push |
| `pn-purr` | `No` | `rfc8599` | Push-related routing/registration token. | push |
| `postbody` | `No` | `rfc5552` | POST-body indicator/content hook. | service-specific |
| `repeat` | `No` | `rfc4240` | Repeat / replay count or flag. | media / service-specific |
| `sg` | `No` | `rfc6140` | Service/group marker token. | service-specific |
| `sigcomp-id` | `No` | `rfc5049` | SigComp identifier. | transport / compression |
| `target` | `No` | `rfc4458` | Explicit target designator. | routing |
| `transport` | `Yes` | `rfc3261, rfc7118` | Transport protocol selector. | transport |
| `ttl` | `No` | `rfc3261` | Time-to-live value. | transport / routing |
| `user` | `Yes` | `rfc3261, rfc4967` | User-part interpretation selector. | user-identification |
| `voicexml` | `No` | `rfc4240` | VoiceXML-related service parameter. | service-specific |

## 5. 읽는 법
- 이 registry는 헤더가 아니라 `sip:` / `sips:` URI 자체에 붙는 parameter를 다룬다.
- 즉 `Request-URI`, `Route`, `Contact`, `Refer-To` 같은 URI-bearing field를 해석할 때 중요하다.

## 6. 공식 출처
- [IANA Session Initiation Protocol (SIP) Parameters](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml)
- [IANA XML export](https://www.iana.org/assignments/sip-parameters/sip-parameters.xml)
