# SIP IANA 기타 레지스트리 Survey

기준 일자: 2026-03-18

## 1. 문서 목적
이 문서는 IANA SIP Parameters 전체 registry가 현재 어떤 전수 문서로 커버되는지 보여주는 coverage matrix다. 이제 survey는 단순 overview가 아니라, 누락 여부를 확인하는 인덱스 역할을 한다.

## 2. 공식 기준
- IANA registry: `Session Initiation Protocol (SIP) Parameters`
- IANA page last updated: `2026-01-07`
- IANA XML source: `.omx/research/sip-iana-full-20260318/sip-parameters.xml`

## 3. Coverage Matrix
| Registry ID | Exact registry title | Count | Covered by |
| --- | --- | ---: | --- |
| `sip-parameters-2` | `Header Fields` | `134` | [`SIP-IANA-전체-필드-전수조사.md`](SIP-IANA-전체-필드-전수조사.md) |
| `sip-parameters-3` | `Reason Protocols` | `22` | [`SIP-IANA-값-레지스트리-전수조사.md`](SIP-IANA-값-레지스트리-전수조사.md) |
| `sip-parameters-4` | `Option Tags` | `36` | [`SIP-IANA-옵션-태그-전수조사.md`](SIP-IANA-옵션-태그-전수조사.md) |
| `sip-parameters-5` | `Warning Codes (warn-codes)` | `15` | [`SIP-IANA-값-레지스트리-전수조사.md`](SIP-IANA-값-레지스트리-전수조사.md) |
| `sip-parameters-6` | `Methods and Response Codes` | `14` | [`SIP-IANA-메서드-응답코드-전수조사.md`](SIP-IANA-메서드-응답코드-전수조사.md) |
| `sip-parameters-7` | `Response Codes` | `75` | [`SIP-IANA-메서드-응답코드-전수조사.md`](SIP-IANA-메서드-응답코드-전수조사.md) |
| `sip-parameters-8` | `SIP Privacy Header Field Values` | `7` | [`SIP-IANA-값-레지스트리-전수조사.md`](SIP-IANA-값-레지스트리-전수조사.md) |
| `sip-parameters-9` | `Security Mechanism Names` | `5` | [`SIP-IANA-값-레지스트리-전수조사.md`](SIP-IANA-값-레지스트리-전수조사.md) |
| `sip-parameters-10` | `Compression Schemes` | `1` | [`SIP-IANA-값-레지스트리-전수조사.md`](SIP-IANA-값-레지스트리-전수조사.md) |
| `sip-parameters-11` | `SIP/SIPS URI Parameters` | `35` | [`SIP-IANA-URI-파라미터-전수조사.md`](SIP-IANA-URI-파라미터-전수조사.md) |
| `sip-parameters-12` | `Header Field Parameters and Parameter Values` | `201` | [`SIP-IANA-헤더-필드-파라미터-전수조사.md`](SIP-IANA-헤더-필드-파라미터-전수조사.md) |
| `sip-parameters-13` | `URI Purposes` | `7` | [`SIP-IANA-값-레지스트리-전수조사.md`](SIP-IANA-값-레지스트리-전수조사.md) |
| `sip-parameters-14` | `Resource-Priority Namespaces` | `48` | [`SIP-IANA-리소스-우선순위-전수조사.md`](SIP-IANA-리소스-우선순위-전수조사.md) |
| `sip-parameters-15` | `Resource-Priority Priority-values` | `48 child registries / 463 rows` | [`SIP-IANA-리소스-우선순위-전수조사.md`](SIP-IANA-리소스-우선순위-전수조사.md) |
| `sip-parameters-61` | `Identity Parameters` | `2` | [`SIP-IANA-기능-식별자-전수조사.md`](SIP-IANA-기능-식별자-전수조사.md) |
| `sip-parameters-62` | `Identity-Info Algorithm Parameter Values` | `2` | [`SIP-IANA-기능-식별자-전수조사.md`](SIP-IANA-기능-식별자-전수조사.md) |
| `sip-parameters-64` | `SIP Forum User Agent Configuration Parameters` | `5` | [`SIP-IANA-기능-식별자-전수조사.md`](SIP-IANA-기능-식별자-전수조사.md) |
| `sip-parameters-65` | `Service-ID/Application-ID Labels` | `2` | [`SIP-IANA-기능-식별자-전수조사.md`](SIP-IANA-기능-식별자-전수조사.md) |
| `sip-parameters-66` | `Info Packages Registry` | `13` | [`SIP-IANA-기능-식별자-전수조사.md`](SIP-IANA-기능-식별자-전수조사.md) |
| `sip-parameters-67` | `SIP Configuration Profile Types` | `3` | [`SIP-IANA-기능-식별자-전수조사.md`](SIP-IANA-기능-식별자-전수조사.md) |
| `sip-parameters-68` | `Geolocation-Error Codes` | `5` | [`SIP-IANA-값-레지스트리-전수조사.md`](SIP-IANA-값-레지스트리-전수조사.md) |
| `sip-parameters-69` | `Reason Codes` | `8` | [`SIP-IANA-값-레지스트리-전수조사.md`](SIP-IANA-값-레지스트리-전수조사.md) |
| `sip-parameters-70` | `Proxy-Feature Feature-Capability Indicator Trees` | `2` | [`SIP-IANA-기능-식별자-전수조사.md`](SIP-IANA-기능-식별자-전수조사.md) |
| `sip-parameters-71` | `Global Feature-Capability Indicator Registration Tree` | `33` | [`SIP-IANA-기능-식별자-전수조사.md`](SIP-IANA-기능-식별자-전수조사.md) |
| `sip-parameters-72` | `SIP Feature-Capability Indicator Registration Tree` | `6` | [`SIP-IANA-기능-식별자-전수조사.md`](SIP-IANA-기능-식별자-전수조사.md) |
| `sip-parameters-73` | `Priority Header Field Values` | `5` | [`SIP-IANA-값-레지스트리-전수조사.md`](SIP-IANA-값-레지스트리-전수조사.md) |
| `sip-transport` | `SIP Transport` | `7` | [`SIP-IANA-값-레지스트리-전수조사.md`](SIP-IANA-값-레지스트리-전수조사.md) |
| `uui-packages` | `UUI Packages` | `1` | [`SIP-IANA-기능-식별자-전수조사.md`](SIP-IANA-기능-식별자-전수조사.md) |
| `uui-content` | `UUI Content Parameters` | `1` | [`SIP-IANA-기능-식별자-전수조사.md`](SIP-IANA-기능-식별자-전수조사.md) |
| `uui-encoding` | `UUI Encoding Parameters` | `1` | [`SIP-IANA-기능-식별자-전수조사.md`](SIP-IANA-기능-식별자-전수조사.md) |
| `sip-pns` | `Push Notification Service (PNS)` | `3` | [`SIP-IANA-값-레지스트리-전수조사.md`](SIP-IANA-값-레지스트리-전수조사.md) |
| `sip-alertmsg-error-codes` | `SIP AlertMsg-Error Codes` | `4` | [`SIP-IANA-값-레지스트리-전수조사.md`](SIP-IANA-값-레지스트리-전수조사.md) |

## 4. 읽는 법
- 이 문서는 registry 자체를 설명하는 본문보다, `무엇이 어디에 문서화됐는지`를 보여주는 인덱스다.
- `sip-parameters-15`는 top-level row는 0개지만 child registry 48개와 total 463 priority-value row를 별도 문서에서 다룬다.
- Methods / Response Codes도 이제 [`SIP-IANA-메서드-응답코드-전수조사.md`](SIP-IANA-메서드-응답코드-전수조사.md)에서 IANA inventory 기준으로 별도 정리했다. UE 관점 필드 의미 설명은 [`SIP-요청-응답-오피셜-필드-리서치.md`](SIP-요청-응답-오피셜-필드-리서치.md)를 같이 본다.

## 공식 출처
- [IANA Session Initiation Protocol (SIP) Parameters](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml)
- [IANA XML export](https://www.iana.org/assignments/sip-parameters/sip-parameters.xml)
