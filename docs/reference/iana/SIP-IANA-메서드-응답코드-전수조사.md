# SIP IANA 메서드-응답코드 전수조사

기준 일자: 2026-03-18

## 1. 문서 목적
이 문서는 IANA SIP Parameters의 `Methods and Response Codes`와 `Response Codes` registry를 IANA inventory 관점에서 그대로 전수 정리한 문서다. 프로젝트용 설명 문서와 분리해서, method token과 response code surface 자체를 공식 registry 기준으로 1:1 대응시키는 데 목적이 있다.

## 2. 공식 기준
- IANA registry: `Session Initiation Protocol (SIP) Parameters`
- IANA page last updated: `2026-01-07`
- IANA XML source: `.omx/research/sip-iana-full-20260318/sip-parameters.xml`

## 3. 문서 범위
- `sip-parameters-6` `Methods and Response Codes`: `14` methods
- `sip-parameters-7` `Response Codes`: `75` response codes

## 4. Methods and Response Codes (`sip-parameters-6`)
- Registry reference(s): `rfc3261, rfc5727`
- Note: registry title은 `Methods and Response Codes`이지만, 실제 record는 현재 method token `14개`를 담는다.

| Method | Reference(s) |
| --- | --- |
| ACK | rfc3261 |
| BYE | rfc3261 |
| CANCEL | rfc3261 |
| INFO | rfc6086 |
| INVITE | rfc3261, rfc6026 |
| MESSAGE | rfc3428 |
| NOTIFY | rfc6665 |
| OPTIONS | rfc3261 |
| PRACK | rfc3262 |
| PUBLISH | rfc3903 |
| REFER | rfc3515 |
| REGISTER | rfc3261 |
| SUBSCRIBE | rfc6665 |
| UPDATE | rfc3311 |

## 5. Response Codes (`sip-parameters-7`)
- Registry reference(s): `rfc3261`
- Total rows: `75`

| Code | Reason Phrase | Class | Reference(s) |
| --- | --- | --- | --- |
| 100 | Trying | 1xx | rfc3261 |
| 180 | Ringing | 1xx | rfc3261 |
| 181 | Call Is Being Forwarded | 1xx | rfc3261 |
| 182 | Queued | 1xx | rfc3261 |
| 183 | Session Progress | 1xx | rfc3261 |
| 199 | Early Dialog Terminated | 1xx | rfc6228 |
| 200 | OK | 2xx | rfc3261 |
| 202 | Accepted (Deprecated) | 2xx | rfc6665 |
| 204 | No Notification | 2xx | rfc5839 |
| 300 | Multiple Choices | 3xx | rfc3261 |
| 301 | Moved Permanently | 3xx | rfc3261 |
| 302 | Moved Temporarily | 3xx | rfc3261 |
| 305 | Use Proxy | 3xx | rfc3261 |
| 380 | Alternative Service | 3xx | rfc3261 |
| 400 | Bad Request | 4xx | rfc3261 |
| 401 | Unauthorized | 4xx | rfc3261 |
| 402 | Payment Required | 4xx | rfc3261 |
| 403 | Forbidden | 4xx | rfc3261 |
| 404 | Not Found | 4xx | rfc3261 |
| 405 | Method Not Allowed | 4xx | rfc3261 |
| 406 | Not Acceptable | 4xx | rfc3261 |
| 407 | Proxy Authentication Required | 4xx | rfc3261 |
| 408 | Request Timeout | 4xx | rfc3261 |
| 410 | Gone | 4xx | rfc3261 |
| 412 | Conditional Request Failed | 4xx | rfc3903 |
| 413 | Request Entity Too Large | 4xx | rfc3261 |
| 414 | Request-URI Too Long | 4xx | rfc3261 |
| 415 | Unsupported Media Type | 4xx | rfc3261 |
| 416 | Unsupported URI Scheme | 4xx | rfc3261 |
| 417 | Unknown Resource-Priority | 4xx | rfc4412 |
| 420 | Bad Extension | 4xx | rfc3261 |
| 421 | Extension Required | 4xx | rfc3261 |
| 422 | Session Interval Too Small | 4xx | rfc4028 |
| 423 | Interval Too Brief | 4xx | rfc3261 |
| 424 | Bad Location Information | 4xx | rfc6442 |
| 425 | Bad Alert Message | 4xx | rfc8876 |
| 428 | Use Identity Header | 4xx | rfc8224 |
| 429 | Provide Referrer Identity | 4xx | rfc3892 |
| 430 | Flow Failed | 4xx | rfc5626 |
| 433 | Anonymity Disallowed | 4xx | rfc5079 |
| 436 | Bad Identity Info | 4xx | rfc8224 |
| 437 | Unsupported Credential | 4xx | rfc8224 |
| 438 | Invalid Identity Header | 4xx | rfc8224 |
| 439 | First Hop Lacks Outbound Support | 4xx | rfc5626 |
| 440 | Max-Breadth Exceeded | 4xx | rfc5393 |
| 469 | Bad Info Package | 4xx | rfc6086 |
| 470 | Consent Needed | 4xx | rfc5360 |
| 480 | Temporarily Unavailable | 4xx | rfc3261 |
| 481 | Call/Transaction Does Not Exist | 4xx | rfc3261 |
| 482 | Loop Detected | 4xx | rfc3261 |
| 483 | Too Many Hops | 4xx | rfc3261 |
| 484 | Address Incomplete | 4xx | rfc3261 |
| 485 | Ambiguous | 4xx | rfc3261 |
| 486 | Busy Here | 4xx | rfc3261 |
| 487 | Request Terminated | 4xx | rfc3261 |
| 488 | Not Acceptable Here | 4xx | rfc3261 |
| 489 | Bad Event | 4xx | rfc6665 |
| 491 | Request Pending | 4xx | rfc3261 |
| 493 | Undecipherable | 4xx | rfc3261 |
| 494 | Security Agreement Required | 4xx | rfc3329 |
| 500 | Server Internal Error | 5xx | rfc3261 |
| 501 | Not Implemented | 5xx | rfc3261 |
| 502 | Bad Gateway | 5xx | rfc3261 |
| 503 | Service Unavailable | 5xx | rfc3261 |
| 504 | Server Time-out | 5xx | rfc3261 |
| 505 | Version Not Supported | 5xx | rfc3261 |
| 513 | Message Too Large | 5xx | rfc3261 |
| 555 | Push Notification Service Not Supported | 5xx | rfc8599 |
| 580 | Precondition Failure | 5xx | rfc3312 |
| 600 | Busy Everywhere | 6xx | rfc3261 |
| 603 | Decline | 6xx | rfc3261 |
| 604 | Does Not Exist Anywhere | 6xx | rfc3261 |
| 606 | Not Acceptable | 6xx | rfc3261 |
| 607 | Unwanted | 6xx | rfc8197 |
| 608 | Rejected | 6xx | rfc8688 |

## 6. Response Class Summary
| Class | Count |
| --- | --- |
| 1xx | 6 |
| 2xx | 3 |
| 3xx | 5 |
| 4xx | 46 |
| 5xx | 9 |
| 6xx | 6 |

## 공식 출처
- [IANA Session Initiation Protocol (SIP) Parameters](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml)
- [IANA XML export](https://www.iana.org/assignments/sip-parameters/sip-parameters.xml)
