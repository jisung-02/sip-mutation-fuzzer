# SIP 공격면 우선순위표

## 목적
대형 SIP/IANA 조사 문서를 바로 구현 계획으로 쓰기 어렵기 때문에, Phase 4 실험 시작 순서를 **단말 자극 효율** 기준으로 압축한다. 이번 표는 softphone-first Phase 4와 직접 연결되는 우선순위만 남긴다.

## Tier 1 — 즉시 실험할 surface
| 영역 | 이유 | 필요한 타깃 | 필요한 evidence |
| --- | --- | --- | --- |
| `INVITE` provisional/final response | dialog 형성, early/final 상태 전이가 크고 응답 분기 수가 많다 | softphone | socket response |
| `MESSAGE` success/error | non-dialog request/response 규칙이 단순해 baseline 검증에 좋다 | softphone | socket response |
| `REGISTER` 성공 응답 필드 | `Contact`, `Path`, `Service-Route` 같이 registrar state가 반영된다 | softphone 또는 registrar test double | socket response |
| `SUBSCRIBE` / `NOTIFY` / `PUBLISH` | event-state, body, expires, subscription-state 같은 상태성 필드가 집중된다 | programmable softphone 또는 test double | socket response |

현재 staged 코드가 이미 이 티어를 직접 보강하고 있다.
- `PUBLISH` 초기 body 기본값
- `Subscription-State`의 expires 제약
- `2xx to SUBSCRIBE`, `2xx to REGISTER`, `MESSAGE 2xx` 응답 규칙
- `INVITE` dialog-establishing response의 `To-tag` / `Contact` 제약

## Tier 2 — IMS/확장 상태 surface
| 영역 | 이유 | 필요한 타깃 | 비고 |
| --- | --- | --- | --- |
| `PRACK`, `UPDATE` | early dialog와 precondition 흐름을 더 깊게 자극 | softphone 또는 IMS-friendly peer | softphone baseline 안정화 후 |
| `INFO`, `INFO package`, `Recv-Info` | mid-dialog feature negotiation surface | programmable peer | event/debug 용도 큼 |
| `Security-*`, `WWW-Authenticate`, `Proxy-Authenticate` | IMS/AKA 및 security agreement와 연결 | IMS-friendly softphone 또는 real UE | softphone sanity 이후 |

## Tier 3 — IMS private / carrier-specific surface
| 영역 | 이유 | 필요한 타깃 |
| --- | --- | --- |
| `P-Asserted-Identity`, `P-Access-Network-Info`, `P-Charging-*` | 3GPP/IMS 특화 처리 경로 | real-ue/pcscf |
| `Feature-Caps`, `Resource-Priority` | capability / policy / namespace 처리 경로 | real-ue/pcscf 또는 controlled IMS peer |
| `Path`, `Service-Route`, routing extensions | registrar / proxy state 반영 | real-ue/pcscf |

## Tier 4 — parser robustness / byte damage
| 영역 | 이유 | 필요한 타깃 |
| --- | --- | --- |
| header 삭제/중복/순서 변경 | parser robustness | softphone 또는 test double |
| Content-Length mismatch | framing robustness | softphone 또는 test double |
| delimiter damage / byte truncation | low-level parser stress | softphone 또는 test double |

이 티어는 Mutator가 이미 만드는 wire/byte artifact를 `fuzzer send packet`으로 직접 흘릴 수 있을 때 본격적으로 실험한다.

## Softphone-first 실험 순서
1. `OPTIONS` / `MESSAGE` baseline 송신으로 send/receive 경로 안정화
2. `INVITE` provisional/final response 수집 검증
3. `SUBSCRIBE` / `NOTIFY` / `PUBLISH` 상태성 필드 실험
4. 그 다음 wire/byte mutation artifact 투입
5. 마지막으로 real-ue/pcscf, real-ue/direct에 같은 우선순위 체계를 재사용

## 이번 브랜치에서 바로 쓰는 acceptance focus
- sender/reactor가 Tier 1 baseline packet을 보낼 수 있어야 한다.
- outcome 분류가 provisional / success / error / timeout / invalid-response를 구분해야 한다.
- mutator wire output을 그대로 sender에 연결할 수 있어야 한다.
