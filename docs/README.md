# 문서 인덱스

## 핵심 문서

| 문서 | 설명 |
|------|------|
| [`AI_AGENT_GUIDE.md`](AI_AGENT_GUIDE.md) | AI/에이전트용 온보딩, 우선순위, skill 추천, mutation profile 축 해설 |
| [`AI_AGENT_GUIDE_EXPLAINED.md`](AI_AGENT_GUIDE_EXPLAINED.md) | 위 AI 가이드를 사람이 읽기 쉽게 풀어쓴 설명 문서 |
| [`프로젝트-개요.md`](프로젝트-개요.md) | 프로젝트 소개, 아키텍처, 모듈 요약, CLI, 개발 환경 |
| [`구현-문서.md`](구현-문서.md) | 모듈별 설계 배경, 동작 방식, 코드 구조 상세 |
| [`퍼징-캠페인-명령셋.md`](퍼징-캠페인-명령셋.md) | 현재 honest runtime 기준으로 바로 복붙해 돌릴 수 있는 실기기 우선 캠페인 명령 모음 |
| [`프로토콜/SIP-메시지-완성도-매트릭스.md`](프로토콜/SIP-메시지-완성도-매트릭스.md) | `runtime_complete` / `generator_complete`, `runtime_path`, `baseline_scope`를 함께 읽는 현재 SIP packet completeness 기준 |
| [`Fuzzer.md`](Fuzzer.md) | 퍼저 이론, SIP 프로토콜 퍼저 고려사항, 공격면 분류 (그룹 A~K) |
| [`발전-로드맵.md`](발전-로드맵.md) | Phase 완료 현황, 미해결 의사결정, 단기/장기 로드맵 |

## 디렉터리별 문서

### `기획/` — 범위, 요구사항, 설계 문서

| 문서 | 설명 |
|------|------|
| [`기획/PRD.md`](기획/PRD.md) | 프로젝트 목표, 범위, 기능/비기능 요구사항, 단계별 완료 기준 |
| [`기획/GENERATOR_PRD.md`](기획/GENERATOR_PRD.md) | Generator 책임, 공개 API, 생성 흐름, CLI 경계 |
| [`기획/MUTATOR_PRD.md`](기획/MUTATOR_PRD.md) | Mutator model/wire/byte 변조 구조, CLI 모드, 구현 우선순위 |
| [`기획/PHASE4_PRD.md`](기획/PHASE4_PRD.md) | historical softphone-first Sender/Reactor 1차 범위 문서. 현재 운영 우선순위는 real-ue-direct 기준 |
| [`기획/REAL_UE_DIRECT_PRD.md`](기획/REAL_UE_DIRECT_PRD.md) | real-ue-direct resolver 순서, route readiness, CLI 규칙 |

### `결과/` — 구현 결과, 리서치

| 문서 | 설명 |
|------|------|
| [`결과/GENERATOR-구현-결과.md`](결과/GENERATOR-구현-결과.md) | Generator 구현 상태, CLI 엔트리포인트, 검증 결과 |
| [`결과/PHASE4-SENDER-REACTOR-리서치.md`](결과/PHASE4-SENDER-REACTOR-리서치.md) | Phase 4 Sender/Reactor 구현 경로 비교 리서치 |
| [`결과/PHASE4-REAL-UE-SOFTPHONE-후속-리서치.md`](결과/PHASE4-REAL-UE-SOFTPHONE-후속-리서치.md) | historical 비교 리서치. 현재 기본 운용 모드는 real-ue-direct |
| [`결과/SIP-공격면-우선순위표.md`](결과/SIP-공격면-우선순위표.md) | 공격면 우선순위 정리. 일부 softphone-first 맥락은 역사적 참고용 |

### `프로토콜/` — SIP 프로토콜 참조 자료

| 문서 | 설명 |
|------|------|
| [`SIP-프로토콜-연구-종합.md`](SIP-프로토콜-연구-종합.md) | IANA 전수조사 결과 종합 (헤더 134개, 파라미터 201개, 옵션 태그 36개 등) |
| [`프로토콜/단말-기준-SIP-메시지-분류.md`](프로토콜/단말-기준-SIP-메시지-분류.md) | 단말 기준 SIP Request/Response 분류 |
| [`프로토콜/SIP-요청-응답-패킷-필드-비교-매트릭스.md`](프로토콜/SIP-요청-응답-패킷-필드-비교-매트릭스.md) | 요청 14개 × 응답 75개 × 필드 69개 비교 매트릭스 |
| [`프로토콜/SIP-요청-응답-오피셜-필드-리서치.md`](프로토콜/SIP-요청-응답-오피셜-필드-리서치.md) | IANA/RFC 기준 필수/선택/조건부 필드 정리 |
| [`프로토콜/SIP-메시지-완성도-매트릭스.md`](프로토콜/SIP-메시지-완성도-매트릭스.md) | SIP request method별 runtime/generator 완성도와 baseline scope 매트릭스 |
| [`프로토콜/요청-패킷-예시.md`](프로토콜/요청-패킷-예시.md) | 요청 메시지별 대표 SIP 패킷 예시 |
| [`프로토콜/응답-패킷-예시.md`](프로토콜/응답-패킷-예시.md) | 응답 코드별 대표 SIP 패킷 예시 |
| IANA 전수조사 9건 | `SIP-IANA-전체-필드-전수조사.md` 외 8건 — 헤더, 파라미터, URI, 옵션 태그, 값 레지스트리, 기능 식별자, 리소스 우선순위, 기타 |

### `이슈/` — 미결정 사항

| 문서 | 설명 |
|------|------|
| [`이슈/오픈-이슈.md`](이슈/오픈-이슈.md) | ISSUE-01~05 추적 (결정/미정 상태 관리) |
| [`이슈/2026-04-21-srsenb-일부-단말-attach-불안정-정리.md`](이슈/2026-04-21-srsenb-일부-단말-attach-불안정-정리.md) | `srsENB + B210` 환경에서 일부 UE가 간헐적으로 camp/attach에 실패할 때의 원인 후보, RF/EPC 구분 기준, 1차 점검 순서 |

## 문서 갱신 규칙

- 요청/응답 패킷 예시 문서는 `scripts/generate_packet_docs.py` 로 생성
- 이슈가 해결되면 오픈-이슈.md에서 상태를 갱신하고 관련 문서에도 반영
- 결과 문서는 구현 완료 시점의 명령어, 검증 결과, 후속 TODO를 함께 기록
