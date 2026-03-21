# 문서 인덱스

이 디렉터리는 프로젝트 문서를 성격별로 정리한 공간이다.

## 디렉터리 규칙
- `기획/`: 범위, 요구사항, 완료 기준 같은 상위 기획 문서
- `결과/`: 구현 결과, 검증 로그, 단계별 산출물 요약
- `프로토콜/`: SIP 분류, 패킷 예시, RFC 기반 참조 문서
- `이슈/`: 아직 결정되지 않았거나 추적이 필요한 쟁점

## 현재 문서
| 분류 | 문서 | 설명 |
| --- | --- | --- |
| 기획 | [`기획/PRD.md`](기획/PRD.md) | 프로젝트 목표, 범위, 기능/비기능 요구사항, 단계별 완료 기준 |
| 기획 | [`기획/GENERATOR_PRD.md`](기획/GENERATOR_PRD.md) | Generator의 책임, 공개 API, 내부 생성 흐름, CLI 경계를 정의한 상세 설계 문서 |
| 기획 | [`기획/MUTATOR_PRD.md`](기획/MUTATOR_PRD.md) | Mutator의 책임, model/wire/byte 기반 변조 구조, Typer CLI 2가지 입력 모드, 사용자 노출 옵션 정책, 초기 구현 우선순위를 정의한 상세 설계 문서 |
| 기획 | [`기획/PHASE4_PRD.md`](기획/PHASE4_PRD.md) | softphone-first Sender/Reactor의 1차 범위, capstone reference mapping, 공개 인터페이스, CLI 표면을 정의한 Phase 4 설계 문서 |
| 기획 | [`기획/REAL_UE_DIRECT_PRD.md`](기획/REAL_UE_DIRECT_PRD.md) | capstone dumpipe 경로를 현재 sender에 이식하는 real-ue-direct 1차 범위, resolver 순서, route readiness 정책, 공개 CLI 규칙을 고정한 상세 설계 문서 |
| 결과 | [`결과/GENERATOR-구현-결과.md`](결과/GENERATOR-구현-결과.md) | Generator 구현 상태, CLI 엔트리포인트 변경, 검증 결과 요약 |
| 결과 | [`결과/PHASE4-SENDER-REACTOR-리서치.md`](결과/PHASE4-SENDER-REACTOR-리서치.md) | 현재 코드베이스, 이전 연구실 Kamailio/Open5GS 실험 자산, 공식 문서를 바탕으로 Phase 4 Sender/Reactor의 가능한 구현 경로를 비교한 사전 리서치 문서 |
| 결과 | [`결과/PHASE4-REAL-UE-SOFTPHONE-후속-리서치.md`](결과/PHASE4-REAL-UE-SOFTPHONE-후속-리서치.md) | SDR/USRP 기반 실제 UE 경로와 softphone 경로를 별도로 깊게 조사하고, Linphone/Baresip/PJSIP 후보를 비교한 후속 리서치 문서 |
| 결과 | [`결과/SIP-공격면-우선순위표.md`](결과/SIP-공격면-우선순위표.md) | staged SIP 조사 자산을 Tier 1~4 공격면으로 압축해 Softphone-first Phase 4 실행 순서를 정리한 문서 |
| 프로토콜 | [`프로토콜/SIP-IANA-전체-필드-전수조사.md`](프로토콜/SIP-IANA-전체-필드-전수조사.md) | IANA SIP Header Fields 134개 전체와 관련 registry를 공식 registry 기준으로 전수 inventory한 대형 조사 문서 |
| 프로토콜 | [`프로토콜/SIP-IANA-헤더-필드-파라미터-전수조사.md`](프로토콜/SIP-IANA-헤더-필드-파라미터-전수조사.md) | IANA `Header Field Parameters and Parameter Values` 201개를 header별로 전수 inventory한 조사 문서 |
| 프로토콜 | [`프로토콜/SIP-IANA-URI-파라미터-전수조사.md`](프로토콜/SIP-IANA-URI-파라미터-전수조사.md) | IANA `SIP/SIPS URI Parameters` 35개를 전수 inventory한 조사 문서 |
| 프로토콜 | [`프로토콜/SIP-IANA-옵션-태그-전수조사.md`](프로토콜/SIP-IANA-옵션-태그-전수조사.md) | IANA `Option Tags` 36개를 전수 inventory한 조사 문서 |
| 프로토콜 | [`프로토콜/SIP-IANA-메서드-응답코드-전수조사.md`](프로토콜/SIP-IANA-메서드-응답코드-전수조사.md) | IANA `Methods and Response Codes` 14개와 `Response Codes` 75개를 registry 기준으로 전수 inventory한 조사 문서 |
| 프로토콜 | [`프로토콜/SIP-IANA-값-레지스트리-전수조사.md`](프로토콜/SIP-IANA-값-레지스트리-전수조사.md) | Warning/Privacy/Priority/Transport/PNS 같은 값 중심 SIP IANA registry를 전수 inventory한 조사 문서 |
| 프로토콜 | [`프로토콜/SIP-IANA-기능-식별자-전수조사.md`](프로토콜/SIP-IANA-기능-식별자-전수조사.md) | Identity, Feature-Caps, Info-Package, UUI 같은 구조화된 식별자 registry를 전수 inventory한 조사 문서 |
| 프로토콜 | [`프로토콜/SIP-IANA-리소스-우선순위-전수조사.md`](프로토콜/SIP-IANA-리소스-우선순위-전수조사.md) | Resource-Priority namespace 48개와 child priority-value registry 48개, 총 463개 값을 전수 inventory한 조사 문서 |
| 프로토콜 | [`프로토콜/SIP-IANA-기타-레지스트리-survey.md`](프로토콜/SIP-IANA-기타-레지스트리-survey.md) | SIP IANA 전체 registry가 어떤 전수 문서로 커버되는지 보여주는 coverage matrix 문서 |
| 프로토콜 | [`프로토콜/단말-기준-SIP-메시지-분류.md`](프로토콜/단말-기준-SIP-메시지-분류.md) | 단말 기준 SIP Request/Response 전체 분류 문서 |
| 프로토콜 | [`프로토콜/SIP-요청-응답-패킷-필드-비교-매트릭스.md`](프로토콜/SIP-요청-응답-패킷-필드-비교-매트릭스.md) | 현재 catalog/model이 노출하는 요청 14개, 응답 75개, union field 69개를 기준으로 request/response packet field surface를 누락 없이 비교한 읽기 좋은 매트릭스 문서 |
| 프로토콜 | [`프로토콜/SIP-요청-응답-오피셜-필드-리서치.md`](프로토콜/SIP-요청-응답-오피셜-필드-리서치.md) | IANA/RFC Editor 공식 자료를 기준으로 UE 관점의 SIP 요청 14종과 응답 75코드, 필수/선택/조건부 필드와 각 필드 의미를 정리한 대형 프로토콜 리서치 문서 |
| 프로토콜 | [`프로토콜/요청-패킷-예시.md`](프로토콜/요청-패킷-예시.md) | 요청 메시지별 대표 SIP 패킷 예시 |
| 프로토콜 | [`프로토콜/응답-패킷-예시.md`](프로토콜/응답-패킷-예시.md) | 응답 코드별 대표 SIP 패킷 예시 |
| 이슈 | [`이슈/오픈-이슈.md`](이슈/오픈-이슈.md) | 설계/실험 단계에서 추가 결정이 필요한 항목 |

## 문서 갱신 규칙
- 요청/응답 패킷 예시 문서는 `scripts/generate_packet_docs.py` 로 생성한다.
- 루트 `README.md` 는 프로젝트 소개용 엔트리 포인트로 유지한다.
- 결과 문서는 구현 완료 시점의 명령어, 검증 결과, 후속 TODO를 함께 남긴다.
- 새 이슈 문서는 가능하면 `이슈/` 하위에 별도 파일로 추가한다.
