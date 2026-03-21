# SIP 통합 연구 보고서

기준 일자: 2026-03-21

## 1. 문서 목적

이 문서는 현재 워크스페이스에 축적된 SIP 조사 문서들을 하나로 통합해, 다음 질문에 답하는 연구 보고서다.

1. 지금까지 무엇을 어디까지 조사했는가
2. SIP를 어떤 구조로 이해해야 하는가
3. 단말 지향 SIP 퍼저 관점에서 어떤 표면이 중요한가
4. 현재 프로젝트의 다음 설계 단계에 어떤 함의를 주는가

이 문서는 새 사실을 추가로 발굴하는 문서가 아니라, 이미 조사된 내용을 분석적으로 재정리하는 문서다.

## 2. 분석에 사용한 문서 범위

이번 통합 보고서는 아래 문서군을 기준으로 작성했다.

### 2.1 프로토콜 분류 및 필드 문서

- `docs/프로토콜/단말-기준-SIP-메시지-분류.md`
- `docs/프로토콜/SIP-요청-응답-오피셜-필드-리서치.md`
- `docs/프로토콜/SIP-요청-응답-패킷-필드-비교-매트릭스.md`
- `docs/프로토콜/요청-패킷-예시.md`
- `docs/프로토콜/응답-패킷-예시.md`

### 2.2 IANA 전수조사 문서

- `docs/프로토콜/SIP-IANA-전체-필드-전수조사.md`
- `docs/프로토콜/SIP-IANA-헤더-필드-파라미터-전수조사.md`
- `docs/프로토콜/SIP-IANA-URI-파라미터-전수조사.md`
- `docs/프로토콜/SIP-IANA-옵션-태그-전수조사.md`
- `docs/프로토콜/SIP-IANA-메서드-응답코드-전수조사.md`
- `docs/프로토콜/SIP-IANA-값-레지스트리-전수조사.md`
- `docs/프로토콜/SIP-IANA-기능-식별자-전수조사.md`
- `docs/프로토콜/SIP-IANA-리소스-우선순위-전수조사.md`
- `docs/프로토콜/SIP-IANA-기타-레지스트리-survey.md`

### 2.3 프로젝트 및 구현 방향 문서

- `README.md`
- `docs/기획/PRD.md`
- `docs/기획/GENERATOR_PRD.md`
- `docs/기획/MUTATOR_PRD.md`
- `docs/결과/GENERATOR-구현-결과.md`
- `docs/결과/PHASE4-SENDER-REACTOR-리서치.md`
- `docs/결과/PHASE4-REAL-UE-SOFTPHONE-후속-리서치.md`
- `docs/이슈/오픈-이슈.md`

## 3. Executive Summary

현재까지의 조사 결과를 한 문장으로 요약하면 다음과 같다.

> SIP는 단순한 텍스트 프로토콜이 아니라, request/response 종류, transaction/dialog 상태, capability negotiation, IMS private extension, 대량의 IANA registry가 겹쳐진 다층 상태 프로토콜이며, 단말 지향 퍼징은 이 전체 표면 중 무엇을 우선적으로 흔들지 정하는 문제다.

핵심 결론은 아래와 같다.

1. 현재 워크스페이스는 SIP IANA 표면을 거의 전수 수준으로 문서화했다.
2. 가장 중요한 공격면은 단순 header syntax가 아니라 transaction, dialog, authentication, event, security negotiation이다.
3. VoLTE/IMS 단말을 겨냥한다면 RFC 3261 core SIP만 보면 부족하고, IMS/3GPP private header와 private parameter를 별도 표면으로 봐야 한다.
4. 현재 프로젝트는 Generator/Mutator 기반은 많이 정리됐고, 실제 남은 큰 공백은 Phase 4 Sender/Reactor와 관측 계층이다.
5. 다음 단계는 추가 조사보다도 우선순위화된 실험 설계와 송신/관측 구조 구현에 가깝다.

## 4. 현재까지 확보한 조사 자산의 규모

현재 문서군이 커버하는 SIP 표면은 다음과 같다.

| 조사 대상 | 현재 문서 기준 규모 | 의미 |
| --- | ---: | --- |
| Request Method | 14 | IANA 등록 request 전체 |
| Response Code | 75 | IANA 등록 response 전체 |
| Header Field | 134 | SIP header registry 전체 |
| Header Parameter / Value | 201 | 헤더 내부 parameter/value 표면 |
| SIP/SIPS URI Parameter | 35 | URI 기반 제어 표면 |
| Option Tag | 36 | capability/extension negotiation 표면 |
| 값 중심 registry row | 89 | Warning, Privacy, Transport, PNS 등 |
| 기능 식별자 registry row | 71 | Identity, Feature-Caps, Info Package, UUI 등 |
| Resource-Priority namespace | 48 | 우선순위 네임스페이스 |
| Resource-Priority child value | 463 | namespace별 실제 priority token |

이 수치는 단순 참고 수치가 아니라, 다음 의미를 가진다.

- 프로젝트가 더 이상 “SIP가 어떤 필드를 가지는가”를 모르는 상태는 아니다.
- 향후 실패는 조사 부족보다 우선순위 설정 실패, 상태 모델링 실패, 또는 실험 환경 부족에서 날 가능성이 높다.

## 5. SIP를 어떻게 이해해야 하는가

## 5.1 SIP는 메시지 목록이 아니라 상태 기계다

SIP를 단순 request/response 집합으로만 보면 중요한 부분을 놓친다.

현재 조사 문서들이 공통으로 보여주는 SIP의 본질은 다음 네 층이다.

1. 메시지 종류 층  
   `INVITE`, `BYE`, `REGISTER`, `SUBSCRIBE`, `NOTIFY`, `UPDATE` 같은 method와 `1xx`~`6xx` response code
2. 상관관계 층  
   `Via`, `Call-ID`, `CSeq`, `From tag`, `To tag`, `Contact`, `Route`, `Record-Route`
3. 의미/확장 층  
   `Event`, `Subscription-State`, `Recv-Info`, `Info-Package`, `Security-*`, `Identity`, `Privacy`
4. 환경/사설 확장 층  
   IMS/3GPP private header, private parameter, Resource-Priority, Feature-Caps, push, charging

즉 SIP는 “헤더 몇 개를 채운 문자열”이 아니라, 상태 전이가 헤더와 응답 코드에 분산된 프로토콜이다.

## 5.2 Request보다 failure path가 더 넓다

응답 코드 전수조사에서 가장 눈에 띄는 점은 `4xx`가 `46개`로 가장 많다는 것이다.

이는 다음을 뜻한다.

- SIP 구현은 성공 경로보다 실패 경로 분기가 더 많다.
- 퍼징 우선순위도 `200 OK`를 잘 받는지보다, 실패 분기에서 구현체가 얼마나 일관되게 무너지지 않는지 보는 쪽이 더 중요하다.
- 단말 구현체의 취약점은 파싱 성공 후의 “상태 거절 처리”에서 날 가능성이 높다.

실제로 `401`, `407`, `420`, `421`, `422`, `423`, `469`, `489`, `494` 같은 코드는 인증, 확장 협상, session timer, event framework, security agreement와 직접 연결된다.

## 5.3 공통 필드는 적고, 조건부 규칙이 많다

패킷 필드 비교 문서 기준으로 현재 프로젝트 surface는 아래처럼 요약된다.

- shared fields: 28
- request-only fields: 22
- response-only fields: 19

여기서 중요한 건 단순 개수보다 구조다.

- 공통 필드는 상관관계 유지에 쓰인다.
- request-only 필드는 동작 의도와 대상 제어에 가깝다.
- response-only 필드는 실패 원인, 협상 결과, 정책 설명에 가깝다.

즉 SIP 퍼징은 아무 필드나 무작정 깨는 게 아니라,

1. 상관관계 필드는 유지할지 깨뜨릴지 의도적으로 선택하고
2. 조건부 필드는 “맞는 문맥에서만” 삽입 또는 삭제하고
3. 실패 응답을 유도하는 negotiation field를 우선적으로 흔들어야 한다.

## 6. 현재 문서군이 보여주는 핵심 공격면

## 6.1 Transaction / Dialog 불변식

가장 중요한 표면은 아래 필드들이다.

- `Via.branch`
- `Call-ID`
- `CSeq`
- `From tag`
- `To tag`
- `Contact`
- `Route`
- `Record-Route`

이 필드들은 단순 metadata가 아니라, SIP가 “같은 요청/응답인지”, “같은 dialog인지”, “어디로 되돌아가야 하는지”를 판단하는 핵심 축이다.

따라서 이 필드에 대한 변조는 크게 두 갈래로 나뉜다.

1. **일관성 유지형 변조**  
   나머지 필드는 유지하면서 값만 경계 조건으로 흔들기
2. **상태 붕괴형 변조**  
   branch/tag/CSeq 상관관계를 깨서 state machine을 혼란시키기

단말 지향 퍼저라면 두 번째가 특히 중요하다. 서버는 완전하지 않은 상관관계를 많이 본다고 가정하고 방어적으로 작성되는 경우가 많지만, 단말 스택은 그 정도로 강건하지 않을 수 있다.

## 6.2 Authentication / Security / Identity 표면

헤더 parameter 전수조사에서 가장 밀집한 영역 중 하나가 `Authorization`, `Proxy-Authorization`, `Proxy-Authenticate`, `WWW-Authenticate`, `Security-*` 계열이다.

이 표면이 중요한 이유는 다음과 같다.

- 토큰 종류가 많다.
- `algorithm`, `nonce`, `qop`, `nc`, `cnonce`, `realm`, `response`, `auts` 같은 필드가 서로 의미적으로 엮인다.
- IMS/AKA 문맥에서는 일반 digest보다 상태와 파생 규칙이 더 복잡하다.
- `494 Security Agreement Required`와 `Security-Server`, `Require: sec-agree` 같은 response-driven negotiation이 들어간다.

즉 이 영역은 단순 parser bug뿐 아니라 “반쯤 맞는 인증 상태”를 처리하는 로직 버그 후보군이다.

## 6.3 Event / Subscription / Publication 표면

`Event`, `Subscription-State`, `Info-Package`, `Recv-Info`, `SIP-ETag`, `SIP-If-Match`, `Allow-Events`, `RSeq`, `RAck`는 core call flow보다 덜 유명하지만, 상태 의존성이 훨씬 강하다.

이 계열이 중요한 이유는 다음과 같다.

- `SUBSCRIBE` / `NOTIFY` / `PUBLISH`는 lifetime과 state token을 갖는다.
- `PRACK`은 reliable provisional response를 전제로 한다.
- `INFO`는 package negotiation이 맞아야 한다.
- publication은 `SIP-ETag` / `SIP-If-Match`로 conditional update semantics를 가진다.

즉 이쪽은 “문자열 형식은 맞지만 상태가 어긋난 메시지”를 만들기 좋은 영역이다.

## 6.4 IMS / 3GPP Private Header 표면

전체 필드 전수조사와 header parameter 조사 문서가 공통으로 보여주는 건, IMS/3GPP private 표면이 생각보다 넓다는 점이다.

대표 예시는 아래와 같다.

- `P-Access-Network-Info`
- `P-Charging-Vector`
- `P-Charging-Function-Addresses`
- `P-Asserted-Identity`
- `P-Served-User`
- `P-Associated-URI`
- `Feature-Caps`
- 3GPP 관련 `Info Package`

이 영역이 중요한 이유는 두 가지다.

1. 상용 VoLTE/IMS 단말에서는 실제로 이런 header가 들어오는 맥락이 존재한다.
2. 일반 SIP 실습 도구나 오픈소스 예제는 이 표면을 충분히 다루지 않는 경우가 많다.

즉 단말 지향 퍼저의 차별점은 바로 이 private surface를 다룰 수 있느냐에 달린다.

## 6.5 Rare but High-Value 표면

전수조사 문서 중 특수하지만 가치가 높은 표면은 다음이다.

- `Resource-Priority` namespaces / values
- `Feature-Caps` indicator trees
- push notification 관련 `sip.pns`, `pn-*`, `PNS`
- `Warning`, `Reason`, `Geolocation-Error`, `AlertMsg-Error`
- `UUI` 관련 parameter/encoding

이 영역은 메시지 빈도는 낮을 수 있지만, 구현체 분기 수는 크다.

즉 자주 오는 정상 메시지보다 “드물지만 별도 코드 경로를 타는 메시지”가 취약점 탐색 효율이 높을 가능성이 있다.

## 7. 퍼징 관점에서의 해석

## 7.1 가장 먼저 흔들어야 할 축

현재 조사 결과만 기준으로 할 때, 우선순위는 아래처럼 보는 것이 합리적이다.

### Tier 1. 핵심 상태 불변식

- `Via.branch`
- `Call-ID`
- `CSeq`
- `From/To tag`
- `Contact`

이 영역은 거의 모든 method와 response에 영향을 준다.

### Tier 2. 실패 분기 유도 표면

- `Supported`
- `Require`
- `Proxy-Require`
- `Allow`
- `Allow-Events`
- `Unsupported`
- `Security-*`
- 인증 challenge/response 계열

이 영역은 4xx를 대량으로 유도할 수 있다.

### Tier 3. 상태 의존 확장

- `Event`
- `Subscription-State`
- `Info-Package`
- `Recv-Info`
- `RAck` / `RSeq`
- `SIP-ETag` / `SIP-If-Match`

이 영역은 event framework와 provisional reliability 등 확장 상태 기계를 자극한다.

### Tier 4. IMS/VoLTE 특화 표면

- `P-Access-Network-Info`
- `P-Charging-*`
- `P-Asserted-Identity`
- `Feature-Caps`
- `Resource-Priority`

이 영역은 상용 단말에 더 직접적이다.

## 7.2 Generator와 Mutator에 주는 함의

현재 PRD와 Generator/Mutator PRD를 함께 보면, 구현 방향은 이미 논리적으로 정리돼 있다.

### Generator 측 함의

- 정상 baseline은 “문법적으로 맞는 메시지” 이상이어야 한다.
- 최소한 method/code별 필수 필드와 문맥 필드를 보존해야 한다.
- Generator는 wire text가 아니라 구조화된 모델을 기준 산출물로 유지하는 것이 맞다.

### Mutator 측 함의

- model mutation은 상태 필드와 의미 필드에 적합하다.
- wire mutation은 헤더 삭제/중복/순서 변경/Content-Length 불일치에 적합하다.
- byte mutation은 parser robustness와 lower-level input handling에 적합하다.

즉 현재 프로젝트의 `model -> wire -> byte` 3계층 변조 분리는 조사 결과와 잘 맞는다. 이건 과도한 설계가 아니라 SIP 특성상 필요한 분리다.

## 7.3 Oracle와 Reactor에 주는 함의

SIP는 “응답이 없으면 실패”라고 단순 판정하기 어렵다.

특히 real UE 환경에서는 아래 가능성이 동시에 있다.

- proxy에서 드랍됨
- UE까지 가지 않음
- UE가 받았지만 무시함
- 다른 경로로 응답함
- 보안/라우팅 조건 때문에 중간에서 소실됨

따라서 Reactor는 단일 소켓 응답 수집기로 끝나면 안 된다.

최소한 아래 계층 구조가 자연스럽다.

1. socket response
2. network trace
3. optional device-side observer

이 결론은 Phase 4 리서치 문서의 결론과도 일치한다.

## 8. 현재 프로젝트 상태에 대한 분석

## 8.1 강한 점

현재 저장소의 강점은 아래와 같다.

1. SIP 표면 인벤토리가 이미 매우 넓다.
2. Generator와 Mutator 책임 경계가 비교적 명확하다.
3. 문서, catalog, 구현 방향이 대체로 같은 축을 보고 있다.
4. 단말 지향 퍼징이라는 문제 정의가 흔들리지 않는다.

즉 “무엇을 만들려는가”가 불명확한 프로젝트는 아니다.

## 8.2 약한 점

현재 약점도 명확하다.

1. Sender/Reactor가 아직 구현되지 않았다.
2. Oracle/Controller도 아직 비어 있다.
3. 실험 환경의 현실적 제약이 아직 결정되지 않았다.
4. 조사 결과가 많지만, 우선순위가 정교하게 접힌 실행 계획은 아직 없다.

즉 지금 병목은 연구 부족보다 실행 계층 부족이다.

## 8.3 실제 공백은 어디인가

현재 공백은 크게 세 가지다.

### A. 실험 환경 공백

- 초기 타깃 단말 종류
- 실험 네트워크 구성
- REGISTER/인증 선행 여부
- transport 우선순위
- oracle 관측 채널

### B. 송신/관측 계층 공백

- P-CSCF 경유 vs direct-to-UE
- socket-only vs multi-observer reactor
- target resolver 방식

### C. 우선순위화 공백

- 어떤 method/code/field를 1차 실험 대상으로 둘 것인가
- 어떤 rare registry를 언제 포함할 것인가
- IMS 전용 표면과 generic SIP 표면을 어떤 비율로 섞을 것인가

## 9. Phase 4 관점에서의 함의

현재 조사 결과만 놓고 보면, 가장 현실적인 방향은 아래와 같다.

1. Sender/Reactor는 Python native로 프로젝트 내부에 구현
2. target mode는 최소 `softphone`, `real-ue/pcscf`, `real-ue/direct`
3. Reactor는 socket response + optional observer 구조
4. direct mode를 위해 target resolution 계층 분리

이 방향이 맞는 이유는 다음과 같다.

- 현재 Generator/Mutator 산출물을 가장 자연스럽게 재사용한다.
- malformed wire/byte를 직접 밀어 넣는 데 유리하다.
- 기존 연구실 실험 자산과 연결된다.
- later-stage Oracle/Controller로 확장하기 쉽다.

즉 Phase 4는 단순한 “패킷 송신기”가 아니라, 현재까지 조사된 SIP 상태 모델을 실제 실험 환경에 연결하는 어댑터 계층이 되어야 한다.

## 10. 남아 있는 핵심 오픈 이슈

현재 조사 내용을 종합했을 때, 앞으로 반드시 결정해야 하는 질문은 아래와 같다.

1. 1차 타깃은 softphone sanity target인가, real UE인가
2. real UE를 쓴다면 `pcscf`와 `direct` 중 어느 경로를 우선 구현할 것인가
3. 첫 실험에서 인증/등록 상태를 전제로 할 것인가
4. transport는 UDP 우선인가, TCP/TLS까지 바로 볼 것인가
5. oracle truth source는 socket인가, trace인가, device log인가

이 질문들은 구현 디테일이 아니라 실험 설계의 중심 질문이다.

## 11. 최종 결론

현재까지의 조사로부터 얻을 수 있는 최종 결론은 다음과 같다.

### 11.1 조사 범위 측면

SIP 표면 조사는 이미 충분히 깊다. 지금 필요한 것은 더 많은 인벤토리보다는, 그 인벤토리 중 어떤 부분이 단말 퍼징에 가장 큰 효용을 가지는지 우선순위를 정하는 일이다.

### 11.2 프로토콜 이해 측면

SIP는 본질적으로 상태 기계다. 따라서 parser만 흔드는 퍼저는 충분하지 않다. transaction, dialog, capability negotiation, event framework, security agreement를 함께 흔들어야 한다.

### 11.3 VoLTE/IMS 측면

단말 지향 SIP 퍼징의 핵심 차별점은 IMS/3GPP private surface를 정면으로 다룬다는 점이다. generic SIP만으로는 상용 VoLTE 단말의 실제 코드 경로를 충분히 자극하지 못할 수 있다.

### 11.4 프로젝트 실행 측면

현재 프로젝트의 가장 큰 공백은 조사 문서가 아니라, Sender/Reactor와 실험 환경 결정이다. 따라서 다음 단계의 중심은 “추가 조사”보다 “우선순위가 접힌 실행 설계와 구현”이어야 한다.

## 12. 후속 작업 제안

이 보고서 기준으로 다음 문서 작업 우선순위는 아래가 적절하다.

1. **SIP 공격면 우선순위표**
   현재 조사 자산을 Tier 1~4 공격면 목록으로 압축
2. **Phase 4 설계 보고서**
   Sender/Reactor와 Observer 구조를 현재 조사 근거 위에서 확정
3. **실험 시나리오 초안**
   softphone sanity, real-ue/pcscf, real-ue/direct 각각에 대한 최소 실행 시나리오 정의
4. **퍼징 캠페인 우선순위표**
   어떤 method/code/field 조합부터 돌릴지 순서화

## 13. 참고 문서 링크

### 핵심 분류 문서

- [단말-기준-SIP-메시지-분류](../프로토콜/단말-기준-SIP-메시지-분류.md)
- [SIP-요청-응답-오피셜-필드-리서치](../프로토콜/SIP-요청-응답-오피셜-필드-리서치.md)
- [SIP-요청-응답-패킷-필드-비교-매트릭스](../프로토콜/SIP-요청-응답-패킷-필드-비교-매트릭스.md)

### IANA 전수조사 문서

- [SIP-IANA-전체-필드-전수조사](../프로토콜/SIP-IANA-전체-필드-전수조사.md)
- [SIP-IANA-헤더-필드-파라미터-전수조사](../프로토콜/SIP-IANA-헤더-필드-파라미터-전수조사.md)
- [SIP-IANA-URI-파라미터-전수조사](../프로토콜/SIP-IANA-URI-파라미터-전수조사.md)
- [SIP-IANA-옵션-태그-전수조사](../프로토콜/SIP-IANA-옵션-태그-전수조사.md)
- [SIP-IANA-메서드-응답코드-전수조사](../프로토콜/SIP-IANA-메서드-응답코드-전수조사.md)
- [SIP-IANA-값-레지스트리-전수조사](../프로토콜/SIP-IANA-값-레지스트리-전수조사.md)
- [SIP-IANA-기능-식별자-전수조사](../프로토콜/SIP-IANA-기능-식별자-전수조사.md)
- [SIP-IANA-리소스-우선순위-전수조사](../프로토콜/SIP-IANA-리소스-우선순위-전수조사.md)
- [SIP-IANA-기타-레지스트리-survey](../프로토콜/SIP-IANA-기타-레지스트리-survey.md)

### 구현/계획 문서

- [PRD](../기획/PRD.md)
- [GENERATOR_PRD](../기획/GENERATOR_PRD.md)
- [MUTATOR_PRD](../기획/MUTATOR_PRD.md)
- [GENERATOR-구현-결과](./GENERATOR-구현-결과.md)
- [PHASE4-SENDER-REACTOR-리서치](./PHASE4-SENDER-REACTOR-리서치.md)
- [PHASE4-REAL-UE-SOFTPHONE-후속-리서치](./PHASE4-REAL-UE-SOFTPHONE-후속-리서치.md)
- [오픈-이슈](../이슈/오픈-이슈.md)
