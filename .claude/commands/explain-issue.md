---
name: explain-issue
description: VoLTE fuzzer의 약점/이슈를 분석하고 설명한다. 사용자가 이슈 번호, 이슈 제목, 또는 텍스트를 선택해서 "설명해줘", "이게 뭐야", "분석해줘" 등을 요청할 때 사용한다.
---

# VoLTE Fuzzer 이슈 분석기

사용자가 퍼징 약점이나 이슈에 대해 설명을 요청하면, 아래 절차를 따라 분석한다.

## 입력 형태

사용자는 다음 중 하나로 이슈를 지정한다:
- 에디터에서 텍스트를 선택하고 "설명" 요청
- 이슈 제목이나 키워드 언급 (예: "IPsec SA 만료", "ADB 연결 단절")
- 이슈 번호 참조

## 분석 절차

### 1단계: 관련 코드 파악

이슈와 관련된 소스 파일을 탐색한다. 주요 모듈 경로:

| 모듈 | 경로 | 역할 |
|------|------|------|
| campaign | `src/volte_mutation_fuzzer/campaign/` | 캠페인 실행, 설정, circuit breaker |
| sender | `src/volte_mutation_fuzzer/sender/` | 패킷 송신, real-ue-direct, container_exec |
| oracle | `src/volte_mutation_fuzzer/oracle/` | 응답 판정 (verdict 분류) |
| mutator | `src/volte_mutation_fuzzer/mutator/` | 변이 엔진 (model/wire/byte) |
| generator | `src/volte_mutation_fuzzer/generator/` | SIP 패킷 생성, MT 템플릿 |
| adb | `src/volte_mutation_fuzzer/adb/` | Android 디버그 브릿지 연동 |
| capture | `src/volte_mutation_fuzzer/capture/` | pcap 캡처 |
| infra | `src/volte_mutation_fuzzer/infra/` | 라우팅 설정 |

관련 문서:
- `docs/이슈/` — 기존 이슈 기록
- `docs/A31_REAL_UE_GUIDE.md` — 실기기 퍼징 가이드
- `docs/ARCHITECTURE.md` — 시스템 아키텍처

### 2단계: 구조화된 설명 출력

다음 형식으로 설명한다:

```
## [이슈 번호]. [이슈 제목] — 문제 설명

### 현재 동작
[현재 코드가 어떻게 동작하는지. 구체적인 파일:라인 참조 포함]

### 문제점
[왜 이것이 문제인지. 실제 퍼징 시나리오에서 어떤 증상이 나타나는지]

### 영향 범위
[어떤 모듈/파일이 영향을 받는지]

### 해결 방향
[가벼운 해결 방향 제안. 복수의 접근법이 있으면 장단점 비교]

수정할까요?
```

## 설명 원칙

- **한국어**로 설명한다
- 코드 참조는 `파일:라인` 형식으로 구체적으로 한다
- IMS/SIP 도메인 용어는 그대로 쓰되, 필요시 괄호로 부연한다
- 실제 퍼징 시나리오에서의 영향을 반드시 포함한다
- 표(table)를 적극 활용해서 비교/정리한다
- 설명 끝에 "수정할까요?"로 다음 액션을 제안한다

## 서버 환경 컨텍스트

설명 시 아래 환경을 전제한다:
- 서버: `ubuntu@163.180.185.51`
- Docker 네트워크: `br-volte` (`172.22.0.0/16`)
- P-CSCF: `pcscf` 컨테이너 (172.22.0.21)
- 타깃 UE: Samsung A31 (MSISDN 111111, IP 10.20.20.8)
- IPsec 모드: null encryption 또는 xfrm bypass
