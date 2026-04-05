# PHASE4_PRD: Softphone-first Sender/Reactor 설계

## 1. 문서 목적
본 문서는 Phase 4(Sender/Reactor)의 1차 구현 범위를 현재 저장소 기준으로 고정한다. 이번 버전의 목표는 **softphone target에 대해 단일 SIP artifact를 송신하고, socket 반응을 수집해 success / provisional / error / timeout / invalid-response를 구분하는 최소 실행 경로**를 제공하는 것이다.

이 문서는 staged 리서치 문서들과 `/Users/chaejisung/Desktop/Project/fuzzer(capstone)`의 구조를 참조하되, 현재 저장소의 SRP 기준에 맞게 더 작은 책임 경계로 재정리한다.

## 2. 이번 Phase 4의 결정 사항
### 2.1 1차 target
- 기본 target mode는 `softphone`
- `real-ue/pcscf`, `real-ue/direct`는 인터페이스 이름만 예약하고 이번 구현 범위에서는 실제 송신 경로를 만들지 않는다.

### 2.2 truth source
- 1차 truth source는 `socket`이다.
- sniffer / pcap / siptrace / adb는 이번 구현에서 결과 구조만 열어 두고, 실제 observer plugin은 후속 단계로 미룬다.

### 2.3 transport
- 1차 우선 transport는 `UDP`
- 구현은 `TCP`도 지원하지만, 검증 시나리오와 실험 기준 타깃은 UDP를 기본으로 둔다.

## 3. capstone reference mapping
| capstone 자산 | 이번 저장소 대응 |
| --- | --- |
| `fuzzer/fuzzer/sender.py` | `src/volte_mutation_fuzzer/sender/core.py` |
| `fuzzer/fuzzer/dumpipe.py` | 후속 `real-ue/direct` mode 설계 참고 |
| `fuzzer/tools/ue_lookup.py` | 후속 `TargetResolver` 확장 포인트 |
| `fuzzer/monitor/sip_sniffer.py` | 후속 observer plugin 설계 참고 |
| `fuzzer/monitor/pcap_capture.py` | 후속 observer plugin 설계 참고 |

핵심 차이는 capstone이 실험망 전체를 품고 있었다면, 현재 저장소는 **catalog / generator / mutator / sender/reactor를 독립 서비스 계층으로 정리**한다는 점이다.

## 4. 공개 인터페이스
### 4.1 `TargetEndpoint`
- `mode`: `softphone | real-ue-direct`
- `host`, `port`
- `transport`: `UDP | TCP`
- `timeout_seconds`
- `label`

### 4.2 `SendArtifact`
Sender는 아래 셋 중 하나를 입력으로 받는다.
- `packet`: Generator 또는 Mutator가 만든 구조화된 SIP packet
- `wire_text`: wire-level mutation 결과
- `packet_bytes`: byte-level mutation 결과

즉, Sender는 향후 `Generator -> Mutator -> Sender` 전체 파이프라인의 마지막 실행 계층으로 사용된다.

### 4.3 `SIPSenderReactor`
현재 공개 메서드는 아래 4개다.
- `send_artifact(...)`
- `send_packet(...)`
- `send_wire_text(...)`
- `send_packet_bytes(...)`

반환 타입은 항상 `SendReceiveResult`다.

### 4.4 `SendReceiveResult`
최소 포함 정보:
- target
- artifact kind
- correlation key (`Call-ID`, `CSeq`)
- bytes sent
- outcome
- collected socket responses
- send duration

## 5. 내부 책임 분리
### 5.1 Sender
- packet / wire / bytes artifact를 실제 전송 payload로 변환
- UDP/TCP socket 전송 수행
- correlation key를 packet 기준으로 추출

### 5.2 Reactor
- socket response 수집
- SIP status line / header / body를 파싱
- provisional / success / error / invalid를 분류
- response가 없으면 timeout으로 판정

### 5.3 Observer (후속)
현재 구현하지 않지만, 결과 구조에는 아래 observer가 붙을 수 있어야 한다.
- siptrace
- pcap
- sniffer
- adb/logcat

## 6. 1차 실행 시나리오
### 시나리오 A. baseline sanity request
- 입력: `OPTIONS` 또는 `MESSAGE` baseline packet
- target: softphone SIP listener
- 기대: 1개 이상의 socket response를 수집하고 outcome을 구조화해 반환

### 시나리오 B. provisional + final response
- 입력: INVITE 계열 또는 equivalent test double
- 기대: `collect_all_responses=True`일 때 provisional과 final response를 모두 보존

### 시나리오 C. timeout
- 입력: 정상 packet
- target: 응답하지 않는 endpoint
- 기대: `timeout` outcome 반환

## 7. CLI 표면
루트 CLI `fuzzer` 아래에 다음 서브커맨드를 둔다.
- `fuzzer send packet`
- `fuzzer send request`
- `fuzzer send response`

`send packet`은 다음 stdin 입력을 모두 받는다.
- Generator packet JSON
- Mutator result JSON
- raw SIP wire text

## 8. 이번 구현 범위에 포함하지 않는 것
- MSISDN -> UE IP lookup
- Kamailio/Open5GS 연동
- direct-to-UE route setup
- observer plugin 실제 구현
- campaign scheduler / controller
- oracle 판정

## 9. 완료 기준
이번 Phase 4 1차 구현은 아래를 만족하면 완료로 본다.
1. softphone-style target으로 단일 artifact를 전송할 수 있다.
2. success / provisional / error / timeout / invalid-response를 구분한다.
3. packet JSON, mutator JSON, raw wire text를 `fuzzer send packet`에서 소화할 수 있다.
4. sender/reactor 경계와 후속 observer 확장 지점이 문서와 코드에 함께 남아 있다.
