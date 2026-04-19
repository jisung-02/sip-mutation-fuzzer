# Real-UE Native IPsec Mode Design

## 배경

현재 `real-ue-direct` 경로의 `--ipsec-mode null` / `--ipsec-mode bypass` 는 둘 다 결과적으로 평문 UDP 송신 경로다. 이 경로는 Samsung A31 실기기 MT-INVITE 퍼징에는 유효하지만, 실제 등록 후 협상된 IMS IPsec/xfrm 세션을 그대로 타는 모드는 아니다.

이번 설계의 목표는 기존 평문 우회 모드를 유지하면서, 별도의 신규 모드 `native` 를 추가해 실제 연결의 IPsec selector 를 맞춰 송신하고, 응답도 현재 퍼저가 다루는 방식과 유사한 구조로 확인 가능하게 만드는 것이다.

초기 REGISTER / 401 교환이 평문인 점은 이번 범위의 blocker 가 아니다. `native` 는 등록이 끝난 뒤 살아 있는 xfrm 세션이 존재하는 상태를 전제로 한다.

## 목표

- `--ipsec-mode native` 를 추가해 실제 협상된 IMS IPsec/xfrm 경로를 사용하는 송신 모드를 제공한다.
- `real-ue-direct` 의 모든 주요 송신 경로에서 같은 의미로 동작하게 만든다.
  - `campaign run`
  - `send request`
  - `send packet`
  - `--mt`
  - `--mt-invite-template`
- wire/byte 변이 결과처럼 부분적으로 또는 크게 손상된 SIP payload 도 전송 가능해야 한다.
- 응답은 직접 소켓 수신이 아니더라도, 최종적으로는 현재와 비슷한 `response_code`, `raw_response`, `observer_events`, `verdict` 흐름으로 확인 가능해야 한다.
- UE 가 재등록되지 않았거나, 살아 있는 xfrm 매핑이 없거나, native 송신 전제조건이 맞지 않으면 즉시 실패해야 한다.

## 비목표

- 소프트폰 모드 지원
- REGISTER 절차 자체를 IPsec 송신으로 바꾸기
- TCP 기반 native IPsec 지원
- outer-wire pcap 에서 평문 SIP 가 그대로 보이는 경험 제공
- xfrm 세션 재협상이나 자동 재등록까지 수행하는 self-healing 구현

## 고정된 설계 결정

### 1. 사용자 인터페이스

- 허용 모드는 `null`, `bypass`, `native` 다.
- `ipsec` 는 별칭으로 받아 내부적으로 `native` 로 정규화한다.
- `native` 는 `mode=real-ue-direct` 에서만 유효하다.
- `native` 의 초기 구현 범위는 UDP 전용이다. `--transport TCP --ipsec-mode native` 조합은 설정 오류로 처리한다.
- `--mt-local-port` 는 CLI 호환성을 위해 남겨 두지만 `native` 에서는 authoritative 하지 않다. 실제 송신 포트는 살아 있는 IPsec 세션에서 해석한 P-CSCF 보호 포트를 사용한다.

### 2. live IPsec 세션 모델

`native` 모드는 "UE 쪽 보호 포트" 와 "P-CSCF 쪽 보호 포트" 의 매핑을 live 상태에서 알아야 한다. 단순히 `port_pc`, `port_ps` 만 알아서는 부족하고, 어느 UE 보호 포트에 대해 어느 P-CSCF 보호 포트를 source port 로 써야 하는지가 필요하다.

따라서 내부적으로 다음 정보를 가진 세션 모델을 추가한다.

- `ue_ip`
- `pcscf_ip`
- `port_bindings`
  - 의미: `ue_port -> pcscf_port`
  - 예시: `8100 -> 5103`, `8101 -> 6103`
- `observer_events`

이 정보는 우선 `ip xfrm state` 를 파싱해 만든다. 필요 시 기존 로그/리졸버 정보는 UE IP 보조 식별에 사용하지만, native 모드의 핵심 포트 바인딩 진실 공급원은 live xfrm state 다.

### 3. 송신 방식

`native` 는 `pcscf` 컨테이너 netns 안에서 동작한다. 하지만 Kamailio 가 이미 점유 중인 보호 포트(`510x`, `610x`)에 일반 UDP 소켓을 bind 하지는 않는다. 그 방식은 포트 충돌 때문에 퍼저 payload 를 자유롭게 주입하기 어렵다.

대신 native 송신기는 raw IPv4/UDP injector 를 사용한다.

- source IP: live P-CSCF IP
- destination IP: live UE IP
- source port: 세션에서 해석한 P-CSCF 보호 포트
- destination port: 대상 UE 보호 포트
- payload: 변이 후 wire text 또는 raw bytes

이 방식의 목적은 두 가지다.

- Kamailio 와 포트 bind 충돌 없이 보호 포트를 가진 UDP packet 을 만들 수 있다.
- packet 자체는 커널의 실제 routing/xfrm 경로를 타므로, outer wire 에서는 ESP 로 보이는 native IPsec 송신이 된다.

Via/Contact preserve 규칙은 유지한다. 다만 preserve 하지 않는 경우 `native` 의 Via sent-by 포트는 random high port 가 아니라 live P-CSCF 보호 포트로 rewrite 된다.

### 4. 응답 관찰 방식

`native` 에서는 기존 bypass/null 처럼 같은 소켓으로 직접 응답을 `recvfrom()` 할 수 없다. 응답은 실제 보호 포트로 decap 된 뒤 Kamailio 가 받기 때문이다.

그래서 응답 확인은 observer 기반으로 고정한다.

- 1차 수단: `pcscf`/Kamailio 로그 observer
- 2차 수단: campaign pcap 이 켜져 있을 때 outer-wire ESP 흔적을 증거로 남김

observer 는 send 시점 이후의 짧은 window 에서 아래 정보를 기준으로 응답을 찾는다.

- UE IP
- 선택된 UE 보호 포트 / P-CSCF 보호 포트
- 가능하면 Call-ID, branch, CSeq
- 위 값이 payload 손상 때문에 추출 불가하면 time-window + session tuple 로 fallback

observer 가 찾은 응답은 현재 결과 구조와 최대한 호환되도록 `SocketObservation` 계열 객체로 변환한다. 단, source 는 실제 socket 이 아니라 `pcscf-log` 같은 observer source 로 표기한다.

결과적으로 `SendReceiveResult` 는 계속 아래 필드를 채운다.

- `responses`
- `final_response`
- `outcome`
- `observer_events`

이렇게 하면 기존 oracle 흐름을 큰 폭으로 바꾸지 않고 재사용할 수 있다.

### 5. malformed packet 처리

사용자가 우려한 핵심은 "P-CSCF 를 직접 쓰지 않으니 packet 이 malform 되어도 괜찮은가" 였다. 이 설계에서는 괜찮다.

- native injector 는 SIP parser 를 통과한 정상 packet 만 보내는 구조가 아니다.
- wire 변이 결과 문자열도 보낼 수 있다.
- byte 변이 결과 raw bytes 도 그대로 UDP payload 로 담아 보낼 수 있다.

즉, sender 는 malformed payload 를 막지 않는다. 다만 malformed 정도가 심해 Call-ID/CSeq 를 읽어낼 수 없는 경우, observer correlation 정확도는 낮아질 수 있다. 이때는 session tuple 과 time-window 기반으로 response 를 연결한다.

### 6. Wireshark / pcap 가시성

native 모드에서는 outer-wire 기준으로 평문 SIP 가 아니라 ESP(프로토콜 50) 또는 암호화된 payload 가 보일 가능성이 높다. 이 점은 의도된 동작이다.

정리하면:

- `null` / `bypass`: 평문 SIP 가 보일 수 있다.
- `native`: outer-wire pcap 에서는 일반적으로 평문 SIP 가 보이지 않는다.

따라서 native 모드의 "응답 확인" 기준은 wireshark 상 평문 가독성이 아니라, observer 가 추출한 SIP response 와 `observer_events` 다. campaign pcap 은 "실제로 ESP 가 흘렀다" 는 보조 증거 역할을 한다.

### 7. 실패 처리

`native` 는 조용히 fallback 하지 않는다.

다음 상황은 즉시 send error 또는 infra failure 로 처리한다.

- live xfrm state 를 읽을 수 없음
- 대상 UE 에 대한 보호 포트 매핑을 만들 수 없음
- raw socket 생성 권한 없음
- `native` 에 필요한 observer backend 를 시작할 수 없음
- 사용자가 지정한 UDP target port 가 live session 의 UE 보호 포트와 맞지 않음

반대로 아래는 timeout 으로 남긴다.

- native 송신 자체는 성공했지만 observer 가 응답을 못 찾음

또한 현재 있는 SA circuit breaker 는 유지한다. sustained timeout 이후 SA 가 죽은 것으로 판명되면 `infra_failure` 로 재분류한다.

## 아키텍처 변경 요약

### `campaign/contracts.py`

- `ipsec_mode` 에 `native` 추가
- `ipsec` 별칭 정규화
- internal field 로 native 를 sender 까지 전달할 수 있게 정리

### `sender/contracts.py`

- `TargetEndpoint` 에 native 모드 판별에 필요한 `ipsec_mode` 추가
- `SocketObservation.source` 를 socket 고정값에서 확장 가능한 값으로 변경

### `sender/real_ue.py`

- live xfrm state 기반 `ResolvedNativeIPsecSession` 해석 로직 추가
- `ue_port -> pcscf_port` 매핑 함수 추가

### 신규 `sender/ipsec_native.py`

- raw UDP injector
- pcscf log observer
- observer 결과를 `SocketObservation` 으로 변환하는 helper

### `sender/core.py`

- `real-ue-direct + ipsec_mode=native` 분기 추가
- direct socket 수신 대신 native observer 결과를 `SendReceiveResult` 로 합성

### `campaign/core.py`

- MT template path 와 일반 real-ue-direct path 모두 native target 생성 지원
- reproduction command 에 native 반영
- raw response / verdict 흐름은 기존 oracle 경로 재사용

### `sender/cli.py`

- `send packet` 에도 `--ipsec-mode` 지원 추가
- `send request` / `--mt` 경로에서 native 옵션을 같은 의미로 처리

## 테스트 전략

### 단위 테스트

- `native`, `ipsec` alias 정규화
- native + TCP 거부
- xfrm state parser 가 `ue_port -> pcscf_port` 를 정확히 뽑는지 검증
- malformed payload 일 때도 injector 가 raw bytes 를 그대로 넘기는지 검증
- log observer 가 status line / raw snippet 을 `SocketObservation` 으로 변환하는지 검증

### 통합 테스트

- `send request --mode real-ue-direct --ipsec-mode native`
- `send packet --mode real-ue-direct --ipsec-mode native`
- `campaign run --mode real-ue-direct --target-msisdn 111111 --impi 001010000123511 --methods INVITE --layer wire --strategy identity --mt-invite-template a31 --ipsec-mode native`

### 수동 검증

- live UE 등록 후 native MT baseline 1건 전송
- campaign pcap 에서 ESP 가 보이는지 확인
- 결과 JSONL / stdout 에 `response_code`, `observer_events`, `raw_response` 또는 snippet 이 남는지 확인

## 구현 시 주의점

- softphone 는 계속 범위 밖이다.
- 기존 `null` / `bypass` 동작은 깨지면 안 된다.
- native 는 "실제 연결을 쓰는 모드" 이므로 임의 high-port 우회보다 정확성이 우선이다.
- 따라서 특정 옵션이 native 에서 무시되더라도, 결과와 `observer_events` 에 그 사실이 드러나야 한다.
