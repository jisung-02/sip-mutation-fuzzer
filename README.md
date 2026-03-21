# 단말 지향 Mutation 기반 SIP 프로토콜 퍼저 설계 및 구현
## 주제 선정 배경 및 필요성
SIP는 VoIP, VoLTE, IMS 기반 메시징 등에서 세션을 설정·변경·종료하는 신호 프로토콜이다. SIP는 텍스트 기반 프로토콜이며 다양한 옵션 필드와 상태 기반 메시지 흐름을 가지기 때문에 구현 과정에서 파싱 오류나 상태 처리 오류로 인한 메모리 취약점이 발생할 가능성이 존재한다.
기존의 SIP 퍼징 연구는 대부분 서버를 대상으로 수행되어 왔으며, 사용자가 사용하는 단말을 대상으로 한 연구는 상대적으로 부족하다. 특히 상용 단말의 경우 소스코드 접근이 어렵기 때문에 정적 분석 기반 취약점 탐지보다 블랙박스 퍼징 형태의 접근이 요구된다.
또한 SIP는 단순한 메시지 포맷 뿐만 아니라 메시지간 상태 관계를 가지는 프로토콜이기 때문에 단순 랜덤 변조 방식의 퍼징으로는 의미 있는 테스트 케이스를 생성하기 어렵다. 따라서 RFC문서를 기반으로 정상 메시지를 생성하고 변조하는 Generation + Mutation 기반 퍼징 구조가 필요하다.
본 연구에서는 SIP RFC문서를 기반으로 정상 메시지를 생성하고 이를 변조하여 단말 방향으로 전달하는 Mutation 기반 SIP퍼저를 설계 및 구현하여 실제 단말 환경에서 발생 가능한 메모리 오류 및 크래시 징후를 탐지하는 것을 목표로 한다.

## 문서 구조
- [docs/README.md](docs/README.md): 전체 문서 인덱스
- [docs/기획/PRD.md](docs/기획/PRD.md): 프로젝트 목표, 범위, 요구사항, 완료 기준
- [docs/기획/GENERATOR_PRD.md](docs/기획/GENERATOR_PRD.md): Generator 상세 설계 문서
- [docs/기획/MUTATOR_PRD.md](docs/기획/MUTATOR_PRD.md): Mutator 상세 설계 문서 (model/wire/byte 변조 + Typer CLI 설계 포함)
- [docs/기획/PHASE4_PRD.md](docs/기획/PHASE4_PRD.md): Softphone-first Sender/Reactor 상세 설계 문서
- [docs/결과/GENERATOR-구현-결과.md](docs/결과/GENERATOR-구현-결과.md): Generator 구현 및 CLI 적용 결과
- [docs/결과/SIP-공격면-우선순위표.md](docs/결과/SIP-공격면-우선순위표.md): Tier 1~4 공격면 우선순위 문서
- [docs/프로토콜/단말-기준-SIP-메시지-분류.md](docs/프로토콜/단말-기준-SIP-메시지-분류.md): 단말 기준 SIP 메시지 전체 분류
- [docs/프로토콜/요청-패킷-예시.md](docs/프로토콜/요청-패킷-예시.md): 요청 패킷 예시 문서
- [docs/프로토콜/응답-패킷-예시.md](docs/프로토콜/응답-패킷-예시.md): 응답 패킷 예시 문서
- [docs/이슈/오픈-이슈.md](docs/이슈/오픈-이슈.md): 아직 결정되지 않은 설계/실험 이슈

## 프로젝트 주요 구성요소
1. Generator - SIP RFC 문서를 기반으로 하여 정상적인 SIP 메시지를 생성하는 모듈
2. Mutator - Generator가 생성한 메시지를 변조해 다양한 입력을 생성하는 모듈 (Typer 기반 CLI 구현)
3. Sender/Reactor - 생성된 메시지를 단말로 전송하고 단말의 응답 메시지를 처리하는 모듈
4. Oracle - 퍼징 과정에서 단말의 크래시 또는 이상 동작을 탐지하고 기록하는 모듈
5. Controller - ADB를 활용해 단말 동작을 제어하는 모듈



### SIP가 사용되는 영역
1. VoLTE - 인터넷(IP 네트워크)을 이용해 음성 통화를 하는 기술.
2. IP Phone - 인터넷에 직접 연결되는 전화기. 일반 전화선(PSTN)이 아니라 Ethernet + IP 네트워크를 사용한다.
3. Softphone - PC나 스마트폰에서 동작하는 전화 애플리케이션.
4. SMS - RFC 3428에서 정의된 SIP MESSAGE 메서드를 이용하면 텍스트 메시지를 보낼 수 있음
5. IP-PBX - 기업 내부 전화 시스템. 기존 전화 교환기(PBX)를 IP 네트워크로 구현한 것.
6. IMS - 통신사의 IP 멀티미디어 서비스 플랫폼.
7. VoWiFi / VoNR - 모바일 네트워크에서 IP 기반 음성 통화를 제공하는 기술.
8. 화상 회의 시스템 - 여러 사용자가 동시에 영상 통신을 하는 시스템.
9. Unified Communication - 기업 협업 플랫폼.
10. IoT / 인터콤 / CCTV

## Generator CLI 빠른 사용
Generator의 현재 CLI 엔트리포인트는 `project.scripts` 기준으로 **`fuzzer`** 이다.

초기 설정:

```bash
uv sync --dev
```

기본 request 생성:

```bash
uv run fuzzer request OPTIONS
```

response 생성:

```bash
uv run fuzzer response 200 INVITE --context '{"call_id":"call-1","local_tag":"ue-tag","local_cseq":7}'
```

환경 변수 기반 기본값 변경:

```bash
VMF_GENERATOR_REQUEST_URI_HOST=ims.example.net uv run fuzzer request OPTIONS
```

override 주입:

```bash
uv run fuzzer request OPTIONS --override '{"Max-Forwards": 10}'
```

CLI 상세 옵션:

```bash
uv run fuzzer --help
uv run fuzzer request --help
uv run fuzzer response --help
```

## Mutator CLI 빠른 사용
현재 루트 CLI `fuzzer` 아래에서 Mutator 서브커맨드를 사용할 수 있다.

Mutator CLI는 아래 두 가지 입력 모드를 지원한다.

1. **Generator CLI 출력 입력 모드**
   - Generator CLI가 출력한 JSON baseline을 stdin 또는 파일로 받아 변조 결과를 출력
   - 예시 목표 형태:

```bash
uv run fuzzer request OPTIONS | uv run fuzzer mutate packet --strategy header_chaos
```

2. **내부 generator 호출 모드**
   - Mutator CLI가 내부적으로 `SIPGenerator`를 호출해 baseline을 만든 뒤 곧바로 변조
   - 예시 목표 형태:

```bash
uv run fuzzer mutate request OPTIONS --strategy state_breaker
uv run fuzzer mutate response 200 INVITE --context '{"call_id":"call-1","local_tag":"ue-tag","local_cseq":7}'
```

사용자에게 기본적으로 노출할 옵션은 아래와 같다.

- `--strategy`
- `--layer`
- `--seed`
- `--target`
- `--max-operations`
- baseline 입력 관련 옵션
- 출력 포맷 관련 옵션

고급 사용자에게는 필요 시 아래 옵션을 추가로 노출할 수 있다.

- `--operator`
- `--byte-offset`
- `--byte-range`
- `--preserve-valid-model`

자세한 책임 분리와 내부 구현 원칙은 `docs/기획/MUTATOR_PRD.md`를 기준으로 한다.

## Sender/Reactor CLI 빠른 사용
Softphone-first Phase 4 1차 구현으로 `fuzzer send ...` 서브커맨드가 추가되었다.

baseline request를 바로 전송:

```bash
uv run fuzzer send request OPTIONS --target-host 127.0.0.1 --target-port 5060
```

Generator JSON을 바로 송신:

```bash
uv run fuzzer request OPTIONS | uv run fuzzer send packet --target-host 127.0.0.1 --target-port 5060
```

Mutator wire/model 결과를 바로 송신:

```bash
uv run fuzzer mutate request OPTIONS --layer wire | uv run fuzzer send packet --target-host 127.0.0.1 --target-port 5060
```

`send packet`은 다음 stdin 입력을 지원한다.
- Generator packet JSON
- Mutator result JSON
- raw SIP wire text

현재 outcome 분류는 다음을 반환한다.
- `success`
- `provisional`
- `error`
- `timeout`
- `invalid_response`
- `send_error`

## real-ue-direct(dumpipe) quick start
현재 브랜치에는 **실제 UE IMS IP로 직접 송신하는 `real-ue-direct` 경로**가 포함된다.
이 경로는 capstone의 dumpipe 아이디어를 현재 sender에 맞게 좁혀 넣은 것이다.

제약:
- 1차 구현은 **UDP only**
- `--target-host` 또는 `--target-msisdn` 중 하나만 사용
- 시스템 route는 자동 변경하지 않고, **route readiness check만 수행**
- `--target-msisdn` 경로는 **등록된 UE contact**가 resolver에서 보일 때만 동작

직접 UE IMS IP를 알고 있을 때:

```bash
uv run fuzzer send request OPTIONS \
  --mode real-ue-direct \
  --target-host 10.20.20.2 \
  --target-port 5060
```

MSISDN으로 contact를 풀 때:

```bash
uv run fuzzer send request OPTIONS \
  --mode real-ue-direct \
  --target-msisdn 222222
```

resolver 기본값은 capstone 실험망을 따른다.
- `VMF_REAL_UE_SCSCF_CONTAINER` (default: `scscf`)
- `VMF_REAL_UE_PCSCF_CONTAINER` (default: `pcscf`)
- `VMF_REAL_UE_PYHSS_URL` (optional)
- `VMF_REAL_UE_PCSCF_LOG_TAIL` (default: `500`)

CLI 결과의 `observer_events`에는 resolver, route check, direct normalization 정보가 함께 기록된다.

## Softphone 실행 quick start
현재 브랜치에는 **Baresip 실행용 poe task** 가 포함된다.
이번 task는 softphone **설치나 SIP 계정 provisioning을 자동화하지 않고**, 이미 준비된 로컬 Baresip 실행만 담당한다.

필수 환경 변수:
- `VMF_SOFTPHONE_CONFIG_DIR`: 기존 Baresip 설정 디렉터리 경로

선택 환경 변수:
- `VMF_SOFTPHONE_BIN`: `baresip` 바이너리 경로 (미지정 시 PATH에서 검색)
- `VMF_SOFTPHONE_ARGS`: Baresip에 그대로 넘길 추가 인자

예시:

```bash
VMF_SOFTPHONE_CONFIG_DIR=$HOME/.baresip poe softphone-run
```

별도 터미널에서 sender와 함께 사용할 수 있다.

```bash
uv run fuzzer send request OPTIONS --target-host 127.0.0.1 --target-port 5060
```

## CI / 품질 체크
이 저장소에는 GitHub Actions 기반 CI가 포함되어 있으며, pull request마다 아래 검사를 수행한다.

- `uv run ruff check .`
- `uv run ruff format --check .`
- `uv run ty check`

워크플로 파일:
- `.github/workflows/ci.yml`

로컬에서도 동일하게 아래 순서로 재현할 수 있다.

```bash
uv sync --dev
uv run ruff check .
uv run ruff format --check .
uv run ty check
```

## 구현 및 분류에 참고한 주요 RFC
- RFC 3261 - SIP 기본 프로토콜: https://www.rfc-editor.org/rfc/rfc3261
- RFC 3262 - PRACK / Reliable Provisional Response: https://www.rfc-editor.org/rfc/rfc3262
- RFC 3311 - UPDATE Method: https://www.rfc-editor.org/rfc/rfc3311
- RFC 3329 - Security Agreement / 494: https://www.rfc-editor.org/rfc/rfc3329
- RFC 3428 - MESSAGE Method: https://www.rfc-editor.org/rfc/rfc3428
- RFC 3515 - REFER Method: https://www.rfc-editor.org/rfc/rfc3515
- RFC 3903 - PUBLISH Method: https://www.rfc-editor.org/rfc/rfc3903
- RFC 5360 - Consent / 470: https://www.rfc-editor.org/rfc/rfc5360
- RFC 5839 - 204 No Notification: https://www.rfc-editor.org/rfc/rfc5839
- RFC 6086 - INFO Package Framework: https://www.rfc-editor.org/rfc/rfc6086
- RFC 6442 - 424 Bad Location Information: https://www.rfc-editor.org/rfc/rfc6442
- RFC 6665 - SUBSCRIBE / NOTIFY framework: https://www.rfc-editor.org/rfc/rfc6665
- RFC 7647 - REFER response updates (202 deprecation context): https://www.rfc-editor.org/rfc/rfc7647
- RFC 8197 - 607 Unwanted: https://www.rfc-editor.org/rfc/rfc8197
- RFC 8599 - 555 Push Notification Service Not Supported: https://www.rfc-editor.org/rfc/rfc8599
- RFC 8688 - 608 Rejected: https://www.rfc-editor.org/rfc/rfc8688
- RFC 8876 - 425 Bad Alert Message: https://www.rfc-editor.org/rfc/rfc8876
