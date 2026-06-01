# MESSAGE native burst 명령 옵션 설명

이 문서는 real-UE 경로에서 SIP `MESSAGE`를 짧은 간격으로 여러 번 보내는
명령과 각 옵션의 의미를 정리한다.

기본 명령:

```bash
uv run fuzzer campaign run --target-msisdn 222222 --methods MESSAGE --mt --ipsec-mode native --layer byte --strategy identity --max-cases 30 --cooldown 0 --timeout 1 --output message-native-burst
```

## 목적

이 명령은 현재 testbed에 등록된 UE를 대상으로 `MESSAGE`를 반복 송신해
baseline 응답성, native IPsec 경로, SMS-over-IMS MESSAGE 처리 상태를 짧게
확인하는 용도다.

`--strategy identity`를 쓰면 변이 없이 같은 계열의 baseline MESSAGE를 반복
전송한다. 실제 fuzzing으로 전환하려면 `--strategy default`로 바꾼다.

## 옵션별 의미와 기본값

| 옵션 | 명령에서 지정한 값 | 생략 시 기본값 | 의미 |
| --- | --- | --- | --- |
| `uv run fuzzer campaign run` | - | - | `uv` 환경에서 fuzzer의 campaign runner를 실행한다. |
| `--mode` | 생략 | `real-ue-direct` | softphone이 아니라 실제 UE로 직접 보내는 sender 경로를 사용한다. softphone 대상이면 `--mode softphone`을 명시한다. |
| `--target-msisdn` | `222222` | `None` | 대상 UE의 MSISDN이다. 현재 testbed 기준 iPhone 16e 슬롯이다. |
| `--methods` | `MESSAGE` | 전체 SIP method set | SIP `MESSAGE` 메서드만 실행한다. |
| `--mt` | enabled | `False` (`--no-mt`) | real-UE용 MT 패킷 생성 경로를 사용한다. `MESSAGE`에서는 SMS-over-IMS용 바이너리 `application/vnd.3gpp.sms` 바디를 만든다. |
| `--ipsec-mode` | `native` | `None`; `--mt` 경로에서는 최종적으로 `null` | 등록된 UE의 live xfrm/IPsec 세션을 사용한다. 평문 UDP 우회가 아니라 실제 native IPsec 경로를 탄다. |
| `--layer` | `byte` | `model,wire,byte` | 바이너리 SMS payload를 보존하기 위해 byte 레이어를 사용한다. |
| `--strategy` | `identity` | `default` | 변이 없이 baseline payload를 보낸다. |
| `--max-cases` | `30` | `1000` | 총 30개 case를 실행한다. 반복 횟수를 늘리거나 줄일 때 바꾼다. |
| `--cooldown` | `0` | `0.2` | case 사이 대기 시간을 두지 않는다. 단기 burst 용도다. |
| `--timeout` | `1` | `5.0` | 각 case 응답 대기 시간을 1초로 제한한다. |
| `--output` | `message-native-burst` | `None` (자동 생성) | campaign 결과 디렉터리 이름에 사용할 label이다. |

## 관련 기본값

이 명령에는 직접 쓰지 않았지만, 같은 경로에서 자주 영향을 주는 기본값은
아래와 같다.

| 옵션 | 생략 시 기본값 | 비고 |
| --- | --- | --- |
| `--transport` | `UDP` | native IPsec MESSAGE burst는 보통 UDP 그대로 둔다. |
| `--target-host` | `None` | `--target-msisdn`으로 UE IP를 live resolve한다. |
| `--target-port` | `5060` | real-UE + MSISDN resolve 경로에서는 protected port가 live resolve된다. |
| `--profile` | `legacy` | mutation profile 기본값이다. |
| `--mutations-per-case` | `1` | case 하나당 변이 적용 횟수다. |
| `--seed-start` | `0` | 첫 case seed다. |
| `--from-msisdn` | `222222` | MT MESSAGE의 SMS originator 기본값으로 쓰인다. |
| `--mt-local-port` | `15100` | `native`에서는 authoritative 하지 않고, null/bypass 경로의 Via/bind port에 중요하다. |
| `--pcap` | mode-aware | `real-ue-direct`에서는 자동 활성화된다. |
| `--pcap-interface` | `any`; real-UE에서는 `br-volte` | `real-ue-direct` validator가 `any`를 `br-volte`로 보정한다. |
| `--adb` | mode-aware | `real-ue-direct`에서는 자동 활성화된다. iOS `--ios`를 켜면 기본적으로 ADB는 꺼진다. |
| `--ios` | `False` | iPhone syslog/crash report 수집은 명시적으로 켠다. |
| `--oracle-log-grace` | method-aware | `MESSAGE` 같은 stateless method는 기본 1초다. |
| `--wait-idle-timeout` | `10.0` | INVITE call-state idle 대기용이라 MESSAGE burst에는 실질 영향이 작다. |
| `--circuit-breaker` | `10` | timeout/unknown verdict가 연속 N회 나오면 중단한다. `0`이면 비활성화한다. |

## 왜 `--mt`를 쓰는가

현재 `MESSAGE`의 SMS-over-IMS 송신은 `--mt` 경로에서 바이너리 packet bytes로
생성된다. 이 경로는 SIP 헤더는 ASCII로 만들고, `\r\n\r\n` 뒤의 SMS RP-DATA
바디는 bytes로 유지한다.

따라서 `MESSAGE` 단기 반복 검증에서는 `--mt-invite-template`를 쓰지 않고
`--mt`만 사용한다.

## 자주 바꾸는 값

대상 UE를 바꿀 때:

```bash
--target-msisdn 111111
```

반복 횟수를 줄일 때:

```bash
--max-cases 5
```

짧은 간격은 유지하되 UE 부담을 조금 낮출 때:

```bash
--cooldown 0.2
```

변이 fuzzing으로 전환할 때:

```bash
--strategy default
```

결과 디렉터리 label을 바꿀 때:

```bash
--output message-native-burst-$(date +%Y%m%d-%H%M%S)
```

## 실행 전 확인사항

- 대상 UE가 IMS testbed에 attach/register 되어 있어야 한다.
- `native` 모드는 live xfrm/IPsec state가 있어야 한다.
- `--target-msisdn`은 native IPsec 세션 resolve에 필요하므로 생략하지 않는다.
- `VMF_IMPI` 또는 resolver가 대상 IMPI를 제공할 수 있어야 한다.
- `VMF_REAL_UE_PCSCF_IP`가 필요한 환경이면 올바른 P-CSCF IP로 설정한다.

예:

```bash
export VMF_REAL_UE_PCSCF_IP=172.22.0.21
```

## 결과 확인

실행 후 campaign output 디렉터리의 `results.jsonl`에서 case별 verdict와
observer event를 확인한다.

예:

```bash
uv run fuzzer campaign report results.jsonl --filter suspicious,crash,stack_failure
```

`native` 모드는 outer wire에서 평문 SIP가 아니라 ESP로 보일 수 있다.
응답 확인은 pcap의 평문 가독성보다 campaign 결과와 observer event를 기준으로
본다.

## 추천 사용 순서

1. 먼저 `--strategy identity --max-cases 3`으로 baseline 응답을 확인한다.
2. 응답이 안정적이면 `--max-cases 30 --cooldown 0`으로 단기 burst를 돌린다.
3. baseline이 안정적일 때만 `--strategy default`로 변이 fuzzing을 시작한다.
