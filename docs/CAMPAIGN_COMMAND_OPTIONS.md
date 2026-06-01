# Campaign Command Options

이 문서는 real-UE 경로에서 짧은 간격으로 SIP `MESSAGE`를 반복 송신하는 campaign 명령의 옵션을 설명한다. 특정 메서드 문서가 아니라 campaign command options 기준으로 정리한다.

## 기본 명령

```bash
uv run fuzzer campaign run --methods MESSAGE --mt --layer byte --strategy identity --max-cases 30 --cooldown 0 --timeout 1 --output message-native-burst
```

## 장시간 고속 실행

timeout/unknown이 10회 연속 나오면 기본 circuit breaker가 캠페인을 중단한다. 응답 verdict와 pcap/ADB 근거를 유지하면서 오래 돌릴 때는 breaker만 끈다.

```bash
sudo uv run fuzzer campaign run --methods MESSAGE --mt --layer byte --strategy default --max-cases 10000 --cooldown 0 --timeout 0.01 --circuit-breaker 0
```

송신량 우선으로 pcap과 ADB 오버헤드까지 줄일 때는 아래처럼 실행한다. 이 모드는 crash/packet 증거 수집력이 떨어지므로 장시간 부하용으로만 쓴다.

```bash
sudo uv run fuzzer campaign run --methods MESSAGE --mt --layer byte --strategy default --max-cases 10000 --cooldown 0 --timeout 0.01 --circuit-breaker 0 --no-pcap --no-adb --oracle-log-grace 0
```

timeout budget를 더 공격적으로 줄여도 된다. 단, native 경로에는 socket timeout 밖의 고정 비용이 있으므로 `--timeout 0.001`로 낮춰도 case wall time이 1ms가 되지는 않는다.

```bash
sudo uv run fuzzer campaign run --methods MESSAGE --mt --layer byte --strategy default --max-cases 10000 --cooldown 0 --timeout 0.001 --circuit-breaker 0 --no-pcap --no-adb --oracle-log-grace 0
```

## 속도 병목과 한계

1. `--mt`를 생략하면 다른 경로를 탄다. `--methods MESSAGE --layer wire --strategy default`만 쓰면 출력이 `MESSAGE legacy:wire/default`로 나오며, 이 문서의 MT MESSAGE byte burst 경로가 아니다. native MESSAGE burst 기준 명령은 `--mt --layer byte`를 포함한다.
2. pcap은 case마다 최소 100ms 오버헤드가 있다. `PcapCapture.start()`는 case별 `tcpdump`를 띄운 뒤 캡처 준비를 위해 `time.sleep(0.1)`을 수행한다. 고속 부하에서는 `--no-pcap`을 써야 이 비용을 없앨 수 있다.
3. ADB/log oracle도 case 처리 비용을 만든다. real-UE에서는 ADB가 자동 활성화된다. 송신량만 우선할 때는 `--no-adb --oracle-log-grace 0`으로 logcat 수집과 grace polling을 줄인다.
4. native IPsec은 timeout보다 느릴 수 있다. native sender는 case마다 `docker exec pcscf python3 -c ...` injector를 실행하고, 필요 시 P-CSCF log observer를 확인한다. 따라서 `--timeout 0.01`이나 `--timeout 0.001`을 줘도 docker exec, xfrm/session resolve, packet normalization 비용은 남는다.
5. 현재 옵션만으로는 fire-and-forget/send-only 모드가 없다. 응답 대기와 oracle 판정을 완전히 건너뛰고 "그냥 쏘기만" 하는 진짜 초고속 경로는 별도 `send-only`류 옵션을 구현해야 한다.

## 확인 기준

옵션 기본값과 불일치 여부는 2026-06-01 기준 아래 소스를 확인해 작성했다.

- `uv run fuzzer campaign run --help`
- `src/volte_mutation_fuzzer/campaign/cli.py`
- `src/volte_mutation_fuzzer/campaign/contracts.py`
- `src/volte_mutation_fuzzer/campaign/core.py`

## 명령 옵션

| 옵션 | 명령 값 | CLI 기본값 | 실제 효과 |
| --- | --- | --- | --- |
| `uv run fuzzer campaign run` | - | - | `uv` 환경에서 campaign runner를 실행한다. |
| `--mode` | 생략 | `real-ue-direct` | CLI 기준 기본 실행 경로가 실기기 direct sender다. softphone을 대상으로 할 때는 `--mode softphone`을 명시해야 한다. |
| `--target-msisdn` | 생략 | `111111` in `real-ue-direct` | 대상 UE 식별자다. native IPsec 세션 resolve와 real-UE Contact resolve에 필요하다. |
| `--methods` | `MESSAGE` | 전체 SIP method set | 이 명령에서는 SIP `MESSAGE` case만 생성한다. |
| `--mt` | enabled | `False` / `--no-mt` | MT 패킷 생성 경로를 사용한다. `MESSAGE`에서는 SMS-over-IMS용 binary `application/vnd.3gpp.sms` body를 만든다. |
| `--ipsec-mode` | 생략 | `native` in `real-ue-direct` | 실제 협상된 xfrm/IPsec 세션을 사용한다. `ipsec` alias는 내부에서 `native`로 정규화된다. |
| `--layer` | `byte` | `model,wire,byte` | binary SMS body를 보존하기 위해 byte layer를 명시한다. |
| `--strategy` | `identity` | CLI 입력 기본은 `None`; legacy profile에서는 최종적으로 `default,state_breaker` | 변이 없이 baseline payload를 반복 송신한다. fuzzing으로 전환할 때는 `--strategy default`를 사용한다. |
| `--max-cases` | `30` | `1000` | 총 30개 case를 실행한다. |
| `--cooldown` | `0` | `0.2` | case 사이 대기 시간을 두지 않는다. |
| `--timeout` | `1` | `5.0` | 각 case 응답 대기 시간을 1초로 제한한다. |
| `--output` | `message-native-burst` | `None` / 자동 생성 | 결과 디렉터리 label로 사용한다. |

## 관련 기본값

| 옵션 | 기본값 | 비고 |
| --- | --- | --- |
| `--transport` | `UDP` | native IPsec MESSAGE burst는 보통 UDP 그대로 둔다. |
| `--target-host` | `None` | `--target-msisdn`으로 UE IP를 live resolve한다. |
| `--target-port` | `5060` | real-UE + MSISDN resolve 경로에서는 MT protected port가 live resolve된다. |
| `--profile` | `legacy` | mutation profile 기본값이다. |
| `--mutations-per-case` | `1` | case 하나당 변이 적용 횟수다. |
| `--seed-start` | `0` | 첫 case seed다. |
| `--from-msisdn` | `222222` | MT MESSAGE의 SMS originator 기본값으로 쓰인다. |
| `--mt-local-port` | `15100` | `native`에서는 authoritative 하지 않고, null/bypass 경로의 Via/bind port에 중요하다. |
| `--pcap` | `None` 입력 후 real-UE에서 자동 활성 | real-UE mode에서는 validator가 pcap을 켠다. |
| `--pcap-interface` | `any` 입력 후 real-UE에서 `br-volte` | CLI help에는 `any`가 보이지만 runtime에서 보정된다. |
| `--adb` | `None` 입력 후 real-UE에서 자동 활성 | `--ios`를 켜고 ADB를 명시하지 않으면 ADB는 꺼진다. |
| `--ios` | `False` | iPhone syslog/crash report 수집은 명시적으로 켠다. |
| `--oracle-log-grace` | method-aware | real-UE 기준 INVITE는 8초, MESSAGE 같은 stateless method는 1초다. |
| `--wait-idle-timeout` | `10.0` | INVITE call-state idle 대기용이라 MESSAGE burst에는 영향이 작다. |
| `--circuit-breaker` | `10` | timeout/unknown verdict가 연속 N회 나오면 중단한다. |

## 전체 옵션 체크리스트

아래 표는 `campaign run`의 CLI 옵션 전체를 기준으로 한다. "최종 기본값"은 CLI 입력 기본값과 validator/runtime 보정이 다른 경우를 함께 적었다.

| 옵션 | 입력 기본값 | 최종 기본값 / 보정 | 사용 위치 |
| --- | --- | --- | --- |
| `--target-host` | `None` | 생략 시 `--target-msisdn`으로 live resolve | 직접 UE IP 또는 softphone host를 지정할 때 사용한다. |
| `--target-port` | `5060` | real-UE MSISDN/native 경로에서는 protected port가 별도 resolve될 수 있음 | 일반 SIP socket 대상 포트다. |
| `--methods` | `None` | method와 response code가 모두 없으면 전체 SIP method set | `MESSAGE`처럼 fuzz 대상 메서드를 좁힌다. |
| `--response-codes` | `None` | 생략 시 request method campaign | SIP response fuzzing 대상 status code 목록이다. |
| `--with-dialog` / `--no-with-dialog` | `None` | `False` | 필요한 request generation에 합성 dialog context를 붙인다. |
| `--strategy` | `None` | 일반 campaign: `default`, legacy 보정 후 `default,state_breaker`; packet-file: `identity` | `identity` baseline 또는 `default` fuzzing 선택. |
| `--profile` | `None` | `legacy` | mutation policy 축이다. |
| `--layer` | `None` | 일반 campaign: `model,wire,byte`; packet-file: `byte` | MESSAGE native burst에서는 보통 `byte`로 고정한다. |
| `--max-cases` | `1000` | 동일 | 총 case 수. 장시간 실행은 `10000` 이상으로 늘린다. |
| `--mutations-per-case` | `1` | 동일 | 한 case에 변이를 여러 번 stacking한다. |
| `--timeout` | `5.0` | 동일 | 응답 대기 시간. 고속 송신은 `0.01`처럼 낮춘다. |
| `--cooldown` | `0.2` | 동일 | case 사이 대기. burst는 `0`을 쓴다. |
| `--oracle-log-grace` | `None` | INVITE: 8초, 그 외 stateless method: 1초 | `0`으로 낮추면 로그 대기 오버헤드를 줄인다. |
| `--wait-idle-timeout` | `10.0` | 동일 | INVITE call state idle 대기. MESSAGE에는 영향이 작다. |
| `--seed-start` | `0` | 동일 | 재현 시작 seed다. |
| `--output` | `None` | `results/YYYYMMDD_HHMMSS_xxxxxxxx` 자동 생성 | 결과 디렉터리 이름을 고정한다. |
| `--process-name` | `baresip` | real-UE에서는 process check가 자동 비활성화될 수 있음 | softphone process liveness check 대상이다. |
| `--no-process-check` | `None` | real-UE mode에서는 자동 비활성화 | process liveness check를 끈다. |
| `--transport` | `UDP` | native IPsec은 현재 UDP/TCP만 허용, 일반적으로 UDP 사용 | SIP transport다. |
| `--mode` | `real-ue-direct` | 동일 | 기본 sender 실행 경로다. |
| `--log-path` | `None` | 생략 시 target process log 검사 없음 | stack trace 탐지용 로그 파일 경로다. |
| `--adb` / `--no-adb` | `None` | real-UE에서는 자동 활성, `--ios`와 함께 명시 없으면 꺼짐 | `--no-adb`는 고속 송신에서 logcat 오버헤드를 줄인다. |
| `--adb-serial` | `None` | 생략 시 adb 기본 선택 | 여러 Android 기기가 붙은 경우 지정한다. |
| `--adb-buffers` | `None` | config 기본 logcat buffer set 사용 | `main,system,radio,crash`처럼 수집 버퍼를 제한한다. |
| `--ios` / `--no-ios` | `False` | 동일 | iPhone syslog/crash report 수집을 켠다. |
| `--ios-udid` | `None` | USB iPhone 1대면 auto resolve | 대상 iPhone UDID다. |
| `--ios-filter-processes` | `None` | config 기본 process filter set 사용 | `idevicesyslog -p` process filter다. |
| `--ios-diagnostics` / `--no-ios-diagnostics` | `False` | 동일 | case별 diagnostics 실행. 느리므로 burst에서는 보통 끈다. |
| `--pcap` / `--no-pcap` | `None` | real-UE에서는 자동 활성 | `--no-pcap`은 고속 송신에서 tcpdump 오버헤드를 줄인다. |
| `--pcap-interface` | `any` | real-UE에서 `br-volte`로 보정 | tcpdump capture interface다. |
| `--target-msisdn` | `None` | real-UE CLI에서 `111111` 주입 | UE Contact, xfrm state, native IPsec resolve 기준이다. |
| `--impi` | `None` | resolver가 Contact user를 IMPI로 사용, 실패 시 `VMF_IMPI` fallback | Contact user/IMPI 자동 resolve가 실패할 때만 명시한다. |
| `--mt` / `--no-mt` | `False` | `--mt`가 template을 `3gpp`로 켬 | MESSAGE에서는 SMS-over-IMS MT packet bytes 경로를 사용한다. |
| `--mt-invite-template` | `None` | `--mt` 사용 시 `3gpp` | INVITE template 이름 또는 파일 경로다. |
| `--packet-file` | `None` | 사용 시 method/layer/strategy가 verbatim contract로 보정 | raw SIP 파일을 변이 없이 보낼 때 사용한다. `--mt`와 상호배타다. |
| `--ipsec-mode` | `None` | real-UE CLI에서 `native` 주입, `ipsec`은 native alias | native/null/bypass 송신 경로를 고른다. |
| `--preserve-via` / `--no-preserve-via` | `False` | `--mt` + non-native에서는 자동 보존 | Via host/port rewrite를 막는다. |
| `--preserve-contact` / `--no-preserve-contact` | `False` | `--mt` + non-native에서는 자동 보존 | Contact host/port rewrite를 막는다. |
| `--pixel` / `--no-pixel` | `False` | 동일 | Request-URI를 resolved UE Contact URI로 바꿔 Pixel/Shannon IMS 호환성을 높인다. |
| `--mo-contact-host` | `10.20.20.9` | 동일 | MT INVITE Contact의 originating UE IP다. |
| `--mo-contact-port-pc` | `31800` | 동일 | MO UE protected client port다. |
| `--mo-contact-port-ps` | `31100` | 동일 | MO UE protected server port다. |
| `--from-msisdn` | `222222` | 동일 | MT INVITE/MESSAGE의 originating identity다. |
| `--mt-local-port` | `15100` | native에서는 authoritative 하지 않음 | null/bypass MT 경로의 local port/Via sent-by 동기화에 쓴다. |
| `--crash-analysis` / `--no-crash-analysis` | `False` | 동일 | 실시간 crash analysis/reporting을 켠다. |
| `--resume` / `--no-resume` | `False` | 동일 | 기존 output checkpoint에서 이어서 실행한다. |
| `--circuit-breaker` | `10` | `0`이면 비활성화 | timeout/unknown 연속 N회에서 abort한다. 장시간 timeout campaign은 `0`을 쓴다. |

## Report / Replay 옵션

실행 옵션은 아니지만 같은 `fuzzer campaign` 하위 명령에서 결과 확인과 재현에 쓰는 옵션이다.

| 명령 | 옵션 | 기본값 | 의미 |
| --- | --- | --- | --- |
| `campaign report <path>` | `--filter` | `None` | verdict 목록으로 case를 필터링한다. 예: `--filter suspicious,crash,stack_failure` |
| `campaign report <path>` | `--html` | `False` | JSONL 결과에서 standalone HTML report를 생성한다. |
| `campaign replay <path>` | `--case-id` | 필수 | 지정한 case의 reproduction command를 다시 실행한다. |

## 확인된 불일치와 주의점

1. `--mt` help 문구가 부정확하다. CLI help는 "MT-INVITE format for all packets"라고 표시하지만, 실제 `MESSAGE` 경로는 MT-INVITE 템플릿이 아니라 binary SMS-over-IMS packet bytes를 생성한다.
2. `--target-msisdn` help 문구는 Typer 기본값 칸과 다르게 보일 수 있다. 현재 help는 real-UE target resolution과 기본값 `111111`을 설명하지만, Typer 기본값 칸에는 내부 주입 기본값이 별도로 표시되지는 않는다.
3. `--pcap-interface` 기본값 표시는 runtime과 다르다. CLI help는 `any`를 기본값으로 보여주지만, `real-ue-direct`에서는 config validator가 `br-volte`로 바꾼다.
4. `--strategy`의 CLI 입력 기본값과 최종 기본값이 다르다. 함수 시그니처 기본값은 `None`이고, 일반 campaign에서는 `default`로 시작한 뒤 legacy profile이면 `default,state_breaker`로 보정된다. 이 문서의 기본 명령은 `identity`를 명시하므로 이 보정을 타지 않는다.
5. `--layer`와 실제 MESSAGE 처리 layer가 다를 수 있다. 옵션을 생략하면 case 생성은 `model,wire,byte`로 잡히지만, MT `MESSAGE` binary payload는 body 손상을 피하기 위해 실행 시 byte mutation path로 강제된다.
6. CLI 기본 mode와 `CampaignConfig` 기본 mode가 다르다. `campaign run` CLI 기본값은 `real-ue-direct`지만, Python에서 `CampaignConfig()`를 직접 만들면 class field 기본값은 아직 `softphone`이다.
7. `--ipsec-mode` 생략 시 최종값은 상황 의존적이다. CLI 입력 기본은 `None`이지만, `campaign run`의 기본 mode가 `real-ue-direct`이므로 별도 지정이 없으면 최종적으로 `native`가 들어간다. `--mode softphone` 경로에는 이 기본값을 주입하지 않는다.

## 추천 실행 순서

1. 먼저 `--strategy identity --max-cases 3`으로 baseline 응답을 확인한다.
2. 응답이 안정적이면 `--max-cases 30 --cooldown 0`으로 단기 burst를 돌린다.
3. baseline이 안정적일 때만 `--strategy default`로 변이 fuzzing을 시작한다.

## 결과 확인

실행 후 campaign output 디렉터리의 `results.jsonl`에서 case별 verdict와 observer event를 확인한다.

```bash
uv run fuzzer campaign report results.jsonl --filter suspicious,crash,stack_failure
```

`native` 모드는 outer wire에서 평문 SIP가 아니라 ESP로 보일 수 있으므로, pcap의 평문 가독성보다 campaign 결과와 observer event를 기준으로 본다.
