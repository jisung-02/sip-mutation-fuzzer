# Real-UE Operations

현재 운영 기준은 `real-ue-direct` 와 실기기 UE 대상 퍼징이다.
Softphone 경로는 회귀/로컬 smoke 용도로만 보고, 별도 요청이 있을 때만
중심 문서로 다룬다.

## Code-Checked Defaults

`campaign run` CLI가 보장하는 현재 기본값은 아래다.

- `--mode real-ue-direct`
- real-UE target MSISDN: `111111`
- real-UE IPsec mode: `native`
- default profile: `legacy`
- default layers: `model,wire,byte`
- legacy default strategies: `default,state_breaker`

저장소에는 현재 testbed의 고정 MSISDN/device/IP 표를 두지 않는다. UE IP,
protected port, device slot은 `kamctl`, P-CSCF logs, xfrm state에서 매 실행
확인하는 live state로 취급한다.

## Baseline First

퍼징 전에는 identity baseline을 먼저 확인한다. 대상이 기본 `111111`이면
`--target-msisdn`은 생략 가능하지만, 운영 로그를 읽기 쉽게 하기 위해 명시해도
된다.

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --methods INVITE \
  --profile legacy \
  --layer wire \
  --strategy identity \
  --ipsec-mode native \
  --preserve-contact --preserve-via \
  --max-cases 1
```

기대값:

- UE가 attach/register 상태다.
- `INVITE` baseline에서 `180` 또는 `200` 계열 응답이 관측된다.
- 결과는 `normal`이어야 한다.

## Native IPsec

현재 real-UE 기본값은 다음과 같다.

- `--target-msisdn 111111`
- `--ipsec-mode native`
- `--mode real-ue-direct`

`native`는 P-CSCF live xfrm state와 `Security-Client` / protected port 매핑을
사용한다. 외부 pcap에서 평문 SIP가 바로 보이지 않을 수 있으므로,
`observer_events`, `responses`, `results.jsonl`을 우선 본다.

## Null / Bypass

`null`과 `bypass`는 비교 실험용 경로다.

- `null`: P-CSCF namespace를 통한 plaintext path
- `bypass`: P-CSCF namespace에서 xfrm policy bypass를 적용하는 path

현재 기본 실험은 `native`다. `null`/`bypass`는 native 경로와 비교하거나
환경을 좁혀 디버깅해야 할 때만 명시한다.

## Focused Fuzzing Examples

Pixel-oriented profile:

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --methods INVITE \
  --pixel \
  --profile pixel_ims \
  --layer wire,byte \
  --strategy default \
  --ipsec-mode native \
  --max-cases 50
```

iPhone-oriented profile with iOS evidence collection:

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn <MSISDN> \
  --methods INVITE \
  --profile iphone_ims \
  --layer wire,byte \
  --strategy default \
  --ipsec-mode native \
  --ios \
  --max-cases 50
```

## Evidence

Real-UE run에서 의미 있는 evidence는 아래 순서로 본다.

1. `results.jsonl` case verdict and `observer_events`
2. `sent.sip`, `response.sip`
3. pcap, native 모드에서는 ESP 여부와 별개로 보조 자료
4. Android ADB snapshot 또는 iOS syslog/crash report
5. campaign HTML/report output
