# Phase 4 후속 리서치: 실제 UE(SDR/USRP) 경로와 Softphone 경로

기준 일자: 2026-03-18

## 1. 문서 목적
이 문서는 기존 `Phase 4 Sender/Reactor 사전 리서치`의 후속 문서다.

이번 문서는 아래 두 질문에만 집중한다.

1. **SDR/USRP를 활용한 실제 UE 경로를 Phase 4 Sender에서 지원할 수 있는가**
2. **Softphone 경로를 Phase 4 Sender에서 지원할 수 있는가**

즉, Phase 4의 target mode를 아래처럼 둘 수 있는지 상세하게 검토한다.

- `real-ue`
- `softphone`

## 2. 이번 후속 조사에서 먼저 확정한 해석
### 2.1 “SDR/USRP로 실제로 보낸다”의 의미
이 표현은 구현 관점에서 두 가지로 갈라진다.

#### A. 현실적인 의미
- USRP/srsRAN/Open5GS/Kamailio로 실제 LTE/IMS 망을 띄운다
- 상용 UE를 해당 망에 attach/register 시킨다
- Sender는 **IP/SIP 레벨에서** P-CSCF나 UE IMS IP로 패킷을 전달한다

이건 **Phase 4 범위 안**이다.

#### B. 비현실적인 의미
- Sender 자체가 UHD/USRP를 직접 제어해 RF 샘플을 만들고
- LTE 무선 계층까지 직접 송신한다

이건 **Phase 4 범위를 크게 넘는다.**
사실상 RAN/PHY 프로젝트다.

이번 문서는 A만 현실적 후보로 본다.

### 2.2 “softphone 연결”의 의미
이번 문서에서는 softphone을 다음처럼 정의한다.

- SIP account로 등록 가능한 software user agent
- desktop/mobile app 또는 라이브러리 기반 test UA
- Sender/Reactor 검증용 target 또는 peer

즉 softphone은 아래 두 역할을 할 수 있다.

- `manual target`: 사람이 직접 계정 등록하고 호출/응답 확인
- `programmable target`: 스크립트/SDK/CLI로 자동 반응 가능

## 3. 실제 UE(SDR/USRP) 경로 조사
## 3.1 가능한가
### 결론
`공식 문서 확인 + 추론`

**가능하다.**
그리고 단순한 이론적 가능성이 아니라, Open5GS와 srsRAN 공식 자료만 봐도 현실적인 경로다.

### 근거 1: Open5GS 공식 VoLTE 문서
Open5GS는 공식 문서에 Kamailio IMS 기반 VoLTE setup과 Dockerized VoLTE setup을 제공한다.

특히 Dockerized VoLTE 문서에는 다음 성격의 구성이 나온다.

- Sysmocom USIM 사용
- srsENB 또는 commercial eNB 사용 가능
- commercial smartphone 테스트 사례 존재
- IMS 전용 UE IPv4 대역(`UE_IPV4_IMS`) 운영

이건 “프로그래밍된 SIM + 상용 단말 + 실험망”이 공식 문서 수준에서도 충분히 성립하는 경로라는 뜻이다.

### 근거 2: srsRAN 공식 문서
srsRAN 공식 문서에는 COTS UE(상용 UE)와 SDR 조합이 정리되어 있다.

특히 확인되는 점:
- USRP B210/B200mini/X410 등의 SDR 조합
- Pixel, OnePlus, Samsung 등 상용 UE 동작 기록
- 일부 항목은 Sysmocom test SIM 조합 명시

즉, USRP 계열 장비로 실제 UE를 붙이는 것 자체는 실험적으로 충분히 현실적이다.

### 근거 3: Ettus USRP 공식 자료
Ettus 공식 자료는 B210을 70 MHz-6 GHz, 2Tx/2Rx, UHD 지원 SDR로 설명한다.
즉, Phase 4 관점에서는 “radio path를 구성하기 위한 실험 장비”로 쓰는 것이 맞다.

## 3.2 Phase 4에 넣을 수 있는 real-ue mode의 실제 형태
실제 UE 경로는 다시 둘로 나뉜다.

### `real-ue / pcscf`
흐름:
- UE는 SDR/RAN을 통해 Open5GS + Kamailio IMS에 attach/register
- Sender는 P-CSCF 쪽으로 SIP를 전송
- Reactor는 소켓 응답, siptrace, sniffer, pcap 등을 통해 반응을 모은다

장점:
- 실제 IMS signalling path에 가깝다
- network-realistic behavior를 볼 수 있다
- Kamailio trace와 결합하기 쉽다

단점:
- malformed packet은 P-CSCF에서 먼저 드랍될 수 있다
- UE까지 도달하지 못하는 case가 늘어난다

### `real-ue / direct`
흐름:
- UE는 동일하게 IMS attach/register 상태
- Sender는 UE IMS IP를 알아낸 뒤 UE로 직접 전송
- Reactor는 소켓 응답 + network trace + optional device trace를 합쳐 본다

장점:
- malformed wire/bytes를 UE까지 밀어 넣기 좋다
- parser robustness 계열 테스트에 유리하다
- 이전 연구실 프로젝트 자산과 가장 잘 맞는다

단점:
- 실제 IMS path를 그대로 재현하지는 않는다
- UE IP discovery와 route setup이 필요하다
- 네트워크 정책에 따라 direct delivery가 안 될 수 있다

## 3.3 real-ue mode에서 반드시 필요한 보조 계층
### 3.3.1 TargetResolver
real-ue/direct를 하려면 UE contact를 알아야 한다.

공식/실무적으로 가능한 후보:
- Open5GS `infoAPI`
- Kamailio usrloc / registrar 계층
- Kamailio DB/RPC
- 운영자가 직접 넘기는 static target

현재까지의 정직한 결론:
- **Open5GS infoAPI는 매우 유망한 새 후보**
- **Kamailio usrloc/DB/log 기반 lookup은 기존 연구실 자산 재사용에 유리**
- 따라서 둘을 경쟁 관계로 보기보다, primary/secondary resolver로 함께 두는 게 좋다

### 3.3.2 RouteSetup
real-ue/direct는 단순 송신이 아니라 라우팅 문제가 있다.

최소한 확인해야 하는 것:
- host에서 UE IMS subnet으로 route가 있는가
- UPF/ogstun/bridge를 통해 return path가 살아 있는가
- UE가 실제로 해당 source IP/port의 SIP를 수용하는가

즉 direct mode는 sender 코드만으로 끝나지 않고, **실험 환경 readiness check**가 필요하다.

### 3.3.3 Multi-observer Reactor
real-ue 경로에서는 “무응답”이 해석하기 어렵다.

가능한 원인:
- P-CSCF drop
- UE 미수신
- UE 수신 후 무시
- response가 다른 경로로 감
- NAT/route/firewall 문제

따라서 real-ue mode에서는 Reactor를 아래처럼 보는 것이 좋다.

- primary: socket response
- secondary: siptrace / sniffer / pcap
- future: ADB/logcat

## 3.4 real-ue mode의 현실적 판정
### 가능 여부
`예`

### 단, Phase 4 안에서의 정확한 범위
- 가능: **SDR이 제공하는 LTE/IMS 실험망 위에서 SIP를 보내는 sender**
- 불가/비현실적: **sender가 직접 RF/LTE PHY를 송신하는 구조**

즉, Phase 4에서 말할 수 있는 정직한 표현은 다음이다.

> “Sender는 SDR/USRP 기반 실험망에 붙은 실제 UE를 대상으로 SIP를 보낼 수 있어야 한다.”

이건 충분히 가능한 요구사항이다.

## 4. Softphone 경로 조사
## 4.1 왜 softphone mode가 필요한가
`추론`

softphone mode는 real-ue mode의 대체재가 아니라 보완재다.

필요 이유:
- 초기 Sender/Reactor 기능 검증이 훨씬 빠르다
- 응답/타임아웃/실패 분류를 안정적으로 먼저 만들 수 있다
- 호출 흐름, MESSAGE, OPTIONS, 응답 correlation 검증이 쉽다
- 상용 UE와 달리 재현성이 좋다

즉, real-ue가 최종 연구 타깃이라면, softphone은 **Phase 4 안정화용 기준 타깃**으로 가치가 크다.

## 4.2 softphone 후보 1: Linphone
### 근거
`공식 문서 확인`

Linphone 공식 문서에서 확인되는 점:
- SIP standard(RFC 3261) 호환
- third-party SIP account 사용 가능
- desktop/mobile 다중 플랫폼 지원
- app 자체와 Liblinphone SDK 문서/샘플 제공

### 장점
- GUI 기반이라 사람이 수동으로 붙여 보기 쉽다
- 계정 연결과 호출 수동 확인이 쉽다
- multi-platform이라 연구실 장비/노트북/폰에서 빨리 확인 가능
- Liblinphone SDK를 쓰면 이후 programmable target 쪽 확장 가능

### 약점
- 순수 headless/automation target로는 다른 후보보다 무겁다
- 이번 조사 범위에서 Linphone 공식 문서만으로는 IMS AKA 친화성이 명확히 확인되지는 않았다
- strict IMS P-CSCF 앞단에 generic softphone을 바로 붙이는 건 별도 검증이 필요하다

### 적합한 역할
- `manual softphone target`: 매우 적합
- `developer-friendly softphone baseline`: 적합
- `headless CI target`: 중간
- `strict IMS/AKA target`: 불확실

## 4.3 softphone 후보 2: Baresip
### 근거
`공식 문서 확인`

Baresip 공식 README/Wiki에서 확인되는 점:
- modular SIP user-agent
- SIP outbound, re-INVITE, MESSAGE, INFO, TLS, STUN/TURN/ICE 지원
- CLI, HTTP interface, TCP control interface 등 관리 인터페이스 존재
- BSD license
- cross-platform

### 장점
- 경량이고 모듈형이라 자동화에 유리하다
- CLI/control interface가 있어서 스크립트화하기 좋다
- SIP signalling 기능이 풍부하다
- GUI보다 test harness 느낌이 강하다

### 약점
- 일반 사용자 관점에서는 설정 난도가 Linphone보다 높다
- 공식 자료에서 IMS AKA 친화성은 이번 조사 범위에서 명확히 확인되지 않았다
- commercial VoLTE IMS edge에 바로 붙이는 건 별도 검증이 필요하다

### 적합한 역할
- `headless / automation softphone target`: 매우 적합
- `manual GUI target`: 낮음
- `strict IMS/AKA target`: 불확실

## 4.4 softphone 후보 3: PJSUA / PJSUA2 (PJSIP)
### 근거
`공식 문서 확인`

PJSIP 공식 문서에서 확인되는 점:
- account 생성 및 registration
- userless account 지원
- UDP/TCP/TLS transport
- `onIncomingCall`, `onCallState`, `onCallTsxState` callback
- CLI/telnet interface 제공
- **Digest AKAv1/AKAv2 API 제공**

### 장점
- 프로그래머블 softphone로 가장 강력하다
- callback 기반 reactor를 직접 만들기 쉽다
- userless account 지원이 있어 peer-to-peer / direct target 실험에도 유연하다
- IMS AKA 관련 공식 문서가 확인되어, softphone 후보 중 **IMS 친화성 근거가 가장 뚜렷하다**

### 약점
- 완성형 GUI softphone라기보다 SDK/샘플/CLI 성격이 강하다
- 테스트 타깃을 빨리 수동으로 붙여보는 용도로는 Linphone보다 번거로울 수 있다

### 적합한 역할
- `programmable softphone target`: 매우 적합
- `headless automated reactor target`: 매우 적합
- `IMS/AKA 실험용 softphone 후보`: 가장 강함

## 4.5 softphone 후보 비교
| 후보 | 공식 근거 | 수동 사용성 | 자동화 적합성 | IMS/AKA 근거 | Phase 4 추천 역할 |
| --- | --- | --- | --- | --- | --- |
| Linphone | 매우 충분 | 매우 높음 | 중간 | 이번 조사 범위에선 불명확 | 수동 baseline target |
| Baresip | 충분 | 중간 | 매우 높음 | 이번 조사 범위에선 불명확 | headless test target |
| PJSUA/PJSUA2 | 매우 충분 | 중간 | 매우 높음 | 높음 | programmable softphone target |

## 4.6 Softphone 경로의 중요한 현실 체크
### generic SIP vs IMS SIP
`추론`

softphone을 붙일 때 가장 중요한 건 “어디에 붙이느냐”다.

가능한 경우:
- 일반 SIP proxy/registrar에 붙임
- 테스트용 Kamailio edge를 따로 두고 붙임
- P-CSCF를 덜 엄격하게 구성한 lab profile에 붙임

어려운 경우:
- strict IMS AKA / IPsec / IMS-specific policy가 강한 P-CSCF에 generic softphone을 그대로 붙임

정직한 결론:
- softphone mode는 **확실히 가능**
- 하지만 “상용 VoLTE 단말과 동일한 방식으로 strict IMS에 붙이는 것”은 softphone마다 다르다
- 이번 조사 근거상, 그 부분은 **PJSIP 계열이 가장 유리**하고, Linphone/Baresip은 별도 현장 검증이 필요하다

## 5. Phase 4 관점에서의 권장 target mode 구조
## 5.1 권장 구조
이번 후속 조사 기준으로, target mode는 최소 아래 3개로 나누는 것이 가장 현실적이다.

1. `softphone`
2. `real-ue/pcscf`
3. `real-ue/direct`

이 구조의 장점:
- softphone으로 빠르게 기능 검증
- real-ue/pcscf로 실제 IMS path 검증
- real-ue/direct로 malformed delivery 검증

## 5.2 권장 역할 분리
### Sender
- artifact 선택
- transport 선택
- target resolution
- 실제 송신

### Reactor
- socket response 수집
- timeout / failure 분류
- correlation
- optional observer plugin

### Observer plugin
- siptrace
- pcap
- sniffer
- adb (future)

즉, softphone과 real-ue를 같은 sender abstraction 아래 두되, **target adapter만 다르게** 가져가는 구조가 적합하다.

## 6. 후속 계획 전에 답해야 하는 질문
이번 문서도 아직 계획 문서는 아니므로, 아래는 계획 전에 확인할 질문으로 남긴다.

1. 연구실 환경에서 사용하는 SDR이 정확히 USRP B210/B200mini/X 시리즈 중 무엇인가
2. 현재 real UE가 붙는 경로가 srsRAN 4G 기반인지, commercial eNB 기반인지
3. softphone은 “수동 sanity target”이 필요한지, “자동화된 programmable target”이 필요한지
4. softphone이 strict IMS AKA registration까지 해야 하는지, 아니면 일반 SIP edge만 붙으면 되는지
5. Phase 4 첫 구현에서 softphone과 real-ue를 동시에 넣을지, softphone 먼저 갈지

## 7. 이번 후속 조사에서 얻은 핵심 결론
- **둘 다 가능하다.**
- 다만 `real-ue`는 “SDR이 만든 실험망 위의 SIP 전송”이어야 현실적이다.
- `softphone`은 분명히 가능하지만, 목적에 따라 후보가 달라진다.
- 가장 단순한 수동 sanity target은 **Linphone**
- 가장 자동화 친화적인 경량 softphone 후보는 **Baresip**
- 가장 프로그래머블하고 IMS/AKA 근거가 강한 후보는 **PJSIP/PJSUA2**
- 따라서 Phase 4에서 softphone mode를 넣는다면, 실무적으로는 아래 둘 중 하나가 가장 유력하다.
  - `Linphone` for manual validation
  - `PJSIP` or `Baresip` for automated validation

## 8. 참고한 주요 공식 자료
- [Open5GS Docs](https://open5gs.org/open5gs/docs/)
- [Open5GS VoLTE Setup](https://open5gs.org/open5gs/docs/tutorial/02-VoLTE-setup/)
- [Open5GS Dockerized VoLTE Setup](https://open5gs.org/open5gs/docs/tutorial/03-VoLTE-dockerized/)
- [Open5GS infoAPI](https://open5gs.org/open5gs/docs/tutorial/07-infoAPI-UE-gNB-session-data/)
- [srsRAN COTS UEs](https://docs.srsran.com/projects/project/en/latest/knowledge_base/source/cots_ues/source/index.html)
- [srsRAN 4G Pi4 note with USRP B210](https://docs.srsran.com/projects/4g/en/latest/app_notes/source/pi4/source/index.html)
- [Ettus USRP B210](https://www.ettus.com/all-products/ub210-kit/)
- [UHD USRP-B2x0 manual](https://files.ettus.com/manual_archive/release_003_007_001/manual/html/usrp_b200.html)
- [Linphone softphone](https://www.linphone.org/en/linphone-softphone/)
- [Linphone documentation](https://www.linphone.org/en/documentation/)
- [Linphone download](https://www.linphone.org/en/download/)
- [Linphone FAQ on third-party SIP accounts](https://www.linphone.org/en/faq/)
- [Liblinphone SDK](https://www.linphone.org/en/liblinphone-voip-sdk/)
- [Liblinphone basic call tutorial](https://download.linphone.org/releases/docs/liblinphone/latest/c/group__basic__call__tutorials.html)
- [Baresip README](https://github.com/baresip/baresip)
- [Baresip Wiki](https://github.com/baresip/baresip/wiki)
- [Baresip as a library](https://github.com/baresip/baresip/wiki/Using-baresip-as-a-library)
- [PJSUA2 Accounts](https://docs.pjsip.org/en/2.14/pjsua2/using/account.html)
- [PJSUA2 Calls](https://docs.pjsip.org/en/latest/pjsua2/using/call.html)
- [PJSUA2 onCallTsxState](https://docs.pjsip.org/en/2.12.1/pjsua2/call.html)
- [PJSUA CLI manual](https://docs.pjsip.org/en/latest/specific-guides/other/cli_cmd.html)
- [PJSIP Digest AKA API](https://docs.pjsip.org/en/latest/api/generated/pjsip/group/group__PJSIP__AUTH__AKA__API.html)
- [PJSIP datasheet](https://docs.pjsip.org/en/2.12.1/datasheet.html)
