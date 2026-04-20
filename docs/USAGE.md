# VolteMutationFuzzer 사용법 가이드

## 🚀 기본 사용법

### 설치
```bash
git clone <repository>
cd volte-mutation-fuzzer
poe install   # Ubuntu system dependencies (softphone excluded)
uv sync
```

### 빠른 시작
```bash
# 소프트폰 대상 퍼징
uv run fuzzer campaign run --target-host 127.0.0.1 --max-cases 10

# A31 실기기 대상 퍼징  
uv run fuzzer campaign run --mode real-ue-direct --target-msisdn 111111 \
  --methods INVITE --mt-invite-template a31 --ipsec-mode null --max-cases 5

# A31 실기기 대상 실제 IPsec 경로 검증
uv run fuzzer campaign run --mode real-ue-direct --target-msisdn 111111 \
  --methods INVITE --mt-invite-template a31 --ipsec-mode native --max-cases 1
```

## 📦 SIP Packet Completeness

이 저장소는 SIP 요청 메서드 지원을 하나의 "지원됨"으로 뭉뚱그려 말하지 않고, 두 축으로 구분한다.

- `runtime_complete`: 현재 코드베이스에서 honest runtime path 로 실제 송신/검증 흐름을 갖는 메서드
- `generator_complete`: generator/mutator는 일관되게 동작하지만, 저장소가 아직 honest runtime prerequisite state 를 소유하지 않는 메서드

중요한 점:

- `runtime_complete`가 곧 "실기기 validated"를 뜻하지는 않는다.
- 실제 의미는 `baseline_scope`로 읽어야 한다.
- 현재 `INVITE`만 `real_ue_baseline` 이다.
- `ACK`, `BYE`, `CANCEL`, `INFO`, `PRACK`, `REFER`, `UPDATE`는 `invite_dialog` 범위에서의 honest runtime path 다.
- `MESSAGE`, `OPTIONS`, `SUBSCRIBE`는 `stateless` runtime path 다.
- `NOTIFY`, `PUBLISH`, `REGISTER`는 현재 `generator_complete`이며, coherent generation/mutation 은 되지만 runtime prerequisite state 는 아직 저장소 범위 밖이다.
- `real-ue-direct`에서 `--mt-invite-template`를 써도 dialog가 필요한 runtime-complete 메서드는 standalone MT path 로 덮어쓰지 않고, 각 dialog setup path 를 우선 사용한다.

요약 표:

| 분류 | 메서드 |
| --- | --- |
| `runtime_complete` + `real_ue_baseline` | `INVITE` |
| `runtime_complete` + `invite_dialog` | `ACK`, `BYE`, `CANCEL`, `INFO`, `PRACK`, `REFER`, `UPDATE` |
| `runtime_complete` + `stateless` | `MESSAGE`, `OPTIONS`, `SUBSCRIBE` |
| `generator_complete` + `generator_only` | `NOTIFY`, `PUBLISH`, `REGISTER` |

세부 기준과 notes 는 [`docs/프로토콜/SIP-메시지-완성도-매트릭스.md`](프로토콜/SIP-메시지-완성도-매트릭스.md)를 단일 기준으로 본다.

## 📋 CLI 옵션 상세

### 기본 옵션
```bash
# 대상 설정
--target-host <IP>          # 목적지 IP (auto-resolve 가능)
--target-port <PORT>        # 목적지 포트 (기본: 5060)  
--target-msisdn <MSISDN>    # UE MSISDN (111111=A31, 222222=Test)
--transport UDP|TCP         # 전송 프로토콜 (기본: UDP)
--mode softphone|real-ue-direct  # 동작 모드

# 퍼징 설정
--methods <LIST>            # SIP 메서드 (OPTIONS,INVITE,MESSAGE,...)
--profile <LIST>            # 변이 프로필 목록 (legacy,delivery_preserving,ims_specific,parser_breaker; 쉼표 구분)
--layer model,wire,byte     # 변이 레이어 선택
--strategy <LIST>           # 변이 전략 (identity,default,state_breaker,safe,
                            # header_targeted,header_whitespace_noise,
                            # final_crlf_loss,duplicate_content_length_conflict,
                            # tail_chop_1,tail_garbage,alias_port_desync)
--max-cases <N>             # 최대 케이스 수 (기본: 1000)
--timeout <SEC>             # 소켓 timeout (기본: 5.0)
--seed-start <N>            # 시작 시드값 (재현용)

# 출력 설정  
--output <PATH>             # 결과 파일 (.jsonl)
--pcap --pcap-dir <DIR>     # pcap 캡처 활성화
--pcap-interface <IF>       # 캡처 인터페이스 (기본: any)
```

### Real-UE-Direct 전용 옵션
```bash
# MT Template 설정
--mt-invite-template <NAME> # MT template (a31, 또는 파일경로)
--impi <IMPI>               # IMS Private Identity
--ipsec-mode null|bypass|native  # null/bypass 평문 우회, native 실제 IPsec/xfrm

# 고급 설정
--preserve-via              # Via 헤더 보존 (template용)  
--preserve-contact          # Contact 헤더 보존 (template용)
--mt-local-port <PORT>      # null/bypass용 Via sent-by 포트 (native에서는 비권위적)
--mo-contact-host <IP>      # MO UE IP (기본: 10.20.20.9)
--from-msisdn <MSISDN>      # 발신자 번호 (기본: 222222)

# ADB 연동
--adb --adb-serial <SERIAL> # ADB 자동 스냅샷 (crash 시)
--adb-buffers main,system,radio,crash  # logcat 버퍼
```

### 유틸리티 옵션
```bash
--no-process-check          # 프로세스 체크 비활성화 
--cooldown <SEC>            # 케이스간 대기시간 (기본: 0.2)
--log-path <PATH>           # 애플리케이션 로그 경로
```

### IPsec 모드 가이드
- `null`: host spoofing 기반 평문 우회 경로. 외부 pcap/Wireshark에서 평문 SIP가 보일 수 있다.
- `bypass`: `pcscf` 컨테이너 netns를 통한 평문 우회 경로. 외부 pcap/Wireshark에서 평문 SIP가 보일 수 있다.
- `native`: 실제 협상된 IMS IPsec/xfrm 세션을 사용한다. 현재 구현 범위는 `real-ue-direct + UDP`이며, MT 경로에서는 `--target-msisdn`이 필요하다.
- `native`에서는 응답 확인 기준이 평문 wire 가독성이 아니라 observer가 합성한 SIP 응답과 `observer_events`다.
- `native`에서는 outer wire 기준으로 ESP가 보일 가능성이 높아서 Wireshark에 평문 SIP가 바로 보이지 않을 수 있다.

## 🎚️ Mutation Profile Axis

`--profile`은 mutator가 어떤 성격의 변이를 선택할지 정하는 축이며, sender mode(`--mode softphone` / `--mode real-ue-direct`)와 독립적이다. 같은 `mode`라도 profile이 달라지면 기본 strategy 선택과 허용되는 mutation 경로가 달라진다.

`--strategy default`는 요청값이며, 실제 실행과 결과 저장에는 profile + layer + seed로 해석된 concrete strategy가 기록된다. 그래서 reproduction command도 resolved strategy를 그대로 담아 재현성을 유지한다.

| Profile | 의미 |
| --- | --- |
| `legacy` | 기존 동작과 가장 가까운 호환성 프로필. 기존 시나리오와 회귀 검증에 적합하다. |
| `delivery_preserving` | 전달 가능성을 최대한 유지하면서 약한 변이를 적용한다. 라우팅/전달 경로를 크게 흔들지 않는 분석용이다. |
| `ims_specific` | IMS/3GPP 헤더, alias, routing 정보를 의식한 프로필이다. 실제 UE와 IMS 헤더 구조를 함께 볼 때 유용하다. |
| `parser_breaker` | CRLF, length, tail truncation 같은 파서 경계 조건을 노리는 프로필이다. |

예시는 아래와 같다.

```bash
# IMS 헤더/alias 중심 변이: real-UE 경로에서도 자연스럽게 사용 가능
uv run fuzzer campaign run --mode real-ue-direct --target-msisdn 111111 \
  --mt-invite-template a31 \
  --methods INVITE --profile ims_specific --layer wire --strategy default \
  --max-cases 10

# 파서 경계 조건 집중: softphone 대상에서도 동일하게 적용 가능
uv run fuzzer campaign run --target-host 127.0.0.1 \
  --methods INVITE --profile parser_breaker --layer wire,byte \
  --strategy default --max-cases 20
```

## 🎯 주요 시나리오

### 1. 빠른 기능 테스트
```bash
# OPTIONS 핑테스트 (빠름)
uv run fuzzer campaign run --target-host 127.0.0.1 --methods OPTIONS --max-cases 5

# A31 connectivity 테스트  
uv run fuzzer campaign run --mode real-ue-direct --target-msisdn 111111 \
  --mt-invite-template a31 --profile legacy \
  --strategy identity --max-cases 1
```

### Packet Completeness 스모크 테스트

아래 예시는 `baseline_scope`를 구분해서 읽어야 한다. 복붙용 예시는 현재 운영 가정에 맞춰 `--impi` 없이 적는 것을 기본으로 한다.

```bash
# 1) real-ue baseline smoke: 현재 실기기 baseline 은 INVITE
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --methods INVITE \
  --profile legacy \
  --layer wire \
  --strategy identity \
  --mt-invite-template a31 \
  --ipsec-mode null \
  --preserve-contact --preserve-via \
  --max-cases 1

# 2) stateless runtime smoke: OPTIONS
uv run fuzzer campaign run \
  --target-host 127.0.0.1 --target-port 5060 \
  --methods OPTIONS \
  --profile legacy \
  --layer model \
  --strategy identity \
  --max-cases 1

# 3) stateless runtime smoke: MESSAGE
uv run fuzzer campaign run \
  --target-host 127.0.0.1 --target-port 5060 \
  --methods MESSAGE \
  --profile legacy \
  --layer model \
  --strategy identity \
  --max-cases 1

# 4) invite-dialog runtime smoke: INFO 기본값은 dtmf body/materialization
uv run fuzzer campaign run \
  --target-host 127.0.0.1 --target-port 5060 \
  --methods INFO \
  --profile legacy \
  --layer model \
  --strategy identity \
  --max-cases 1

# 5) invite-dialog runtime smoke: PRACK 는 reliable provisional response 가 필요
# 단순 "아무 18x"가 아니라 Require: 100rel + RSeq 가 있는 provisional response 여야 함
uv run fuzzer campaign run \
  --target-host 127.0.0.1 --target-port 5060 \
  --methods PRACK \
  --profile legacy \
  --layer model \
  --strategy identity \
  --max-cases 1
```

### 2. 표준 변이 퍼징
```bash
# 소프트폰: 전체 메서드 + 모든 레이어
uv run fuzzer campaign run --target-host 192.168.1.100 \
  --methods OPTIONS,INVITE,MESSAGE \
  --profile legacy --layer model,wire,byte --strategy default --max-cases 500

# A31: INVITE 집중 + 바이트 변이
uv run fuzzer campaign run --mode real-ue-direct --target-msisdn 111111 \
  --mt-invite-template a31 \
  --methods INVITE --profile ims_specific --layer byte --strategy default --max-cases 200
```

### 3. 고급 분석 (pcap + adb)
```bash
# 완전한 데이터 수집
uv run fuzzer campaign run --mode real-ue-direct --target-msisdn 111111 \
  --mt-invite-template a31 \
  --profile delivery_preserving --layer wire,byte --strategy default --max-cases 100 \
  --pcap --pcap-interface br-volte --pcap-dir results/pcaps \
  --adb --adb-serial SM_A315F_12345 \
  --output results/full_analysis.jsonl
```

### 4. 특정 시나리오 재현
```bash
# 특정 시드로 재현
uv run fuzzer campaign run --target-host 127.0.0.1 \
  --methods INVITE --profile parser_breaker --layer wire --strategy default \
  --seed-start 12345 --max-cases 1

# 특정 케이스 replay
uv run fuzzer campaign replay results/campaign.jsonl --case-id 42
```

## 📊 결과 분석

### 결과 보기
```bash
# 전체 요약
uv run fuzzer campaign report results/campaign.jsonl

# 특정 verdict만 필터링
uv run fuzzer campaign report results/campaign.jsonl --filter suspicious,crash

# JSON 출력 (파싱용)
uv run fuzzer campaign report results/campaign.jsonl > summary.json
```

### 파일 구조
```
results/
├── campaign.jsonl          # 메인 결과 (헤더 + 케이스들)
├── pcaps/                  # pcap 파일들
│   ├── case_000001.pcap
│   └── case_000042.pcap
└── adb_snapshots/          # ADB 스냅샷들
    └── case_000042/
        ├── logcat.txt
        ├── bugreport.txt
        └── screenshot.png
```

## 🔧 환경변수

### MSISDN 매핑 커스터마이징
```bash
# 기본 매핑 오버라이드  
export VMF_MSISDN_TO_IP_111111=192.168.1.201
export VMF_MSISDN_TO_IP_222222=192.168.1.202
export VMF_MSISDN_TO_IP_333333=192.168.1.203  # 새 UE 추가

# P-CSCF IP 설정
export VMF_REAL_UE_PCSCF_IP=172.22.0.21

# SDP 설정
export VMF_REAL_UE_SDP_OWNER_IP=172.22.0.16
```

### 디버그 모드
```bash
# 상세 로그 출력
export VMF_DEBUG=1

# Docker timeout 조정
export VMF_DOCKER_TIMEOUT=30
```

## 🎭 변이 전략 가이드

### identity (baseline)
```bash
--strategy identity
# 무변이, 원본 그대로 송신
# 용도: 연결성 테스트, oracle baseline
```

### default (표준 퍼징)  
```bash
--strategy default
# 랜덤 필드 변이, 적당한 강도
# 용도: 일반적인 취약점 스캔
```

### state_breaker (고급)
```bash  
--strategy state_breaker
# SIP 상태 기반 공격 변이
# 용도: 프로토콜 상태 머신 공격
```

### realistic malformed / edge 전략
```bash
--strategy header_whitespace_noise
# 헤더 구분자 주변 공백/탭을 비틀어 serializer/proxy 손상처럼 보이게 함

--strategy final_crlf_loss
# 패킷 끝의 terminal blank line을 줄여 final CRLF 손상 케이스 생성

--strategy duplicate_content_length_conflict
# Content-Length를 하나 더 붙여 상충하는 길이 해석 유도

--strategy tail_chop_1
# 마지막 1바이트만 잘라 tail truncation 재현

--strategy tail_garbage
# 짧은 replay-like suffix를 뒤에 덧붙여 parser confusion 유도

--strategy alias_port_desync
# real-UE/MT Contact alias의 port 값을 비틀어 alias-port desync 재현
```

### 조합 사용
```bash
--strategy identity,default,state_breaker
# 여러 전략 혼합 (순서대로 적용)
```

### realistic malformed 예시
```bash
uv run fuzzer mutate packet --layer wire --strategy final_crlf_loss < baseline.json
uv run fuzzer mutate packet --layer wire --strategy duplicate_content_length_conflict < baseline.json
uv run fuzzer mutate packet --layer byte --strategy tail_chop_1 < baseline.json

# MT-template / real-UE 집중 전략
uv run fuzzer campaign run --mode real-ue-direct --target-msisdn 111111 \
  --methods INVITE --layer wire \
  --strategy alias_port_desync --mt-invite-template a31 --ipsec-mode null \
  --max-cases 1
```

## 🔄 워크플로우 예시

### 개발/디버그 사이클
```bash
# 1. 연결성 확인
uv run fuzzer campaign run --mode real-ue-direct --target-msisdn 111111 \
  --mt-invite-template a31 --profile legacy \
  --strategy identity --max-cases 1

# 2. 소규모 테스트
uv run fuzzer campaign run --mode real-ue-direct --target-msisdn 111111 \
  --mt-invite-template a31 --profile ims_specific \
  --strategy default --max-cases 10

# 3. 본격 퍼징
uv run fuzzer campaign run --mode real-ue-direct --target-msisdn 111111 \
  --mt-invite-template a31 --profile delivery_preserving \
  --strategy default --max-cases 1000 \
  --pcap --adb --adb-serial <SERIAL>
```

### 배치 실행
```bash
#!/bin/bash
# overnight_fuzz.sh

DATE=$(date +%Y%m%d)
OUTPUT_DIR="results/overnight_$DATE"
mkdir -p $OUTPUT_DIR

# Layer별 분할 실행
for LAYER in wire byte; do
    uv run fuzzer campaign run \
        --mode real-ue-direct --target-msisdn 111111 \
        --mt-invite-template a31 \
        --profile parser_breaker --layer $LAYER --strategy default --max-cases 2000 \
        --output $OUTPUT_DIR/campaign_$LAYER.jsonl \
        --pcap-dir $OUTPUT_DIR/pcaps_$LAYER \
        --timeout 3 --cooldown 0.1 &
done

wait  # 모든 백그라운드 작업 완료 대기
```

## 📝 로그 및 디버깅

### 실시간 모니터링
```bash
# fuzzer 실행 로그
tail -f results/campaign.jsonl

# A31 상태 확인  
docker logs pcscf --since 1m | grep "Term UE"

# 네트워크 트래픽
sudo tcpdump -i br-volte host 10.20.20.8
```

### 문제 진단
```bash
# 상세 에러 정보
uv run fuzzer campaign run --verbose ...

# 특정 케이스 재현
uv run fuzzer campaign replay results/campaign.jsonl --case-id <ID>

# 네트워크 연결 테스트
ping 10.20.20.8
docker exec pcscf ping 10.20.20.8
```

---

더 자세한 내용은 다음 문서를 참고하세요:
- **[A31 Real-UE 가이드](A31_REAL_UE_GUIDE.md)** - 실기기 퍼징 전용
- **[문제 해결 가이드](TROUBLESHOOTING.md)** - 일반적인 문제들
- **[시스템 아키텍처](ARCHITECTURE.md)** - 내부 구조 이해
