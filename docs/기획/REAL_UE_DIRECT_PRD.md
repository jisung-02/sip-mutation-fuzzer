# REAL_UE_DIRECT_PRD: capstone dumpipe 기반 실제 UE 직접 송신 설계

## 1. 문서 목적
이 문서는 capstone의 `dumpipe.py` / `ue_lookup.py`에서 검증된 **P-CSCF 우회 direct-to-UE SIP delivery** 경로를 현재 저장소의 Sender/Reactor 경계 안으로 이식하기 위한 1차 구현 결정을 고정한다.

이번 범위는 `real-ue-direct` 하나만 다루며, `real-ue-pcscf`는 인터페이스 이름만 유지하고 구현 범위에서 제외한다.

## 2. 이번 slice의 결정 사항
- target mode: `real-ue-direct` only
- transport: `UDP` only
- route 정책: **readiness check only**, 자동 route 추가 없음
- target 입력: `--target-host` 또는 `--target-msisdn` 중 정확히 하나
- 등록 상태: UE가 이미 attach/register 되어 contact를 광고하고 있다고 가정

## 3. Target resolution
### 3.1 우선순위
1. 명시적 `target-host`
2. S-CSCF `docker exec <container> kamctl ul show`
3. P-CSCF `kamctl` 폴백
4. P-CSCF `docker logs`의 `Contact header` 파싱 + optional PyHSS IMSI 매핑

### 3.2 이번 범위에서 제외하는 것
- MySQL direct lookup
- Open5GS infoAPI backend
- 자동 route setup
- ADB/logcat observer
- oracle/controller

## 4. direct mode payload 정책
### 4.1 packet / wire artifact
실제 응답 수신 경로를 유지하기 위해 아래 두 필드만 최소 정규화한다.
- top `Via` sent-by host/port
- parse 가능한 첫 `Contact` URI host/port

추가 규칙:
- `Via`에는 `rport`를 켠다
- branch/tag/request-uri/order/기타 mutation은 그대로 둔다
- malformed wire라 rewrite가 불가능하면 그대로 전송하고 `observer_events`에 skip을 남긴다

### 4.2 bytes artifact
byte-level mutation 결과는 **절대 재작성하지 않고 그대로 전송**한다.

## 5. Route readiness
전송 전에 host에서 target IP로의 route lookup을 수행한다.
- macOS: `route -n get <target-ip>`
- Linux: `ip route get <target-ip>`

실패 시:
- 실제 송신은 하지 않는다
- 결과는 `send_error`
- `observer_events`에 route failure를 기록한다

## 6. 공개 인터페이스
### 6.1 CLI
- `fuzzer send packet --mode real-ue-direct --target-host ...`
- `fuzzer send packet --mode real-ue-direct --target-msisdn ...`
- `fuzzer send request ...` / `fuzzer send response ...`도 같은 규칙 적용

### 6.2 환경 변수
- `VMF_REAL_UE_SCSCF_CONTAINER`
- `VMF_REAL_UE_PCSCF_CONTAINER`
- `VMF_REAL_UE_PYHSS_URL`
- `VMF_REAL_UE_PCSCF_LOG_TAIL`

## 7. 완료 기준
1. explicit UE IP/port로 direct UDP 송신 가능
2. MSISDN 기반 contact resolution 가능
3. route missing을 명확히 판정하고 전송을 중단
4. 결과 JSON에 resolver / route / normalization 증거가 남음
