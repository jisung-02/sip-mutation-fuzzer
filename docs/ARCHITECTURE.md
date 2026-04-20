# VolteMutationFuzzer 시스템 아키텍처

## 📐 전체 구조

```mermaid
graph TB
    CLI[Campaign CLI] --> Config[CampaignConfig]
    Config --> Executor[CampaignExecutor]
    
    Executor --> Generator[SIPGenerator]
    Executor --> Mutator[SIPMutator]  
    Executor --> Sender[SIPSenderReactor]
    Executor --> Oracle[OracleEngine]
    
    Generator --> Template[MT Template]
    Mutator --> |profile/layer/strategy| Mutation[MutatedCase]
    Sender --> |UDP/TCP| Target[UE/Softphone]
    Target --> |SIP Response| Oracle
    Oracle --> Verdict[normal/suspicious/crash]
    
    Executor --> Store[ResultStore]
    Executor --> Capture[PcapCapture]
    Executor --> ADB[AdbConnector]
```

## 🏗️ 주요 구성 요소

### 1. Campaign Layer (캠페인 실행)

#### `CampaignExecutor`
- **역할**: 전체 퍼징 루프 관리 (generate → mutate → send → judge → store)
- **핵심 메서드**:
  - `execute()`: 메인 실행 루프
  - `_execute_case()`: 단일 케이스 실행  
  - `_execute_mt_template_case()`: MT template 전용 경로
- **특징**: softphone과 real-ue-direct 모드 분기 처리

#### `CaseGenerator`
- **역할**: 테스트 케이스 조합 생성 (method × profile × layer × strategy)
- **지원 조합**:
  ```python
  methods: OPTIONS, INVITE, MESSAGE, REGISTER, ...
  profiles: legacy, delivery_preserving, ims_specific, parser_breaker
  layers: model, wire, byte
  strategies: identity, default, state_breaker
  ```
  - `profile`은 mutator 정책 축이고, `mode`는 sender 경로 축이다.
  - 따라서 `softphone`와 `real-ue-direct` 모두 같은 profile을 사용할 수 있으며, mode는 전송 방식만 바꾼다.

#### `CampaignConfig`
- **역할**: 전체 설정 중앙화 + validation
- **핵심 기능**: MSISDN → UE IP 자동 resolve

### 2. Generator Layer (패킷 생성)

#### `SIPGenerator`
- **역할**: 구조적 SIP 패킷 생성 (model layer용)
- **방식**: PacketModel → 렌더링 → wire text

#### `MT Template System`
- **파일**: `generator/templates/mt_invite_a31.sip.tmpl`
- **역할**: 실제 capture 기반 완전한 3GPP MT-INVITE 생성
- **슬롯**: 18개 동적 매개변수 (IMPI, port_pc/port_ps, Call-ID 등)
- **렌더링**: `build_default_slots()` → `render_mt_invite()`

### 3. Mutator Layer (변이 엔진)

#### 변이 레이어 구조
```
Original Input
     ↓
┌─ model ─┐  ┌─ wire ─┐  ┌─ byte ─┐
│ PacketModel │ → │ SIP Text │ → │ Raw Bytes │
│   변이      │   │   변이   │   │    변이    │
└─────────┘   └─────────┘   └──────────┘
     ↓             ↓            ↓
   Model         Wire          Byte
  MutatedCase   MutatedCase   MutatedCase
```

#### `SIPMutator`
- **`mutate()`**: PacketModel 입력 (기존)
- **`mutate_editable()`**: EditableSIPMessage 입력 (MT template용)

#### 변이 전략
| Strategy | 설명 | 용도 |
|----------|------|------|
| **identity** | 무변이 (원본 그대로) | baseline/oracle |
| **default** | 기본 변이 (랜덤 필드 수정) | 일반 퍼징 |
| **state_breaker** | 상태 기반 공격 변이 | 고급 시나리오 |

### 4. Sender Layer (송신 엔진)

#### `SIPSenderReactor`
- **역할**: 다양한 전송 방식 통합
- **지원 모드**:
  - `softphone`: 직접 UDP/TCP 송신
  - `real-ue-direct`: UE 대상 특수 처리

#### Real-UE-Direct 경로
```python
# IPsec 모드에 따른 분기
if ipsec_mode == "null":
    # Host에서 직접 IP spoofing
    _send_with_spoofed_source(source_ip="172.22.0.21")
elif ipsec_mode == "bypass":  
    # Docker exec으로 P-CSCF netns 진입
    _send_via_container(container="pcscf")
```

#### `RealUEDirectResolver`
- **역할**: 동적 UE 정보 resolve
- **기능**:
  - `resolve_protected_ports()`: port_pc/port_ps 실시간 조회
  - `resolve_ue_ip_from_msisdn()`: MSISDN → IP 매핑

### 5. Oracle Layer (응답 판정)

#### `OracleEngine`
- **역할**: SIP 응답을 verdict로 분류
- **판정 로직**:
  ```python
  def evaluate(send_result, context) -> OracleVerdict:
      if process_crashed:
          return "crash"
      if stack_trace_found:
          return "stack_failure"  
      if timeout_exceeded:
          return "timeout"
      if error_response(4xx, 5xx):
          return "suspicious"
      if success_response(1xx, 2xx):
          return "normal"
  ```

#### 통합 Oracle (ADB + Process + Log)
- **AdbAnomalyDetector**: Android logcat 분석
- **ProcessOracle**: 프로세스 생존 확인  
- **LogOracle**: 애플리케이션 로그 분석

### 6. Storage Layer (결과 저장)

#### `ResultStore`
- **형식**: JSONL (JSON Lines)
- **구조**:
  ```json
  {"campaign_id": "...", "config": {...}, "summary": {...}}
  {"case_id": 0, "verdict": "normal", "elapsed_ms": 1523, ...}
  {"case_id": 1, "verdict": "suspicious", "reason": "400 Bad Request", ...}
  ```

#### `PcapCapture`
- **기능**: tcpdump 자동 실행/종료
- **파일명**: `case_XXXXXX.pcap`
- **인터페이스**: `br-volte` (Docker 내부 통신 포함)

#### `AdbConnector` 
- **트리거**: crash/stack_failure 감지 시
- **수집 데이터**: logcat, bugreport, screenshot
- **저장 위치**: `results/adb_snapshots/case_XXXXXX/`

## 🔄 데이터 흐름

### 1. Softphone 모드 (기본)
```
CLI Input → CampaignConfig → TargetEndpoint{host, port}
    ↓
CaseGenerator → (method, profile, layer, strategy) combinations
    ↓  
SIPGenerator → PacketModel → SIPMutator → MutatedCase
    ↓
SIPSenderReactor → UDP/TCP direct send → SoftPhone
    ↓
OracleEngine → Verdict → ResultStore
```

### 2. Real-UE-Direct 모드 (A31)
```
CLI Input{target_msisdn} → resolve_ue_ip → CampaignConfig{target_host}
    ↓
resolve_protected_ports() → port_pc/port_ps (dynamic)
    ↓
MT Template + slots → render_mt_invite() → wire_text
    ↓
parse_editable_from_wire() → EditableSIPMessage
    ↓
SIPMutator.mutate_editable() → MutatedWireCase
    ↓
ipsec_mode routing:
  - null: _send_with_spoofed_source() 
  - bypass: _send_via_container()
    ↓
A31 UE → SIP Response → OracleEngine + AdbConnector
    ↓
Verdict + ADB snapshot → ResultStore + PcapCapture
```

## 🎛️ 설정 시스템

### 계층 구조
```
CLI Options
    ↓ 
CampaignConfig (validation + defaults)
    ↓
TargetEndpoint (auto-resolution + validation)
    ↓
실제 실행 컴포넌트들
```

`profile`과 `mode`는 서로 독립적이다. `profile`은 mutator가 어떤 변이 규칙을 적용할지 정하고, `mode`는 sender가 어떤 전송 경로를 사용할지 정한다.

### 자동 Resolution 체인
```python
# 1단계: MSISDN → UE IP
target_msisdn="111111" → resolve_ue_ip → target_host="10.20.20.8"

# 2단계: UE IP → 동적 포트  
target_host="10.20.20.8" → resolve_protected_ports → port_pc=8100

# 3단계: IPsec 모드 → 송신 방식
ipsec_mode="null" → source_ip="172.22.0.21", bind_container=None
```

## 🔧 핵심 알고리즘

### Port Resolution (동적 포트 조회)
```python
def resolve_protected_ports(msisdn: str) -> tuple[int, int]:
    # Strategy 1: Kamailio logs
    logs = docker_logs("pcscf", since="5m")
    matches = re.findall(r"Port is (\d+)", logs)
    if matches:
        port_pc = int(matches[-1])  # 최근 매치
        return port_pc, port_pc + 1
    
    # Strategy 2: xfrm state parsing
    xfrm_output = docker_exec("pcscf", "ip", "xfrm", "state")
    ue_sports = parse_ue_sports(xfrm_output, "10.20.20.8")
    port_pc = min(ue_sports)
    return port_pc, port_pc + 1
```

### Template Rendering (슬롯 치환)
```python
def render_mt_invite(template: str, slots: MTInviteSlots) -> str:
    # 1. 슬롯 치환
    text = template.replace("{{impi}}", slots.impi)
    text = text.replace("{{request_uri_port_pc}}", str(slots.port_pc))
    # ... 18개 슬롯 처리
    
    # 2. Content-Length 계산
    header, body = text.split("\r\n\r\n", 1)
    content_length = len(body.encode("utf-8"))
    text = text.replace("{{content_length}}", str(content_length))
    
    # 3. CRLF 정규화
    return normalize_crlf(text)
```

### Fragment Guard (단편화 방지)
```python
def check_fragmentation(payload: bytes, ipsec_mode: str) -> bool:
    if ipsec_mode == "null" and len(payload) > 1400:
        # Host → LTE 경로: IP 단편화 치명적
        return False  # TCP 사용 권장
    elif ipsec_mode == "bypass":
        # Docker 내부망: IP 단편화 안전
        return True
```

## 🛡️ 에러 처리 및 복구

### Graceful Degradation
- **포트 조회 실패**: 기본 포트 (5060) fallback  
- **MSISDN 매핑 실패**: 명확한 에러 메시지 + 환경변수 가이드
- **Template 렌더링 실패**: leftover `{{...}}` 검출

### Timeout 처리
- **Socket timeout**: 개별 케이스 레벨 timeout
- **Campaign timeout**: 전체 실행 시간 제한 (옵션)
- **Process timeout**: docker exec, adb 명령어별 timeout

### 리소스 정리
- **PcapCapture**: exception 발생해도 tcpdump 프로세스 종료
- **Container exec**: subprocess cleanup
- **ADB 연결**: device 연결 해제

## 📊 성능 특성

### 처리량
- **Softphone**: ~100 cases/minute (네트워크 속도 제한)
- **Real-UE-Direct**: ~30 cases/minute (UE 응답 지연 + 복잡한 처리)

### 확장성 제약
- **단일 UE**: 동시 다중 세션 불가 (IMS 등록 충돌)
- **Docker exec**: 프로세스 생성 오버헤드  
- **ADB**: 단일 device 연결만 안정적

### 메모리 사용
- **Template 캐싱**: 첫 로드 후 메모리 보관
- **Pcap 버퍼링**: 케이스별 파일 분리로 메모리 절약
- **Oracle 상태**: stateless 설계

---

## 🔮 확장 방향

1. **다중 UE 지원**: IMPI 기반 동시 퍼징
2. **Dialog 확장**: ACK/BYE까지 포함한 full dialog 퍼징  
3. **SDP 전용 mutator**: 미디어 협상 집중 공격
4. **ML 기반 oracle**: 응답 패턴 학습을 통한 anomaly 감지
5. **분산 실행**: 여러 host에서 병렬 캠페인 실행

이 아키텍처는 **확장 가능하고 모듈화된 설계**를 통해 다양한 VoLTE/IMS 퍼징 시나리오를 지원합니다.
