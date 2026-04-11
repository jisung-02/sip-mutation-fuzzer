# Worklog 2026-04-11 Afternoon: IPsec Mode 정리 및 MSISDN Auto-Resolution

## 개요
사용자가 confusing한 `--source-ip`/`--bind-container` 플래그들을 정리하고, MSISDN만으로 자동 resolve가 가능하도록 개선 요청.

---

## 1. IPsec Mode 플래그 통합 (`777e142` → `fc5cf2f`)

### 문제점
- `--source-ip` + `--bind-container` 플래그가 구현 세부사항을 노출
- 사용자가 "뭘 선택해야 하는지" 헷갈림
- 목적과 구현이 혼재된 인터페이스

### 해결책: `--ipsec-mode` 도입
```bash
# 명확한 목적 표시
--ipsec-mode null     # null encryption (간단, 호스트 spoofing)
--ipsec-mode bypass   # xfrm policy bypass (복잡, docker exec)
```

### 구현 내용
- `CampaignConfig.ipsec_mode: Literal["null", "bypass"]` 추가
- Campaign CLI에 `--ipsec-mode` 옵션 추가  
- `_execute_mt_template_case`에서 ipsec_mode에 따른 routing:
  - `null`: `source_ip=pcscf_ip, bind_container=None`
  - `bypass`: `source_ip=None, bind_container="pcscf"`
- 기본값: `null` (MT template 사용 시)

### 정리 작업 (`129ddb0` → `fc5cf2f`)
- Sender CLI에서 `--source-ip`/`--bind-container` 제거
- Reproduction commands를 `--ipsec-mode` 사용하도록 변경
- 직접적인 source_ip 테스트 제거 (campaign ipsec_mode로 통합)
- 내부 `TargetEndpoint.source_ip/bind_container` 필드는 유지

**결과**: 사용자는 명확한 목적만 선택, 구현 세부사항은 숨김

---

## 2. MSISDN Auto-Resolution 구현 (`1a13073`)

### 문제점
```bash
# 중복 입력 필요 (불편함)
--target-host 10.20.20.8 --target-msisdn 111111
```

### 해결책: MSISDN만으로 자동 resolve
```bash
# 간단한 사용법
--target-msisdn 111111  # 자동으로 10.20.20.8 resolve
```

### Codex 위임 시도
- Codex에게 MSISDN auto-resolution 구현 요청
- Agent가 완료되었으나 실제 코드 변경 없음 (응답 없음)
- 직접 구현으로 전환

### 직접 구현 내용

#### 1. MSISDN → IP 매핑 (`real_ue.py`)
```python
_DEFAULT_MSISDN_TO_IP = {
    "111111": "10.20.20.8",  # Samsung A31
    "222222": "10.20.20.9",  # Test MO softphone
}

def resolve_ue_ip_from_msisdn(msisdn: str) -> str:
    # Environment override: VMF_MSISDN_TO_IP_<msisdn>=<ip>
    # Built-in mapping fallback
```

#### 2. TargetEndpoint auto-resolution (`contracts.py`)
```python
# Auto-resolve host from msisdn if host is not provided
if self.host is None and self.msisdn is not None:
    resolved_ip = resolve_ue_ip_from_msisdn(self.msisdn)
    object.__setattr__(self, "host", resolved_ip)
```

#### 3. CampaignConfig auto-resolution (`campaign/contracts.py`)
```python
# target_host를 optional로 변경
target_host: str | None = Field(default=None, min_length=1)

# real-ue-direct 모드에서 auto-resolution
if self.mode == "real-ue-direct" and self.target_host is None:
    resolved_ip = resolve_ue_ip_from_msisdn(self.target_msisdn)
    object.__setattr__(self, "target_host", resolved_ip)
```

#### 4. CLI validation (`campaign/cli.py`)
```python
# target_host를 optional로 변경
target_host: str | None = None

# real-ue-direct 모드 validation
if mode == "real-ue-direct":
    if target_host is None and target_msisdn is None:
        raise typer.Exit("requires either --target-host or --target-msisdn")
```

### 검증 완료
- ✅ MSISDN resolution 함수 (111111→10.20.20.8, 222222→10.20.20.9)
- ✅ Unknown MSISDN 에러 처리
- ✅ Environment variable override 지원
- ✅ TargetEndpoint auto-resolution
- ✅ CampaignConfig auto-resolution
- ✅ CLI validation
- ✅ 기존 방식 호환성 유지
- ✅ Complete workflow 검증

---

## 3. 최종 사용법 비교

### Before (복잡함)
```bash
uv run fuzzer campaign run \
  --mode real-ue-direct --transport UDP \
  --target-host 10.20.20.8 --target-msisdn 111111 \  # 중복!
  --impi 001010000123511 \
  --methods INVITE --layer wire --strategy identity \
  --mt-invite-template a31 \
  --source-ip 172.22.0.21 \                          # 구현 세부사항!
  --preserve-contact --preserve-via \
  --max-cases 1
```

### After (간단명확)
```bash
uv run fuzzer campaign run \
  --mode real-ue-direct --transport UDP \
  --target-msisdn 111111 \                           # 이것만으로 충분!
  --impi 001010000123511 \
  --methods INVITE --layer wire --strategy identity \
  --mt-invite-template a31 \
  --ipsec-mode null \                                # 명확한 목적!
  --preserve-contact --preserve-via \
  --max-cases 1
```

**개선 효과**:
- 🎯 **명확성**: 목적 중심의 옵션 (`--ipsec-mode`)
- 🚀 **편의성**: 중복 입력 제거 (MSISDN만으로 충분)
- 🔧 **확장성**: 환경변수로 매핑 추가 가능
- 🔒 **호환성**: 기존 사용법도 여전히 동작

---

## 4. 기술적 개선점

### 인터페이스 설계
- **Before**: 구현 세부사항 노출 (`source_ip`, `bind_container`)
- **After**: 목적 중심 추상화 (`ipsec-mode`)

### 사용자 경험
- **Before**: 3개 중복 값 입력 (`host`, `msisdn`, `source_ip`)
- **After**: 1개 핵심 값 (`msisdn`) → 자동 resolve

### 코드 구조
- **3단계 validation**: CLI → CampaignConfig → TargetEndpoint
- **Fallback 체계**: Environment → Built-in mapping → Error
- **Backward compatibility**: 기존 명시적 방식 유지

---

## 5. 다음 단계 (Future Work)

1. **다중 UE 지원**: IMPI 기반 필터링으로 multi-UE 환경 대응
2. **Dynamic mapping**: HSS/UDM 조회로 실시간 MSISDN→IP 매핑
3. **Template 확장**: A31 외 다른 단말용 MT template 추가
4. **환경변수 문서화**: VMF_MSISDN_TO_IP_* 패턴 가이드

---

## 커밋 이력

| 커밋 | 내용 | 파일 수 |
|------|------|---------|
| `777e142` | feat: --ipsec-mode 옵션 도입 | 3 |
| `fc5cf2f` | refactor: source_ip/bind_container 정리 | 8 |
| `1a13073` | feat: MSISDN auto-resolution | 4 |

**총 변경**: 15개 파일, 사용자 편의성 대폭 향상 🎉