---
name: fix-issue
description: VoLTE fuzzer의 약점/이슈를 수정한다. 사용자가 "수정해", "고쳐줘", "fix" 등을 요청할 때 사용한다. 이슈 설명이 선행되었거나 사용자가 직접 이슈를 지정한 경우 모두 적용.
---

# VoLTE Fuzzer 이슈 수정기

사용자가 퍼징 약점이나 이슈의 수정을 요청하면 아래 워크플로우를 따른다.

## 수정 워크플로우

### 1단계: 이슈 파악

이미 `/explain-issue`로 분석이 완료된 경우 해당 내용을 활용한다.
그렇지 않으면, 먼저 관련 코드를 읽고 이슈를 이해한다.

### 2단계: 태스크 분해

TaskCreate로 수정 작업을 분해한다. 일반적인 패턴:

1. 핵심 로직 추가/수정 (소스 코드)
2. contracts/타입 변경 (필요 시)
3. 기존 코드에 통합
4. 테스트 작성
5. 전체 테스트 실행 및 회귀 확인

### 3단계: 구현

수정 시 준수할 원칙:

- **최소 변경**: 이슈 해결에 필요한 최소한의 코드만 수정
- **기존 패턴 준수**: 프로젝트의 기존 코딩 스타일을 따름
  - Pydantic `BaseModel` + `ConfigDict(extra="forbid")`
  - `dataclass(frozen=True)` for value objects
  - `threading.Lock` for thread-safe state
  - `subprocess.run` with `timeout` and `check=False`
- **타입 안전**: `Literal` 타입, `Field` 제약조건 활용
- **backward compatibility**: 기존 경로(softphone, 기본 real-ue-direct)에 영향 없어야 함

### 4단계: 테스트

```bash
# 새 테스트만 실행
uv run pytest tests/<module>/test_<file>.py::<TestClass> -v

# 전체 회귀 테스트
uv run pytest tests/ -q
```

pre-existing failure 2개는 무시:
- `test_send_packet_to_silent_udp_target_times_out` (missing import socket)
- `test_resolver_prefers_kamctl_contact_for_msisdn` (MSISDN auto-resolve 간섭)

### 5단계: 결과 보고

```
## 변경 사항 요약

### N. [변경 제목] (`파일`)
- [구체적 변경 내용]

### 테스트 결과
- 새 테스트: X개 pass
- 전체: Y passed, Z failed (pre-existing)
```

## 모듈별 수정 가이드

### campaign/core.py 수정 시
- `run()` 루프의 circuit breaker 로직 주의
- `_execute_case` vs `_execute_mt_template_case` 분기 확인
- `_update_summary`에 새 verdict 추가했으면 동기화
- `find_checkpoint` counts dict도 동기화

### oracle/contracts.py 수정 시
- `Verdict` Literal에 새 값 추가 시:
  - `CampaignSummary` 카운터 추가
  - `_update_summary` match case 추가
  - `find_checkpoint` counts dict 추가

### sender/real_ue.py 수정 시
- `subprocess.run` 호출에 반드시 `timeout` 설정
- Docker 명령은 `pcscf_container` 파라미터 사용 (하드코딩 금지)
- 예외는 graceful하게 처리 (`FileNotFoundError`, `OSError`, `TimeoutExpired`)

### adb/core.py 수정 시
- `_lock`으로 `_procs`, `_dead_buffers`, `_reconnect_count` 보호
- `_running.is_set()` 체크 후 Popen — shutdown race 방지
- `stop()` 에서 `_lock` 안에서 `_procs` 스냅샷 → 밖에서 terminate

## IPsec / IMS 도메인 참고

- SA = Security Association (IPsec 암호화 세션)
- port_pc = protected client port, port_ps = protected server port
- null encryption: 호스트에서 source IP spoofing으로 P-CSCF 사칭
- bypass: docker exec로 P-CSCF netns 안에서 직접 송신
- IMPI = IP Multimedia Private Identity (IMS 가입자 식별)
