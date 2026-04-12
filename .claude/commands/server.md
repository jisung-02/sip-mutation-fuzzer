---
name: server
description: SSH로 원격 서버에 접속하여 퍼징을 실행하고, 결과를 분석하고, 다음 전략을 계획한다. "서버에서", "ssh", "원격", "서버 퍼징", "서버 상태", "SA 확인", "포트 확인" 등을 요청할 때 사용한다. 서버에서 무언가를 실행해야 할 때 항상 이 스킬을 사용한다.
---

# 원격 서버 퍼징 통합 스킬

SSH로 원격 서버에 접속하여 퍼징 실행, 결과 분석, 전략 수립, 케이스 재현 등 모든 퍼징 워크플로우를 수행한다.

## 최초 접속 시: SSH 정보 수집

서버 정보가 대화에서 아직 확인되지 않았으면 반드시 먼저 질문한다:

1. **SSH 접속 주소**: `user@host` 형태 (예: `ubuntu@163.180.185.51`)
2. **퍼저 경로**: 서버의 fuzzer 디렉토리 (예: `/home/ubuntu/Desktop/fuzzer/`)
3. **퍼저 실행 방법**: `uv run fuzzer` 또는 `.venv/bin/fuzzer` 등

메모리에 서버 정보가 있다면 확인 후 사용한다. 이전 대화에서 이미 확인된 정보가 있다면 재질문하지 않는다.

수집 후 변수처럼 사용한다:
- `SSH_TARGET` = `user@host`
- `FUZZER_DIR` = 서버의 퍼저 경로
- `FUZZER_CMD` = `cd <FUZZER_DIR> && uv run fuzzer`

## SSH 명령 실행 패턴

```bash
# 단일 명령
ssh <SSH_TARGET> '<command>'

# 퍼저 명령
ssh <SSH_TARGET> 'cd <FUZZER_DIR> && uv run fuzzer <subcommand>'

# 장시간 실행 (nohup 백그라운드)
ssh <SSH_TARGET> 'cd <FUZZER_DIR> && nohup uv run fuzzer campaign run [options] > /tmp/fuzz_$(date +%Y%m%d_%H%M).log 2>&1 & echo "PID: $!"'
```

## 기능 1: 서버 상태 확인

사용자가 "서버 상태", "연결 확인", "인프라 상태" 등을 요청할 때:

```bash
# 1. SSH 연결 + Docker 컨테이너 상태
ssh <SSH_TARGET> 'docker ps --format "table {{.Names}}\t{{.Status}}"'

# 2. IPsec SA 상태 (UE 등록 여부)
ssh <SSH_TARGET> 'docker exec pcscf ip xfrm state 2>&1 | grep -c "src 10.20.20"'

# 3. port_pc/port_ps 현재값
ssh <SSH_TARGET> "docker logs pcscf --since 5m 2>&1 | grep 'Term UE connection' | tail -1"

# 4. ADB 디바이스 (있다면)
ssh <SSH_TARGET> 'adb devices -l 2>/dev/null || echo "adb not available"'

# 5. 결과 파일 목록
ssh <SSH_TARGET> 'ls -lt <FUZZER_DIR>/results/*.jsonl 2>/dev/null | head -5'
```

출력 형식:
```
## 서버 상태: <SSH_TARGET>

### Docker 컨테이너
| 이름 | 상태 |
|------|------|
| pcscf | Up 3 hours |
| ... | ... |

### IPsec SA
- UE SA 수: N개
- port_pc: XXXX / port_ps: XXXX

### 최근 결과 파일
[파일 목록]
```

## 기능 2: 서버에서 퍼징 실행

`/fuzz` 스킬과 동일한 로직이지만 SSH를 통해 실행한다.

### 실행 전 점검
```bash
# SA 확인 + Docker 상태
ssh <SSH_TARGET> 'docker exec pcscf ip xfrm state 2>&1 | grep "src 10.20.20" | head -2; docker ps --format "{{.Names}}: {{.Status}}" | grep -E "pcscf|scscf"'
```

SA가 없으면 경고: "UE가 등록되지 않았거나 SA가 만료됨. 재등록을 기다리거나 확인 필요."

### 명령 구성

A31 실기기:
```bash
ssh <SSH_TARGET> 'cd <FUZZER_DIR> && uv run fuzzer campaign run \
  --mode real-ue-direct --target-msisdn 111111 \
  --impi 001010000123511 --mt-invite-template a31 \
  --ipsec-mode null --preserve-contact --preserve-via \
  --methods INVITE \
  --layer wire,byte --strategy identity,default \
  --timeout 6 --cooldown 0.1 --no-process-check \
  --max-cases <N> \
  --output results/<filename>.jsonl'
```

소프트폰:
```bash
ssh <SSH_TARGET> 'cd <FUZZER_DIR> && uv run fuzzer campaign run \
  --target-host <ip> --target-port <port> \
  --methods INVITE,OPTIONS,MESSAGE \
  --layer model,wire,byte --strategy default,state_breaker \
  --timeout 3 --cooldown 0.1 \
  --max-cases <N> \
  --output results/<filename>.jsonl'
```

### 실행 방식 결정
- **짧은 퍼징** (max-cases ≤ 50, timeout ≤ 3): 직접 실행, 결과 대기
- **긴 퍼징** (max-cases > 50 또는 timeout 큼): nohup 백그라운드 + 진행 확인 안내

긴 퍼징의 경우:
```bash
ssh <SSH_TARGET> 'cd <FUZZER_DIR> && nohup uv run fuzzer campaign run [options] > /tmp/fuzz.log 2>&1 & echo "PID: $!"'
```
그 후 진행 확인:
```bash
ssh <SSH_TARGET> 'tail -5 /tmp/fuzz.log'
```

## 기능 3: 결과 분석

`/fuzz-analyze` 스킬과 동일한 로직을 SSH를 통해 수행한다.

```bash
# campaign report
ssh <SSH_TARGET> 'cd <FUZZER_DIR> && uv run fuzzer campaign report results/<file>.jsonl'

# verdict 분포
ssh <SSH_TARGET> "jq -r 'select(.type==\"case\") | .verdict' <FUZZER_DIR>/results/<file>.jsonl | sort | uniq -c | sort -rn"

# 응답 코드 패턴
ssh <SSH_TARGET> "jq -r 'select(.type==\"case\") | \"\(.verdict) \(.response_code // \"none\")\"' <FUZZER_DIR>/results/<file>.jsonl | sort | uniq -c | sort -rn | head -20"

# 레이어/전략 효과
ssh <SSH_TARGET> "jq -r 'select(.type==\"case\") | \"\(.layer)/\(.strategy) \(.verdict)\"' <FUZZER_DIR>/results/<file>.jsonl | sort | uniq -c | sort -rn"

# crash/suspicious 상세
ssh <SSH_TARGET> "jq 'select(.type==\"case\" and (.verdict==\"crash\" or .verdict==\"stack_failure\" or .verdict==\"suspicious\"))' <FUZZER_DIR>/results/<file>.jsonl"

# 성능 (처리량)
ssh <SSH_TARGET> "jq -r 'select(.type==\"case\") | .elapsed_ms' <FUZZER_DIR>/results/<file>.jsonl | awk '{sum+=\$1; n++} END {printf \"cases=%d avg=%.0fms throughput=%.1f/min\\n\", n, sum/n, n*60000/sum}'"
```

분석 후 `/fuzz-analyze` 스킬의 출력 형식을 따른다.

## 기능 4: 지능적 다음 전략

`/fuzz-next` 스킬과 동일한 전략 결정 로직을 적용한다.

```bash
# 이전 결과의 summary 확인
ssh <SSH_TARGET> "tail -1 <FUZZER_DIR>/results/<file>.jsonl | python3 -m json.tool"

# crash seed 확인
ssh <SSH_TARGET> "jq -r 'select(.type==\"case\" and (.verdict==\"crash\" or .verdict==\"stack_failure\")) | \"\(.seed) \(.layer) \(.strategy)\"' <FUZZER_DIR>/results/<file>.jsonl"

# 마지막 seed 확인 (다음 시작점)
ssh <SSH_TARGET> "jq -r 'select(.type==\"case\") | .seed' <FUZZER_DIR>/results/<file>.jsonl | sort -n | tail -1"
```

분석 결과에 따라 다음 퍼징 명령을 구성하고 제안한다.

## 기능 5: 케이스 재현

`/fuzz-replay` 스킬과 동일한 재현 로직을 SSH를 통해 수행한다.

```bash
# 특정 케이스 재현
ssh <SSH_TARGET> 'cd <FUZZER_DIR> && uv run fuzzer campaign replay results/<file>.jsonl --case-id <N>'

# reproduction_cmd 추출
ssh <SSH_TARGET> "jq -r 'select(.type==\"case\" and .case_id==<N>) | .reproduction_cmd' <FUZZER_DIR>/results/<file>.jsonl"

# pcap 확인 (있다면)
ssh <SSH_TARGET> "jq -r 'select(.type==\"case\" and .case_id==<N>) | .pcap_path' <FUZZER_DIR>/results/<file>.jsonl"
```

## 기능 6: 코드 동기화

로컬 변경사항을 서버에 반영해야 할 때:

```bash
rsync -avz --exclude='.venv' --exclude='__pycache__' --exclude='.git' --exclude='results' \
  ./ <SSH_TARGET>:<FUZZER_DIR>/
```

동기화 후 서버에서 의존성 업데이트:
```bash
ssh <SSH_TARGET> 'cd <FUZZER_DIR> && uv sync'
```

## 기능 7: 결과 파일 로컬로 가져오기

```bash
scp <SSH_TARGET>:<FUZZER_DIR>/results/<file>.jsonl results/
```

## 주의사항

- SSH 명령에서 작은따옴표(`'`)로 감싸 로컬 셸 확장 방지. jq 필터 등 내부 따옴표는 이스케이프 또는 큰따옴표로 교대 사용
- sudo가 필요한 작업은 사용자에게 `! ssh <SSH_TARGET> '...'` 형태로 직접 실행을 안내
- 장시간 퍼징은 SSH 끊김 방지를 위해 nohup 사용
- 결과 파일이 서버에 있으므로 분석도 서버에서 수행 (jq 활용)
