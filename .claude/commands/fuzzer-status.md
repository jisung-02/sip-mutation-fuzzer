---
name: fuzzer-status
description: VoLTE fuzzer 프로젝트의 현재 상태를 요약한다. "현재 상태", "어디까지 했어", "status", "진행상황" 등을 요청할 때 사용한다.
---

# VoLTE Fuzzer 프로젝트 상태 리포트

프로젝트의 현재 구현 상태, 최근 변경, 남은 이슈를 한눈에 보여준다.

## 수집할 정보

### 1. Git 상태
```bash
git log --oneline -10
git status --short
git branch -v
```

### 2. 테스트 상태
```bash
uv run pytest tests/ -q --tb=no 2>&1 | tail -5
```

### 3. 오픈 이슈
`docs/이슈/오픈-이슈.md` 파일을 읽는다.

### 4. 메모리 확인
`/Users/chaejisung/.claude/projects/-Users-chaejisung-Desktop-volte-mutation-fuzzer/memory/MEMORY.md`를 읽어 프로젝트 컨텍스트를 확인한다.

## 출력 형식

```
## VoLTE Fuzzer 현재 상태

### 브랜치: [branch name]
- 최근 커밋: [hash] [message]
- 작업 트리: [clean/dirty]

### 테스트
- [X passed, Y failed]
- pre-existing failures: [목록]

### 최근 작업 (최근 5커밋)
| 커밋 | 요약 |
|------|------|
| ... | ... |

### 주요 구현 현황
| 기능 | 상태 |
|------|------|
| MT INVITE 템플릿 퍼징 | [구현 완료/진행중] |
| ADB 연결 복구 | [구현 완료/진행중] |
| IPsec SA 만료 감지 | [구현 완료/진행중] |
| ... | ... |

### 남은 이슈
[오픈 이슈 목록 요약]
```
