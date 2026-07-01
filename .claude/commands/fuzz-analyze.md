---
name: fuzz-analyze
description: 퍼징 결과를 분석하고 인사이트를 제공한다. "결과 분석", "결과 봐줘", "report", "분석해", "어떤 결과 나왔어" 등을 요청할 때 사용한다. JSONL 파일 경로를 인자로 받거나, results/ 디렉토리에서 최신 파일을 자동으로 찾는다.
---

# 퍼징 결과 분석기

캠페인 결과 JSONL 파일을 분석하고 지능적인 인사이트를 제공한다.

## 결과 파일 찾기

인자로 경로가 주어지지 않으면:
```bash
ls -t results/*.jsonl | head -1
```
가장 최근 JSONL 파일을 자동 선택한다.

## 분석 절차

### 1단계: 기본 통계 수집

```bash
# campaign report로 전체 요약
uv run fuzzer campaign report <path>
```

### 2단계: verdict 분포 분석

```bash
# verdict별 카운트
jq -r 'select(.type=="case") | .verdict' <path> | sort | uniq -c | sort -rn
```

### 3단계: 응답 코드 패턴

```bash
# 응답 코드별 분포
jq -r 'select(.type=="case") | "\(.verdict) \(.response_code // "none")"' <path> | sort | uniq -c | sort -rn | head -20
```

### 4단계: 레이어/전략 효과성

```bash
# 레이어별 verdict 분포
jq -r 'select(.type=="case") | "\(.layer) \(.verdict)"' <path> | sort | uniq -c | sort -rn

# 전략별 verdict 분포
jq -r 'select(.type=="case") | "\(.strategy) \(.verdict)"' <path> | sort | uniq -c | sort -rn
```

### 5단계: 주요 발견 추출

```bash
# crash/stack_failure 케이스
jq 'select(.type=="case" and (.verdict=="crash" or .verdict=="stack_failure"))' <path>

# suspicious 케이스 (비정상 응답)
jq 'select(.type=="case" and .verdict=="suspicious")' <path>

# 가장 느린 케이스 (잠재적 DoS)
jq -r 'select(.type=="case") | "\(.elapsed_ms)\t\(.case_id)\t\(.method)\t\(.verdict)"' <path> | sort -rn | head -10
```

### 6단계: mutation ops 패턴

```bash
# 어떤 변이가 crash를 유발했는지
jq -r 'select(.type=="case" and (.verdict=="crash" or .verdict=="suspicious")) | .mutation_ops[]' <path> | sort | uniq -c | sort -rn | head -10
```

## 출력 형식

분석 결과를 다음 형식으로 보고한다:

```
## 퍼징 결과 분석: <파일명>

### 요약
| 항목 | 값 |
|------|-----|
| 총 케이스 | N |
| 실행 시간 | Xm Ys |
| 처리량 | N cases/min |

### Verdict 분포
| Verdict | 수 | 비율 |
|---------|-----|------|
| normal | N | X% |
| suspicious | N | X% |
| timeout | N | X% |
| crash | N | X% |
| ... | | |

### 레이어/전략 효과성
| 조합 | 총 | crash+suspicious | 발견율 |
|------|-----|-----------------|--------|
| wire/default | N | M | X% |
| byte/default | N | M | X% |
| ... | | | |

### 주요 발견
[crash/suspicious 케이스 상세]

### 응답 코드 패턴
[비정상 응답 코드 분석]

### 다음 단계 제안
[분석 결과에 기반한 다음 퍼징 전략 제안]
```

## 지능적 인사이트 생성 규칙

분석 결과를 바탕으로 다음을 판단한다:

### crash가 발견된 경우
- reproduction_cmd 강조
- 해당 pcap 경로 안내
- 동일 seed로 재현 테스트 제안
- crash 카테고리 분류 (메모리, 파서, 프로토콜 등)

### suspicious가 많은 경우
- 응답 코드 패턴 분석 (400→파싱 문제, 5xx→서버 불안정)
- 특정 레이어/전략에 집중된다면 해당 방향으로 집중 퍼징 제안

### timeout이 많은 경우
- SA 만료 가능성 점검 제안
- timeout 임계값 조정 제안
- 네트워크 연결 상태 확인 제안

### 전부 normal인 경우
- 변이 강도 증가 제안 (byte 레이어 추가)
- 다른 메서드 탐색 제안
- timeout 줄여서 경계값 탐색 제안
