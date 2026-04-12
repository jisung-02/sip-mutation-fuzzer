---
name: fuzz-replay
description: 특정 퍼징 케이스를 재현한다. "재현해줘", "replay", "이 케이스 다시", "case N 다시" 등을 요청할 때 사용한다. case ID 또는 verdict 필터로 재현 대상을 지정한다.
---

# 퍼징 케이스 재현기

특정 케이스를 재현하여 결과를 검증하거나 추가 진단을 수행한다.

## 재현 방법

### 방법 1: campaign replay (case ID 지정)

```bash
uv run fuzzer campaign replay <jsonl_path> --case-id <N>
```

### 방법 2: reproduction_cmd 직접 실행

JSONL에서 해당 케이스의 `reproduction_cmd`를 추출하여 실행:

```bash
jq -r 'select(.type=="case" and .case_id==N) | .reproduction_cmd' <path>
```

### 방법 3: pcap 분석

해당 케이스의 pcap 파일을 읽어 패킷 내용을 확인:

```bash
# pcap 경로 확인
jq -r 'select(.type=="case" and .case_id==N) | .pcap_path' <path>

# tcpdump로 내용 확인
sudo tcpdump -r <pcap_path> -A -v
```

## 사용 시나리오

### crash 케이스 재현
1. JSONL에서 crash 케이스 목록 추출
2. reproduction_cmd 실행
3. 동일 verdict가 나오는지 확인
4. pcap 비교 (있다면)

### suspicious 케이스 상세 분석
1. raw_response 확인
2. 어떤 변이(mutation_ops)가 적용됐는지 확인
3. 해당 seed로 동일 변이 재생성 확인

### 특정 verdict 일괄 추출

```bash
# 모든 crash 케이스의 재현 명령 추출
jq -r 'select(.type=="case" and .verdict=="crash") | 
  "# Case \(.case_id) (seed=\(.seed))\n\(.reproduction_cmd)\n"' <path>

# suspicious 케이스의 응답 확인
jq -r 'select(.type=="case" and .verdict=="suspicious") | 
  "Case \(.case_id): \(.response_code) - \(.reason)"' <path>
```

## 출력 형식

```
## 케이스 #N 재현 결과

### 원본 결과
| 항목 | 값 |
|------|-----|
| verdict | [원본] |
| response_code | [원본] |
| elapsed_ms | [원본] |
| mutation_ops | [원본] |

### 재현 결과
| 항목 | 값 |
|------|-----|
| verdict | [재현] |
| response_code | [재현] |
| elapsed_ms | [재현] |

### 비교
[동일/다른 결과에 대한 분석]

### pcap 분석 (있다면)
[패킷 내용 요약]
```
