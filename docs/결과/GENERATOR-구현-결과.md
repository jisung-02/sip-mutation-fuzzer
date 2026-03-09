# Generator 구현 결과

기준 일자: 2026-03-09

## 요약
- `SIPGenerator`의 request/response 공개 API가 구현되었다.
- request/response 기본값 생성, override 반영, precondition 검증, Pydantic 검증 흐름이 연결되었다.
- Generator CLI가 추가되었고, `project.scripts` 엔트리포인트는 `fuzzer` 로 정리되었다.

## 이번 결과에서 확정된 것
### 1. 공개 API
- `generate_request(spec, context=None)`
- `generate_response(spec, context)`

두 메서드는 내부적으로 아래 순서로 동작한다.
1. catalog 기반 모델 해석
2. precondition 검증
3. 기본값 payload 생성
4. override 병합
5. `model_validate(...)` 를 통한 최종 Pydantic 인스턴스 생성

### 2. CLI 어댑터
Generator CLI는 `src/volte_mutation_fuzzer/generator/cli.py` 에 구현되어 있다.

`pyproject.toml` 기준 엔트리포인트:

```toml
[project.scripts]
fuzzer = "volte_mutation_fuzzer.generator.cli:main"
```

지원 커맨드:
- `fuzzer request`
- `fuzzer response`

### 3. 대표 실행 예시
기본 request 생성:

```bash
uv run fuzzer request OPTIONS
```

context 포함 response 생성:

```bash
uv run fuzzer response 200 INVITE --context '{"call_id":"call-1","local_tag":"ue-tag","local_cseq":7}'
```

환경 변수로 기본값 변경:

```bash
VMF_GENERATOR_REQUEST_URI_HOST=ims.example.net uv run fuzzer request OPTIONS
```

override 주입:

```bash
uv run fuzzer request OPTIONS --override '{"Max-Forwards": 10}'
```

## 검증 결과
아래 명령으로 generator 관련 구현을 검증했다.

```bash
uv run python -m unittest tests/generator/test_contracts.py tests/generator/test_core.py tests/generator/test_cli.py -v
uv run ruff check src tests
uv run ty check
```

검증 결과:
- generator 테스트 **43개 통과**
- `ruff check` 통과
- `ty check` 통과

## 현재 의미
이 결과로 Generator는 더 이상 내부 helper 수준의 스캐폴딩이 아니라,
**catalog 기반 request/response Pydantic 인스턴스를 실제로 생성할 수 있는 서비스 + CLI 어댑터** 상태가 되었다.

## 후속 후보 작업
- CLI에 파일 입력/출력 옵션 추가
- scenario / body_kind 를 실제 생성 로직에 반영
- 생성된 Pydantic 모델을 SIP wire 문자열로 직렬화하는 별도 계층 설계
