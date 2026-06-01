# 2026-05-30 Implementation Audit

대상 브랜치: `audit/dead-code-cleanup-implementation-check`  
감사 기준 커밋: `1dcbe5c chore: remove unused dead code`  
기준 브랜치: `main` (`5829e6b feat(tools): add docker-clean task to stop and remove all Docker containers`)

이 보고서는 사용자 요청의 "잘못 구현된 것"을 구현/검증 증거 기준으로 분류한다. 현재 프로젝트 지침에 맞춰 `real-ue-direct` 및 실기기 경로를 우선했고, 소프트폰 경로는 테스트 실패 분류에 필요한 범위에서만 확인했다.

## 결론

실제 구현 버그는 `--packet-file` 캠페인 계약 쪽에 집중되어 있다.

| 분류 | 항목 | 판단 |
| --- | --- | --- |
| 실제 구현 버그 | `--packet-file` layer validation 누락 | 수정 필요 |
| 실제 구현 버그 | `--packet-file` 가 methods/response_codes/strategy metadata 를 느슨하게 받아 잘못된 case 를 생성 | 수정 필요 |
| 테스트 debt | ADB/oracle/reproduction/native-IPsec 관련 7개 실패 | 구현보다 테스트 기대값이 낡은 것으로 판단 |
| 타입 debt | `uv run ty check src` 10 diagnostics | 런타임 버그 증거는 약하지만 정리 필요 |
| 브랜치 diff | dead-code cleanup 자체 | repo 내부 참조 기준 추가 구현 버그는 발견하지 못함 |

## 검증 명령

```bash
git status --short --branch
# ## audit/dead-code-cleanup-implementation-check
# ?? docs/이슈/2026-05-30-implementation-audit.md
# ?? 설명.txt
# ?? 설명2.txt

git diff --stat main...HEAD
# 11 files changed, 134 insertions(+), 210 deletions(-)

git diff --check main...HEAD
# 통과

uv run python -m compileall -q src scripts
# 통과

uv run ruff check .
# All checks passed!

uv run --with vulture vulture src scripts --min-confidence 90
# 통과, 출력 없음

uv run ty check src
# 10 diagnostics

uv run pytest -q
# 8 failed, 902 passed, 182 subtests passed
```

## 실제 구현 문제

### P1. `--packet-file` 이 `wire`/`model` layer 를 거부하지 않는다

근거:

- [README.md:202](../../README.md:202) 는 `--packet-file` 이 파일 SIP 패킷을 변이 없이 바이트 1:1로 송신한다고 설명한다.
- [README.md:218](../../README.md:218) 는 `--layer` 를 `byte` 또는 `auto` 만 허용한다고 명시한다.
- [tests/campaign/test_contracts.py:259](../../tests/campaign/test_contracts.py:259) 는 `layers=("wire",)` 를 `ValidationError` 로 기대한다.
- [src/volte_mutation_fuzzer/campaign/contracts.py:233](../../src/volte_mutation_fuzzer/campaign/contracts.py:233) 의 `packet_file` validator 는 `mode`, `target_msisdn`, 파일 존재 여부만 확인하고 layer 를 검사하지 않는다.
- [src/volte_mutation_fuzzer/campaign/core.py:133](../../src/volte_mutation_fuzzer/campaign/core.py:133) 는 `packet_file_active` 일 때 `effective_layers = ("byte",)` 로 조용히 collapse 한다.

실제 실패:

```text
tests/campaign/test_contracts.py::PacketFileConfigTests::test_packet_file_rejects_wire_layer
AssertionError: ValidationError not raised
```

영향:

- 사용자가 `--packet-file --layer wire` 또는 `--layer model` 을 줘도 즉시 실패하지 않는다.
- 실제 실행은 사용자가 요청한 layer 와 다르게 `byte` case 로 저장된다.
- raw bytes/NUL 보존 경로에서 "명시적 거부" 대신 "묵시적 변환"이 일어나 재현 명령과 결과 메타데이터를 흐린다.

권장 수정:

- `CampaignConfig` 의 `packet_file` validator 에서 `set(self.layers) <= {"byte", "auto"}` 를 강제한다.
- 위반 시 `ValueError("packet_file supports layers: byte, auto")` 를 발생시킨다.
- `CaseGenerator` 의 silent collapse 는 `auto` 처리 정도로만 남기고, invalid layer 는 config 단계에서 막는다.

### P1. `--packet-file` 이 단일 raw packet 계약인데 여러 method/response case 를 생성할 수 있다

근거:

- [src/volte_mutation_fuzzer/campaign/contracts.py:141](../../src/volte_mutation_fuzzer/campaign/contracts.py:141) 는 `methods` 와 `response_codes` 가 모두 비어 있으면 모든 SIP method 를 기본값으로 넣는다.
- [src/volte_mutation_fuzzer/campaign/core.py:141](../../src/volte_mutation_fuzzer/campaign/core.py:141) 는 `config.methods` 를 그대로 순회해 case 를 생성한다.
- [src/volte_mutation_fuzzer/campaign/core.py:156](../../src/volte_mutation_fuzzer/campaign/core.py:156) 는 `response_codes` 도 별도로 case 로 생성한다.
- [src/volte_mutation_fuzzer/campaign/core.py:814](../../src/volte_mutation_fuzzer/campaign/core.py:814) 는 `spec.response_code is None` 인 경우에만 packet-file executor 로 보낸다. response case 는 packet-file 을 무시하고 일반 synthetic response path 로 간다.
- [src/volte_mutation_fuzzer/campaign/core.py:1447](../../src/volte_mutation_fuzzer/campaign/core.py:1447) 와 [src/volte_mutation_fuzzer/campaign/core.py:1480](../../src/volte_mutation_fuzzer/campaign/core.py:1480) 은 packet-file 내부에서도 `spec.method` 로 INVITE teardown/oracle grace 를 결정한다.

재현 가능한 current-state 증거:

```bash
uv run python - <<'PY'
import tempfile
from pathlib import Path
from volte_mutation_fuzzer.campaign.contracts import CampaignConfig
from volte_mutation_fuzzer.campaign.core import CaseGenerator

p = Path(tempfile.NamedTemporaryFile(delete=False).name)
p.write_bytes(b"OPTIONS sip:u@h SIP/2.0\r\n\r\n")
cfg = CampaignConfig(
    mode="real-ue-direct",
    target_host="10.20.20.8",
    target_msisdn="111111",
    packet_file=str(p),
    max_cases=5,
)
print(cfg.layers, cfg.strategies)
for case in CaseGenerator(cfg).generate():
    print(case.model_dump())
p.unlink()
PY
```

출력 요지:

```text
layers ('model', 'wire', 'byte') strategies ('default', 'state_breaker')
case_id=0 method='ACK'    layer='byte' strategy='default'
case_id=1 method='BYE'    layer='byte' strategy='default'
case_id=2 method='CANCEL' layer='byte' strategy='default'
case_id=3 method='INFO'   layer='byte' strategy='default'
case_id=4 method='INVITE' layer='byte' strategy='default'
```

같은 파일 바이트가 ACK/BYE/CANCEL/INFO/INVITE 라벨로 저장된다. 파일 start-line 이 `OPTIONS` 여도 oracle/teardown 판단은 case label 을 따른다.

`response_codes` 도 같이 허용된다.

```text
CampaignConfig(..., packet_file=..., methods=("INVITE",), response_codes=(486,))
=> case 0: packet-file INVITE
=> case 1: synthetic response 486 INVITE
```

영향:

- "파일 패킷 그대로 송신" 캠페인 안에 synthetic response fuzzing 이 섞일 수 있다.
- raw packet 의 실제 method 와 result metadata 의 `method` 가 달라질 수 있다.
- INVITE 파일이 ACK/BYE 라벨로 실행되면 `collect_all_responses`, teardown, oracle grace 가 잘못 적용된다.
- `strategy=default` / seed 값이 저장되지만 packet-file path 는 mutator 를 전혀 호출하지 않아 실제 변이는 없다.

권장 수정:

- `packet_file` 모드에서는 `response_codes` 를 금지한다.
- `packet_file` 모드에서는 method 를 정확히 하나만 허용하거나, 파일 start-line 에서 method 를 파싱해 `methods` 를 자동 고정한다. 운영 실수 방지 관점에서는 "파일에서 파싱하고 사용자가 다른 method 를 주면 reject" 가 가장 안전하다.
- `packet_file` 모드에서는 strategy 를 `identity` 로 강제하거나, non-identity strategy 를 reject 한다. 적어도 result/reproduction metadata 가 "mutated default strategy" 처럼 보이면 안 된다.
- 테스트를 추가한다:
  - `packet_file` + methods omitted => reject 또는 파일 method 로 one-case
  - `packet_file` + multiple methods => reject
  - `packet_file` + response_codes => reject
  - `packet_file` + non-identity strategy => reject 또는 metadata identity 고정

## 테스트 기대값이 낡은 항목

`uv run pytest -q` 의 8개 실패 중 위 `packet_file` validator 실패 1개만 실제 구현 버그로 봤다. 아래 7개는 현재 구현, 주석, 문서화된 운영 이력과 대조했을 때 테스트가 예전 동작을 기대한다.

### ADB logcat clear 호출 횟수

실패:

```text
tests/adb/test_core.py::AdbLogCollectorTests::test_start_spawns_process_per_buffer_and_clears_logcat
```

현재 구현:

- [src/volte_mutation_fuzzer/adb/core.py:529](../../src/volte_mutation_fuzzer/adb/core.py:529) 에서 configured buffer 마다 `adb logcat -b <buffer> -c` 를 호출한다.
- [docs/이슈/2026-04-26-워크로그.md:188](2026-04-26-워크로그.md:188) 는 `adb logcat -c` 가 main buffer 만 비워 stale radio/system/crash 로그가 재매칭되던 문제를 기록한다.

판단: 구현이 맞고 테스트가 낡았다. 테스트는 `run_mock.assert_called_once_with(["adb", ..., "logcat", "-c"])` 대신 buffer별 clear 호출을 기대해야 한다.

### RILJ unexpected response 분류

실패:

```text
tests/adb/test_core.py::AdbAnomalyDetectorTagFilterTests::test_rilj_unexpected_response_kept
tests/adb/test_core.py::AdbAnomalyDetectorTagFilterTests::test_source_tag_recorded_on_event
```

현재 구현:

- [src/volte_mutation_fuzzer/adb/patterns.py:141](../../src/volte_mutation_fuzzer/adb/patterns.py:141) 은 `oem_ril_error` 를 명시적 failure token 만 critical 로 잡게 좁혔다.
- [src/volte_mutation_fuzzer/adb/patterns.py:165](../../src/volte_mutation_fuzzer/adb/patterns.py:165) 은 `RILJ processResponse: Unexpected response` 를 `rilj_unexpected_response` warning 으로 분리한다.
- [docs/이슈/2026-04-26-워크로그.md:90](2026-04-26-워크로그.md:90) 와 [docs/이슈/2026-04-26-워크로그.md:167](2026-04-26-워크로그.md:167) 가 false positive 제거 의도를 기록한다.

판단: 구현이 맞고 테스트가 낡았다. `error: 0` 을 critical `oem_ril_error` 로 승격하면 routine stale modem response 가 `stack_failure` 를 만든다.

### unrelated process death 매칭

실패:

```text
tests/adb/test_patterns.py::AnomalyPatternsTests::test_process_died_unrelated_proc_matches
```

현재 구현:

- [src/volte_mutation_fuzzer/adb/patterns.py:282](../../src/volte_mutation_fuzzer/adb/patterns.py:282) 근처 주석과 process death 계열은 일반 앱 lifecycle noise 를 줄이도록 좁혀져 있다.
- [docs/이슈/2026-04-26-워크로그.md:160](2026-04-26-워크로그.md:160) 은 `process_died` 를 IMS daemon/RIL/system_server/surfaceflinger 로 제한한 이유를 기록한다.

판단: 구현이 맞고 테스트가 낡았다. `Process com.example.unrelated ... has died` 까지 critical 로 잡으면 fuzzing oracle 이 일반 앱 종료 noise 에 오염된다.

### request reproduction command 형식

실패:

```text
tests/campaign/test_core.py::CampaignExecutorTests::test_reproduction_cmd_contains_method_and_seed
tests/campaign/test_core.py::ReproductionCmdMultiMutationTests::test_default_omits_mutations_per_case
```

현재 구현:

- [src/volte_mutation_fuzzer/campaign/core.py:1924](../../src/volte_mutation_fuzzer/campaign/core.py:1924) 의 request case reproduction command 는 `uv run fuzzer campaign run --seed-start <seed> --max-cases 1 ...` 형식이다.
- [src/volte_mutation_fuzzer/campaign/core.py:1972](../../src/volte_mutation_fuzzer/campaign/core.py:1972) 주석대로 response_code dialog case 만 `mutate response | send packet` pipe 형식을 유지한다.
- `git log` 에 `4e7800e fix(campaign): rewrite reproduction_cmd to use campaign run format` 이 존재한다.

판단: 구현이 맞고 테스트가 낡았다. request case 재현은 timeout/cooldown/pcap/circuit breaker/oracle grace/ipsec 등 campaign 실행 조건까지 같이 보존해야 한다.

### native IPsec mock expectation

실패:

```text
tests/sender/test_core.py::SIPSenderReactorTests::test_send_real_ue_direct_native_uses_native_ipsec_observer_path
```

현재 구현:

- [src/volte_mutation_fuzzer/sender/core.py:540](../../src/volte_mutation_fuzzer/sender/core.py:540) 가 `send_via_native_ipsec(..., alt_src_port=0, alt_dst_port=0)` 를 명시 전달한다.
- [docs/이슈/IMS-IPsec-SA-dispatch.md:148](IMS-IPsec-SA-dispatch.md:148) 는 `send_via_native_ipsec` 시그니처 확장과 default 0 의 기존 동작 보존을 기록한다.

판단: 구현이 맞고 테스트 mock expectation 이 새 optional args 를 반영하지 못했다.

## 타입 체크 debt

`uv run ty check src` 는 10 diagnostics 를 낸다. 현재 런타임 실패 증거가 있는 항목과 순수 타입 narrowing noise 를 분리한다.

우선 정리할 항목:

- [src/volte_mutation_fuzzer/campaign/cli.py:323](../../src/volte_mutation_fuzzer/campaign/cli.py:323)
  - `CampaignConfig.profiles` 타입은 `tuple[str, ...]` 이지만 CLI 는 `profiles=profile` 로 `str | None` 을 넘긴다.
  - Pydantic validator 가 런타임에서는 처리하지만 CLI boundary 에서 `_parse_csv(profile) or ("legacy",)` 로 맞추는 편이 명확하다.
- [src/volte_mutation_fuzzer/mutator/cli.py:98](../../src/volte_mutation_fuzzer/mutator/cli.py:98)
  - `MutationConfig.layer` 는 `Literal["model", "wire", "byte", "auto"]` 인데 `_build_config(..., layer: str)` 를 그대로 넘긴다.
  - CLI validation/cast 위치를 명확히 해야 한다.
- [src/volte_mutation_fuzzer/mutator/core.py:871](../../src/volte_mutation_fuzzer/mutator/core.py:871)
  - wire branch 에서 `editable_message` 가 Optional 로 남은 채 `_mutate_wire` 에 전달된다.
  - 런타임 invariant 는 맞지만 `assert editable_message is not None` 로 명시하는 편이 안전하다.

타입 narrowing noise 로 보이는 항목:

- [src/volte_mutation_fuzzer/campaign/report.py:59](../../src/volte_mutation_fuzzer/campaign/report.py:59)
  - `case.details.get(...)` 결과를 `dict` 로 좁힌 뒤 `.get("matched_line")` 를 호출하지만 ty 가 key type 을 `Never` 로 본다.
- [src/volte_mutation_fuzzer/mutator/cli.py:403](../../src/volte_mutation_fuzzer/mutator/cli.py:403)
  - mutation record display formatting 에서 dict/list narrowing 이 ty 에 충분히 전달되지 않는다.

## Dead-code cleanup branch audit

`main...HEAD` diff 는 주로 unused symbol 제거와 formatting 변경이다.

제거된 repo-internal symbol 참조 확인:

```bash
rg -n "CrashAnalyzer|grouped_response_counts|REGISTER_PUBLISH\\b|MESSAGE_SUBSCRIBE_REFER|VARIANTS|STRUCT_VARIANTS|replace_headers|print_live_stats" -S .
```

결과 요지:

- repo 내부에서 제거된 `CrashAnalyzer` alias, `grouped_response_counts`, `REGISTER_PUBLISH`, `MESSAGE_SUBSCRIBE_REFER`, `VARIANTS`, `STRUCT_VARIANTS`, `replace_headers`, `print_live_stats` 를 호출하는 production path 는 발견하지 못했다.
- 남은 `BYTE_EDIT_VARIANTS` 참조는 제거 대상이 아니며 현재 tests/source 에서 쓰인다.

주의:

- `scripts/crash_analyzer.py` 의 `CrashAnalyzer = CampaignCrashAnalyzer` alias 제거는 repo 내부 기준으로는 안전해 보인다.
- 다만 외부에서 이 script module 을 import 해 `CrashAnalyzer` 라는 이름을 사용했다면 깨질 수 있다. 이 저장소가 `scripts/` 를 public API 로 약속한 증거는 찾지 못해 구현 버그로 분류하지 않았다.

## 문서/운영 주의

감사 중 구현 버그와 별개로 문서 staleness 가 보였다.

- `AGENTS.md` 와 [docs/AI_AGENT_GUIDE.md:55](../AI_AGENT_GUIDE.md:55) 는 현재 testbed 에서 `111111` 이 Pixel 9 / Galaxy A17 로 회전 중이고 UE IP 는 live resolver 기준이라고 한다.
- [docs/A31_REAL_UE_GUIDE.md:10](../A31_REAL_UE_GUIDE.md:10) 과 [docs/A31_REAL_UE_GUIDE.md:307](../A31_REAL_UE_GUIDE.md:307) 은 여전히 `111111 = A31`, `10.20.20.8` 중심 설명을 강하게 담고 있다.

이는 이번 구현 버그 범위에는 넣지 않았지만, 실기기 운영자가 오래된 guide 를 복붙하면 stale target 으로 오판할 수 있다. 별도 문서 정리가 필요하다.

## 우선순위

1. `packet_file` 계약 수정
   - layer: `byte`/`auto` 만 허용
   - response_codes: 금지
   - methods: 파일 start-line 과 일치하는 단일 method 로 강제
   - strategy: `identity` 강제 또는 non-identity reject
2. stale test 7개 업데이트
   - ADB buffer별 clear
   - RILJ unexpected response warning 분리
   - unrelated process death suppression
   - request reproduction command = campaign run
   - native IPsec `alt_src_port=0`, `alt_dst_port=0`
3. `ty check src` 의 CLI boundary / Optional narrowing 정리
4. A31 guide / USAGE 의 stale device mapping 문서 정리

