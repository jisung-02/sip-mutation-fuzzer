# SIP 메시지 완성도 매트릭스

이 문서는 `volte_mutation_fuzzer.sip.completeness` 의 요청 메서드별 완성도 기준을 사람이 읽기 쉽게 정리한 표다.

- `runtime_complete` 는 현재 코드베이스에서 honest runtime path 로 검증할 수 있는 메서드다.
- `generator_complete` 는 `SIPGenerator.generate_request(RequestSpec(method=...))` 로는 생성되지만, 저장소가 아직 honest runtime prerequisite state 를 소유하지 않는 메서드다.
- `runtime_path` 는 가능한 경우 `dialog.scenarios.scenario_for_method()` 와 대응되는 실제 경로를 뜻한다.
- `baseline_scope` 는 해당 메서드를 어떤 범위까지 정직하게 설명할 수 있는지를 뜻한다.
- `runtime_complete` 가 자동으로 "real-device validated"를 뜻하지는 않는다. 현재 real-device baseline 은 `INVITE`에만 있다.

| Method | Tier | Runtime path | Baseline scope | Note |
|---|---|---|---|---|
| INVITE | runtime_complete | stateless | real_ue_baseline | Primary real-UE baseline for inbound INVITE handling. |
| ACK | runtime_complete | invite_ack | invite_dialog | Exercises the ACK leg after a successful INVITE transaction. |
| BYE | runtime_complete | invite_dialog | invite_dialog | Uses the established INVITE dialog teardown path. |
| CANCEL | runtime_complete | invite_cancel | invite_dialog | Uses the early-dialog INVITE cancellation path. |
| INFO | runtime_complete | invite_dialog | invite_dialog | Invite-dialog path defaults to `info_package=dtmf`; real-ue-direct packet generation also materializes the DTMF body on the wire. |
| MESSAGE | runtime_complete | stateless | stateless | Stateless MESSAGE handling is exercised directly in runtime flows. |
| NOTIFY | generator_complete | unsupported | generator_only | Generator coverage exists, but there is no honest runtime path yet because subscription/notifier prerequisite state is not owned by the repo. |
| OPTIONS | runtime_complete | stateless | stateless | Stateless OPTIONS handling is available in runtime flows. |
| PRACK | runtime_complete | invite_prack | invite_dialog | Requires a reliable provisional response, specifically `Require: 100rel` plus `RSeq`; this is not "any 18x". |
| PUBLISH | generator_complete | unsupported | generator_only | Generator coverage exists, but runtime support is not modeled yet. |
| REFER | runtime_complete | invite_dialog | invite_dialog | Uses the INVITE dialog referral path and stays bodyless by default unless explicitly overridden. |
| REGISTER | generator_complete | unsupported | generator_only | Generator coverage exists, but runtime handling is not modeled yet. |
| SUBSCRIBE | generator_complete | unsupported | generator_only | Generator coverage exists, but the honest runtime prerequisite subscription/service state is not modeled yet. |
| UPDATE | runtime_complete | invite_dialog | invite_dialog | Uses the established INVITE dialog update path. |

## Registry Notes

The registry is intentionally exhaustive over `REQUEST_MODELS_BY_METHOD`. If a new SIP request method is added, this matrix and `PACKET_COMPLETENESS` should be updated together.

`baseline_scope` 해석 요약:

- `real_ue_baseline`: 실기기 기준 baseline 이 있다. 현재는 `INVITE`.
- `invite_dialog`: INVITE로 honest state 를 세운 뒤 그 다이얼로그 안에서 검증된다.
- `stateless`: 별도 dialog setup 없이 runtime path 를 직접 검증한다.
- `generator_only`: 생성/렌더/변이 계층까지는 정직하게 말할 수 있지만 runtime path 는 아직 저장소 범위 밖이다.
