# SIP 메시지 완성도 매트릭스

이 문서는 `volte_mutation_fuzzer.sip.completeness` 의 요청 메서드별 완성도 기준을 사람이 읽기 쉽게 정리한 표다.

- `runtime_complete` 는 현재 코드베이스에서 실제 runtime path 로 검증할 수 있는 메서드다.
- `generator_complete` 는 `SIPGenerator.generate_request(RequestSpec(method=...))` 로는 생성되지만, 아직 honest runtime path 가 없는 메서드다.
- `runtime_path` 는 가능한 경우 `dialog.scenarios.scenario_for_method()` 와 대응되는 실제 경로를 뜻한다.
- `baseline_scope` 는 해당 메서드를 검증할 때 기대하는 기준 범위를 뜻한다.

| Method | Tier | Runtime path | Baseline scope | Note |
|---|---|---|---|---|
| INVITE | runtime_complete | stateless | real_ue_baseline | Primary real-UE baseline for inbound INVITE handling. |
| ACK | runtime_complete | invite_ack | invite_dialog | Exercises the ACK leg after a successful INVITE transaction. |
| BYE | runtime_complete | invite_dialog | invite_dialog | Uses the established INVITE dialog teardown path. |
| CANCEL | runtime_complete | invite_cancel | invite_dialog | Uses the early-dialog INVITE cancellation path. |
| INFO | runtime_complete | invite_dialog | invite_dialog | Routes through the established INVITE dialog path. |
| MESSAGE | runtime_complete | stateless | stateless | Stateless MESSAGE handling is exercised directly in runtime flows. |
| NOTIFY | generator_complete | unsupported | generator_only | Generator coverage exists, but there is no honest runtime path yet. |
| OPTIONS | runtime_complete | stateless | stateless | Stateless OPTIONS handling is available in runtime flows. |
| PRACK | runtime_complete | invite_prack | invite_dialog | Exercises the reliable provisional response path. |
| PUBLISH | generator_complete | unsupported | generator_only | Generator coverage exists, but runtime support is not modeled yet. |
| REFER | runtime_complete | invite_dialog | invite_dialog | Uses the INVITE dialog referral path. |
| REGISTER | generator_complete | unsupported | generator_only | Generator coverage exists, but runtime handling is not modeled yet. |
| SUBSCRIBE | generator_complete | unsupported | generator_only | Generator coverage exists; runtime support is not modeled yet. |
| UPDATE | runtime_complete | invite_dialog | invite_dialog | Uses the established INVITE dialog update path. |

## Registry Notes

The registry is intentionally exhaustive over `REQUEST_MODELS_BY_METHOD`. If a new SIP request method is added, this matrix and `PACKET_COMPLETENESS` should be updated together.
