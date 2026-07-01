# Documentation Index

This tree contains the current operating documentation only. Historical
worklogs, implementation-process PRDs, and rough notes were intentionally
removed; use git history when old decision context is needed.

## Current Truth

| Document | Purpose |
| --- | --- |
| [AI_AGENT_GUIDE.md](AI_AGENT_GUIDE.md) | Agent onboarding, priority order, and current operating assumptions. |
| [USAGE.md](USAGE.md) | CLI usage, profile/strategy semantics, and result handling. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Current module and data-flow architecture. |

## Operations

| Document | Purpose |
| --- | --- |
| [operations/real-ue.md](operations/real-ue.md) | Real-UE defaults, native IPsec, resolver behavior, evidence order. |
| [operations/campaign-commands.md](operations/campaign-commands.md) | Copy-paste campaign commands for the current runtime. |
| [operations/ios.md](operations/ios.md) | iPhone/libimobiledevice setup and evidence collection. |
| [operations/server-setup.md](operations/server-setup.md) | IMS server/container checks and resolver inputs. |
| [operations/troubleshooting.md](operations/troubleshooting.md) | Common timeout, IPsec, attach, and oracle issues. |
| [operations/mt-invite-template.md](operations/mt-invite-template.md) | MT-INVITE template scope and dynamic fields. |

## Reference

| Document | Purpose |
| --- | --- |
| [reference/fuzzer.md](reference/fuzzer.md) | Fuzzer theory and SIP fuzzing surface reference. |
| [reference/sip-protocol.md](reference/sip-protocol.md) | SIP protocol research summary. |
| [reference/sip-completeness.md](reference/sip-completeness.md) | Runtime/generator completeness and baseline scope matrix. |
| [reference/sip-message-classification.md](reference/sip-message-classification.md) | UE-oriented SIP message classification. |
| [reference/sip-fields-matrix.md](reference/sip-fields-matrix.md) | Request/response field matrix. |
| [reference/sip-official-fields.md](reference/sip-official-fields.md) | RFC/IANA field research. |
| [reference/packet-examples-requests.md](reference/packet-examples-requests.md) | Request packet examples. |
| [reference/packet-examples-responses.md](reference/packet-examples-responses.md) | Response packet examples. |
| [reference/iana/](reference/iana/) | IANA registry surveys. |

## Maintenance Rules

- Keep real-UE examples aligned with `--ipsec-mode native` unless a comparison
  experiment explicitly requires `null` or `bypass`.
- Keep copy-paste campaign commands in `operations/campaign-commands.md`.
- Keep protocol surveys under `reference/`; do not mix them with operational
  runbooks.
- Do not add one-off worklogs or implementation scratch notes back into `docs/`.
