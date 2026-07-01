# SIP IANA Resource-Priority 전수조사

기준 일자: 2026-03-18

## 1. 문서 목적
이 문서는 IANA SIP Parameters의 `Resource-Priority Namespaces`와 그 하위 `Resource-Priority Priority-values` namespace registry 전체를 전수 inventory한 문서다. 이전 survey에서 가장 누락 가능성이 컸던 부분이라, namespace registry와 child registry 48개를 모두 한 번에 묶어 정리한다.

## 2. 공식 기준
- IANA registry: `Session Initiation Protocol (SIP) Parameters`
- IANA page last updated: `2026-01-07`
- IANA XML source: `.omx/research/sip-iana-full-20260318/sip-parameters.xml`
- Local extraction: `.omx/research/sip-iana-full-20260318/resource-priority-priority-values-detailed.json`

## 3. 범위 요약
- Namespace registry rows: `48`
- Child priority-value registries: `48`
- Total priority-value rows: `463`
- Top registry ids: `sip-parameters-14`, `sip-parameters-15`

## 4. Resource-Priority Namespaces (`sip-parameters-14`)
- Registry reference(s): `rfc4412, rfc7134`
- Why it matters: `Resource-Priority` header는 `namespace.value` 조합으로 동작하므로 namespace inventory와 각 namespace의 allowed priority value inventory를 함께 봐야 전체 표면이 보인다.

| Namespace | Numeric Value | Levels | Algorithm | New Response Code | New Warning Code | Reference(s) |
| --- | --- | --- | --- | --- | --- | --- |
| dsn | 0 | 5 | preemption | no | no | rfc4412 |
| drsn | 1 | 6 | preemption | no | no | rfc4412 |
| q735 | 2 | 5 | preemption | no | no | rfc4412 |
| ets | 3 | 5 | queue | no | no | rfc4412 |
| wps | 4 | 5 | queue | no | no | rfc4412 |
| dsn-000000 | 5 | 10 | preemption | no | no | rfc5478 |
| dsn-000001 | 6 | 10 | preemption | no | no | rfc5478 |
| dsn-000002 | 7 | 10 | preemption | no | no | rfc5478 |
| dsn-000003 | 8 | 10 | preemption | no | no | rfc5478 |
| dsn-000004 | 9 | 10 | preemption | no | no | rfc5478 |
| dsn-000005 | 10 | 10 | preemption | no | no | rfc5478 |
| dsn-000006 | 11 | 10 | preemption | no | no | rfc5478 |
| dsn-000007 | 12 | 10 | preemption | no | no | rfc5478 |
| dsn-000008 | 13 | 10 | preemption | no | no | rfc5478 |
| dsn-000009 | 14 | 10 | preemption | no | no | rfc5478 |
| drsn-000000 | 15 | 10 | preemption | no | no | rfc5478 |
| drsn-000001 | 16 | 10 | preemption | no | no | rfc5478 |
| drsn-000002 | 17 | 10 | preemption | no | no | rfc5478 |
| drsn-000003 | 18 | 10 | preemption | no | no | rfc5478 |
| drsn-000004 | 19 | 10 | preemption | no | no | rfc5478 |
| drsn-000005 | 20 | 10 | preemption | no | no | rfc5478 |
| drsn-000006 | 21 | 10 | preemption | no | no | rfc5478 |
| drsn-000007 | 22 | 10 | preemption | no | no | rfc5478 |
| drsn-000008 | 23 | 10 | preemption | no | no | rfc5478 |
| drsn-000009 | 24 | 10 | preemption | no | no | rfc5478 |
| rts-000000 | 25 | 10 | preemption | no | no | rfc5478 |
| rts-000001 | 26 | 10 | preemption | no | no | rfc5478 |
| rts-000002 | 27 | 10 | preemption | no | no | rfc5478 |
| rts-000003 | 28 | 10 | preemption | no | no | rfc5478 |
| rts-000004 | 29 | 10 | preemption | no | no | rfc5478 |
| rts-000005 | 30 | 10 | preemption | no | no | rfc5478 |
| rts-000006 | 31 | 10 | preemption | no | no | rfc5478 |
| rts-000007 | 32 | 10 | preemption | no | no | rfc5478 |
| rts-000008 | 33 | 10 | preemption | no | no | rfc5478 |
| rts-000009 | 34 | 10 | preemption | no | no | rfc5478 |
| crts-000000 | 35 | 10 | preemption | no | no | rfc5478 |
| crts-000001 | 36 | 10 | preemption | no | no | rfc5478 |
| crts-000002 | 37 | 10 | preemption | no | no | rfc5478 |
| crts-000003 | 38 | 10 | preemption | no | no | rfc5478 |
| crts-000004 | 39 | 10 | preemption | no | no | rfc5478 |
| crts-000005 | 40 | 10 | preemption | no | no | rfc5478 |
| crts-000006 | 41 | 10 | preemption | no | no | rfc5478 |
| crts-000007 | 42 | 10 | preemption | no | no | rfc5478 |
| crts-000008 | 43 | 10 | preemption | no | no | rfc5478 |
| crts-000009 | 44 | 10 | preemption | no | no | rfc5478 |
| esnet | 45 | 5 | queue | no | no | rfc7135 |
| mcpttp | 46 | 16 | preemption | no | no | rfc8101 |
| mcpttq | 47 | 16 | queue | no | no | rfc8101 |

## 5. Resource-Priority Priority-values Summary (`sip-parameters-15`)
- Registry reference(s): `rfc4412, rfc7134`
- Note: top-level `sip-parameters-15` 자체는 direct record가 없고, namespace별 child registry 48개가 실제 값을 가진다.

| Namespace | Registry ID | Priority Values | Reference(s) |
| --- | --- | --- | --- |
| drsn | sip-parameters-16 | 6 | rfc4412 |
| dsn | sip-parameters-17 | 5 | rfc4412 |
| q735 | sip-parameters-18 | 5 | rfc4412 |
| ets | sip-parameters-19 | 5 | rfc4412 |
| wps | sip-parameters-20 | 5 | rfc4412 |
| dsn-000000 | sip-parameters-21 | 10 | rfc5478 |
| dsn-000001 | sip-parameters-22 | 10 | rfc5478 |
| dsn-000002 | sip-parameters-23 | 10 | rfc5478 |
| dsn-000003 | sip-parameters-24 | 10 | rfc5478 |
| dsn-000004 | sip-parameters-25 | 10 | rfc5478 |
| dsn-000005 | sip-parameters-26 | 10 | rfc5478 |
| dsn-000006 | sip-parameters-27 | 10 | rfc5478 |
| dsn-000007 | sip-parameters-28 | 10 | rfc5478 |
| dsn-000008 | sip-parameters-29 | 10 | rfc5478 |
| dsn-000009 | sip-parameters-30 | 10 | rfc5478 |
| drsn-000000 | sip-parameters-31 | 10 | rfc5478 |
| drsn-000001 | sip-parameters-32 | 10 | rfc5478 |
| drsn-000002 | sip-parameters-33 | 10 | rfc5478 |
| drsn-000003 | sip-parameters-34 | 10 | rfc5478 |
| drsn-000004 | sip-parameters-35 | 10 | rfc5478 |
| drsn-000005 | sip-parameters-36 | 10 | rfc5478 |
| drsn-000006 | sip-parameters-37 | 10 | rfc5478 |
| drsn-000007 | sip-parameters-38 | 10 | rfc5478 |
| drsn-000008 | sip-parameters-39 | 10 | rfc5478 |
| drsn-000009 | sip-parameters-40 | 10 | rfc5478 |
| rts-000000 | sip-parameters-41 | 10 | rfc5478 |
| rts-000001 | sip-parameters-42 | 10 | rfc5478 |
| rts-000002 | sip-parameters-43 | 10 | rfc5478 |
| rts-000003 | sip-parameters-44 | 10 | rfc5478 |
| rts-000004 | sip-parameters-45 | 10 | rfc5478 |
| rts-000005 | sip-parameters-46 | 10 | rfc5478 |
| rts-000006 | sip-parameters-47 | 10 | rfc5478 |
| rts-000007 | sip-parameters-48 | 10 | rfc5478 |
| rts-000008 | sip-parameters-49 | 10 | rfc5478 |
| rts-000009 | sip-parameters-50 | 10 | rfc5478 |
| crts-000000 | sip-parameters-51 | 10 | rfc5478 |
| crts-000001 | sip-parameters-52 | 10 | rfc5478 |
| crts-000002 | sip-parameters-53 | 10 | rfc5478 |
| crts-000003 | sip-parameters-54 | 10 | rfc5478 |
| crts-000004 | sip-parameters-55 | 10 | rfc5478 |
| crts-000005 | sip-parameters-56 | 10 | rfc5478 |
| crts-000006 | sip-parameters-57 | 10 | rfc5478 |
| crts-000007 | sip-parameters-58 | 10 | rfc5478 |
| crts-000008 | sip-parameters-59 | 10 | rfc5478 |
| crts-000009 | sip-parameters-60 | 10 | rfc5478 |
| esnet | sip-parameters-esnet | 5 | rfc7135 |
| mcpttp | sip-parameters-mcpttp | 16 | rfc8101 |
| mcpttq | sip-parameters-mcpttq | 16 | rfc8101 |

## 6. Namespace별 Priority-values Inventory
## 6.1 Namespace: drsn (`sip-parameters-16`)
- Total rows: `6`
- Reference(s): `rfc4412`

| Priority Name | Numeric Value |
| --- | --- |
| "routine" | 5 |
| "priority" | 4 |
| "immediate" | 3 |
| "flash" | 2 |
| "flash-override" | 1 |
| "flash-override-override" | 0 |

## 6.2 Namespace: dsn (`sip-parameters-17`)
- Total rows: `5`
- Reference(s): `rfc4412`

| Priority Name | Numeric Value |
| --- | --- |
| "routine" | 4 |
| "priority" | 3 |
| "immediate" | 2 |
| "flash" | 1 |
| "flash-override" | 0 |

## 6.3 Namespace: q735 (`sip-parameters-18`)
- Total rows: `5`
- Reference(s): `rfc4412`

| Priority Name | Numeric Value |
| --- | --- |
| "4" | 4 |
| "3" | 3 |
| "2" | 2 |
| "1" | 1 |
| "0" | 0 |

## 6.4 Namespace: ets (`sip-parameters-19`)
- Total rows: `5`
- Reference(s): `rfc4412`

| Priority Name | Numeric Value |
| --- | --- |
| "4" | 4 |
| "3" | 3 |
| "2" | 2 |
| "1" | 1 |
| "0" | 0 |

## 6.5 Namespace: wps (`sip-parameters-20`)
- Total rows: `5`
- Reference(s): `rfc4412`

| Priority Name | Numeric Value |
| --- | --- |
| "4" | 4 |
| "3" | 3 |
| "2" | 2 |
| "1" | 1 |
| "0" | 0 |

## 6.6 Namespace: dsn-000000 (`sip-parameters-21`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.7 Namespace: dsn-000001 (`sip-parameters-22`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.8 Namespace: dsn-000002 (`sip-parameters-23`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.9 Namespace: dsn-000003 (`sip-parameters-24`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.10 Namespace: dsn-000004 (`sip-parameters-25`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.11 Namespace: dsn-000005 (`sip-parameters-26`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.12 Namespace: dsn-000006 (`sip-parameters-27`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.13 Namespace: dsn-000007 (`sip-parameters-28`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.14 Namespace: dsn-000008 (`sip-parameters-29`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.15 Namespace: dsn-000009 (`sip-parameters-30`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.16 Namespace: drsn-000000 (`sip-parameters-31`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.17 Namespace: drsn-000001 (`sip-parameters-32`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.18 Namespace: drsn-000002 (`sip-parameters-33`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.19 Namespace: drsn-000003 (`sip-parameters-34`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.20 Namespace: drsn-000004 (`sip-parameters-35`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.21 Namespace: drsn-000005 (`sip-parameters-36`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.22 Namespace: drsn-000006 (`sip-parameters-37`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.23 Namespace: drsn-000007 (`sip-parameters-38`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.24 Namespace: drsn-000008 (`sip-parameters-39`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.25 Namespace: drsn-000009 (`sip-parameters-40`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.26 Namespace: rts-000000 (`sip-parameters-41`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.27 Namespace: rts-000001 (`sip-parameters-42`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.28 Namespace: rts-000002 (`sip-parameters-43`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.29 Namespace: rts-000003 (`sip-parameters-44`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.30 Namespace: rts-000004 (`sip-parameters-45`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.31 Namespace: rts-000005 (`sip-parameters-46`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.32 Namespace: rts-000006 (`sip-parameters-47`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.33 Namespace: rts-000007 (`sip-parameters-48`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.34 Namespace: rts-000008 (`sip-parameters-49`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.35 Namespace: rts-000009 (`sip-parameters-50`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.36 Namespace: crts-000000 (`sip-parameters-51`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.37 Namespace: crts-000001 (`sip-parameters-52`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.38 Namespace: crts-000002 (`sip-parameters-53`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.39 Namespace: crts-000003 (`sip-parameters-54`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.40 Namespace: crts-000004 (`sip-parameters-55`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.41 Namespace: crts-000005 (`sip-parameters-56`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.42 Namespace: crts-000006 (`sip-parameters-57`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.43 Namespace: crts-000007 (`sip-parameters-58`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.44 Namespace: crts-000008 (`sip-parameters-59`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.45 Namespace: crts-000009 (`sip-parameters-60`)
- Total rows: `10`
- Reference(s): `rfc5478`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 9 |
| "1" | 8 |
| "2" | 7 |
| "3" | 6 |
| "4" | 5 |
| "5" | 4 |
| "6" | 3 |
| "7" | 2 |
| "8" | 1 |
| "9" | 0 |

## 6.46 Namespace: esnet (`sip-parameters-esnet`)
- Total rows: `5`
- Reference(s): `rfc7135`

| Priority Name | Numeric Value |
| --- | --- |
| "0" | 4 |
| "1" | 3 |
| "2" | 2 |
| "3" | 1 |
| "4" | 0 |

## 6.47 Namespace: mcpttp (`sip-parameters-mcpttp`)
- Total rows: `16`
- Reference(s): `rfc8101`

| Priority Name | Numeric Value |
| --- | --- |
| "mcpttp.0" | 15 |
| "mcpttp.1" | 14 |
| "mcpttp.2" | 13 |
| "mcpttp.3" | 12 |
| "mcpttp.4" | 11 |
| "mcpttp.5" | 10 |
| "mcpttp.6" | 9 |
| "mcpttp.7" | 8 |
| "mcpttp.8" | 7 |
| "mcpttp.9" | 6 |
| "mcpttp.10" | 5 |
| "mcpttp.11" | 4 |
| "mcpttp.12" | 3 |
| "mcpttp.13" | 2 |
| "mcpttp.14" | 1 |
| "mcpttp.15" | 0 |

## 6.48 Namespace: mcpttq (`sip-parameters-mcpttq`)
- Total rows: `16`
- Reference(s): `rfc8101`

| Priority Name | Numeric Value |
| --- | --- |
| "mcpttq.0" | 15 |
| "mcpttq.1" | 14 |
| "mcpttq.2" | 13 |
| "mcpttq.3" | 12 |
| "mcpttq.4" | 11 |
| "mcpttq.5" | 10 |
| "mcpttq.6" | 9 |
| "mcpttq.7" | 8 |
| "mcpttq.8" | 7 |
| "mcpttq.9" | 6 |
| "mcpttq.10" | 5 |
| "mcpttq.11" | 4 |
| "mcpttq.12" | 3 |
| "mcpttq.13" | 2 |
| "mcpttq.14" | 1 |
| "mcpttq.15" | 0 |

## 공식 출처
- [IANA Session Initiation Protocol (SIP) Parameters](https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml)
- [IANA XML export](https://www.iana.org/assignments/sip-parameters/sip-parameters.xml)
