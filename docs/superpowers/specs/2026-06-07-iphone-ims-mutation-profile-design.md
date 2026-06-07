# iPhone IMS Mutation Profile Design

## Goal

Improve iPhone real-UE fuzzing by keeping MT-INVITE delivery prerequisites intact while adding iPhone/CommCenter-specific pressure on SIP/SDP negotiation surfaces that are likely to be parsed after delivery.

## Context

The repository already had an `iphone_ims` profile before this change. It covered:

- `iphone_sdp_media_negotiation`
- `iphone_security_agreement_pressure`
- `iphone_option_tag_negotiation`
- `iphone_identity_privacy_pressure`
- iPhone-biased byte targeting

That was a useful start, but it still left a gap around capability negotiation headers. iPhone IMS messages commonly carry feature tags, accepted body types, allowed methods, and content negotiation fields that are parsed separately from `Supported` / `Require` option tags. Reusing the Pixel capability strategy would blur device assumptions, so the iPhone profile needs its own concrete strategy.

## Design

The profile remains named `iphone_ims`. It is a mutator policy profile, not a sender mode. Operators still use `--ios` for iOS log/crash collection and `real-ue-direct` / native IPsec for the delivery path. `iphone_ims` only controls mutation selection and byte target narrowing.

The profile supports `wire` and `byte`, not `model`, because the real-UE MT-INVITE path is template/editable-message driven.

### Wire Strategies

`iphone_ims` supports these iPhone-specific wire strategies:

- `iphone_sdp_media_negotiation`: mutates SDP media/QoS/AMR-WB fields while keeping SIP framing valid and updating `Content-Length`.
- `iphone_security_agreement_pressure`: mutates RFC 3329 / 3GPP Security Agreement fields, including `q`, `prot`, `mod`, `spi-c`, `spi-s`, `port-c`, `port-s`, `alg`, and `ealg`.
- `iphone_option_tag_negotiation`: mutates `Supported`, `Require`, and `Proxy-Require` option-tag combinations around `sec-agree`, `precondition`, `100rel`, and `timer`.
- `iphone_capability_negotiation_pressure`: mutates capability negotiation headers that are distinct from option tags:
  - `Contact`
  - `Accept-Contact`
  - `Allow`
  - `Allow-Events`
  - `Accept`
  - `Content-Type`
- `iphone_identity_privacy_pressure`: mutates IMS identity, access, service, charging, and privacy headers.

The new capability strategy deliberately does not mutate `Supported` / `Require`; those stay under `iphone_option_tag_negotiation`. This keeps crash/anomaly attribution cleaner in campaign results.

### Capability Variants

`iphone_capability_negotiation_pressure` uses in-place header value mutations:

- duplicate or contradictory `Contact` feature tags such as `audio`, `video`, `+g.3gpp.smsip`, `+g.3gpp.mid-call`, `reg-id`, and `methods`
- malformed `Accept-Contact` feature-tag combinations with empty `+g.3gpp.icsi-ref`, repeated ICSI references, `explicit`, and `require`
- skewed `Allow` method lists, including duplicates, missing commas, and unknown method names
- empty or parameterized `Allow-Events`
- malformed `Accept` MIME lists, duplicate separators, and out-of-range `q` values
- suspicious `Content-Type` parameters and multi-value content types

Each mutation records `variant=capability.<name>` in the mutation note and targets `header[N].capability` so downstream analysis can group capability cases separately.

### Byte Targeting

For `iphone_ims` + byte `header_targeted`, byte flips prefer iPhone-relevant headers first:

- `contact`
- `accept`
- `accept-contact`
- `allow`
- `allow-events`
- `content-type`
- `p-called-party-id`
- `p-asserted-identity`
- `p-preferred-identity`
- `p-access-network-info`
- `p-preferred-service`
- `p-visited-network-id`
- `p-charging-vector`
- `privacy`
- `security-client`
- `security-server`
- `security-verify`
- `proxy-require`
- `require`
- `supported`

If none exist, the mutator falls back to IMS header ranges and then generic mutable headers.

### Default Pool

`iphone_ims` defaults:

- `wire`: `iphone_sdp_media_negotiation`, `iphone_security_agreement_pressure`, `iphone_option_tag_negotiation`, `iphone_capability_negotiation_pressure`, `iphone_identity_privacy_pressure`, `sdp_struct_only`, `sdp_byte_edit`, `safe`, `header_whitespace_noise`
- `byte`: `header_targeted`

The default resolver skips strategies whose prerequisites are absent. For packets without SDP, sec-agree, option-tag, capability, or identity/privacy surfaces, it falls back to body-agnostic safe wire strategies.

## Operational Use

Baseline first:

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 222222 \
  --methods INVITE \
  --profile iphone_ims \
  --layer wire \
  --strategy identity \
  --mt-invite-template a31 \
  --ipsec-mode native \
  --ios \
  --max-cases 1
```

Default iPhone campaign:

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 222222 \
  --methods INVITE \
  --profile iphone_ims \
  --layer wire,byte \
  --strategy default \
  --mt-invite-template a31 \
  --ipsec-mode native \
  --ios \
  --max-cases 50
```

Capability-only repro:

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 222222 \
  --methods INVITE \
  --profile iphone_ims \
  --layer wire \
  --strategy iphone_capability_negotiation_pressure \
  --mt-invite-template a31 \
  --ipsec-mode native \
  --ios \
  --max-cases 20
```

Use `VMF_MSISDN_TO_IP_222222=10.20.20.2` only when live Contact resolution fails because the iPhone Contact is user-less.

## Error Handling

Explicit iPhone strategies raise `ValueError` when their required target headers are absent. Default strategy resolution should skip missing-prerequisite strategies before mutation. Multi-round mutation treats later deterministic strategy `ValueError`s as graceful stop points, matching existing behavior.

## Testing

The implementation is covered by:

- `iphone_ims` profile advertisement and default-pool tests
- explicit `iphone_capability_negotiation_pressure` mutation test
- CLI help/default acceptance tests
- iPhone byte targeting tests
- full mutator regression tests

Verification run for the shipped change:

```bash
uv run pytest -q
uv run ruff check .
uv run ruff format --check src/volte_mutation_fuzzer/mutator/core.py src/volte_mutation_fuzzer/mutator/profile_catalog.py src/volte_mutation_fuzzer/mutator/cli.py tests/mutator/test_core.py tests/mutator/test_cli.py tests/mutator/test_sdp.py
git diff --check
```
