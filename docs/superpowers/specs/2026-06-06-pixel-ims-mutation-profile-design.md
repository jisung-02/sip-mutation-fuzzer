# Pixel IMS Mutation Profile Design

## Goal

Add a Pixel-focused SIP mutation strategy that is more effective for real-UE MT-INVITE campaigns by preserving Pixel delivery prerequisites while concentrating mutations on Android/Pixel IMS parser surfaces.

## Context

The current real-UE path already has `--pixel`, which rewrites the Request-URI to the resolved UE Contact URI so Pixel-class devices accept the packet. Existing mutation profiles are generic:

- `delivery_preserving` keeps packets broadly deliverable.
- `ims_specific` biases to IMS headers and SDP, but remains device-agnostic.
- `parser_breaker` targets low-level framing and often risks early timeout.

Pixel campaigns need a profile that composes with `--pixel` instead of replacing sender behavior. The mutator should avoid breaking Request-URI/Via framing first, then stress fields Pixel is likely to parse after delivery: SDP media negotiation, session timer headers, IMS P-headers, Contact alias parameters, and targeted bytes inside those regions.

## Design

Add a new mutation profile named `pixel_ims`. It is a mutator policy profile, not a sender mode. Operators will still opt into Pixel delivery with `--pixel`; `pixel_ims` only controls mutation selection and target narrowing.

The profile supports `wire` and `byte`, not `model`, because the current Pixel real-UE MT-INVITE path is template/editable-message driven. `--strategy default` resolves deterministically from the profile default pool using the existing seed-based contract.

### Wire Strategies

Add four concrete wire strategies:

- `pixel_sdp_media_negotiation`: mutate SDP media parser inputs while keeping SIP framing valid. Targets `m=audio`, payload type lists, `a=rtpmap`, AMR `a=fmtp` parameters, `a=curr/des/conf:qos` preconditions, `a=rtcp`, `a=ptime`, and `a=maxptime`.
- `pixel_session_timer_skew`: mutate `Session-Expires`, `Min-SE`, and `Supported`/`Require` timer combinations. This targets call/session state handling without changing transport routing.
- `pixel_p_header_pressure`: mutate IMS identity/access/charging P-headers in place, especially `P-Access-Network-Info`, `P-Asserted-Identity`, and `P-Charging-Vector`.
- `pixel_capability_header_pressure`: mutate Android/IMS feature-tag and capability negotiation headers in place: `Contact` feature tags, `Accept-Contact`, `Supported`, `Require`, `Allow`, `Accept`, `P-Preferred-Service`, and `P-Early-Media`.

Keep existing `alias_port_desync` and SDP strategies available, but do not make alias desync dominate the default pool. Pixel delivery already depends on sender Request-URI rewriting, so Contact alias corruption is useful but should not be the primary signal.

### Byte Targeting

For `pixel_ims` + byte `header_targeted`, narrow byte flips to Pixel-relevant headers first:

- `contact`
- `accept`
- `accept-contact`
- `allow`
- `allow-events`
- `p-asserted-identity`
- `p-preferred-identity`
- `p-access-network-info`
- `p-preferred-service`
- `p-early-media`
- `p-visited-network-id`
- `p-charging-vector`
- `session-expires`
- `min-se`
- `supported`
- `require`
- `content-type`

If none exist, fall back to the existing IMS header range behavior, then generic mutable headers.

### Default Pool

`pixel_ims` defaults:

- `wire`: `pixel_sdp_media_negotiation`, `pixel_session_timer_skew`, `pixel_p_header_pressure`, `pixel_capability_header_pressure`, `sdp_struct_only`, `sdp_byte_edit`, `alias_port_desync`, `safe`, `header_whitespace_noise`
- `byte`: `header_targeted`

The default resolver must skip strategies whose prerequisites are absent, as it already does for SDP body and Contact alias strategies. `safe` and `header_whitespace_noise` are final body-agnostic fallbacks for packets that have no SDP, timer, P-header, or Contact alias surface.

## Error Handling

Prerequisite-specific strategies raise `ValueError` when their target fields are absent. The default strategy resolver should skip inapplicable strategies before mutation, and multi-mutation loops should continue to treat later `ValueError`s as graceful stop points.

Explicitly requested Pixel strategies should fail honestly when their required target fields are missing, matching existing deterministic strategy behavior.

## Testing

Add focused unit tests for:

- `pixel_ims` profile validation and default strategy resolution.
- Pixel wire default skips absent prerequisites and remains deterministic by seed.
- `pixel_sdp_media_negotiation` mutates only SDP/media content and updates `Content-Length`.
- `pixel_session_timer_skew` mutates timer headers or adds a timer pressure header when supported timer headers exist.
- `pixel_p_header_pressure` mutates P-headers in place.
- `pixel_capability_header_pressure` mutates feature-tag/capability headers in place.
- `pixel_ims` byte targeting stays inside Pixel-relevant headers when available.
- CLI/campaign accepts `--profile pixel_ims` and reports it in output.

## Documentation

Update `docs/AI_AGENT_GUIDE.md` and `docs/USAGE.md` with a Pixel campaign example:

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --methods INVITE \
  --pixel \
  --profile pixel_ims \
  --layer wire,byte \
  --strategy default \
  --ipsec-mode native \
  --max-cases 50
```

Document that `pixel_ims` is not a substitute for `--pixel`; use both for Pixel-class real-UE campaigns.
