# Troubleshooting

## Timeout

Likely causes:

- UE is not registered.
- Resolver picked stale IP or stale protected ports.
- Native IPsec xfrm state is missing or old.
- `null` / `bypass` source IP or bind port does not match the expected path.

Checks:

```bash
docker exec pcscf kamctl ul show
docker logs pcscf --since 2m | grep -iE 'REGISTER|OPTIONS|408|200'
docker exec pcscf ip xfrm state
```

If live resolver cannot identify the UE:

```bash
export VMF_MSISDN_TO_IP_<MSISDN>=<live-ue-ip>
```

Use this only as an explicit operator override.

## Native IPsec Looks Empty In Pcap

That can be normal. Native mode uses the negotiated xfrm/IPsec path, so outer capture may show ESP rather than readable SIP. Check:

- `observer_events`
- `responses`
- `results.jsonl`
- P-CSCF logs

## Suspicious 4xx / 5xx

Common causes:

- malformed SIP after mutation
- capability or option-tag conflict
- wrong identity/header state
- body/content length mismatch

Inspect:

```bash
uv run fuzzer campaign report <results.jsonl> --filter suspicious,crash,stack_failure
uv run fuzzer campaign replay <results.jsonl> --case-id <id>
```

## iPhone IMS Does Not Register

Symptoms:

- EPS attach exists, but no IMS APN/REGISTER.
- P-CSCF has no xfrm state.
- `kamctl ul show` is empty.

Actions:

1. Enable VoLTE on iPhone.
2. Select the test PLMN manually if automatic network selection attaches
   elsewhere.
3. Recheck SMF/P-CSCF logs.
4. Wait until stale IP churn stops before fuzzing.

Useful log:

```bash
docker logs pcscf --since 2m 2>&1 | grep -iE 'OPTIONS.*10.20.20.*(200|408)'
```

The live UE IP is the one responding `200`, not stale entries returning `408`.

## Android ADB Noise

`stack_failure` must be read with case evidence. Routine Android services can emit noisy logs. Use:

- case `anomalies.json`
- `logcat_radio.txt`
- `observer_events`
- actual SIP response

## Recovery Checklist

1. Confirm UE attach.
2. Confirm IMS REGISTER.
3. Confirm live xfrm state.
4. Run identity baseline.
5. Only then run `default` fuzzing.
