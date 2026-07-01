# MT-INVITE Template

The MT-INVITE template is the real-UE packet shape used for inbound call
fuzzing. The only campaign selector is `--mt`, which uses the bundled
`mt_invite_3gpp.sip.tmpl` template for INVITE campaigns.

## Templates

Current template files live under:

```text
src/volte_mutation_fuzzer/generator/templates/
```

Known template:

- `mt_invite_3gpp.sip.tmpl`: selected by `--mt`.

## Dynamic Values

The renderer fills values such as:

- target MSISDN / IMPI
- UE IP
- `port_pc`
- `port_ps`
- Call-ID
- From/To tags
- Via branch
- P-CSCF identity
- Contact and alias values

Do not hardcode UE IPs or adjacent port assumptions. Live resolver output wins.

## Baseline Usage

```bash
uv run fuzzer campaign run \
  --mode real-ue-direct \
  --target-msisdn 111111 \
  --methods INVITE \
  --mt \
  --profile legacy \
  --layer wire \
  --strategy identity \
  --ipsec-mode native \
  --max-cases 1
```

## Mutation Path

INVITE template output is parsed into `EditableSIPMessage`, then mutated in wire
or byte layers. The campaign runner drops `model` for active MT template runs
because the rendered packet is already concrete wire text.

For non-INVITE MT campaigns, `--mt` uses the generator's MT packet builders
instead of the INVITE template renderer. Packet-file campaigns force the byte
layer and require `--strategy identity`.
