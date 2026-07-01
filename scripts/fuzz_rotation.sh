#!/usr/bin/env bash
#
# 4-profile rotation fuzzing — sequential, non-overlapping seeds.
#
#   round 1: legacy(0..299) -> ims_specific(300..599) -> parser_breaker(600..899) -> iphone_ims(900..1199)
#   round 2: legacy(1200..) -> ims_specific(1500..) -> parser_breaker(1800..) -> iphone_ims(2100..)
#   ...
#   round 100
#
# Total: 4 profiles x 300 cases x 100 rounds = 120,000 cases.
# Each run waits for the previous to finish (300 -> 300 -> 300 -> 300).
# seed-start increments globally so no case-seed is ever reused.
#
# Run on the IMS server (needs docker access to pcscf + the iPhone over USB).
#   chmod +x scripts/fuzz_rotation.sh
#   ./scripts/fuzz_rotation.sh [INVITE|MESSAGE|OPTIONS]
# Or use the per-method wrappers:
#   ./scripts/fuzz_rotation_invite.sh
#   ./scripts/fuzz_rotation_message.sh
#   ./scripts/fuzz_rotation_options.sh
#
set -u

# Method: 1st arg, else $METHOD env, else INVITE.
METHOD="${1:-${METHOD:-INVITE}}"

# ---------------------------- config (edit here) ----------------------------
ROUNDS=100
CASES=300
PROFILES=(legacy ims_specific parser_breaker iphone_ims)

MSISDN=111111
IMPI=001010000123511
FROM=222222

TIMEOUT=0.2                   # >=0.2 : below this the request never reaches the UE
COOLDOWN=0                    # kamailio 486=alive fix lets cooldown 0 run without de-reg

# Teardown (CANCEL) only applies to INVITE; skipping it is ~10x faster per case
# and is essential at 120k scale. Non-INVITE methods have no dialog to tear down.
EXTRA_FLAGS=""
[[ "$METHOD" == "INVITE" ]] && EXTRA_FLAGS="--no-teardown"

# Derive the fuzzer dir from this script's location (scripts/..), so it works
# under sudo too (sudo resets $HOME to /root).
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUZZER_DIR="${FUZZER_DIR:-$(dirname "$_SCRIPT_DIR")}"
PCSCF_CONTAINER="pcscf"
MASTER_LOG="$FUZZER_DIR/results/fuzz_rotation_${METHOD}.log"
# ---------------------------------------------------------------------------

cd "$FUZZER_DIR" || { echo "no fuzzer dir: $FUZZER_DIR" >&2; exit 1; }
mkdir -p results

# Resolve the UE's current live IP from the P-CSCF NATPING 200 replies. The UE
# IP rotates on re-registration, so we re-resolve before every run and pin it
# (live resolver alone fails when kamailio usrloc is empty). Empty -> no pin,
# fall back to the fuzzer's own resolver.
live_ip() {
  docker logs "$PCSCF_CONTAINER" --since 120s 2>&1 \
    | grep -oE '10\.20\.20\.[0-9]+:[0-9]+ completed with code: 200' \
    | grep -oE '^10\.20\.20\.[0-9]+' \
    | tail -1
}

total=$((ROUNDS * ${#PROFILES[@]}))
run=0
seed=0

echo "=== fuzz_rotation start $(date '+%F %T') | rounds=$ROUNDS profiles=${PROFILES[*]} cases=$CASES method=$METHOD ===" | tee -a "$MASTER_LOG"

for ((r=1; r<=ROUNDS; r++)); do
  for prof in "${PROFILES[@]}"; do
    run=$((run+1))
    ip="$(live_ip)"
    out="rot-${METHOD}-r$(printf '%03d' "$r")-${prof}-s${seed}"

    pin=()
    if [[ -n "$ip" ]]; then
      pin=(env "VMF_MSISDN_TO_IP_${MSISDN}=${ip}")
    fi

    echo "[$(date '+%F %T')] run ${run}/${total}  round ${r}/${ROUNDS}  profile=${prof}  seed=${seed}  ip=${ip:-<resolver>}  out=${out}" | tee -a "$MASTER_LOG"

    "${pin[@]}" uv run fuzzer campaign run \
      --target-msisdn "$MSISDN" --impi "$IMPI" --from-msisdn "$FROM" \
      --methods "$METHOD" --profile "$prof" --strategy default --layer wire \
      --mt --ipsec-mode native --ios \
      --cooldown "$COOLDOWN" --timeout "$TIMEOUT" \
      --max-cases "$CASES" --seed-start "$seed" \
      --circuit-breaker 0 --no-pcap --no-adb --oracle-log-grace 0 \
      $EXTRA_FLAGS \
      --output "$out" \
      >> "$MASTER_LOG" 2>&1 \
      || echo "[$(date '+%F %T')] run ${run} FAILED (continuing)" | tee -a "$MASTER_LOG"

    seed=$((seed + CASES))
  done
done

echo "=== fuzz_rotation done $(date '+%F %T') | total runs=$run | last seed=$seed ===" | tee -a "$MASTER_LOG"
