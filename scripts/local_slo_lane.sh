#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# ADR-MCPRE-051 §7 LOCAL SLO lane. ONE command, no copy-paste invocation:
#   scripts/local_slo_lane.sh                # 6 anchor reps + gate each (the default)
#   scripts/local_slo_lane.sh --reps 1       # single rep (quick pre-flight)
#   scripts/local_slo_lane.sh --sweep        # also record the 1→N core sweep
#
# This lane is the CHEAP half of the SLO obligation and runs FIRST — before the
# kind proof harness and before anything that costs money on GKE
# (docs/security/gke-slo-baseline-runbook.md). It measures the same canonical v2
# envelope the GKE Job measures (concurrency 128 / 8000 requests / cold TLS1.3-mTLS)
# and gates the result against the committed local anchor
# (docs/bench/adr-051-baseline-local.json) via scripts/adr051_slo_gate.py.
#
# WHY A SCRIPT AND NOT A DOCUMENTED COMMAND: `tls_load_harness_bench` is NOT
# `#[ignore]` — the whole file is gated to the `redis_replay` feature lane instead,
# so it never runs in the default battery. Several docs used to say `-- --ignored`,
# which selects ONLY ignored tests: cargo then runs ZERO tests, exits 0, and the
# lane looks green while having measured nothing. This script never passes
# `--ignored` and FAILS LOUDLY if a rep did not actually execute one test.
#
# Requirements: Docker (the bench stands up its own primary+2-replica Redis fleet),
# or point MCP_RE_LOADGEN_REDIS_URL at an existing one.
#
# Env:
#   REPS                     (default 6)      — anchor reps; the committed anchor is a 6-rep median
#   OUTDIR                   (default target/slo-local)
#   MCP_RE_LOADGEN_HW_CLASS  (default: the anchor's hardware_class)
#   MCP_RE_LOADGEN_REDIS_URL (default: unset — the bench starts Docker Redis itself)
set -euo pipefail
cd "$(dirname "$0")/.."

REPS=6
SWEEP=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reps) REPS="${2:?--reps needs a count}"; shift 2 ;;
    --sweep) SWEEP=1; shift ;;
    -h|--help) sed -n '3,10p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

BASELINE=docs/bench/adr-051-baseline-local.json
# ABSOLUTE. cargo runs the test binary with cwd = the PACKAGE root (mcp-re-proxy/),
# so a relative MCP_RE_LOADGEN_OUT lands under mcp-re-proxy/ and the gate reads nothing.
OUTDIR="$(mkdir -p "${OUTDIR:-target/slo-local}" && cd "${OUTDIR:-target/slo-local}" && pwd)"

# The anchor config is READ FROM the committed baseline, never restated here: a
# literal that drifts from the baseline would gate a fresh run against numbers
# measured under a different envelope, which is worse than not gating at all.
read -r ANCHOR_HW CONCURRENCY REQUESTS MODE <<<"$(python3 -c "
import json; c = json.load(open('$BASELINE'))['anchor']['config']
print(c['hardware_class'], c['concurrency'], c['requests'], c['connection_mode'])")"
HW="${MCP_RE_LOADGEN_HW_CLASS:-$ANCHOR_HW}"

if [[ -z "${MCP_RE_LOADGEN_REDIS_URL:-}" ]] && ! docker info >/dev/null 2>&1; then
  echo "local-slo-lane: Docker is not running — the bench needs it for its Redis fleet." >&2
  echo "                Start Docker, or set MCP_RE_LOADGEN_REDIS_URL to a reachable primary." >&2
  exit 2
fi
# QUIET-BOX HANDLING. This lane is co-located (loadgen shares cores with the proxy),
# so an unrelated build/test battery on the same machine halves throughput and triples
# the tail. That false alarm already cost one full A/B/B/A investigation (2026-07-18:
# v0.12.1 itself measured ~3225 rps on a loaded box vs its own 4907 anchor).
#
# The asymmetry is what makes this tractable: contention can only DEPRESS throughput
# and inflate latency, never flatter them. So a run that PASSES under load is
# conservative and trustworthy — it cleared the bar while handicapped. Only a FAILURE
# under load is ambiguous, and that is reported as INCONCLUSIVE (exit 3), not as a
# regression. Declaring or refreshing a baseline still requires a quiet box.
NCPU="$(sysctl -n hw.ncpu 2>/dev/null || nproc)"
read_load1() { uptime | sed -E 's/.*load averages?: *//' | tr -d ',' | awk '{print $1}'; }
quiet_enough() { awk -v l="$1" -v n="$NCPU" 'BEGIN{exit !(l <= n * 0.3)}'; }

# SETTLE first, then refuse. Run from scripts/local_gate.sh this lane starts seconds
# after `bazel test //...` finished, so the 1-minute average still carries the gate's
# OWN previous stage — refusing immediately would fail the gate on work it just did.
LOAD1="$(read_load1)"
SETTLE_SECONDS="${SETTLE_SECONDS:-300}"
if ! quiet_enough "$LOAD1"; then
  echo "local-slo-lane: load $LOAD1 on $NCPU cores — waiting up to ${SETTLE_SECONDS}s for the box to settle..."
  waited=0
  while (( waited < SETTLE_SECONDS )); do
    sleep 15; waited=$((waited + 15))
    LOAD1="$(read_load1)"
    quiet_enough "$LOAD1" && { echo "local-slo-lane: settled at load $LOAD1 after ${waited}s."; break; }
  done
fi
NOISY=0
if ! quiet_enough "$LOAD1"; then
  NOISY=1
  echo "local-slo-lane: NOTE measuring on a LOADED box — 1-min load $LOAD1 on $NCPU cores"
  echo "                (quiet would be <= $(awk -v n="$NCPU" 'BEGIN{printf "%.1f", n*0.3}')). Contention only depresses throughput, so a"
  echo "                PASS still counts; a FAIL will be reported INCONCLUSIVE, not as a"
  echo "                regression. Do NOT declare a baseline from this run."
fi

if [[ "$HW" != "$ANCHOR_HW" ]]; then
  echo "local-slo-lane: NOTE hardware_class '$HW' != anchor '$ANCHOR_HW' — the relative"
  echo "                regression gate still applies, but the anchor was not recorded here."
fi

FEATURES=async_serve,redis_replay
# The harness spawns the REAL CLI as a child (MCP_RE_PROXY_CLI → target/release/mcp-re-proxy),
# so the BIN must be built with the same features as the test, not just the test target.
echo "=== building (release, --features $FEATURES) ==="
# Explicit checks: the script does not run under `set -e` (the guards below need to
# inspect a non-zero cargo run), so a failed build would otherwise measure a stale binary.
cargo build --release -p mcp-re-proxy --features "$FEATURES" --bins \
  || { echo "local-slo-lane: FAIL — the proxy bin did not build." >&2; exit 1; }
cargo test --release -p mcp-re-proxy --features "$FEATURES" --test tls_load_harness_bench --no-run \
  || { echo "local-slo-lane: FAIL — the bench did not build." >&2; exit 1; }

# One measurement. `--exact` selects the single bench fn; NEVER `--ignored` (see header).
run_one() {
  local cores="$1" out="$2" log="$3"
  MCP_RE_LOADGEN_CORES="$cores" \
  MCP_RE_LOADGEN_CONCURRENCY="$CONCURRENCY" \
  MCP_RE_LOADGEN_REQUESTS="$REQUESTS" \
  MCP_RE_LOADGEN_MODE="$MODE" \
  MCP_RE_LOADGEN_HW_CLASS="$HW" \
  MCP_RE_LOADGEN_OUT="$out" \
    cargo test --release -p mcp-re-proxy --features "$FEATURES" \
      --test tls_load_harness_bench tls_load_harness_bench -- --exact --nocapture >"$log" 2>&1 || true
  grep -E 'declared_cores|successes/failures|throughput|added_latency' "$log" || true

  # THE GUARD. A lane that selected no test exits 0 with "0 passed" and writes no
  # report — indistinguishable from a pass unless it is checked. Check it.
  grep -qE 'test result: ok\. 1 passed' "$log" || {
    echo "local-slo-lane: FAIL — the run did not execute exactly one bench test." >&2
    echo "                (0 passed usually means a filter/--ignored mistake: nothing was measured.)" >&2
    exit 1
  }
  [[ -s "$out" ]] || { echo "local-slo-lane: FAIL — no report written to $out" >&2; exit 1; }
}

echo
echo "=== anchor: ${REPS} rep(s) @ ${HW} / 1 core / concurrency $CONCURRENCY / $REQUESTS req / $MODE mTLS ==="
reports=()
for i in $(seq 1 "$REPS"); do
  echo "--- rep $i/$REPS"
  # NOT piped: a pipeline runs run_one in a subshell, where its guard's `exit 1`
  # would abort only that subshell and the lane would sail on past a bad rep.
  run_one 1 "$OUTDIR/rep$i.json" "$OUTDIR/rep$i.log"
  reports+=("$OUTDIR/rep$i.json")
done

echo
echo "=== gate: each rep vs $BASELINE ==="
fails=0
for r in "${reports[@]}"; do
  python3 scripts/adr051_slo_gate.py --report "$r" || fails=$((fails + 1))
done

python3 - "${reports[@]}" <<'PY'
import json, statistics, sys
rps = [json.load(open(p))["results"]["throughput_rps"] for p in sys.argv[1:]]
if len(rps) > 1:
    print(f"\nmedian throughput over {len(rps)} rep(s): {statistics.median(rps):.1f} rps"
          f"  (min {min(rps):.1f}, max {max(rps):.1f})")
PY

if [[ "$SWEEP" == 1 ]]; then
  echo
  echo "=== 1→N core sweep (RECORDED, NON-AUTHORITATIVE — co-located loadgen flattens it) ==="
  for c in 2 4 8; do
    echo "--- cores=$c"
    run_one "$c" "$OUTDIR/cores$c.json" "$OUTDIR/cores$c.log"
  done
  echo "The authoritative 1→N curve is the GKE fleet run, not this."
fi

echo
if (( fails > 0 )); then
  if (( NOISY == 1 )); then
    echo "RESULT: INCONCLUSIVE — $fails of ${#reports[@]} rep(s) missed tolerance, but the box was" >&2
    echo "        loaded (1-min load $LOAD1 on $NCPU cores). Contention alone produces exactly this," >&2
    echo "        so this is NOT evidence of a regression. Re-run on a quiet box to decide." >&2
    exit 3
  fi
  echo "RESULT: FAIL — $fails of ${#reports[@]} rep(s) outside local-regression tolerances." >&2
  exit 1
fi
if (( NOISY == 1 )); then
  echo "RESULT: PASS — ${#reports[@]}/${#reports[@]} rep(s) within tolerance DESPITE a loaded box"
  echo "        (1-min load $LOAD1 on $NCPU cores). Contention only depresses these numbers, so"
  echo "        clearing the bar while handicapped is a conservative pass. Not baseline-grade."
else
  echo "RESULT: PASS — ${#reports[@]}/${#reports[@]} rep(s) within local-regression tolerances."
fi
echo "Reports under $OUTDIR/. Only now is it worth spending on kind / GKE."
