#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# THE local gate. Everything that can be proven on this machine, in cost order,
# stopping at the first failure. Run it BEFORE anything else — before opening a PR,
# before `gcloud builds submit`, before creating a GKE cluster, before declaring a
# baseline. See docs/dev/local-gate-order.md for why each stage exists.
#
#   scripts/local_gate.sh                # stages 1-4 (the default: everything free)
#   scripts/local_gate.sh --fast         # stages 1-2 only (static + unit/feature suites)
#   scripts/local_gate.sh --with-kind    # also stage 5: the four fleet proofs on kind
#   scripts/local_gate.sh --from 3       # resume at a stage (after fixing a failure)
#
# Env: SKIP_BAZEL=1 to skip the Bazel parity stage; SLO_REPS=N for stage 4 reps.
set -uo pipefail
cd "$(dirname "$0")/.."

# Before ANY stage: make `cargo`/`rustc` the toolchain pinned in rust-toolchain.toml
# (the one CI and Bazel use), or refuse to run. A gate that builds with a different
# compiler than CI proves nothing about CI, and the substitution is silent — a
# non-rustup `cargo` earlier on PATH just ignores rust-toolchain.toml.
. scripts/use_pinned_toolchain.sh || exit 1

FROM=1
LAST=4
WITH_KIND=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fast) LAST=2; shift ;;
    --with-kind) WITH_KIND=1; LAST=5; shift ;;
    --from) FROM="${2:?--from needs a stage number}"; shift 2 ;;
    -h|--help) sed -n '3,16p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# `--from 5` alone would otherwise resume into a range that ends at 4 and run nothing.
if (( FROM > LAST )); then LAST="$FROM"; fi
if (( LAST >= 5 )); then WITH_KIND=1; fi

STAGE=0
run() { # run <label> <command...>
  local label="$1"; shift
  STAGE=$((STAGE + 1))
  if (( STAGE < FROM || STAGE > LAST )); then
    printf '\n[stage %d] %-56s SKIPPED\n' "$STAGE" "$label"
    return 0
  fi
  printf '\n=====================================================================\n'
  printf '[stage %d] %s\n' "$STAGE" "$label"
  printf '=====================================================================\n'
  if ! "$@"; then
    printf '\n[stage %d] FAILED: %s\n' "$STAGE" "$label" >&2
    printf 'Fix it, then resume with: scripts/local_gate.sh --from %d\n' "$STAGE" >&2
    exit 1
  fi
}

# --- stage 1: deterministic structural gates (seconds, no build) --------------
# These are the cheapest possible failures — image tags that name a version nobody
# built, a port that drifted from the registry, a chart guard that stopped refusing.
# They are the ones that used to be discovered on a cluster that was already billing.
# No `set -e` in these functions: errexit set inside a function persists for the WHOLE
# shell afterwards, so a later harmless non-zero would abort the run with no message.
# Chain with && instead — the function's exit status is what `run` checks.
stage_static() {
  python3 scripts/jcs_vocabulary_gate.py --selftest \
    && python3 scripts/jcs_vocabulary_gate.py \
    && python3 scripts/check_port_registry.py \
    && python3 scripts/discriminator_gate.py \
    && python3 scripts/tracked_secrets_gate.py --selftest \
    && python3 scripts/tracked_secrets_gate.py \
    && python3 scripts/deploy_image_tag_gate.py --selftest \
    && python3 scripts/deploy_image_tag_gate.py \
    && python3 scripts/slo_invocation_gate.py --selftest \
    && python3 scripts/slo_invocation_gate.py \
    && python3 scripts/bazel_srcs_gate.py --selftest \
    && python3 scripts/bazel_srcs_gate.py \
    && python3 scripts/slo_gate.py --selftest \
    || return 1
  if command -v helm >/dev/null 2>&1; then
    python3 scripts/helm_render_gate.py
  else
    echo "helm not installed — SKIPPING the chart render gate (CI still enforces it)."
  fi
}

# --- stage 2: the code suites --------------------------------------------------
# The default workspace battery does NOT compile the non-default feature backends,
# so the feature-gated lane is a SEPARATE, required run — the same split CI makes.
FEATURES=dev_env_key_source,pkcs11_keysource,redis_replay,online_ocsp,aws_kms_keysource,gcp_kms_keysource,async_serve,cpstore_etcd
stage_suites() {
  cargo build --workspace --all-targets \
    && cargo test --workspace \
    && cargo build --workspace --all-targets --features "$FEATURES" \
    && cargo test -p mcp-re-proxy --features "$FEATURES"
}

# --- stage 3: Bazel parity ------------------------------------------------------
stage_bazel() {
  if [[ "${SKIP_BAZEL:-0}" == 1 ]]; then echo "SKIP_BAZEL=1 — skipped."; return 0; fi
  command -v bazel >/dev/null 2>&1 || { echo "bazel not installed — skipped (CI enforces)."; return 0; }
  python3 scripts/bazel_gazelle_gate.py && bazel test //... --test_output=errors
}

# --- stage 4: the local SLO lane ------------------------------------------------
# ADR-MCPRE-051 §7, free, same envelope as the GKE Job. A red lane here means the
# declared-hardware run would only pay money to reproduce the same regression.
stage_slo() {
  scripts/local_slo_lane.sh --reps "${SLO_REPS:-6}"
  local rc=$?
  # Neither 2 (could not measure: no Docker) nor 3 (measured, missed tolerance on a
  # loaded box) is evidence of a regression. Both still fail the gate — "could not
  # decide" is not "passed" — but say which one it was so nobody reads it as a code
  # failure.
  if (( rc == 2 )); then
    echo "stage 4 could not MEASURE (see the reason above) — not a code regression," >&2
    echo "but the gate cannot pass without it. Resume: scripts/local_gate.sh --from 4" >&2
  elif (( rc == 3 )); then
    echo "stage 4 was INCONCLUSIVE — it measured, but on a loaded box, and contention" >&2
    echo "alone produces that result. Re-run on a quiet box: scripts/local_gate.sh --from 4" >&2
  fi
  return $rc
}

# --- stage 5 (opt-in): the four fleet proofs on a local kind cluster -------------
# IDENTICAL harness, chart and images the GKE run uses — only the cluster substrate
# differs. This is what caught six deploy defects before a single cloud charge.
stage_kind() {
  if [[ "$WITH_KIND" != 1 ]]; then echo "not requested (pass --with-kind)."; return 0; fi
  PROVIDER=kind docs/security/gke-multi-replica-validation.sh
}

run "static gates (tags, ports, secrets, chart, vocabulary)" stage_static
run "cargo suites (workspace + feature-gated backends)"      stage_suites
run "bazel parity (//...)"                                   stage_bazel
run "local SLO lane (ADR-051 §7 anchor + gate)"              stage_slo
run "kind fleet proofs (identical harness to GKE)"           stage_kind

printf '\n=====================================================================\n'
printf 'LOCAL GATE: PASS (stages %d-%d)\n' "$FROM" "$LAST"
printf 'Only now is cloud spend justified — docs/security/gke-slo-baseline-runbook.md\n'
printf '=====================================================================\n'
