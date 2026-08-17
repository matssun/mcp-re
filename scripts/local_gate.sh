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
    # Symmetric with the PASS banner, and on stdout as well as stderr. A reader who
    # pipes this script (`| tail`, `| grep`) gets the PIPE's exit status, not the
    # gate's — a failed gate then looks like a pass. So the verdict is also a line in
    # the output itself: exactly one `LOCAL GATE:` line is printed per run, and its
    # absence means the run did not finish. Check the line, never the piped status.
    printf '\n=====================================================================\n'
    printf 'LOCAL GATE: FAIL (stage %d — %s)\n' "$STAGE" "$label"
    printf '=====================================================================\n'
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

# The four cargo universes. `--workspace` sees only the first, so every lint and
# format check has to name the other three explicitly or they go unchecked.
MANIFESTS=(sdk/python/Cargo.toml sdk/typescript/Cargo.toml mcp-re-proxy/tests/mock-pkcs11/Cargo.toml)

# Formatting needs no build, so it belongs in the no-build stage.
fmt_check() {
  cargo fmt --all -- --check || return 1
  for m in "${MANIFESTS[@]}"; do
    cargo fmt --all --manifest-path "$m" -- --check || return 1
  done
}

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
    && python3 scripts/startup_backedges.py --selftest \
    && python3 scripts/module_map.py --selftest \
    && python3 scripts/bazel_srcs_gate.py \
    && python3 scripts/es256_containment_gate.py --selftest \
    && python3 scripts/es256_containment_gate.py \
    && python3 scripts/owned_worker_gate.py --selftest \
    && python3 scripts/owned_worker_gate.py \
    && python3 scripts/seam_posture_gate.py --selftest \
    && python3 scripts/seam_posture_gate.py \
    && python3 scripts/proxy_flag_doc_gate.py --selftest \
    && python3 scripts/proxy_flag_doc_gate.py \
    && python3 scripts/conformance_claims_gate.py --selftest \
    && python3 scripts/conformance_claims_gate.py \
    && python3 scripts/verification_trigger_gate.py --selftest \
    && python3 scripts/verification_trigger_gate.py \
    && python3 scripts/cargo_test_target_gate.py --selftest \
    && python3 scripts/cargo_test_target_gate.py \
    && python3 scripts/lifecycle_purity_gate.py --selftest \
    && python3 scripts/lifecycle_purity_gate.py \
    && python3 scripts/registry_approval_gate.py --selftest \
    && python3 scripts/registry_approval_gate.py \
    && python3 tools/verification/test_verdict_algebra.py \
    && python3 tools/verification/test_invalidation.py \
    && python3 tools/verification/test_attest.py \
    && python3 tools/verification/test_verus_lane.py \
    && python3 tools/verification/test_test_lane.py \
    && python3 tools/verification/test_measured_inputs.py \
    && python3 tools/verification/test_escape_hatches.py \
    && python3 tools/verification/test_theorems.py \
    && python3 tools/verification/test_theorem_review.py \
    && python3 tools/verification/test_views.py \
    `# A display, not a gate: run so a broken import or a renamed component surfaces here` \
    `# rather than the first time someone reaches for the review state.` \
    && python3 tools/verification/review >/dev/null \
    `# Ahead of the verdict, so a host that cannot run the verifier says so in those` \
    `# words. Same script the CI lanes start with: the environment it checks is the` \
    `# one both places depend on, and it names the fix instead of surfacing as a TOML` \
    `# import error or a missing rustup deep inside Verus.` \
    && ./scripts/verification_runner_preflight.sh \
    `# --gate, not --manifests: the manifests-only form validates the registry's shape` \
    `# and stops, so it never reads the code. Three uninterpreted spec functions sat` \
    `# unregistered in the TCB while this lane reported PASS, because the half that` \
    `# scans for escape hatches and runs Verus only ever ran in a CI job whose runner` \
    `# is scoped to another repository. ~26s warm, which buys the whole verdict.` \
    && python3 tools/verification/verify --gate \
    && python3 tools/scitt_fetch_service_key.py --selftest \
    && python3 scripts/slo_gate.py --selftest \
    && fmt_check \
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
  clippy_check \
    && cargo build --workspace --all-targets \
    && cargo test --workspace \
    && cargo build --workspace --all-targets --features "$FEATURES" \
    && cargo test -p mcp-re-proxy --features "$FEATURES" \
    && stage_demo \
    && stage_sdk
}

# The two downloader artefacts. `cargo test --workspace` cannot reach them: both SDKs
# are their OWN Cargo workspaces linking mcp-re-client-core by path, and their suites
# exercise the bindings from Python and Node, not from Rust. So a change to the core's
# emission contract compiles, passes every cargo and Bazel lane, and fails only in CI —
# which is how a nonce-length floor in build_signed_request_with reached a PR with both
# downloader jobs red and four green stages above them.
stage_sdk() {
  sdk_typescript && sdk_python
}

# Mirrors the "downloader — TypeScript napi package" job: the published build, the
# generated-loader drift check, and the coverage-gated suite.
sdk_typescript() {
  if ! command -v npm >/dev/null 2>&1; then
    echo "npm not installed — SKIPPING the TypeScript SDK suite (CI still enforces it)."
    return 0
  fi
  ( cd sdk/typescript \
      && { [[ -d node_modules ]] || npm ci; } \
      && npm run build \
      && npx vitest run --coverage ) || return 1
  git diff --exit-code -- sdk/typescript/native/binding.js sdk/typescript/native/binding.d.ts
}

# Mirrors the "downloader — Python maturin wheel" job: build the wheel, reinstall it,
# run the coverage-gated suite, then regenerate the cross-language parity oracle from
# the freshly built core. The regeneration is the part that matters — a binding that
# drifts from the core shows up as a diff in a committed fixture, not as a test that
# forgot to assert.
sdk_python() {
  local venv=sdk/python/.venv
  if [[ ! -x "$venv/bin/python" ]]; then
    python3 -m venv "$venv" || return 1
    "$venv/bin/pip" install --quiet -e "sdk/python[dev]" || return 1
  fi
  ( cd sdk/python \
      && ./.venv/bin/maturin build --release --out dist \
      && ./.venv/bin/pip install --quiet --force-reinstall dist/*.whl \
      && ./.venv/bin/python -m pytest -q ) || return 1

  # A throwaway interpreter, exactly as CI does it: the oracle must come from the
  # INSTALLED wheel alone, never from anything else already on a developer's venv.
  local oracle; oracle="$(mktemp -d)/oracle"
  python3 -m venv "$oracle" \
    && "$oracle/bin/pip" install --quiet sdk/python/dist/*.whl \
    && "$oracle/bin/python" tools/gen_sdk_parity_fixture.py \
    && git diff --exit-code -- sdk/fixtures/parity_vectors.json
}

# The public "no cloud credentials" demo. In a gate because it is the one artefact
# an evaluator runs first, and it was pointing at two test targets that had been
# deleted — so it could not exit 0, and nothing anywhere ran it to notice.
stage_demo() {
  bash scripts/demo-local.sh >/dev/null
}

# The tree carries zero warnings; `-D warnings` keeps it that way. Runs before the
# suites so lint drift surfaces in one build rather than after the full test battery.
# The feature lane is required, not thorough: the default features do not compile
# etcd_store.rs / redis_store.rs at all, so the default lane cannot see them.
clippy_check() {
  cargo clippy --workspace --all-targets -- -D warnings \
    && cargo clippy --workspace --all-targets --features "$FEATURES" -- -D warnings \
    || return 1
  for m in "${MANIFESTS[@]}"; do
    cargo clippy --manifest-path "$m" --all-targets -- -D warnings || return 1
  done
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

  # The proof client is reached only AFTER a full three-replica fleet rollout, so a
  # client that cannot start costs an entire cluster deploy before it surfaces — and
  # surfaces as "PROOF FAILED: replica A did not accept a fresh pinned nonce", which
  # reads as a serving defect when nothing was ever sent. Smoke the EXACT command the
  # harness will run, first, and let a non-zero --help say so plainly.
  #
  # MCP_RE_CLIENT is the WHOLE command, interpreter AND script (the harness appends
  # only flags: `$CLIENT --server-name ...`). A bare interpreter therefore makes
  # python parse `--server-name` as its own option. `:-` before any expansion: the
  # script runs under `set -u`, where a bare ${MCP_RE_CLIENT%% *} on an unset variable
  # aborts the whole shell — the stage would not fail, it would take the gate down.
  local client_cmd="${MCP_RE_CLIENT:-python3 $PWD/docs/security/mcp_re_gke_client.py}"
  if ! $client_cmd --help >/dev/null 2>&1; then
    printf 'the four-proof client cannot start:\n  %s --help\nexited non-zero. MCP_RE_CLIENT must be the FULL command (interpreter AND script),\ne.g. "/path/to/venv/bin/python3 %s/docs/security/mcp_re_gke_client.py", and that\ninterpreter needs the SDK: <interpreter> -m pip install %s/sdk/python\n' \
      "$client_cmd" "$PWD" "$PWD" >&2
    return 1
  fi

  # The harness reads its mTLS material and identity tuple from the environment. Supply
  # the emit_mtls_fixtures bundle and the tuple that bundle signs whenever the operator
  # has not, so this stage is self-contained. Every value is overridable.
  if [[ -z "${MCP_RE_FIXTURES_DIR:-}" ]]; then
    MCP_RE_FIXTURES_DIR="$(mktemp -d)" || return 1
    cargo run -q -p mcp-re-demo --example emit_mtls_fixtures -- "$MCP_RE_FIXTURES_DIR" || return 1
    export MCP_RE_FIXTURES_DIR
  fi
  local fx="$MCP_RE_FIXTURES_DIR"

  # kind has no metadata server, and this stage is the free local one: root the
  # delegated issuer in the mounted seed rather than requiring a live Cloud KMS key.
  # KMS-rooted issuance is proven by the cloud-KMS live lanes, not here.
  export MCP_RE_KEY_SOURCE="${MCP_RE_KEY_SOURCE:-fileSeed}"

  # The proxy port comes from the registry (config/ports.toml), never a literal.
  local proxy_port
  proxy_port="$(python3 -c 'import tomllib,sys; print(tomllib.load(open(sys.argv[1],"rb"))["services"]["mcp_re_proxy"]["port"])' config/ports.toml 2>/dev/null)"
  [[ -n "$proxy_port" ]] || { echo "could not read mcp_re_proxy port from config/ports.toml" >&2; return 1; }

  export MCP_RE_SERVER_NAME="${MCP_RE_SERVER_NAME:-proxy.internal}"
  export MCP_RE_AUDIENCE="${MCP_RE_AUDIENCE:-did:example:server-1}"
  export MCP_RE_TARGET_URI="${MCP_RE_TARGET_URI:-https://proxy.internal:$proxy_port/mcp}"
  export MCP_RE_TRUST_DOMAIN="${MCP_RE_TRUST_DOMAIN:-example.com}"
  export MCP_RE_SIGNER_ID="${MCP_RE_SIGNER_ID:-did:example:agent-1}"
  export MCP_RE_KEY_ID="${MCP_RE_KEY_ID:-key-1}"
  export MCP_RE_SIGNING_KEY_SEED="${MCP_RE_SIGNING_KEY_SEED:-@$fx/client_signing_seed}"
  export MCP_RE_SERVER_SIGNER="${MCP_RE_SERVER_SIGNER:-did:example:server-1}"
  export MCP_RE_SERVER_KEY_ID="${MCP_RE_SERVER_KEY_ID:-server-key-1}"
  export MCP_RE_SERVER_PUBKEY="${MCP_RE_SERVER_PUBKEY:-@$fx/server_pubkey}"
  export MCP_RE_TRUST_EPOCH="${MCP_RE_TRUST_EPOCH:-epoch-1}"
  # Transport binding is always `exact`, so the client presents the SHORT-lived leaf.
  export MCP_RE_TLS_CERT="${MCP_RE_TLS_CERT:-$fx/client_cert_short.pem}"
  export MCP_RE_TLS_KEY="${MCP_RE_TLS_KEY:-$fx/client_key_short.pem}"
  export MCP_RE_SERVER_CA="${MCP_RE_SERVER_CA:-$fx/server_ca.pem}"

  PROVIDER=kind docs/security/gke-multi-replica-validation.sh
}

run "static gates (tags, ports, secrets, chart, vocabulary)" stage_static
run "cargo suites + SDK downloaders (workspace, features, py/ts)" stage_suites
run "bazel parity (//...)"                                   stage_bazel
run "local SLO lane (ADR-051 §7 anchor + gate)"              stage_slo
run "kind fleet proofs (identical harness to GKE)"           stage_kind

printf '\n=====================================================================\n'
printf 'LOCAL GATE: PASS (stages %d-%d)\n' "$FROM" "$LAST"
printf 'Only now is cloud spend justified — docs/security/gke-slo-baseline-runbook.md\n'
printf '=====================================================================\n'
