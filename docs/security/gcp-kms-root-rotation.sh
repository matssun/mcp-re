#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fenced, self-provisioning runner for the LIVE Cloud KMS trust-anchor (master/root
# key) rotation lane (ADR-MCPRE-052 §H). It creates TWO DISPOSABLE Ed25519 KMS key
# versions, runs the root-rotation/overlap/revocation scenario against them
# (`gcp_kms_root_rotation_live_test`), then schedules those versions for destruction.
#
# NO human-in-the-loop key creation — the guardrails below ARE the governance. This is
# a TEST provisioner only; production root rotation is a separate, governed mechanism
# (docs/spec/root-authority-rotation.md). It NEVER touches the shared long-lived test
# root (mcps-ed25519-object): it only ever creates a brand-new key whose name carries
# the fenced disposable prefix.
#
# Run:
#   MCP_RE_LIVE_KMS_TESTS=1 MCP_RE_ALLOW_TEST_KMS_CREATE=1 docs/security/gcp-kms-root-rotation.sh
#
# HARD refusals (fail before creating anything) if any of these do not hold:
#   * MCP_RE_LIVE_KMS_TESTS=1 and MCP_RE_ALLOW_TEST_KMS_CREATE=1 (explicit opt-in)
#   * PROJECT_ID in the test-only allowlist
#   * KEYRING matches the test-ring prefix (mcps-test-*)
#   * the disposable key name carries the fenced prefix (mcps-live-test-*)
set -euo pipefail

fail() { echo "gcp-kms-root-rotation: $*" >&2; exit 1; }

# --- Guardrail 1: explicit opt-in (two independent switches) ------------------
[[ "${MCP_RE_LIVE_KMS_TESTS:-}" == "1" ]] \
  || fail "refusing: set MCP_RE_LIVE_KMS_TESTS=1 to run the live KMS lane"
[[ "${MCP_RE_ALLOW_TEST_KMS_CREATE:-}" == "1" ]] \
  || fail "refusing: set MCP_RE_ALLOW_TEST_KMS_CREATE=1 to allow creating disposable KMS keys"

# --- Guardrail 2: fenced project / keyring / key-name -------------------------
PROJECT_ID="${MCP_RE_TEST_PROJECT_ID:-project-b19bbb5e-9be8-4fcb-a2f}"
# The explicit test-project allowlist. Add ids here deliberately; nothing else runs.
ALLOWED_PROJECTS=("project-b19bbb5e-9be8-4fcb-a2f")
printf '%s\n' "${ALLOWED_PROJECTS[@]}" | grep -qx "$PROJECT_ID" \
  || fail "refusing: PROJECT_ID '$PROJECT_ID' is not in the test-only allowlist"

LOCATION="${MCP_RE_TEST_KMS_LOCATION:-global}"
KEYRING="${MCP_RE_TEST_KEYRING:-mcps-test-ring}"
[[ "$KEYRING" == mcps-test-* ]] \
  || fail "refusing: KEYRING '$KEYRING' is not a test ring (must match mcps-test-*)"

# The disposable key name carries the fenced prefix + a run-unique suffix. This is a
# BRAND-NEW key; the shared roots (mcps-ed25519-*) are never referenced.
KEY_PREFIX="mcps-live-test-rootrot"
KEY="${KEY_PREFIX}-$(date +%Y%m%d-%H%M%S)-$$"
[[ "$KEY" == mcps-live-test-* ]] || fail "internal: disposable key name lost its fence prefix"
[[ "$KEY" != "mcps-ed25519-object" ]] || fail "internal: refusing to touch the shared root"

kv() { echo "projects/$PROJECT_ID/locations/$LOCATION/keyRings/$KEYRING/cryptoKeys/$KEY/cryptoKeyVersions/$1"; }

# --- Guardrail 3: a cleanup trap registered BEFORE any creation ---------------
# On ANY exit, schedule both disposable versions for destruction (24h min delay per
# GCP; the empty CryptoKey object is inert + unbilled and cannot be deleted — a KMS
# limitation, not a leak). Never touches anything outside this disposable key.
DESTROY_ON_EXIT=0
cleanup() {
  if [[ "$DESTROY_ON_EXIT" == "1" ]]; then
    echo "gcp-kms-root-rotation: scheduling disposable key versions for destruction ($KEY)..." >&2
    for v in 1 2; do
      gcloud kms keys versions destroy "$v" \
        --location "$LOCATION" --keyring "$KEYRING" --key "$KEY" --project "$PROJECT_ID" \
        --quiet >/dev/null 2>&1 || echo "  (version $v already destroyed or absent)" >&2
    done
    echo "gcp-kms-root-rotation: disposable versions scheduled for destruction; the empty key '$KEY' remains (KMS keys cannot be deleted)." >&2
  fi
}
trap cleanup EXIT

# --- Provision: create the disposable key (version 1) + version 2 -------------
echo "gcp-kms-root-rotation: creating disposable Ed25519 root key '$KEY' in $KEYRING..." >&2
gcloud kms keys create "$KEY" \
  --location "$LOCATION" --keyring "$KEYRING" --project "$PROJECT_ID" \
  --purpose asymmetric-signing --default-algorithm ec-sign-ed25519 \
  --labels "owner=mcp-re-test,ttl=disposable,purpose=root-rotation-live-test" >/dev/null
DESTROY_ON_EXIT=1   # from here on, always attempt cleanup

echo "gcp-kms-root-rotation: creating the second disposable version..." >&2
gcloud kms keys versions create \
  --location "$LOCATION" --keyring "$KEYRING" --key "$KEY" --project "$PROJECT_ID" >/dev/null

# Wait for BOTH versions to reach ENABLED (Ed25519 generation is quick).
for v in 1 2; do
  for _ in $(seq 1 30); do
    state="$(gcloud kms keys versions describe "$v" \
      --location "$LOCATION" --keyring "$KEYRING" --key "$KEY" --project "$PROJECT_ID" \
      --format='value(state)' 2>/dev/null || true)"
    [[ "$state" == "ENABLED" ]] && break
    sleep 2
  done
  [[ "$state" == "ENABLED" ]] || fail "version $v did not reach ENABLED (state=$state)"
done
echo "gcp-kms-root-rotation: both disposable versions ENABLED." >&2

# --- Run the live lane against the two disposable roots -----------------------
export MCP_RE_ROOT_A_KEY_VERSION="$(kv 1)"
export MCP_RE_ROOT_B_KEY_VERSION="$(kv 2)"
export MCP_RE_GCP_ACCESS_TOKEN="${MCP_RE_GCP_ACCESS_TOKEN:-$(gcloud auth print-access-token --project "$PROJECT_ID")}"

echo "gcp-kms-root-rotation: running the live root-rotation lane..." >&2
cargo test -p mcp-re-proxy --features gcp_kms_keysource \
  --test gcp_kms_root_rotation_live_test -- --ignored --nocapture
rc=$?

echo "gcp-kms-root-rotation: lane exited rc=$rc." >&2
exit "$rc"
