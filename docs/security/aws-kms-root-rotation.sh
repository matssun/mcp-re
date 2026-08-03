#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fenced, self-provisioning runner for the LIVE AWS KMS trust-anchor (master/root key)
# rotation lane (ADR-MCPRE-052 §H) — the AWS twin of gcp-kms-root-rotation.sh. It
# creates TWO DISPOSABLE ECC_NIST_EDWARDS25519 keys, runs the
# root-rotation/overlap/revocation scenario against them
# (`aws_kms_root_rotation_live_test`), then schedules both for deletion.
#
# NO human-in-the-loop key creation — the guardrails below ARE the governance. This is
# a TEST provisioner only; production root rotation is a separate, governed mechanism
# (docs/spec/root-authority-rotation.md). It NEVER touches the shared long-lived test
# root (alias/mcp-re-ed25519-object): every key it creates carries a fenced
# disposable alias prefix, and it refuses to proceed if that prefix is ever lost.
#
# Run:
#   MCP_RE_LIVE_KMS_TESTS=1 MCP_RE_ALLOW_TEST_KMS_CREATE=1 docs/security/aws-kms-root-rotation.sh
#
# HARD refusals (fail before creating anything) if any of these do not hold:
#   * MCP_RE_LIVE_KMS_TESTS=1 and MCP_RE_ALLOW_TEST_KMS_CREATE=1 (explicit opt-in)
#   * the AWS account is in the test-only allowlist
#   * both disposable aliases carry the fenced prefix (alias/mcp-re-live-test-*)
#
# Cost: two ECC_NIST_EDWARDS25519 CMKs at $1.00/month each, prorated hourly, plus a
# handful of asymmetric requests. A full run is a few cents. Both keys are scheduled
# for deletion on exit (7 days is the KMS minimum window; they are unbilled while
# pending deletion).
set -euo pipefail

fail() { echo "aws-kms-root-rotation: $*" >&2; exit 1; }

# --- Guardrail 1: explicit opt-in (two independent switches) ------------------
[[ "${MCP_RE_LIVE_KMS_TESTS:-}" == "1" ]] \
  || fail "refusing: set MCP_RE_LIVE_KMS_TESTS=1 to run the live KMS lane"
[[ "${MCP_RE_ALLOW_TEST_KMS_CREATE:-}" == "1" ]] \
  || fail "refusing: set MCP_RE_ALLOW_TEST_KMS_CREATE=1 to allow creating disposable KMS keys"

REGION="${MCP_RE_AWS_KMS_REGION:-eu-north-1}"

# --- Guardrail 2: fenced account + alias names --------------------------------
# The account is read from the CALLER's live identity, not from a variable, so a
# mis-set variable cannot point this at an account the allowlist was not written for.
ACCOUNT="$(aws sts get-caller-identity --query 'Account' --output text)"
# The explicit test-account allowlist. Add ids here deliberately; nothing else runs.
ALLOWED_ACCOUNTS=("455880745808")
printf '%s\n' "${ALLOWED_ACCOUNTS[@]}" | grep -qx "$ACCOUNT" \
  || fail "refusing: account '$ACCOUNT' is not in the test-only allowlist"

# Two BRAND-NEW keys. The shared root (alias/mcp-re-ed25519-object) is never named.
STAMP="$(date +%Y%m%d-%H%M%S)-$$"
ALIAS_A="alias/mcp-re-live-test-rootrot-a-${STAMP}"
ALIAS_B="alias/mcp-re-live-test-rootrot-b-${STAMP}"
for a in "$ALIAS_A" "$ALIAS_B"; do
  [[ "$a" == alias/mcp-re-live-test-* ]] || fail "internal: disposable alias lost its fence prefix"
  [[ "$a" != "alias/mcp-re-ed25519-object" ]] || fail "internal: refusing to touch the shared root"
done

# --- Guardrail 3: a cleanup trap registered BEFORE any creation ---------------
# On ANY exit, schedule every disposable key created by this run for deletion. Never
# touches anything outside the two ARNs this run itself created.
CREATED=()
cleanup() {
  for arn in "${CREATED[@]:-}"; do
    [[ -n "$arn" ]] || continue
    echo "aws-kms-root-rotation: scheduling $arn for deletion (7-day window)..." >&2
    aws kms delete-alias --region "$REGION" --alias-name "$ALIAS_A" >/dev/null 2>&1 || true
    aws kms delete-alias --region "$REGION" --alias-name "$ALIAS_B" >/dev/null 2>&1 || true
    aws kms schedule-key-deletion --region "$REGION" --key-id "$arn" \
      --pending-window-in-days 7 --query 'DeletionDate' --output text >/dev/null 2>&1 \
      || echo "  ($arn already scheduled or absent)" >&2
  done
}
trap cleanup EXIT

create_root() {
  local alias="$1" arn
  arn="$(aws kms create-key --region "$REGION" \
    --key-spec ECC_NIST_EDWARDS25519 \
    --key-usage SIGN_VERIFY \
    --description "MCP-RE DISPOSABLE root-rotation live-test key (ADR-MCPRE-052 §H)" \
    --tags TagKey=owner,TagValue=mcp-re-test TagKey=ttl,TagValue=disposable \
           TagKey=purpose,TagValue=root-rotation-live-test \
    --query 'KeyMetadata.Arn' --output text)"
  # Registered for cleanup BEFORE the alias call, so a failure there still tears down.
  CREATED+=("$arn")
  aws kms create-alias --region "$REGION" --alias-name "$alias" --target-key-id "$arn" >/dev/null
  echo "$arn"
}

echo "aws-kms-root-rotation: creating two disposable Ed25519 root keys in $REGION..." >&2
ROOT_A="$(create_root "$ALIAS_A")"
ROOT_B="$(create_root "$ALIAS_B")"

# Asymmetric key generation is not instantaneous; wait for both to be usable rather
# than letting the lane fail with an opaque KMSInvalidStateException.
for arn in "$ROOT_A" "$ROOT_B"; do
  for _ in $(seq 1 30); do
    state="$(aws kms describe-key --region "$REGION" --key-id "$arn" \
      --query 'KeyMetadata.KeyState' --output text 2>/dev/null || true)"
    [[ "$state" == "Enabled" ]] && break
    sleep 2
  done
  [[ "$state" == "Enabled" ]] || fail "key $arn did not reach Enabled (state=$state)"
done
echo "aws-kms-root-rotation: both disposable keys Enabled." >&2

# --- Run the live lane against the two disposable roots -----------------------
export MCP_RE_AWS_KMS_REGION="$REGION"
export MCP_RE_AWS_ROOT_A_KEY_ID="$ROOT_A"
export MCP_RE_AWS_ROOT_B_KEY_ID="$ROOT_B"

echo "aws-kms-root-rotation: running the live root-rotation lane..." >&2
rc=0
cargo test -p mcp-re-proxy --features aws_kms_keysource \
  --test aws_kms_root_rotation_live_test -- --ignored --nocapture || rc=$?

echo "aws-kms-root-rotation: lane exited rc=$rc." >&2
exit "$rc"
