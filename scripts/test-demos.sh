#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# MCP-RE — smoke test for the evaluator demo scripts.
#
# Proves the public demo entry points actually work, end to end, on a clean
# checkout — so a stale binary, a moved fixture, or a broken path-resolution
# fallback is caught here rather than by an evaluator. MCP-RE is HTTP-profile only;
# the local demo runs the hermetic HTTP-profile end-to-end proofs. It asserts:
#
#   1. ./scripts/demo-local.sh exits 0 and prints the completion line (the HTTP
#      full_stack_test + client mTLS proofs pass — no stdio, no external infra);
#   2. ./scripts/demo-gcp-kms.sh fails closed (exit 2) when PROJECT_ID is unset,
#      WITHOUT contacting any cloud — the guard is testable offline.
#
# No cloud credentials are required. Run from anywhere:
#   ./scripts/test-demos.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "  ok: $*"; }

echo "== 1. ./scripts/demo-local.sh (HTTP-profile end-to-end) =="
# Capture combined output; -e would abort on the script's exit code, so guard it.
set +e
LOCAL_OUT="$(./scripts/demo-local.sh 2>&1)"
LOCAL_RC=$?
set -e
if [[ $LOCAL_RC -ne 0 ]]; then
  echo "$LOCAL_OUT" >&2
  fail "demo-local.sh exited $LOCAL_RC (expected 0)"
fi
pass "demo-local.sh exited 0"

grep -q "OK: MCP-RE local demo completed" <<<"$LOCAL_OUT" \
  || fail "missing final completion line"
pass "completion line present"

echo
echo "== 2. ./scripts/demo-gcp-kms.sh guard (offline) =="
set +e
GCP_OUT="$(./scripts/demo-gcp-kms.sh 2>&1)"
GCP_RC=$?
set -e
[[ $GCP_RC -eq 2 ]] || fail "demo-gcp-kms.sh without PROJECT_ID exited $GCP_RC (expected 2)"
grep -q "PROJECT_ID is required" <<<"$GCP_OUT" || fail "guard message missing"
pass "demo-gcp-kms.sh fails closed without PROJECT_ID (no cloud contacted)"

echo
echo "OK: demo scripts verified"
