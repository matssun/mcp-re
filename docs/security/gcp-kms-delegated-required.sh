#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# MCP-RE — ADR-MCPRE-052 delegated-REQUIRED validation against a LIVE Google Cloud
# KMS root (MCPRE-122). The local pre-GKE gate for the delegated path: the KMS is
# the credential ISSUER (off the request path), an in-memory delegated key signs
# each response, and the response-signing AUTHORITY flip is a real boundary.
#
# WHAT THIS PROVES, against a LIVE Cloud KMS, private key never leaving the cloud:
#   1. Serving — the production wiring build_delegated_signing(config, KMS_root) +
#      HttpProfileProxy::new_delegated serves real requests; N responses invoke
#      Cloud KMS ZERO extra times (one op per key issuance/rotation, none per
#      request); rotation to a successor; the client revocation seam (allow + deny).
#   2. Authority flip — on ONE KMS key: a pre-052 direct-root response is REJECTED
#      under delegated-required (no downgrade); the delegated authority is accepted;
#      a trust-epoch advance rejects the old-epoch credential; rotating + revoking
#      the predecessor authority fails its responses closed while the successor's
#      still verify.
#
# This is a TEMPLATE — it contains NO secrets. Set PROJECT_ID (and, if your key
# names differ from the defaults, KEY_RING / KEY_NAME), authenticate with
# `gcloud auth login`, then run it. It reuses an existing EC_SIGN_ED25519 key as
# the delegated-signing root; it creates nothing.
#
# Usage:
#   PROJECT_ID="my-project-123" ./docs/security/gcp-kms-delegated-required.sh
#
# Prereqs: a GCP project with billing + Cloud KMS enabled, an EC_SIGN_ED25519 key
# (see docs/security/gcloud-kms-validation.sh to provision one), gcloud authed,
# cargo. Cost: a handful of asymmetricSign/getPublicKey ops per run.

set -euo pipefail

export PROJECT_ID="${PROJECT_ID:-REPLACE_WITH_YOUR_PROJECT_ID}"
export LOCATION="${LOCATION:-global}"
export KEY_RING="${KEY_RING:-mcp-re-test-ring}"
# The EC_SIGN_ED25519 key used as the delegated-signing ROOT issuer.
export KEY_NAME="${KEY_NAME:-mcp-re-ed25519-object}"
export KEY_VERSION="${KEY_VERSION:-1}"

if [[ "$PROJECT_ID" == "REPLACE_WITH_YOUR_PROJECT_ID" ]]; then
  echo "ERROR: set PROJECT_ID (edit this script or run: PROJECT_ID=... $0)" >&2
  exit 1
fi
if ! command -v gcloud >/dev/null 2>&1; then
  echo "ERROR: gcloud CLI not found on PATH." >&2
  exit 1
fi
if ! gcloud auth print-access-token >/dev/null 2>&1; then
  echo "ERROR: not authenticated. Run: gcloud auth login" >&2
  exit 1
fi

export MCP_RE_GCP_KEY_VERSION="projects/$PROJECT_ID/locations/$LOCATION/keyRings/$KEY_RING/cryptoKeys/$KEY_NAME/cryptoKeyVersions/$KEY_VERSION"
export MCP_RE_GCP_ACCESS_TOKEN="$(gcloud auth print-access-token)"

echo "Delegated-required root key: $MCP_RE_GCP_KEY_VERSION"
echo "Running the delegated-required serving + authority-flip lanes against live Cloud KMS..."

# Both #[ignore] live entry points: the production serving path on the KMS root,
# and the authority flip. FAIL LOUDLY if MCP_RE_GCP_* is unset (never a silent pass).
cargo test -p mcp-re-proxy --features gcp_kms_keysource \
  --test gcp_kms_delegated_required_live_test -- --ignored --nocapture

echo "OK — delegated-required + authority flip verified on live Cloud KMS."
