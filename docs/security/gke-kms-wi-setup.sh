#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# One-time Workload-Identity → Cloud KMS binding for a KMS-rooted GKE fleet.
#
# The GKE proxy roots its delegated-credential ISSUER in Cloud KMS (keySource=gcpKms)
# and authenticates to KMS with the GKE metadata-server token — NOT a user access
# token (KMS rejects those from inside GCP: ACCESS_TOKEN_TYPE_UNSUPPORTED) and NOT a
# key file (no private material ever enters the pod). That requires a Google Service
# Account (GSA) that (a) may sign+verify with the key and (b) may be impersonated by
# the fleet's Kubernetes ServiceAccount (KSA) via Workload Identity.
#
# This script performs ONLY additive, non-destructive IAM:
#   1. create the GSA (if absent),
#   2. grant it roles/cloudkms.signerVerifier on the ONE named key (key-scoped, not
#      project-wide) — this does NOT mutate, rotate, disable, or read the key,
#   3. grant the KSA roles/iam.workloadIdentityUser on the GSA (the WI binding).
# The KSA annotation itself is applied THROUGH helm by the validation harness
# (serviceAccount.annotations), so this script never touches the cluster.
#
# It is IDEMPOTENT (re-running is a no-op) and REVERSIBLE (see the teardown block at
# the end — commented, run by hand). It is GATED behind an explicit confirm so it can
# never run by accident.
#
#   MCP_RE_CONFIRM_WI_KMS_SETUP=1 docs/security/gke-kms-wi-setup.sh
#
set -euo pipefail

# --- Fixed, allow-listed targets (this project's isolated test root) ----------
PROJECT_ID="${PROJECT_ID:-project-b19bbb5e-9be8-4fcb-a2f}"
LOCATION="${LOCATION:-global}"
KEY_RING="${KEY_RING:-mcps-test-ring}"
KEY_NAME="${KEY_NAME:-mcps-ed25519-object}"     # the SHARED test root — grant only, no mutation
GSA_NAME="${GSA_NAME:-mcp-re-kms-signer}"
NAMESPACE="${NAMESPACE:-mcp-re}"
KSA_NAME="${KSA_NAME:-mcp-re-proxy-mcp-re-proxy}"  # chart fullname for release mcp-re-proxy
GSA_EMAIL="${GSA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
WI_MEMBER="serviceAccount:${PROJECT_ID}.svc.id.goog[${NAMESPACE}/${KSA_NAME}]"

say() { printf '\n=== %s ===\n' "$*"; }

# --- Guardrails ---------------------------------------------------------------
[[ "${MCP_RE_CONFIRM_WI_KMS_SETUP:-}" == "1" ]] \
  || { cat >&2 <<EOF
REFUSING to run without explicit confirmation.
This GRANTS a signing role (roles/cloudkms.signerVerifier) on:
  key      = ${KEY_NAME}  (ring ${KEY_RING}, ${LOCATION})
to a NEW service account:
  gsa      = ${GSA_EMAIL}
and lets the fleet KSA impersonate it via Workload Identity:
  ksa      = ${WI_MEMBER}
It is additive + non-destructive (never mutates/disables/reads the key) and
idempotent, but it is a real IAM change. Re-run with:
  MCP_RE_CONFIRM_WI_KMS_SETUP=1 $0
EOF
  exit 2; }

# Only ever the isolated test project + the allow-listed test ring/key.
[[ "$PROJECT_ID" == project-* ]]        || { echo "unexpected PROJECT_ID: $PROJECT_ID" >&2; exit 2; }
[[ "$KEY_RING"   == mcps-*     ]]        || { echo "KEY_RING not allow-listed: $KEY_RING" >&2; exit 2; }
[[ "$KEY_NAME"   == mcps-*     ]]        || { echo "KEY_NAME not allow-listed: $KEY_NAME" >&2; exit 2; }

say "Target project ${PROJECT_ID}"
gcloud config set project "$PROJECT_ID" >/dev/null

# --- 1. GSA (create if absent) ------------------------------------------------
say "GSA ${GSA_EMAIL}"
if ! gcloud iam service-accounts describe "$GSA_EMAIL" --project "$PROJECT_ID" >/dev/null 2>&1; then
  gcloud iam service-accounts create "$GSA_NAME" --project "$PROJECT_ID" \
    --display-name "MCP-RE KMS signer (WI, test)"
else
  echo "  exists — reusing"
fi

# --- 2. Key-scoped signerVerifier (additive; NOT project-wide, NOT a mutation) -
say "grant roles/cloudkms.signerVerifier on ${KEY_NAME} (key-scoped)"
gcloud kms keys add-iam-policy-binding "$KEY_NAME" \
  --project "$PROJECT_ID" --location "$LOCATION" --keyring "$KEY_RING" \
  --member "serviceAccount:${GSA_EMAIL}" \
  --role roles/cloudkms.signerVerifier --condition=None >/dev/null
echo "  ok"

# --- 3. Workload-Identity binding (KSA may impersonate the GSA) ----------------
say "grant roles/iam.workloadIdentityUser to ${WI_MEMBER}"
gcloud iam service-accounts add-iam-policy-binding "$GSA_EMAIL" \
  --project "$PROJECT_ID" \
  --member "$WI_MEMBER" \
  --role roles/iam.workloadIdentityUser --condition=None >/dev/null
echo "  ok"

say "DONE — export for the run:"
echo "  export MCP_RE_GCP_KMS_GSA=${GSA_EMAIL}"

# --- Teardown (run by hand to fully revert) -----------------------------------
# gcloud kms keys remove-iam-policy-binding "$KEY_NAME" --location "$LOCATION" \
#   --keyring "$KEY_RING" --member "serviceAccount:${GSA_EMAIL}" \
#   --role roles/cloudkms.signerVerifier --project "$PROJECT_ID"
# gcloud iam service-accounts delete "$GSA_EMAIL" --project "$PROJECT_ID" --quiet
