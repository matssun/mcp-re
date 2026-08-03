#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# One-time IRSA → AWS KMS binding for a KMS-rooted EKS fleet. The AWS twin of
# gke-kms-wi-setup.sh.
#
# The EKS proxy roots its delegated-credential ISSUER in AWS KMS (keySource=awsKms)
# and authenticates with credentials STS issues in exchange for the pod's projected
# service-account token — NOT a mounted IAM key pair (which does not expire and
# authorizes kms:Sign for as long as the Secret exists). That requires an IAM role
# that (a) may Sign+GetPublicKey with the key and (b) trusts the cluster's OIDC
# provider for exactly this namespace and service account.
#
# This script performs ONLY additive, non-destructive IAM:
#   1. create the role with a trust policy scoped to ONE cluster's OIDC provider, ONE
#      namespace and ONE service account (if absent),
#   2. attach an inline policy granting kms:Sign + kms:GetPublicKey on the ONE named
#      key ARN — key-scoped, not account-wide — which does NOT mutate, rotate,
#      disable, schedule, or read the key.
# The service-account annotation itself is applied THROUGH helm by the validation
# harness (serviceAccount.annotations), so this script never touches the cluster.
#
# It is IDEMPOTENT (re-running updates the two policy documents in place) and
# REVERSIBLE (see the teardown block at the end — commented, run by hand). It is
# GATED behind an explicit confirm so it can never run by accident.
#
#   MCP_RE_CONFIRM_IRSA_KMS_SETUP=1 docs/security/eks-kms-irsa-setup.sh
#
# Then, for the fleet run:
#   export MCP_RE_AWS_KMS_ROLE_ARN="$(aws iam get-role --role-name mcp-re-kms-signer \
#     --query 'Role.Arn' --output text)"
#   PROVIDER=eks MCP_RE_AWS_KMS_KEY_ID=<key> docs/security/gke-multi-replica-validation.sh
set -euo pipefail

# --- Fixed, allow-listed targets (this project's isolated test root) ----------
AWS_REGION="${MCP_RE_AWS_REGION:-eu-north-1}"
EKS_CLUSTER="${EKS_CLUSTER:-mcp-re-fleet}"
KEY_ALIAS="${KEY_ALIAS:-alias/mcp-re-ed25519-object}"   # the SHARED test root — grant only, no mutation
ROLE_NAME="${ROLE_NAME:-mcp-re-kms-signer}"
NAMESPACE="${NAMESPACE:-mcp-re}"
KSA_NAME="${KSA_NAME:-mcp-re-proxy-mcp-re-proxy}"       # chart fullname for release mcp-re-proxy
POLICY_NAME="${POLICY_NAME:-mcp-re-kms-sign}"

say() { printf '\n=== %s ===\n' "$*"; }
fail() { printf 'eks-kms-irsa-setup: %s\n' "$*" >&2; exit 1; }

# --- Guardrails ---------------------------------------------------------------
[[ "${MCP_RE_CONFIRM_IRSA_KMS_SETUP:-}" == "1" ]] \
  || { cat >&2 <<EOF
REFUSING to run without explicit confirmation.
This CREATES an IAM role and GRANTS kms:Sign + kms:GetPublicKey on:
  key      = ${KEY_ALIAS}  (${AWS_REGION})
to a NEW role:
  role     = ${ROLE_NAME}
trusted ONLY by the OIDC provider of cluster ${EKS_CLUSTER}, for the single
service account ${NAMESPACE}/${KSA_NAME}.

Re-run with MCP_RE_CONFIRM_IRSA_KMS_SETUP=1 to proceed.
EOF
      exit 1; }

command -v aws >/dev/null || fail "the aws CLI is required"

ACCOUNT="$(aws sts get-caller-identity --query 'Account' --output text)"

# The key ARN is RESOLVED from the alias, not composed from strings: an alias that
# does not exist must stop this script, rather than produce a policy granting signing
# on an ARN nothing answers to — which would look like a successful setup and fail
# only later, in the pod, as an opaque AccessDenied.
KEY_ARN="$(aws kms describe-key --region "$AWS_REGION" --key-id "$KEY_ALIAS" \
  --query 'KeyMetadata.Arn' --output text 2>/dev/null)" \
  || fail "key $KEY_ALIAS not found in $AWS_REGION"
say "key $KEY_ALIAS -> $KEY_ARN"

# The OIDC issuer is READ FROM THE CLUSTER. Composing it by hand is how a trust policy
# ends up naming a provider that does not exist, which does not fail here — it fails
# as an unassumable role at the first KMS call.
ISSUER="$(aws eks describe-cluster --name "$EKS_CLUSTER" --region "$AWS_REGION" \
  --query 'cluster.identity.oidc.issuer' --output text 2>/dev/null)" \
  || fail "cluster $EKS_CLUSTER not found in $AWS_REGION"
[[ -n "$ISSUER" && "$ISSUER" != "None" ]] \
  || fail "cluster $EKS_CLUSTER has no OIDC provider — create it with 'eksctl utils associate-iam-oidc-provider --cluster $EKS_CLUSTER --region $AWS_REGION --approve'"
ISSUER_HOST="${ISSUER#https://}"
PROVIDER_ARN="arn:aws:iam::${ACCOUNT}:oidc-provider/${ISSUER_HOST}"
say "OIDC provider $PROVIDER_ARN"

aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$PROVIDER_ARN" >/dev/null 2>&1 \
  || fail "no IAM OIDC provider registered for $ISSUER_HOST — run 'eksctl utils associate-iam-oidc-provider --cluster $EKS_CLUSTER --region $AWS_REGION --approve'"

# --- 1. The role, trusted for exactly one service account --------------------
# Both conditions are load-bearing and both are `StringEquals`, never `StringLike`:
#   * `:sub` pins the ONE namespace/serviceaccount. Without it, ANY pod in the
#     cluster could assume this role and sign with the fleet's root key.
#   * `:aud` pins the audience to sts.amazonaws.com. Without it a token minted for a
#     different audience — one some other component hands out more freely — would be
#     accepted here.
TRUST_POLICY="$(cat <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "${PROVIDER_ARN}" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "${ISSUER_HOST}:sub": "system:serviceaccount:${NAMESPACE}:${KSA_NAME}",
        "${ISSUER_HOST}:aud": "sts.amazonaws.com"
      }
    }
  }]
}
JSON
)"

if aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  say "role $ROLE_NAME exists — updating its trust policy in place (idempotent)"
  aws iam update-assume-role-policy --role-name "$ROLE_NAME" \
    --policy-document "$TRUST_POLICY"
else
  say "creating role $ROLE_NAME"
  aws iam create-role --role-name "$ROLE_NAME" \
    --description "MCP-RE delegated-credential ISSUER root (ADR-MCPRE-052); IRSA-only" \
    --assume-role-policy-document "$TRUST_POLICY" >/dev/null
fi

# --- 2. Key-scoped signing permission ----------------------------------------
# Exactly the two operations the adapter uses. Not kms:* and not Resource "*": the
# role is a SIGNING principal, and nothing about that requires the ability to
# schedule the key for deletion.
KEY_POLICY="$(cat <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["kms:Sign", "kms:GetPublicKey"],
    "Resource": "${KEY_ARN}"
  }]
}
JSON
)"
say "granting kms:Sign + kms:GetPublicKey on $KEY_ARN to $ROLE_NAME"
aws iam put-role-policy --role-name "$ROLE_NAME" \
  --policy-name "$POLICY_NAME" --policy-document "$KEY_POLICY"

ROLE_ARN="$(aws iam get-role --role-name "$ROLE_NAME" --query 'Role.Arn' --output text)"
say "done"
cat <<EOF

  role     = ${ROLE_ARN}
  key      = ${KEY_ARN}
  trusted  = system:serviceaccount:${NAMESPACE}:${KSA_NAME} (aud sts.amazonaws.com)

Export this for the fleet run:

  export MCP_RE_AWS_KMS_ROLE_ARN="${ROLE_ARN}"

EOF

# --- Teardown (run BY HAND; deliberately not automated) -----------------------
# Removing the role is the whole reversal — the key is untouched by this script and
# must not be deleted as part of undoing an IAM grant.
#
#   aws iam delete-role-policy --role-name ${ROLE_NAME} --policy-name ${POLICY_NAME}
#   aws iam delete-role       --role-name ${ROLE_NAME}
