# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
#
# Image build for the MCP-RE fleet reference (deploy/helm/mcp-re-proxy). MCP-RE is
# HTTP-profile only — the image is the PEP (mcp-re-proxy). A stdio-only inner MCP
# server is fronted by an EXTERNAL plain-MCP adapter (e.g. FastMCP) that exposes
# HTTP; MCP-RE ships no stdio bridge.
#
# The image compiles nothing. The proxy binary is built by Bazel, for the image's
# architecture, and staged first:
#
#   scripts/stage_image_binaries.sh --arch amd64      # or arm64 for the local kind fleet
#   docker build -f deploy/docker/Dockerfile --target proxy \
#     --build-arg DIST=deploy/docker/dist/amd64 -t mcp-re-proxy:0.17.0 .
#
# Local validation loads it into a kind cluster (`kind load docker-image …`); for GKE,
# Cloud Build stages amd64 and pushes to Artifact Registry.

# --- runtime base ------------------------------------------------------------
FROM debian:bookworm-slim AS runtime-base
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 65532 --user-group --no-create-home --shell /usr/sbin/nologin nonroot

# --- the PEP image -----------------------------------------------------------
FROM runtime-base AS proxy
# The shipped feature set is the deploy flavor's (`_PROXY_DEPLOY_FEATURES` in
# mcp-re-proxy/BUILD.bazel): registration, the shared Redis replay tier, and BOTH cloud
# KMS custodies. Every KMS backend is ADDITIVE — each signer is inert unless the chart
# selects the matching `--key-source` — and the image must serve every posture the chart
# can express, since an un-compiled arm fails closed at startup after the operator has
# already provisioned the KMS key, IAM role and OIDC provider it needs.
ARG DIST=deploy/docker/dist/amd64
COPY ${DIST}/mcp-re-proxy /usr/local/bin/mcp-re-proxy
# NON-ROOT, declared by the ARTIFACT. This image mounts the response-signing seed and
# the TLS private key, so a container escape here is a key-compromise event — it is
# the last process in the system that should run as uid 0. Stating it in the image
# rather than only in the Helm chart's podSecurityContext means `docker run`, a plain
# k8s manifest, a kind side-load or a chart fork all get the non-root posture, and it
# gives `runAsNonRoot: true` a numeric uid to admit against.
#
# 65532 is the distroless `nonroot` uid, matching the chart's runAsUser/runAsGroup/
# fsGroup and the inner backend image. That alignment is load-bearing: the material
# Secret is mounted 0440 owned by fsGroup 65532, and the proxy reads the key files
# through its group membership.
USER 65532:65532
# The Helm chart appends every flag as args; the binary is the entrypoint.
ENTRYPOINT ["/usr/local/bin/mcp-re-proxy"]
