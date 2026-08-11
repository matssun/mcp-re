# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
#
# Image build for the MCP-RE fleet reference (deploy/helm/mcp-re-proxy). MCP-RE is
# HTTP-profile only — the image is the PEP (mcp-re-proxy). A stdio-only inner MCP
# server is fronted by an EXTERNAL plain-MCP adapter (e.g. FastMCP) that exposes
# HTTP; MCP-RE ships no stdio bridge.
#
#   docker build -f deploy/docker/Dockerfile --target proxy -t mcp-re-proxy:0.16.0 .
#
# Local validation: this loads into a kind cluster (`kind load docker-image …`) —
# native arch, no cross-compile. For GKE: build the SAME target for linux/amd64
# (Cloud Build or `buildx --platform linux/amd64`) and push to Artifact Registry.

FROM rust:1.94.1-slim-bookworm AS builder
# ring/rustls need a C toolchain; openssl-sys (pulled transitively) needs
# libssl-dev + perl + pkg-config. Installed once in the builder only.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential perl pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
# The PEP feature set: async per-core fleet (async_serve) + shared Redis replay
# tier (redis_replay) + BOTH cloud KMS custodies (gcp_kms_keysource,
# aws_kms_keysource). Every KMS backend is ADDITIVE — each signer is inert unless
# the chart selects the matching `--key-source`, so one image serves the fileSeed,
# gcpKms and awsKms deployments the chart offers (values.yaml `keySource`).
#
# Both are compiled because the chart renders all three and the un-compiled arm
# fails closed at startup with a feature-flag error: an EKS/IRSA install would
# CrashLoopBackOff after the operator had already provisioned a KMS key, an IAM role
# and an OIDC provider. The image must be able to serve every posture the chart can
# express.
#
# ADR-MCPRE-052: KMS is the delegated-credential ISSUER (off the request path).
# Override --build-arg FEATURES=… to drop KMS from a fileSeed-only image.
ARG FEATURES=async_serve,redis_replay,gcp_kms_keysource,aws_kms_keysource
RUN cargo build --release --locked \
        -p mcp-re-proxy --features "${FEATURES}" \
        --bin mcp-re-proxy

# --- runtime base ------------------------------------------------------------
FROM debian:bookworm-slim AS runtime-base
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 65532 --user-group --no-create-home --shell /usr/sbin/nologin nonroot

# --- the PEP image -----------------------------------------------------------
FROM runtime-base AS proxy
COPY --from=builder /build/target/release/mcp-re-proxy /usr/local/bin/mcp-re-proxy
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
