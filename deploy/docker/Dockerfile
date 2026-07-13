# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
#
# Image build for the MCP-RE fleet reference (deploy/helm/mcp-re-proxy). MCP-RE is
# HTTP-profile only — the image is the PEP (mcp-re-proxy). A stdio-only inner MCP
# server is fronted by an EXTERNAL plain-MCP adapter (e.g. FastMCP) that exposes
# HTTP; MCP-RE ships no stdio bridge.
#
#   docker build -f deploy/docker/Dockerfile --target proxy -t mcp-re-proxy:0.12.0 .
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
# The PEP: async per-core fleet (async_serve) + shared Redis replay tier
# (redis_replay).
RUN cargo build --release --locked \
        -p mcp-re-proxy --features async_serve,redis_replay \
        --bin mcp-re-proxy

# --- runtime base ------------------------------------------------------------
FROM debian:bookworm-slim AS runtime-base
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- the PEP image -----------------------------------------------------------
FROM runtime-base AS proxy
COPY --from=builder /build/target/release/mcp-re-proxy /usr/local/bin/mcp-re-proxy
# The Helm chart appends every flag as args; the binary is the entrypoint.
ENTRYPOINT ["/usr/local/bin/mcp-re-proxy"]
