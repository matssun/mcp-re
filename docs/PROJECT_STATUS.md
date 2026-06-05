<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-S Project Status

## Current status

MCP-S is an experimental third-party security extension proposal for MCP.

It is not an official MCP extension unless accepted through the official MCP governance and proposal process.

## Current implementation claim

The current implementation may claim:

> MCP-S is production-hardened for single-node Rust-native deployments.

This claim is bounded and should not be broadened without additional implementation, tests, and documentation.

## Demonstrated capabilities

The current demonstration package should prove:

- HostSession signs outbound requests;
- client transport verifies server certificate and identity;
- mTLS connection is established to `mcps-proxy`;
- `mcps-proxy` verifies object signatures;
- freshness/replay checks are enforced;
- delegated authorization is evaluated before dispatch;
- caller-supplied verified context is stripped;
- sidecar-owned verified context is injected;
- a persistent inner MCP-style server can handle multiple requests through one process;
- denied requests do not reach the inner server;
- responses are signed;
- HostSession verifies response signature and request-hash binding.

## Not yet claimed

MCP-S does not currently claim:

- horizontally scaled replay protection;
- HSM/KMS-backed key custody;
- full certificate revocation through CRL/OCSP;
- reverse-proxy mTLS provider support;
- OS-level filesystem/network containment for wrapped servers;
- signed tool manifest enforcement;
- official MCP extension status;
- offline-hermetic build reproducibility.

## Proposal readiness

Before submitting MCP-S as an MCP extension proposal, ensure that the repository contains a clear specification, security boundary, test traceability document or manifest, runnable reference implementation, conformance vectors, demo evidence, explicit non-claims, and license/contribution files.
