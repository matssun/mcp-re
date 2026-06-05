<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-S Security Boundary

## Allowed claim

The current implementation may claim:

> MCP-S is production-hardened for single-node Rust-native deployments.

This is the entire current release claim.

## What is protected

MCP-S protects the following within the current claim boundary:

- object-signature verification of MCP-S JSON-RPC requests;
- object-signature verification of MCP-S JSON-RPC responses;
- request freshness through `issued_at` / `expires_at`;
- replay detection for a single replay-cache authority;
- canonicalization-safety rejection for unsafe JSON values;
- trust resolution for signer/key binding;
- delegated authorization through the configured authorization profile;
- deny-before-dispatch for failed signature, freshness, replay, trust, authorization, or transport checks;
- Rust-native mTLS transport binding where configured;
- verified-context stripping and sidecar-owned verified-context injection;
- response binding to the request hash;
- host-side response verification.

## What is not protected

The current implementation does not provide or claim:

| Capability | Status | Required future work |
|---|---|---|
| Horizontal-scale replay protection | Not provided | Shared atomic ReplayCache |
| HSM/KMS key custody | Not provided | HSM/KMS/remote-signer KeySource |
| Full CRL/OCSP certificate revocation | Not provided | Revocation profile |
| Reverse-proxy mTLS integration | Not provided | ReverseProxyMtlsProvider |
| OS-level filesystem/network sandboxing | Not provided | Kernel/container sandbox profile |
| Signed tool manifest enforcement | Not provided | Manifest format, signing, verification, revocation |
| Offline-hermetic build | Not provided | Vendoring or registry mirror |

## Inner-server boundary

`mcps-proxy` controls what it forwards to the inner server and what verified context is injected.

Portable launch hardening may include environment minimization, working-directory control, stderr/stdout hygiene, structured process logs, and best-effort resource limits.

These controls do not contain a malicious or compromised inner server at the kernel/filesystem/network level.

A malicious inner server may still access files, network, and OS resources available to its operating-system user unless a separate OS/container sandbox is configured.

## mTLS boundary

mTLS proves the transport peer when configured. It does not replace object-level MCP-S signatures.

A valid client certificate is never sufficient by itself to execute a tool call.

## Authorization boundary

`authorization_hash` binds the request to an authorization artifact. Core does not interpret the artifact. The configured authorization profile determines whether the artifact authorizes the action.

## Scale boundary

File-backed replay protection is single-node only.

Horizontally scaled deployments require shared atomic replay protection across all verifier instances serving the same audience.

## Key custody boundary

File and environment key sources may be useful for development or controlled deployments.

Do not claim enterprise-grade or hardware-backed key custody until a non-exporting HSM/KMS/remote-signer KeySource is implemented and tested.
