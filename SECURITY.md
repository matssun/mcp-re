<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security Policy

MCP-RE is a security-sensitive project. Please report suspected vulnerabilities responsibly.

## Supported status

MCP-RE is currently an experimental/incubating third-party MCP security extension proposal.

The current implementation claim is limited to:

> production-hardened for single-node Rust-native deployments.

Do not assume that MCP-RE currently provides:

- horizontally scaled replay protection;
- HSM/KMS-backed key custody;
- full CRL/OCSP certificate revocation;
- reverse-proxy mTLS integration;
- OS-level filesystem/network sandboxing;
- signed tool manifest enforcement;
- official MCP extension status.

## Reporting a vulnerability

Please report security issues privately to:

```text
<security-contact@example.com>
```

Replace this placeholder before public release.

Please include:

- affected component;
- version/commit;
- reproduction steps;
- expected versus actual behavior;
- impact assessment;
- whether the issue allows bypass of signature, authorization, replay, transport, or verified-context checks.

## Security boundaries

The current security boundary is described in:

```text
docs/SECURITY_BOUNDARY.md
```

## Examples of high-severity issues

Examples include:

- invalid signatures accepted;
- replayed requests accepted within the protected window;
- authorization-denied requests reaching the inner server;
- caller-supplied verified context reaching the inner server;
- mTLS identity mismatch accepted when binding is required;
- response accepted with the wrong request hash;
- private key material exposed through logs, errors, or APIs;
- unknown obligations or unsupported policy requirements silently ignored.

## Secret hygiene & key custody

(MCPS-076, audit gap G-3.)

### In-memory scrubbing (zeroize)

The proxy holds two long-lived private secrets in process memory: the Ed25519
signing seed and the TLS server private key (the latter is held by `rustls` for the
lifetime of the process — its in-memory custody is managed by `rustls`, not by this
scrubbing path). The Ed25519 signing seed is handled so that its raw bytes are wiped
from memory as soon as they are no longer needed:

- Every OWNED temporary that carries the raw 32-byte seed — the Base64URL-decoded
  `Vec<u8>`, the `[u8; 32]` seed array, and the file/env seed text — is wrapped in
  [`zeroize::Zeroizing`](https://docs.rs/zeroize), so its backing memory is
  scrubbed the instant the temporary drops.
- The resulting `ed25519_dalek::SigningKey` (the expanded in-memory private key)
  is `ZeroizeOnDrop`: we enable dalek's `zeroize` feature, so dalek wipes the
  secret scalar on drop. `SigningKey::from_seed_bytes` only BORROWS the seed, so
  the key is constructed and the `Zeroizing` seed temporaries then drop scrubbed.

This is verified by `//mcp-re-proxy:dev_env_key_source_test` (the canonical
`Zeroizing` heap-scrub sentinel check) and by the `KeyError`-no-leak tests (a
malformed seed never appears in an error's `Display`/`Debug`).

### Constant-time posture

- Signature verification uses `ed25519-dalek`'s `verify_strict`, which is
  constant-time and additionally rejects weak/small-order keys and non-canonical
  encodings.
- The audience and request-hash equality checks are ordinary byte comparisons.
  This is stated honestly: those values are NOT secrets (the audience is the
  server's public identity; the request hash is a public digest of the request),
  so constant-time comparison is not required there. No secret-dependent branch or
  table lookup is performed on the seed or signing key.

### Key-source tiers

- **Default / production — `FileKeySource`.** The seed is read from a file ONCE at
  startup and held only in `Zeroizing` temporaries (scrubbed on drop). Operators
  MUST set restrictive, non-inheriting permissions on the seed and TLS-key files
  (`0600`, owned by the proxy's user). The proxy WARNS at startup if a key file is
  group/world-accessible, but does NOT yet *enforce* `0600` — perm enforcement and
  O_NOFOLLOW/non-inheriting open are documented FUTURE hardening, not a current
  guarantee.
- **`EnvKeySource` — development / CI ONLY.** It is gated behind the non-default
  `dev_env_key_source` cargo feature and is NOT compiled into a production build;
  `--key-source env` still parses but fails closed at construction in a default
  build. Even in a dev build, the seed value is held in `Zeroizing` and the env var
  is REMOVED (`std::env::remove_var`) immediately after it is read (defense in
  depth). Environment variables are visible to the whole process tree and may leak
  via crash dumps, `ps e`, `/proc/<pid>/environ`, and orchestrator inspection —
  never use this source in production.
- **Future / high-assurance roadmap (NOT implemented here).**
  - stdin/fd injection of the seed (e.g. systemd `LoadCredential`, a Kubernetes
    projected secret), so the seed never lands in a file or environment variable;
  - a non-exporting HSM/KMS or remote signer, where the private key never enters
    the proxy process at all and signing is delegated.

## Deferred capabilities are not vulnerabilities by themselves

The following are known non-claims unless the documentation later changes:

- horizontal-scale replay protection without shared atomic ReplayCache;
- HSM/KMS key custody;
- CRL/OCSP/live certificate revocation;
- reverse-proxy mTLS;
- OS sandboxing;
- signed tool manifest enforcement.
