<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-S security scans — raw artifacts

This directory holds the **raw machine output** of automated security scans, as
opposed to the human-written audit narratives in the parent directory
([`../audit-v0.1.md`](../audit-v0.1.md), [`../audit-v0.2.md`](../audit-v0.2.md),
[`../audit-v0.5.md`](../audit-v0.5.md)) and the cross-round
[`../finding-ledger.jsonl`](../finding-ledger.jsonl).

The audit `.md` files and the ledger cover the **Rust `mcps-core` / `mcps-proxy`**
tree. The two `security-pre*.json` files here are older and broader: they scan
the **Python `components/common/security` precursor component** — the prior-art
security codebase whose hard lessons (fail-open defaults, stub services exported
as public API, dead-wired orchestration) motivated the from-scratch, fail-closed
Rust rewrite that became MCP-S Core. They are preserved as the project's earliest
security-scan evidence; none of their content was previously captured in any
`.md` writeup, which is why this index exists.

## Artifacts

| File | Target scanned | Tool stage | Verdict | Headline |
|---|---|---|---|---|
| [`security-prescan.json`](security-prescan.json) | `components/common/security` (Python, 916 files) | pre-flight readiness gate | **NO-GO** | 15 `dead-wired` block findings |
| [`security-prerun.json`](security-prerun.json) | `components/common/security` (Python, 17 units) | 46-agent multi-lens deep scan | — | **415 findings** |
| [`mcps-core-postfix131-prescan.json`](mcps-core-postfix131-prescan.json) | `mcps-core/src` (Rust, 16 files, this repo) | pre-flight readiness gate | **GO** | 0 findings |

> **Provenance note.** The `security-pre*.json` files target a path in a separate
> working tree (outside this repository), under `components/common/security`.
> They are the *precursor* component's scans, kept here as the historical "first scan"
> record per the maintainer's intent. The Rust prescan
> (`mcps-core-postfix131-prescan.json`) targets this repo directly.

## `security-prescan.json` — readiness gate (NO-GO)

A pre-flight gate over the Python component: 916 `.py` files (889 library, 24
adapter, 1 comproot, 2 script). Verdict **NO-GO** on **15 `block`-severity
`dead-wired` findings** — orchestration/service classes defined but never
referenced in any production file outside their own definition:

```
AttributeResolver            CredentialService          CredentialVerifier
EncryptionService            HashingService              IdentityVerifier
JWTSigningService            JWTSubResolver              JsonWebSignatureProofVerifier
MandateService               OIDCDiscoveryService        PKCEHandler
SecurityCoordinator          SigningService             ZeroTrustEntityBindingVerifier
```

The signal: a security component whose core primitives — signing, hashing,
encryption, credential verification, PKCE, OIDC discovery, zero-trust entity
binding — were wired to nothing in production. That is the exact failure class
MCP-S Core's "bind, don't interpret" boundary and its CI wiring/conformance
guards are designed to make impossible.

## `security-prerun.json` — 46-agent deep scan (415 findings)

A multi-agent, multi-lens scan across **17 units** of the Python component, run
by **46 agents** under three lenses (`general` 151, `conformance` 124,
`security` 140), producing **415 findings**.

**By severity:** crit 27 · high 105 · med 132 · low 122 · info 29.

**By category (top):**

| Category | n | Category | n |
|---|---:|---|---:|
| fail-open | 94 | stub | 43 |
| logic | 69 | validation | 43 |
| crypto | 48 | dead-wire | 31 |
| noop | 47 | missing-auth | 17 |

**Units:** crypto-services, kms-envelope, identity-providers, identity-trust,
identity-revocation, identity-services, auth-sso-oidc, auth-oauth-pkce,
auth-saml, auth-jwt-protocol, authz-pdp, adapters-wire, delegation,
trust-verification, orchestration, primitives-context, persistence-telemetry.

**Representative finding** (illustrative of the `stub` + `fail-open` clustering):

> `JWTSigningService.create_access_token` unconditionally raises — the entire
> signing service is a non-functional stub exported as public API. The
> create-token method raises before building a payload; all downstream
> payload/encode/sign code is unreachable dead code.

The dominant signal is **`fail-open` (94)** — the single most dangerous posture
for a security component, and the direct antithesis of MCP-S Core's fail-closed
invariant (every uncertain verdict rejects; `TrustResolverUnavailable` and
`ReplayCacheUnavailable` never fall back to allow). This scan is, in effect, the
motivating evidence for that design choice.

## `mcps-core-postfix131-prescan.json` — Rust prescan (GO)

The readiness gate run against this repository's `mcps-core/src` after the
post-MCPS-131 fix: Rust, 16 library files, 1 crate (`has_serve`, `has_verify`),
**0 findings, verdict GO**. The clean contrast to the precursor component's
NO-GO — the same gate, the rewritten codebase, no `dead-wired` or `fail-open`
findings.

## How this relates to the audited Rust tree

These scans are **not** part of the v0.1/v0.2/v0.5 Rust audit chain and their
findings are **not** in `../finding-ledger.jsonl` (that ledger is keyed to Rust
source files and begins at round `2026-06-22@32f1430`). They are retained as
historical context: the prior-art failure modes that justified the MCP-S Core
security model. Do not merge their counts into the Rust audit totals.
