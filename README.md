<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP Runtime Evidence (MCP-RE)

> **MCP Runtime Evidence (MCP-RE)** is a runtime-evidence layer for high-value MCP
> tool calls, carried in the RFC 9421 + RFC 9530 HTTP profile. *(Formerly **MCP-S**;
> renamed to avoid confusion with the unrelated SEP-2395 / "MCPS (MCP Secure)" work —
> see [#289](https://github.com/matssun/mcp-re/issues/289).)*

## Why should I care?

**Problem.** An MCP tool call crosses a trust boundary as plain JSON-RPC. Nothing
stops it being forged, replayed, stripped of its authorization context, or
answered by a tampered response.

**MCP-RE answer.** MCP-RE protects *individual MCP calls* with RFC 9421 HTTP
Message Signatures over an RFC 9530 `Content-Digest`, freshness, replay protection,
delegated-authorization binding, response binding, and sidecar-injected verified
context. Responses are **delegated-signed** (a short-TTL key attested by a JOSE/JWS
credential from a root in HSM/KMS). It is proven end to end across a real
multi-process path — an unmodified plain-MCP client → a client-side MCP-RE proxy or
SDK → mTLS → a server-side proxy that verifies and serves — and against live Google
Cloud KMS key custody, including a live GKE run with custody via Workload Identity
(v0.12.1).

**Non-goals.** MCP-RE is **not** OAuth, **not** EMA, **not** sandboxing, **not** a
full audit-receipt format, **not** Agent Passports, **not** an L0–L4 trust
framework, **not** tool-definition signing, and **not** a Trust Authority. It
composes with those layers rather than replacing them.

See [`docs/MCP-RE-IN-ONE-PAGE.md`](docs/MCP-RE-IN-ONE-PAGE.md) for the one-page
overview and [`CHANGELOG.md`](CHANGELOG.md) for what each release proved.

## Overview

MCP-RE is an experimental third-party security extension proposal for the Model Context Protocol (MCP).

It provides a reference implementation and conformance package for protecting MCP tool calls with:

- RFC 9421 HTTP Message Signatures over an RFC 9530 `Content-Digest`, the sole
  over-the-wire carrier (`mcp-re-http-v1`, ADR-MCPRE-050) — the earlier native/object
  (Ed25519-over-JCS) envelope was removed, not kept as a fallback;
- **delegated-required response signing** — a root in HSM/KMS issues a short-TTL
  delegated key via a JOSE/JWS credential (ADR-MCPRE-052); direct-root signing is gone;
- freshness and replay protection;
- delegated authorization binding, bound into the signed evidence;
- **stateless multi-round-trip continuation** — request-associated elicitation
  stays cryptographically bound turn to turn (ADR-MCPS-047);
- Rust-native mTLS transport hardening;
- sidecar-based protection of ordinary Streamable-HTTP MCP servers (MCP-RE is
  HTTP-profile only; a stdio-only server is fronted by an external plain-MCP
  adapter such as FastMCP);
- signed response verification on the host/client side, via a client-side proxy
  **or** the Python/TypeScript **SDK bindings** (both bound to the same audited
  `mcp-re-client-core`, so the signed evidence is byte-identical across languages —
  a frozen parity oracle gates it).

The SDKs provide bindings for signing, delegated-response verification, rejection
verification, non-exporting custody, correlation, and parity-tested evidence handling —
plus `McpReHttpTransport`, an MCP transport adapter that signs each request and verifies
each delegated response underneath a standard MCP client. Application code calls
`session.call_tool(...)` and never invokes sign/verify itself; every failure is delivered
as a JSON-RPC error correlated to its request, so an unverifiable response can neither
reach the application nor hang it.

**Callers still supply the HTTP leg.** The adapter takes an injected `poster` that
performs the POST; the mTLS connection helper (`connect_mtls_http` / `connectMtlsHttp`)
is not built yet, so establishing and hardening the connection remains the caller's job.
The client-side proxy is the path that requires no application change at all.

MCP-RE is not part of the official MCP specification unless and until it is accepted through the MCP governance and SEP process.

## Quickstart — see MCP-RE fail closed

Run the single-node HTTP-profile demo and watch the **real `mcp-re-proxy` PEP**
— over real mTLS, in front of a Streamable-HTTP inner backend — accept a valid
signed call and fail closed on a missing/untrusted client cert, a tampered
signature, and a wrong transport binding — no cloud credentials, no external infra:

```sh
./scripts/demo-local.sh
```

Expected final line: `OK: MCP-RE local demo completed`. The underlying proofs also
run directly: `bazel test //mcp-re-proxy:full_stack_test //mcp-re-demo:demo_mtls_client_test`
(or the `cargo test --test …` equivalents). See [`docs/quickstart-local.md`](docs/quickstart-local.md).

Full walkthrough and what each case proves:
[`docs/quickstart-local.md`](docs/quickstart-local.md). For the live Google Cloud
KMS key-custody path (optional, separate): [`docs/quickstart-gcp-kms.md`](docs/quickstart-gcp-kms.md).

For the **end-to-end** path (a plain-MCP client → client-side proxy → mTLS →
server-side MCP-RE proxy → Streamable-HTTP MCP backend), the transparent client leg is
the **client-side proxy**. The **Python** and **TypeScript** SDK bindings cover the same
evidence obligation in-process over the same audited `mcp-re-client-core`, but the caller
still drives the HTTP leg and calls sign/verify explicitly — they are not yet transport
adapters. See [`sdk/python`](sdk/python) and [`sdk/typescript`](sdk/typescript). MCP-RE is
HTTP-profile only; the over-the-wire persona-ladder walkthrough runs over the HTTP
profile (a stdio-only endpoint is fronted by an external adapter such as FastMCP).

## Project status

Current status:

> Experimental / incubating third-party MCP security extension proposal.

Current implementation claim:

> MCP-RE is production-hardened for single-node Rust-native deployments — and, at the
> declared shared-tier fleet profile, for horizontally-scaled multi-node deployments
> within one trust domain / one operator (proven live on a 2-node GKE cluster, v0.11,
> with KMS custody via Workload Identity added in v0.12.1) — with a proven end-to-end
> client-integration path (client-side proxy + Python/TypeScript SDKs) over the
> RFC 9421 + RFC 9530 HTTP profile, delegated-required response signing.

### Recent releases (0.6 → 0.12.1)

Full detail per release is in [`CHANGELOG.md`](CHANGELOG.md); the design lines are
in [`docs/adr/`](docs/adr/). In brief:

- **0.6** froze the **`draft-02` runtime-evidence** wire envelope — the canonical
  signed preimage that every later release builds on.
- **0.7** proved the real **end-to-end four-hop** path as separate OS processes
  (plain-MCP client → `mcp-re-client-proxy` → mTLS → `mcp-re-proxy` server PEP →
  unmodified inner server), organized as a runnable persona ladder
  (ADR-MCPS-045), with scoped deny-before-dispatch authorization,
  transport-identity binding, integrated Cloud-KMS custody on both signing legs,
  and the first **Python SDK** slice.
- **0.8** added **stateless multi-round-trip continuation** — request-associated
  elicitation folded into strict MCP-RE as signed evidence, fail-closed on
  arbitrary server push (ADR-MCPS-047) — and shipped the **TypeScript SDK**,
  bound to the same audited `mcp-re-client-core` as Python so the signed preimage
  is byte-identical across languages. Both SDKs are exercised through the real
  four-hop matrix.
- **0.9** hardened the **enterprise operational envelope** — a strict Mode-A
  short-lived-cert lifetime ceiling, static-CRL fail-closed-on-stale, and offline
  KMS-lifecycle-vs-trust-policy custody negatives (ADR-MCPS-021/023/028) — and
  moved the dual Cargo/Bazel build to a **generated-first graph** with a CI
  semantic-drift gate (ADR-MCPS-048), killing the #220 parity-rot class.
- **0.10** added **Mode C — attested ingress** (ADR-MCPS-023 §C): a controlled
  ingress attestor signs a request-bound `mcp-re/lb-ingress-assertion/v2` assertion the
  node verifies over a pinned attestor→node channel, admitted under `--strict` as an
  explicit opt-in — *attested delegation*, **not** end-to-end mTLS, with the load
  balancer in the trusted computing base. The node binds the assertion
  (bind-not-interpret) and records three trust facts; the forwarded request is
  byte-identical to Mode A (**zero draft-02 preimage change**). Ships with an offline
  rejection-conformance spine and a non-normative
  [Google Cloud cookbook](docs/mode-c-attested-ingress-gcp-cookbook.md).
- **0.11** is the **HTTP-profile release**: the RFC 9421 + RFC 9530 HTTP standards
  profile is the **sole carrier** (ADR-MCPRE-050), the async **per-core serving
  fleet** lands (ADR-MCPRE-051), and **delegated signing** ships as a JOSE/JWS
  credential (ADR-MCPRE-052, python-cryptography cross-verified). **stdio is removed
  from MCP-RE** — HTTP in, HTTP out only; a stdio-only server is fronted by an
  external adapter (e.g. FastMCP). Both **SDKs are retargeted to the HTTP model** and
  exercised by live mTLS e2es against the real proxy. The fleet is proven on a **live
  GKE cluster** (cross-replica replay coherence + a rolling update over a real L4
  LoadBalancer, fronting FastMCP), with live GCP-KMS custody lanes and an
  **ADR-051 §7 SLO baseline measured on real GKE hardware** (e2/c3-standard-8) — the
  targets flip from provisional to **declared**, gate-enforced.
- **0.12** consolidates the proxy **serving path**: the RFC 9421 `HttpProfileProxy`
  wiring moves into a dedicated `App` runner (`mcp-re-proxy/src/app.rs`), slimming
  `main.rs`/`cli.rs`. Online **OCSP is now always fail-closed** (the `--ocsp-soft-fail`
  relaxation is gone). The **ADR-051 §7 SLO baseline is re-measured on GKE** under the
  v2 canonical envelope (RFC 9421, concurrency 128 / 8000 requests) and re-declared;
  the SLO Job runner grows an in-pod primary+2-replica Redis. SDK downloader smoke
  tests are restored.
- **0.12.1** is the **first live KMS-via-Workload-Identity GKE run**: it surfaced and
  fixed a real on-GKE custody bug (the WI metadata token URL, which crash-looped the
  fleet under `gcpKms`), made the GKE harness one deterministic cluster shape, and
  re-measured the ADR-051 §7 SLO on the **delegated-required serving path**
  (e2-standard-8 **395.6 rps** / c3-standard-8 **492.9 rps** at 8 cores, both gated
  PASS). **Known residual:** the zero-drop rolling-update proof is not yet green on GKE
  — a rollout dropped 2 of 590 in-flight requests (a kube-proxy endpoint-propagation
  timing gap; in-process and kind lanes are clean). Topology-independent zero-drop is
  therefore not claimed.

Predecessors: **0.5** was a proposal-readiness release (conformance + claim
hardening over `draft-01`, ADR-MCPS-031..036); **0.4** wired the tiered
multi-node profile into enforced backends. Decisions are recorded across
ADR-MCPS-001..048.

The current implementation demonstrates a complete end-to-end **four-hop** path:

```text
plain-MCP client (unmodified)
  -> mcp-re-client-proxy / Python or TypeScript SDK  (signs the RFC 9421 request, binds authz)
  -> mTLS transport
  -> mcp-re-proxy  (server-side PEP)
  -> Core signature / freshness / replay verification
  -> delegated authorization (deny-before-dispatch)
  -> verified-context injection
  -> unmodified inner MCP server
  -> signed response
  -> client-side response verification (correlated, bound, stripped to plain MCP)
```

## Deployment profiles

`mcp-re-proxy` is one binary. The cargo features you compile it with determine
which controls are available — do not conflate the lean default with the
production high-assurance profile.

### Lean default (no cargo features)

- Minimal runtime closure (ADR-MCPS-018): no Redis, no PKCS#11, no online-OCSP
  dependency is linked in.
- Intended for local, dev, and minimal single-node deployments.
- Shared replay protection, HSM/KMS key custody, and online OCSP revocation are
  **unavailable** in this build: selecting `--replay-cache shared` or a PKCS#11
  key source fails closed at startup rather than degrading.

Build with:

```sh
cargo build --release -p mcp-re-proxy
```

### High-assurance profile (`--features pkcs11_keysource,redis_replay,online_ocsp`)

Enables the three high-assurance backends:

- **distributed replay protection** via a shared atomic Redis ReplayCache
  (`redis_replay`);
- **HSM/KMS-backed key custody** via a PKCS#11 key source (`pkcs11_keysource`);
- **online certificate revocation** via OCSP (`online_ocsp`), alongside the
  offline CRL path available in both flavors.

Build with:

```sh
cargo build --release -p mcp-re-proxy \
    --features pkcs11_keysource,redis_replay,online_ocsp
```

**Multi-node MCP-RE deployments MUST use the high-assurance profile** with
`--replay-cache shared --replay-redis-url redis://...` so all proxy nodes share
replay state. A per-node cache (the lean default) does not prevent cross-node
replays.

## What MCP-RE does not yet claim

The current implementation does not claim:

- official MCP extension status;
- reverse-proxy mTLS integration in the lean default (it is available via the
  forwarded-identity path, but enterprise ingress hardening is delivered through
  the high-assurance feature profile);
- offline-hermetic or air-gapped build reproducibility (the cold-clone gate is
  "no-submodule, lockfile-reproducible with network access to crates.io", not
  offline-hermetic).

Horizontal-scale replay protection, HSM/KMS-backed key custody, full CRL/OCSP
certificate revocation, OS-level sandboxing of wrapped servers, and signed
tool-manifest enforcement are gated on the
`pkcs11_keysource,redis_replay,online_ocsp` cargo features (see Deployment
profiles); they are **not** linked into the lean default build and must not be
implied for it.

## Extension identifier

During incubation, MCP-RE should use a controlled third-party identifier, for example:

```text
se.syncom/mcp-re
```

Do not use:

```text
io.modelcontextprotocol/...
```

unless MCP-RE is accepted through the official MCP extension process.

## Build and test

The workspace builds with either Cargo or Bazel. Cargo is the public-facing
default; Bazel is the hermetic build path the maintainer uses internally and
both `Cargo.toml` and `BUILD.bazel` files are committed for every crate.

### Cargo (recommended for OSS contributors)

```sh
# Compile the whole workspace (libs + bins).
cargo build --workspace --bins

# Run the full test suite. The first step is required because Cargo does not
# auto-build cross-crate binaries for integration tests; the bins must exist on
# disk before the multi-process tests spawn them. With the bins in place, the
# suite is fully green.
cargo test --workspace
```

The SDK suites live outside the cargo workspace and run separately:
`sdk/python` (`pytest`, needs `maturin develop`) and `sdk/typescript`
(`npm test` — builds the native binding then runs `vitest`).

`#[ignore]`-gated tests (developer-only fixture writers and the live Cloud-KMS
lanes) are deliberate, not skipped production tests.

### Bazel

```sh
bazel test //...
```

## Repository layout

```text
README.md                  This file.
CHANGELOG.md               Release notes (Keep a Changelog format).
CONTRIBUTING.md            Contribution + licensing-of-contributions terms.
SECURITY.md                Vulnerability-reporting process.
THIRD_PARTY.md             Third-party-component policy.
LICENSE                    Apache-2.0.
NOTICE.md                  Required Apache-2.0 attributions.
Cargo.toml                 Workspace manifest.
MODULE.bazel               Bazel module definition.

mcp-re-core/                 Pure verification crate (no networking/async/fs).
mcp-re-host/                 Client-side ambassador (signing + bound verify).
mcp-re-transport/            Verifying mTLS client.
mcp-re-proxy/                Server-side sidecar (TLS termination, OCSP, sandbox, Redis/PKCS#11).
mcp-re-policy/               Delegated-authorization profiles (Phase 5).
mcp-re-client-core/          Client-side shared seam (signed RFC 9421 requests, response binding, enforcement) — the audited core both SDKs and the client proxy bind to (ADR-MCPS-044).
mcp-re-client-proxy/         Client-side MCP-RE proxy library — transport-agnostic seam (plain-MCP -> sign -> forward -> verify).
mcp-re-conformance/          Black-box conformance harness (object + HTTP; MCP-RE is HTTP-profile only).
mcp-re-demo/                 mTLS/fixtures demo surface (host-side HostSession client + DemoFixtures).
mcp-re-test-paths/           Test-only: resolve binaries + fixtures under Bazel OR Cargo.

sdk/python/                Python SDK — maturin/PyO3 binding to mcp-re-client-core (ADR-MCPS-044).
sdk/typescript/            TypeScript SDK — napi-rs binding to mcp-re-client-core (byte-identical evidence).

docs/adr/                  Architecture decision records (ADR-MCPS-001..047).
docs/spec/                 Spec briefs (core spec, security boundary, claim matrix, proposal scope).
docs/security/             Multi-agent audit reports + per-finding remediation log + cross-round ledger.
docs/LICENSING.md          Per-file licensing notes.
docs/PROJECT_STATUS.md     Current stage and what "experimental" means here.
docs/SECURITY_BOUNDARY.md  What MCP-RE protects (and what it explicitly does not).
docs/UPSTREAM_PROPOSAL_PROCESS.md  Path from third-party extension to an MCP SEP.
docs/RELEASE_CHECKLIST.md  Steps run before tagging a release.
docs/*-guide.md            Operator runbooks (sidecar, host, transport, conformance, dogfood).
```

## For security reviewers

If you are evaluating MCP-RE, read these in order — they route through the same
materials the [upstream-proposal package](docs/UPSTREAM_PROPOSAL_PROCESS.md)
requires (motivation/threat model, security boundary, envelope and signature
rules, replay/freshness model, authorization profile, transport hardening,
conformance, reference implementation, demos, and non-goals):

1. **One page** — [`docs/MCP-RE-IN-ONE-PAGE.md`](docs/MCP-RE-IN-ONE-PAGE.md):
   what it is, the threat, where it sits, what the current release proves, and what
   it does not claim.
2. **Security boundary** — [`docs/spec/security-boundary.md`](docs/spec/security-boundary.md):
   what MCP-RE protects and what it explicitly does not.
3. **v0.5 claim matrix** — [`docs/spec/v0.5-claim-matrix.md`](docs/spec/v0.5-claim-matrix.md):
   every reviewer-facing claim, each traceable to a green test.
4. **GCP KMS validation** — [`docs/quickstart-gcp-kms.md`](docs/quickstart-gcp-kms.md)
   (front door) and [`docs/security/google-validation-plan.md`](docs/security/google-validation-plan.md)
   (full plan): the live enterprise key-custody proof.
5. **Conformance guide** — [`docs/conformance-guide.md`](docs/conformance-guide.md):
   the black-box conformance harness and vectors.
6. **EMA composition** — [`docs/spec/ema-composition.md`](docs/spec/ema-composition.md):
   how MCP-RE would compose with Enterprise-Managed Authorization (a **proposed**
   design note — EMA is not implemented or demoed).
7. **Run it** — [`docs/quickstart-local.md`](docs/quickstart-local.md): the
   local fail-closed demo (`./scripts/demo-local.sh`), no cloud credentials.

## Documentation index

- **One-page overview:** [`docs/MCP-RE-IN-ONE-PAGE.md`](docs/MCP-RE-IN-ONE-PAGE.md) —
  what MCP-RE is, the threat it addresses, where it sits relative to EMA/OAuth, and
  what the current release proves.
- **Quickstarts:** [`docs/quickstart-local.md`](docs/quickstart-local.md)
  (local fail-closed demo, no cloud) and
  [`docs/quickstart-gcp-kms.md`](docs/quickstart-gcp-kms.md) (live GCP Cloud KMS).
- **Releases:** [`CHANGELOG.md`](CHANGELOG.md).
- **Architecture decisions:** [`docs/adr/`](docs/adr/) — start with
  [ADR-MCPS-001](https://github.com/matssun/mcp-re/discussions/350) (trust model) and
  [ADR-MCPS-011](https://github.com/matssun/mcp-re/discussions/360) (core firewall).
- **Specification briefs:** [`docs/spec/`](docs/spec/) — the core spec, the
  [security boundary](docs/SECURITY_BOUNDARY.md), and the upstream-proposal
  brief intended for an eventual MCP SEP submission.
- **Security:** [`docs/security/`](docs/security/) — multi-agent
  Claude Opus 4.8 audits (v0.1 and v0.2), the per-finding remediation log for
  v0.2.0, and the cross-round [finding ledger](docs/archive/security/finding-ledger.jsonl).
  Vulnerability reporting: [`SECURITY.md`](SECURITY.md).
- **Operator guides:** [`docs/sidecar-deployment-guide.md`](docs/sidecar-deployment-guide.md),
  [`docs/host-integration-guide.md`](docs/host-integration-guide.md),
  [`docs/transport-hardening-guide.md`](docs/transport-hardening-guide.md),
  [`docs/conformance-guide.md`](docs/conformance-guide.md),
  [`docs/dogfood-runbook.md`](docs/dogfood-runbook.md).
- **Contributing:** [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Unless otherwise stated, all files in this repository are licensed under the
Apache License, Version 2.0. See [`LICENSE`](LICENSE), [`NOTICE.md`](NOTICE.md),
and [`docs/LICENSING.md`](docs/LICENSING.md).

## Disclaimer

MCP-RE is an independent experimental proposal. It is not endorsed by the MCP project, Anthropic, or any MCP maintainer unless explicitly accepted through the relevant public governance process.
