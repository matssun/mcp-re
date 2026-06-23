<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to MCP-S are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until
1.0 the public surface is explicitly unstable: minor versions may break API
or wire-format compatibility while the design lines from
[`docs/adr/`](docs/adr/) settle.

## [0.5.0] — 2026-06-23

**Proposal-readiness release over the frozen `draft-01` wire envelope.** 0.5 adds
**zero** wire-envelope fields; request and response envelopes are unchanged. The
work is documentation, conformance, and claim hardening — making every security
claim reviewable and traceable to a green test — not new protocol mechanism. Any
claim `draft-01` cannot support is ejected to a future `draft-02` ADR rather than
smuggled in as a field addition (ADR-MCPS-031, [`docs/spec/proposal-scope.md`](docs/spec/proposal-scope.md)).
Proposal-readiness is gated twice: mechanical CI **and** owner HITL sign-off over
one evidence spine (ADR-MCPS-036; [`security-boundary.md`](docs/spec/security-boundary.md) §10).

### Added — proposal-readiness artifacts

- **ADR-MCPS-031..036 (Accepted).** 031 frames 0.5 as proposal-readiness over a
  frozen `draft-01`; 032 consolidates docs to one canonical boundary + docs root;
  033 defines the two-section v0.5 claim matrix (NSA/threat-coverage matrix
  derived from §A, one evidence spine); 034 makes method-transparency
  CI-enforced; 035 derives the audit-evidence vocabulary from the frozen error
  taxonomy; 036 defines the dual proposal-readiness gate (mechanical CI + owner
  HITL).
- **v0.5 claim matrix** ([`docs/spec/v0.5-claim-matrix.md`](docs/spec/v0.5-claim-matrix.md),
  supersedes the v0.3 matrix): §A per-capability reviewer-facing claims, §B the
  four-axis deployment-tier composition (AND of declared tiers, bounded by the
  weakest).
- **New spec briefs:** [`proposal-scope.md`](docs/spec/proposal-scope.md) (draft-01
  freeze + bind-not-interpret authorization), [`composability.md`](docs/spec/composability.md),
  [`threat-coverage-matrix.md`](docs/spec/threat-coverage-matrix.md); glossary and
  v0.5 grilling seed.
- **Method-transparency is CI-enforced (ADR-MCPS-034):** a behavioral-equivalence
  test plus a static drift guard in `mcps-conformance` (`method_transparency_test`,
  `method_name_drift_guard_test`, `security_traceability_guard_test`,
  `forbidden_claim_guard_test`, `audit_vocabulary_guard_test`).

### Security

- **OCSP DNS-rebinding fix (#128).** The OCSP fetch is pinned to the vetted
  resolved IPs, closing a rebinding window between resolution and connection.
- **OCSP freshness when `nextUpdate` is absent (#136).** Acceptance age is bounded
  by `thisUpdate` + a `max_age` cap instead of being accepted unbounded.
- **Verify-before-return at the remote-signer seams (#137, #138).** PKCS#11 and
  KMS response signing now verify the produced signature before returning it,
  centralized at the response-signer seam.
- **Per-method key-reference scope (#133).** A key reference scopes its target
  per-method; empty-tool grants are rejected.
- **LB-assertion fails closed without a transport binding (#135).** A wired
  load-balancer ingress assertion with no transport binding now fails closed
  rather than admitting.
- **Replay-cache growth bounded (#140).** The file and in-memory replay paths are
  growth-bounded, and durable inline-prune is anchored on a real clock rather than
  request expiry.
- **Non-positive-TTL replay rejected pre-store (MCPS-08, #142).** Requests with a
  non-positive TTL are rejected before the store write, on the etcd backend too.

### Note

Internal version (`VERSION`, workspace `Cargo.toml`) advances from 0.3.1 to 0.5.0.
0.4.0 (below) was tagged retroactively from the hardening-epic history; it carried
no separate release commit, so the source tree at the v0.4.0 tag still declares
0.3.1.

## [0.4.0] — 2026-06-22

**Hardening-epic release (#68).** 0.4 wires the v0.3 tiered multi-node profile from
declared tiers into enforced backends, lands the full audit-remediation cluster
from the v0.4 Stage 1–2 audit round, and purifies MCP-S Core. *Tagged
retroactively* at the first-parent tip of the epic (`09f3250`, just before the 0.5
proposal-readiness work) — the tag was created after the fact, so no release commit
bumps `VERSION`/`Cargo.toml` at this point in history.

### Added — four-axis multi-node profile, wired

- **Axis 1 — LINEARIZABLE CP replay backend (#69).** An etcd-backed CPStore
  replay backend, the concrete realization of the v0.3 `LINEARIZABLE` tier.
- **Axis 2 — near-zero revocation tiers (#70).** Live + push revocation tiers
  wired into the trust resolver, with an injective trust-cache key.
- **Axis 4 — Tier-3 LB-signed ingress assertion (#71).** A request-bound,
  load-balancer-signed ingress assertion, wired into the serve path with
  serve-level acceptance.

### Security & hardening — v0.4 audit remediation

- **Seccomp egress (#98).** `io_uring` egress is denied in the `DenyAll` seccomp
  posture.
- **Production-surface sealing (#81, #83).** Test nonce/clock fixtures are
  feature-gated off the production surface; `VerifiedResult`/`VerifiedResponse`
  are sealed against out-of-band construction.
- **Strict-mode replay durability (#78, #90).** Replay caches self-declare a
  type-level durability class; strict mode rejects a non-durable in-memory cache
  and forbids `inherit-env` together with an env key source.
- **Reference-authz acknowledge gate + epoch-clock diagnosis (#94).**
- **Signed-manifest canonicalization & identity (#85, #87).** Duplicate keys in
  signed manifest bytes are rejected, `key_id` is cross-checked, the validity
  window is skew-tolerant, and inverted windows / unknown wire members are
  rejected.
- **Server read-path deadline (#100).** An aggregate wall-clock deadline on the
  server read path closes a slow-loris exposure.
- **Redis handshake watchdog (#97).** Abandoned Redis connect-handshake watchdog
  threads are bounded.
- **Working-dir TOCTOU (#93).** An explicit `--inner-working-dir` is hardened
  against symlink/TOCTOU with an explicit `O_RDONLY` no-follow open.
- **Key custody (#76).** The unused `Clone` on `SigningKey` is dropped and the
  custody boundary documented.
- **OCSP SSRF guards (#130).** Redirect-follow and empty-label-host SSRF bypasses
  on the OCSP fetch path are closed.
- **Centralized Ed25519 alg gate (#131).** The Ed25519 envelope algorithm gate is
  centralized in Core.

### Changed — Core purification (ADR-MCPS-030)

- The tool-catalog **signed-manifest subsystem is removed from MCP-S Core**; the
  manifest-enforcement design (formerly ADR-MCPS-029) is relocated to MTCI. Core
  is once again pure verification.

### Added — security process

- **Cross-round finding ledger** ([`docs/security/finding-ledger.jsonl`](docs/security/finding-ledger.jsonl)):
  durable per-finding disposition memory so a later audit round verifies only what
  is genuinely new and flags regressions loudly.

## [0.3.1] — 2026-06-21

Security-hardening patch release. No API or wire-format change relative to
0.3.0 — every change is a defensive fix or documentation correction surfaced by
the **Stage 1–2 security-audit funnel** (deterministic pre-scan + 3-lens review,
without the verify gate). Findings were triaged file-by-file: 10 fixed with
regression tests, 3 closed as false positives, and the remaining cluster
deferred to the v0.4 hardening epic (#68) as intentional ADR-MCPS-017
single-node-ceiling posture. The full verified (3-skeptic) scan is scheduled for
v0.4.

### Security

- **OCSP delegated-responder validity window (#95, RFC 6960).** A delegated
  responder certificate presented outside its `notBefore`/`notAfter` window is
  now rejected instead of trusted.
- **Authorization-grant timestamp taxonomy (#88).** An unparseable RFC 3339
  expiry on a delegated grant now fails as `AuthorizationMalformed` rather than
  being misclassified as `AuthorizationExpired`.
- **JCS duplicate-key invariant (#74).** A hand-built `JcsValue::Object`
  containing duplicate keys now fails closed (`CanonicalizationFailed`) rather
  than producing an ambiguous canonical form.
- **Injective trust-resolver composite key (#79).** `InMemoryTrustResolver`
  composes its lookup key with a length-prefixed encoding, removing a
  delimiter-collision class across `(signer, key_id)` pairs.
- **Bounded KMS response reads (#89, #92).** The AWS-KMS response body is read
  under an explicit byte cap (reject only when the length exceeds the cap), and
  GCP-KMS token-expiry arithmetic saturates on overflow instead of panicking.

### Fixed

- **Freshness-window overflow (#82).** Freshness-window expiry uses
  `checked_add`, failing closed instead of panicking on `i64` overflow.
- **Replay prune boundary (#91).** Durable-replay pruning is now inclusive at
  `retain_until` (`>=`), matching the in-memory store and removing a one-tick
  off-by-one retention gap.
- **Response taxonomy precision (#77).** `verify_response` rejects batch and
  notification shapes *before* canonicalization, restoring symmetry with
  `verify_request`.

### Documentation

- Corrected a stale `shared_replay` module doc and documented the
  `sandbox_linux` `try_clone` async-signal-safety caveat (#99, #98).

## [0.3.0] — 2026-06-16

This release adds the **tiered multi-node profile within one trust domain**
(epic #7). v0.2 was production-hardened for single-node deployments; v0.3
makes a *bounded, honest* multi-node claim: each of four security axes declares
a tier, and the composed claim is the **conjunction of the four declared tiers,
bounded by the weakest**. The proxy can never surface a claim stronger than its
configured tier. The enforcement artifacts are
[`docs/spec/v0.3-claim-matrix.md`](docs/spec/v0.3-claim-matrix.md),
[`docs/spec/v0.3-claim-boundary.md`](docs/spec/v0.3-claim-boundary.md), and
[`docs/spec/security-boundary.md`](docs/spec/security-boundary.md), backed by
the conformance manifest and `mcps-conformance` drift guard.

### Added — tiered multi-node claim matrix (the four axes)

- **Axis 1 — replay-store durability (ADR-MCPS-020).** Tiers `REDIS_ASYNC`,
  `REDIS_WAIT_QUORUM`, `LINEARIZABLE` (named; CP backend deferred), and
  `SINGLE_STORE_FAIL_CLOSED`, each surfacing its own honest guarantee.
  Strict-production deployments must declare `REDIS_WAIT_QUORUM` or stronger.
- **Axis 2 — trust propagation / revocation window `T` (ADR-MCPS-021).**
  Bounded-cache eventual trust: revocation enforced fleet-wide within `T`
  (default 60s), fail-closed on store outage past `T`. Zero-window revocation
  is a forbidden claim in v0.3.
- **Axis 3 — signing-key custody (ADR-MCPS-022 / ADR-MCPS-028).**
  `per_node_keyset` (default; tight blast radius) or `shared_remote_signer`
  (one non-exporting KMS/HSM identity). Copying a private key across nodes is
  normatively forbidden in every mode.
- **Axis 4 — ingress / transport binding (ADR-MCPS-023).** `end_to_end_mtls`
  (peer bound to the request signer end-to-end) or `trusted_ingress_asserted`
  (explicitly weakened; ingress in the TCB, authenticated LB↔node hop).

### Added — native cloud-KMS + delegated TLS key custody (ADR-MCPS-028 §B–§G)

- **Native cloud-KMS Ed25519 response signers** — AWS KMS
  (`ECC_NIST_EDWARDS25519`, `ED25519_SHA_512`, `MessageType=RAW`) and GCP Cloud
  KMS (`EC_SIGN_ED25519`), each over a blocking, hand-audited transport
  (SigV4 / OAuth2 + `ureq`), **not** the async vendor SDKs — the ADR-MCPS-018
  lean-sync firewall is preserved. The private key never leaves the KMS.
- **Delegated TLS-server-key custody (§G)** — the TLS server key can also stay
  non-exporting, via the `RawEd25519TlsSigner` seam and a delegated rustls
  certificate resolver, wired across PKCS#11, AWS KMS, and GCP KMS backends.
  Cross-cutting invariants enforced fail-closed: Ed25519-only, cert↔signer
  public-key match at config construction, a TLS credential distinct from the
  object-signing key, and delegated-XOR-exported mutual exclusion.
- **Cloud-KMS live CI lanes** — nightly-real-only (no faithful Ed25519 KMS
  emulator exists), secret-gated and non-blocking, with an anti-gaming hard
  fail; the load-bearing proof is `mcps-core` verifying the signature over the
  exact canonical preimage, never the provider's own `Verify`.

### Added — MCP SEP composition and trust hygiene

- **Replay safety under MCP multi round-trip requests (ADR-MCPS-024, SEP-2322).**
- **Untrusted transport routing headers (ADR-MCPS-025, SEP-2243)** — `Mcp-Method`
  / `Mcp-Name` never assert identity and never influence a security decision, in
  every ingress mode.
- **Signing scope vs. stateless per-request `_meta` (ADR-MCPS-026, SEP-2575).**
- **Extension-identifier reassignment to `se.syncom/mcps` (ADR-MCPS-027).**

### Known limitations — forbidden claims (tracked for v0.4, epic #68)

The composed claim licenses none of the following; each is a deferred tier
named in its ADR and tracked as v0.4 axis-hardening:

- Linearizable / unconditional replay safety (Axis 1 — needs the `CPStore`
  backend).
- Zero-window / instantaneous revocation (Axis 2 — needs live or push tiers).
- Smaller-than-per-node blast radius for a shared signer (Axis 3).
- End-to-end binding under `trusted_ingress_asserted` (Axis 4 — needs the
  LB-signed, request-bound Tier 3 assertion).
- Multi-tenant isolation between distrusting operators, and a hostile-shared-store
  threat model, both remain explicitly excluded from v0.3.

### Build

- Workspace version bumped to `0.3.0` across all crates. Cargo + Bazel still
  coexist; every crate carries both a `Cargo.toml` and a `BUILD.bazel`.

## [0.2.0] — 2026-06-05

This is the **initial public release** of MCP-S. v0.1 existed only inside the
authoring monorepo and was never published as source; it is captured here for
historical accuracy because both the architecture and the security review
process span it.

### Public-release scope

- Apache-2.0 licensed Rust workspace, ten crates:
  `mcps-core` (pure verification), `mcps-host` (client-side ambassador),
  `mcps-transport` (verifying mTLS client), `mcps-proxy` (server-side sidecar
  with TLS termination, OCSP, sandbox, Redis replay, PKCS#11 key sources),
  `mcps-policy` (delegated-authorization profiles, Phase 5),
  `mcps-conformance` (black-box conformance harness), three demo crates
  (`mcps-demo`, `mcps-demo-server`, `mcps-demo-fileserver`), and the test-only
  `mcps-test-paths` helper that lets the same integration tests run under
  Bazel runfiles OR a plain Cargo build.
- 19 architecture-decision records under [`docs/adr/`](docs/adr/) covering the
  trust model, core invariants, transport layering, authorization profile
  abstraction, and Phase 7 external backends.
- Specification briefs under [`docs/spec/`](docs/spec/) including the core
  spec, security boundary, and the upstream-proposal brief intended for an
  eventual MCP SEP submission.
- Two multi-agent Claude Opus 4.8 security audits and a per-finding
  remediation log under [`docs/security/`](docs/security/).

### Added — Phase 6 transport hardening

- **mTLS transport (`mcps-transport`)** — a blocking rustls client that
  presents a client certificate AND verifies the proxy's server certificate +
  identity against a configured server CA, including
  per-socket DoS hardening (read/write timeouts) and an aggregate
  response-read deadline that bounds slow-trickle peers
  (ADR-MCPS-015, [`mcps-transport/src/lib.rs`](mcps-transport/src/lib.rs)).
- **Server-side mTLS termination + identity verification** in `mcps-proxy`
  with configurable identity policies (SAN URI / SAN DNS / CN-legacy),
  exact transport-binding enforcement, and short-lived-cert posture
  (ADR-MCPS-014).

### Added — Phase 5 delegated authorization

- **`AuthorizationProfile` abstraction** with the Reference Signed
  Authorization Profile as the first implementation; policy evaluator runs
  AFTER core verification and BEFORE dispatch
  (ADR-MCPS-013, [`mcps-policy/src/`](mcps-policy/src/)).
- **Per-profile conformance vectors** under
  [`mcps-policy/tests/vectors/`](mcps-policy/tests/vectors/) covering every
  documented allow / deny code (12-token coverage).

### Added — Phase 7 external backends (feature-gated, off by default)

- **`pkcs11_keysource`** — vendor-neutral PKCS#11 backend for the
  response-signing key; key material never leaves the token.
- **`redis_replay`** — Redis-backed shared atomic replay cache for
  horizontally-scaled deployments, with bounded connection/read/write timeouts
  and TTL aligned to clock skew.
- **`online_ocsp`** — RFC 6960 §3.2 OCSP client-cert revocation, including
  full responder-signature trust chain
  (signature + responder identity + CertID binding + freshness + nonce).
- **Linux sandbox enforcement** (Landlock fs allowlists + seccomp egress
  filter), fail-closed on platforms without a kernel backend
  (ADR-MCPS-016 / ADR-MCPS-017).

### Security

This release is the product of two independent multi-agent Claude Opus 4.8
audits, totalling **282 agents and ~14.55M tokens** of review across both
rounds. The full audit reports are committed under
[`docs/security/`](docs/security/), alongside a per-finding remediation log.

- **v0.1 audit (2026-06-01)** — 3 High / 14 Medium / 36 Low / 53 Info,
  0 Critical. Overall residual-risk rating at audit time: **MODERATE**.
- **v0.2 audit (2026-06-02)** — 4 Critical / 15 High / 30 Medium / 59 Low /
  254 Info on the hardening branch. Overall residual-risk rating at audit
  time: **HIGH**.
- **Remediation in this release**: all 4 Critical, all 15 High, and 28 of 30
  Medium findings are **Addressed** with regression tests. The remaining 2
  Mediums (M01/M02 in [`docs/security/remediation-v0.2.md`](docs/security/remediation-v0.2.md))
  are **Deferred to v0.3**; their fail-mode is fail-closed and does NOT admit
  unauthorized requests.

Notable cross-cutting fixes folded in:

- OCSP responder verification rebuilt to enforce signature + identity +
  CertID + freshness + nonce per RFC 6960 §3.2; the single OCSP defect
  surfaced by four audit lenses is closed
  ([`mcps-proxy/src/ocsp.rs`](mcps-proxy/src/ocsp.rs)).
- Manifest pin atomicity (audit H-1) — repository now writes the pin file
  atomically via rename
  ([`mcps-policy/src/manifest_verifier.rs`](mcps-policy/src/manifest_verifier.rs)).
- Redis replay backend (audit H-8 / H-9 / H-10) — bounded connect, read, and
  write timeouts so the single-threaded serve loop cannot hang
  ([`mcps-proxy/src/redis_store.rs`](mcps-proxy/src/redis_store.rs)).
- `--strict` / `--production` postures now reject group/world-readable key
  files and disabled client-cert lifetime enforcement
  ([`mcps-proxy/src/main.rs`](mcps-proxy/src/main.rs),
  [`mcps-proxy/src/cli.rs`](mcps-proxy/src/cli.rs)).

### Build

- Cargo and Bazel coexist by design: every crate carries both a `Cargo.toml`
  and a `BUILD.bazel`, and the workspace is buildable with **either**
  toolchain. Cargo is the public-facing default for OSS contributors;
  Bazel remains the hermetic build path the maintainer uses internally.
- A small `mcps-test-paths` dev-dependency lets the same integration tests
  resolve child-process binaries and data fixtures under Bazel runfiles OR
  a plain Cargo build — see
  [`mcps-test-paths/src/lib.rs`](mcps-test-paths/src/lib.rs).

### Known limitations

- Two Medium findings (`M-01`, `M-02`) remain deferred to v0.3; both relate
  to fail-closed correctness gaps that do NOT admit unauthorized requests.
- Sandbox kernel enforcement (Landlock + seccomp) is Linux-only; on
  macOS / Windows / older Linux the proxy fails closed if
  `--inner-sandbox enforce` is requested (ADR-MCPS-017).
- The crate names and wire formats are explicitly unstable until 1.0; the
  ADR set names the surfaces most likely to evolve.

---

## [0.1.0] — 2026-06-01 (unpublished)

v0.1 is the internal pre-public baseline. It is NOT released as a public
crate or source archive; this entry is recorded so the v0.2 changelog,
audit, and remediation documents have an unambiguous predecessor to refer
to. The v0.1 audit report at
[`docs/security/audit-v0.1.md`](docs/security/audit-v0.1.md) captures the
state of the codebase at this point.

### Highlights

- Pure `mcps-core` verification crate with canonicalization, signature
  verification, replay detection, and the verified-context contract.
- `mcps-proxy` server-side sidecar with stdio transport, response signing,
  and verified-context propagation to an unmodified inner MCP server.
- `mcps-host` client-side ambassador for request signing and bound
  response verification.
- Black-box `mcps-conformance` harness (object + stdio targets).
- 18 ADRs covering the trust model, core invariants, and Phase 1-5 design
  decisions.

### Audit summary

- 3 High / 14 Medium / 36 Low / 53 Info, 0 Critical.
- Residual-risk rating at audit time: **MODERATE**.
- Four findings were partial carry-overs into the v0.2 hardening branch;
  all are closed in v0.2.0 per the
  [v0.2 remediation log](docs/security/remediation-v0.2.md).

[0.3.1]: https://github.com/matssun/mcps/releases/tag/v0.3.1
[0.3.0]: https://github.com/matssun/mcps/releases/tag/v0.3.0
[0.2.0]: https://github.com/matssun/mcps/releases/tag/v0.2.0
[0.1.0]: https://github.com/matssun/mcps/releases/tag/v0.1.0
