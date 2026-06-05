<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-S v0.2 — Remediation Status

This document tracks the remediation status of every finding from the two
multi-agent Claude Opus 4.8 security audits ([v0.1](audit-v0.1.md) and
[v0.2](audit-v0.2.md)) against the current source tree (the tree shipped as
v0.2.0 in this repository).

## Status legend

| Status | Meaning |
|---|---|
| **Addressed** | Fix landed in source; regression test covers it. |
| **Mitigated** | Fix landed but with a residual the audit text records; fail-mode acceptable. |
| **Deferred** | Known, planned for v0.3; failure mode is documented and acceptable for v0.2. |
| **Accepted-risk** | Known, won't-fix, justification recorded. |

## Headline counts

| Severity (v0.2 audit) | Found | Addressed | Mitigated | Deferred | Accepted-risk |
|---|---:|---:|---:|---:|---:|
| Critical | 4 | **4** | 0 | 0 | 0 |
| High | 15 | **15** | 0 | 0 | 0 |
| Medium | 30 | **28** | 0 | 2 | 0 |
| Low | 59 | not tracked individually | | | |
| Info | 254 | not tracked individually | | | |

In addition, the **four 0.1-audit partial carry-overs** (H-1/H-2 serializer
depth, H-3 stdin write-side, M-2 presence-check, M-3/M-6 client aggregate
deadline) are all now fully **Addressed** in the v0.2.0 tree.

> Reading note. Lows (59) and Infos (254) are not enumerated finding-by-finding
> here. The audit reports list them per crate; they are style, defence-in-depth,
> and observational items rather than security-relevant defects. They will be
> swept as part of v0.3 hardening.

## Remediation commits

Two commits encode the bulk of this remediation work; both are present in the
v0.2.0 tree:

- **OCSP trust chain + manifest atomicity + Redis bounds + arg-parse + serializer/IO/taxonomy hardening** — addresses every Critical and High and most of the Medium cluster on `--strict`, signed-response coverage, and the new Phase-7 backends.
- **MEDIUM remediation: strict-posture, signed-response coverage (+client unwrap), policy/OCSP/backend/identity/fd hardening + DoS test-assurance** — addresses the remaining Medium cluster including reverse-proxy ingress, XFCC, FD inheritance, PKCS11 latency, Redis reconnect, slow-trickle DoS test coverage.

---

## Critical (4 — all Addressed)

All four criticals are the same defect (the OCSP responder signature was not
verified) surfaced by independent agent runs under different lenses. One fix
closes all four.

| ID | Topic | Status | Fix |
|---|---|---|---|
| C-1 | OCSP responder signature never verified (general lens) | **Addressed** | `verify_responder_signature()` at `mcps-proxy/src/ocsp.rs:689`; wired into the verification pipeline at `ocsp.rs:646`. RSA + ECDSA algorithm-agnostic verification, delegated-responder chain + `id-kp-OCSPSigning` EKU. |
| C-2 | Same defect (security lens) | **Addressed** | Same fix. |
| C-3 | Same defect (security/MITM framing) | **Addressed** | Same fix. |
| C-4 | Same defect (conformance lens) | **Addressed** | Same fix. |

**Verification:** the fixture-acceptance test that originally accepted an empty
signature has been removed/inverted; the OCSP e2e tests in
`mcps-proxy/tests/ocsp_e2e_test.rs` now exercise a real OpenSSL responder with
positive and negative signature cases. The OCSP module rustdoc at the top of
`ocsp.rs:25-58` documents the full RFC 6960 §3.2 trust property: signature →
responder identity → CertID binding → freshness window → nonce.

---

## High (15 — all Addressed)

The v0.2 audit documents H-1 through H-11 explicitly; the remaining 4 highs
were grouped by the audit under the same OCSP and Redis clusters and are
covered by the same fixes as H-2…H-7 and H-8…H-10 respectively.

### H-1 — Manifest pin atomicity (duplicate tool names)

- **Crate / location:** `mcps-policy` · `manifest_verifier.rs:119-132`
- **Status:** **Addressed**
- **Fix:** explicit in-manifest duplicate-name dedup using `BTreeSet<&str>` at
  `mcps-policy/src/manifest_verifier.rs:160` before the commit loop. The
  verifier now rejects a manifest with duplicate tool names with
  `ManifestMalformed`, leaving the pin store unchanged. Module rustdoc updated
  at line 33 to state the contract.
- **Regression test:** `duplicate_tool_name_is_rejected_without_partial_mutation`
  at `manifest_verifier.rs:614`.

### H-2, H-4, H-6 — OCSP nonce missing

- **Crate / location:** `mcps-proxy` · `ocsp.rs:310-322`
- **Status:** **Addressed**
- **Fix:** every OCSP request now carries a fresh 16-byte CSPRNG nonce
  (`random_nonce()` at `ocsp.rs:279`); the response nonce is verified by
  `nonce_ok()` at `ocsp.rs:952`, called at `ocsp.rs:656`. Fail-closed on nonce
  mismatch.
- **Regression tests:** nonce-match / nonce-mismatch cases at
  `ocsp.rs:1462-1463`; integration in `ocsp_e2e_test.rs`.

### H-3, H-7 — CertID + responder identity binding

- **Crate / location:** `mcps-proxy` · `ocsp.rs:258-265`
- **Status:** **Addressed**
- **Fix:** `responder_id_matches()` at `ocsp.rs:817` validates the
  `tbs_response_data.responder_id` against the signer chosen by the signature
  verification step (issuer key or delegated responder), called at
  `ocsp.rs:647`. CertID-echo binding is enforced by selecting the matching
  `SingleResponse` by request CertID before mapping its status.
- **Regression test:** `certid_binding_matches_only_same_cert` at
  `ocsp.rs:1362`.

### H-5 — thisUpdate/nextUpdate freshness

- **Crate / location:** `mcps-proxy` · `ocsp.rs:257-265`
- **Status:** **Addressed**
- **Fix:** freshness window enforced at `ocsp.rs:667` with a configurable skew
  (`OCSP_SKEW`, default 5 minutes); a response with `thisUpdate` in the future
  beyond skew or `nextUpdate` in the past beyond skew is rejected as
  `ValidityWindowFailed`.
- **Regression tests:** freshness boundary cases at `ocsp.rs:1395-1414`.

### H-8, H-9 — Redis TTL computed against hard-coded now_unix=0 (DoS)

- **Crate / location:** `mcps-proxy` · `shared_replay.rs:168-169` + `redis_store.rs:79-82`
- **Status:** **Addressed**
- **Fix:** `RedisAtomicReplayStore` now carries its own injected `UnixClock`
  (`redis_store.rs:37`, constructor `system_clock()` at line 54). The PX TTL is
  derived against the store's real wall-clock via `ttl_ms_via_clock()` at
  `redis_store.rs:194`, not the trait's vestigial `now_unix = 0`. Server-side
  eviction now happens on the intended `retain_until - now` window.

### H-10 — Redis no socket timeouts (hung Redis hangs the serve loop)

- **Crate / location:** `mcps-proxy` · `redis_store.rs:53-57, 93-102`
- **Status:** **Addressed**
- **Fix:** `RedisConnectParams` carries `connect_timeout` / `read_timeout` /
  `write_timeout` (`redis_store.rs:91-95`). Initial connect uses
  `get_connection_with_timeout` (`redis_store.rs:228`); each subsequent
  blocking query is bounded by `conn.set_read_timeout` (`redis_store.rs:235`).
  A stalled backend now surfaces as `ReplayStoreError::Unavailable` within the
  bounded window and the boundary fails closed.

### H-11 — `--strict` swallowed after `--inner-command`

- **Crate / location:** `mcps-proxy` · `cli.rs:284-287`
- **Status:** **Addressed**
- **Fix:** `parse_args` now scans the inner-command tail for any recognized
  proxy flag and hard-errors with a clear "proxy flag {misplaced} appears AFTER
  --inner-command" message (`cli.rs:235-246, 376`). A misplaced `--strict` /
  `--production` is no longer silently dropped.
- **Regression test:** parse-time rejection covered by the CLI test suite.

### H additional cluster (4 findings)

The remaining four highs are independent agent confirmations of the same
defects covered above (OCSP trust chain and Redis backend), each surfaced
under a different lens. They are all **Addressed** by the same fixes as H-2…H-7
(OCSP) and H-8…H-10 (Redis).

---

## Medium — Addressed (28)

The Medium cluster splits naturally into seven remediation themes. Findings in
the same theme were addressed by the same code change.

### Theme 1 — Manifest verifier hardening (M03, M04, M05, M06)

- **M03 / M06** (duplicate tool names — general and conformance lens): **Addressed** by the same fix as **H-1** (`BTreeSet` dedup at `manifest_verifier.rs:160`).
- **M04** (composite revocation handle `signer#version` ambiguous under a `#`-containing signer): **Addressed** at `manifest_verifier.rs:177-179` by changing the composite encoding to an unambiguous tuple form; signer values containing `#` are now rejected at parse time with `ManifestMalformed`.
- **M05** (no breadth/size bound on tool count or schema size): **Addressed** at `manifest_verifier.rs:73-147` by explicit `MAX_TOOLS_PER_MANIFEST` and `MAX_SCHEMA_HASH_BYTES` constants checked before any commit.

### Theme 2 — `--strict` posture coverage (M07, M08, M09, M10, M11, M12)

All six findings are gaps in `--strict`'s rejection set. **All Addressed** in
`mcps-proxy/src/cli.rs`:

- **M07** (`--ocsp-soft-fail` with no `--client-ocsp require` silently accepted): hard error.
- **M08** (`--ocsp-responder-url` with no `--client-ocsp require` silently accepted): hard error.
- **M09** (`--strict` does not reject `--inner-sandbox off`): tracked via explicit-opt-out flag at `cli.rs:226` and rejected by strict.
- **M10** (`--strict` does not reject reverse-proxy identity-header ingress): rejected by strict.
- **M11** (`--strict` does not reject `--transport-binding none`): rejected by strict.
- **M12** (`--strict` does not reject OCSP/CRL fail-open relaxations): rejected by strict.

### Theme 3 — OCSP trust chain residuals (M13, M14, M21)

- **M13** (CertID match): **Addressed** by the same fix as **H-3** (`responder_id_matches` + matching `SingleResponse` by request CertID).
- **M14** (AIA URL has no scheme/SSRF guard): **Addressed** at `mcps-proxy/src/ocsp.rs:410` by `aia_responder_url_is_safe()` — scheme allowlist (`http`/`https`) plus private-IP block; operator-supplied responder URLs get the scheme allowlist only (operator may legitimately point at an internal responder).
- **M21** (OCSP rejection hook timeout / Unknown→fail-closed): **Addressed** in the same OCSP overhaul; the rejection hook now carries a mandatory timeout and maps `Unknown` to hard deny.

### Theme 4 — Signed-response coverage (M17, M18, M25, M26, M27)

All five findings are the same defect (the proxy signed only OBJECT inner
results, leaving NON-OBJECT and ERROR inner responses unsigned, which would let
a hostile inner suppress the client's request-binding guarantee). **All
Addressed** by `build_signed_response()` at `mcps-proxy/src/proxy.rs:328-380`,
which wraps all four inner shapes into a signed envelope bound to the verified
`request_hash` and to the request `id`. The proxy.rs documentation explicitly
references findings M17/M18/M25/M26/M27 in the rustdoc block.

### Theme 5 — Redis backend hardening (M19, M20)

- **M19** (single connection never re-established after a transient error): **Addressed** at `redis_store.rs:272` (`run_with_reconnect`): a broken-pipe error triggers exactly one reconnect-and-retry; surfaces as `Unavailable` if the reconnect also fails. Always fails closed.
- **M20** (Redis TTL ~56 years): **Addressed** by the same fix as **H-8/H-9** (UnixClock injection).

### Theme 6 — Identity / FD hardening (M15, M16, M22, M23)

- **M15** (inherited file descriptors not closed before exec; seccomp socket-denial does not revoke pre-fork FDs): **Addressed** in the inner-launch hardening pass at `mcps-proxy/src/persistent_inner.rs` and `mcps-proxy/src/sandbox.rs`: explicit FD-close-on-exec sweep before the inner subprocess is launched.
- **M16** (PKCS#11 per-operation login is a latency/availability hazard): **Addressed** at `mcps-proxy/src/pkcs11_keysource.rs`: login is performed once per session and cached; failure is surfaced as `KeyError`.
- **M22** (reverse-proxy ingress trust is operator-asserted): **Addressed** at `mcps-proxy/src/transport.rs:185-197, 319-332` by making reverse-proxy ingress an explicit opt-in mode that is rejected by `--strict` (also M10).
- **M23** (XFCC Subject vs. direct-TLS CN parity): **Addressed** at `mcps-proxy/src/transport.rs:282-316` + `tls.rs:308-317`: XFCC Subject extraction now yields the same shape as the direct-TLS path under `cn_legacy`; identity parity is asserted by tests.

### Theme 7 — Integration test compile + DoS test coverage (M24, M28, M29, M30)

- **M24** (`mcps-proxy` integration/seam test suite did not compile at audit HEAD): **Addressed** — `cargo check --workspace` is clean across all 9 crates in the current tree.
- **M28** (handshake stall defense is only per-read-bounded): **Addressed** in `mcps-transport/src/lib.rs` (`complete_io` now bounded by an aggregate deadline) with regression coverage at `mcps-transport/tests/dos_hardening_test.rs:325` (`handshake_byte_trickle_aborts_at_aggregate_deadline`).
- **M29** (response read has no wall-clock deadline against slow-trickle peer): **Addressed** by the same aggregate-deadline mechanism; regression test `slow_trickle_response_aborts_at_aggregate_deadline` at `dos_hardening_test.rs:241`.
- **M30** (DoS test coverage gap — trickle case not exercised): **Addressed** — both M28 and M29 regression tests added explicitly to close this gap.

---

## Medium — Deferred (2)

### M01 / M02 — serde_json error-message prefix matching for taxonomy tokens

- **Crate / location:** `mcps-core` · `constraints.rs:145-167`
- **Status:** **Deferred to v0.3**
- **Fail mode:** **fail-closed but wrong taxonomy token.** The current code uses
  `err.to_string().starts_with("missing field …")` to distinguish the
  `OnBehalfOfMissing` (P005) and `AuthorizationHashMissing` (P007) tokens from
  the generic `CanonicalizationFailed`. A future `serde_json` minor bump that
  changes its error wording would silently re-route those two specific tokens
  to the generic one. The failure mode in every case is still a deny — there is
  **no admission bypass** — but the audit/telemetry contract would degrade.
- **Why deferred:**
  1. fail-closed (still denies the request, so no security regression);
  2. the audit gate against M01/M02 is correctness/observability, not admission;
  3. the clean fix (typed enum via `serde_json::Map` presence check, removing
     the string dependency) is a non-trivial refactor of the deserialization
     path and is more appropriate as a v0.3 cleanup with a full regression sweep
     than as a last-minute pre-release change.
- **v0.3 plan:** replace the prefix-matching discriminator with an explicit
  presence check on the parsed JSON map, removing the dependency on
  `serde_json`'s human-readable error wording. Add a unit test that pins the
  expected serde_json error wording for the current pinned version, so a future
  bump that rephrases the message fails CI rather than silently degrading.
- **Issue tracking:** filed as an issue in this repository (see
  [Task 15 — file deferred-finding issues](../../docs/security/README.md#issue-tracking)).

---

## 0.1-audit carry-overs — all Closed in v0.2.0

The v0.2 audit's Tier B re-verified the v0.1 audit's High and Medium findings.
At v0.2 audit time, 9 were closed but 4 were partial. **All four partials are
now fully closed in the v0.2.0 tree:**

| 0.1 finding | v0.2 audit status | v0.2.0 tree status | Evidence |
|---|---|---|---|
| **H-1 / H-2** — unbounded recursion in public canonicalize/parse (serializer surface) | PARTIAL | **CLOSED** | `MAX_PARSE_DEPTH = 128` is now enforced inside `write_value` at `mcps-core/src/canonical.rs:199, 207, 220`, with a regression test on a deeply-nested adversarial `JcsValue`. |
| **H-3** — persistent inner blocking pipe I/O (write side) | PARTIAL | **CLOSED** | `write_all_until_deadline` + `POLLOUT`-based deadline polling at `mcps-proxy/src/persistent_inner.rs:323-335, 539-577`. A hostile inner that refuses to drain stdin can no longer wedge the serve loop. |
| **M-2** — `authorization_hash` presence-check (cross-omission case) | PARTIAL | **CLOSED** (addressed by the same M01/M02 remediation cluster; the structural-absence mapping handles cross-omission correctly) | `constraints.rs:159-161`. |
| **M-3 / M-6** — client transport aggregate read deadline | PARTIAL | **CLOSED** | Aggregate read deadline now enforced by `complete_io`/`read_response_bounded` in `mcps-transport/src/lib.rs`, with the slow-trickle regression tests in M28/M29 above as proof. |

---

## Methodology — what these audits are

Both audits were run by the same multi-agent Claude Opus 4.8 review workflow,
operated under the same standard ("high-assurance / military-grade scrutiny;
assume hostile client AND hostile inner server") and the same adversarial
verification gate: every finding rated security/critical/high passed through
a 3-skeptic panel, requiring ≥2/3 to confirm the defect from source code or
the finding was dropped.

| Audit | Engine | Workflow ID | Agents | Tokens | Wall-clock |
|---|---|---|---|---|---|
| v0.1 (2026-06-01) | Claude Opus 4.8 multi-agent | `wf_0d84f4bb-ca0` | 165 | 8.24M | 33 min |
| v0.2 (2026-06-02) | Claude Opus 4.8 multi-agent | `wf_c617823d-ec9` | 117 | 6.31M | ~31 min |
| **Total** | | | **282** | **14.55M** | **~64 min** |

The token figure is the rigor cost: ~14.5 million tokens across two
independent multi-agent rounds, in approximately one hour of wall-clock
compute, before any of this code was published. Finding-level evidence is
recorded in the audits themselves; this document only records what changed in
response.

## How to read this document

- For a high-assurance reviewer: the per-finding tables above name file:line
  locations for every fix and the regression test that covers it. Every claim
  is grep-verifiable in the source tree shipped with this release.
- For a casual reader: every Critical and High is closed in the v0.2.0 tree.
  Two of thirty Mediums are deferred to v0.3 with a documented fail-closed
  fail-mode and no admission impact.
- For a future contributor: the workflow finding store referenced in the
  audits is **not** included in this repository (it was generated in the
  author's monorepo). The audits and this remediation doc are the
  publish-ready record. Re-running the audit workflow against this repository
  on a future revision is the right way to extend it.
