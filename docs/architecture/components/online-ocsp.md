<!-- SPDX-License-Identifier: Apache-2.0 -->

# Component Blueprint: Online OCSP Client-Certificate Revocation

**Status:** Authority census (ADR-MCPRE-061 §8), MCPRE-141 / issue #577. Investigation only — no code changed by the census.

**Scope split:** this document owns the **target** design for `mcp-re-proxy/src/ocsp.rs`. Current sealed state lives in [`docs/dev/sealed-owners.md`](../../dev/sealed-owners.md) (ADR-061 §13.1). §9 is the diff.

**Measured on `main` @ `68e821b`: 1271 production lines**, 2792 total, by `scripts/module_size_gate.py::production_lines`. The registry baseline agrees.

## 1. Purpose

Ask a certificate's OCSP responder (RFC 6960) whether a chain-verified mTLS client leaf is revoked, establish that the answer is trustworthy under RFC 6960 §3.2 before acting on it, and decide admission fail-closed.

## 2. Authority

### Owns

- the **RFC 6960 request**: SHA-256 CertID construction and a CSPRNG nonce;
- the **RFC 6960 §3.2 trust chain**: responder signature, responder identity, CertID binding, freshness, nonce echo;
- the **status mapping** and the **fail-closed admission policy** (`decide_allow`);
- the **outbound-fetch network policy**: scheme allowlist, literal-private-IP block for cert-supplied URLs, resolved-address vetting against DNS rebinding, no redirect following, response size cap.

### Does not own

- offline CRL revocation (`client_revocation.rs`) or certificate lifetime (`tls.rs`) — the two revocation postures that **do** run on the production plane;
- chain verification (rustls / `webpki`) — this module runs after it;
- whether a deployment may enable online OCSP (`config_state::validation::residue`, THM-0013);
- the responder itself. **There is no responder-side code in this product**; the peer in every test is an OpenSSL responder.

## 3. Position in the system

```text
blocking_mtls_harness::connection ──▶ tls::ocsp_rejection_for_chain ──▶ OcspChecker::check
                                                                              │
                          AIA URL ──▶ SSRF guard ──▶ VettingResolver ──▶ HTTP POST
                                                                              │
                                          RFC 6960 §3.2 trust chain ──▶ CertRevocationStatus
                                                                              │
                                                                        decide_allow
```

**Nothing above reaches the production data plane.** `ocsp_rejection_for_chain` has exactly one caller — `blocking_mtls_harness::connection` — and the production plane is the per-core async fleet (ADR-MCPRE-051 §1), which calls `connection_rejection_for_chain` and performs only offline cert-lifetime and CRL checks.

## 4. The twelve questions (ADR-061 §8)

### 1. What single security/control fact does this unit own?

*"This chain-verified client leaf is not revoked, according to a responder we established the trustworthiness of."* That is one fact and it needs no "and" — the §3.2 chain is not five facts, it is five conjuncts of one.

**But the unit also owns an outbound-fetch network policy that is not about revocation at all**, and that is where its "and" is. See Q2/E.

### 2. How many independently describable authorities exist inside it?

**Four**, and their relationship is unusual: one is a complete protocol implementation, one is a general-purpose control that happens to live here, and two are thin.

| # | authority | proposition | lines |
|---|---|---|---:|
| A | **request construction** | this is a well-formed RFC 6960 request about THIS leaf under THIS issuer, with a fresh nonce | 92 |
| B | **response trust chain** | this response is signed by an authority entitled to answer for this issuer, about this CertID, fresh, and not replayed | 393 |
| C | **admission policy** | this status, under this fail posture, admits or denies | ~15 |
| D | **fetch orchestration** | resolve URL, guard, POST with a mandatory timeout, bound the body | 240 |
| E | **outbound-fetch network policy (SSRF / DNS-rebinding)** | this URL, and every address it resolves to, is safe for a server to fetch | **336** |

**E is the finding.** It is 26% of the file, it is a *general* control — scheme allowlist, literal-private-IP classification including `inet_aton` dotted-decimal forms, IPv4/IPv6 public-range predicates, and a `ureq::Resolver` that re-vets every resolved address — and **nothing about it is specific to RFC 6960**. Any future outbound fetch this proxy performs (an async OCSP, a SCITT transparency-service registration, an AIA issuer fetch, a JWKS pull) needs exactly this control, and today it is reachable only through a module compiled out of the default build.

### 3. What does it decide?

Whether a response is trustworthy (B), and whether a status admits (C). E decides whether a URL may be fetched at all — a decision with no OCSP content.

### 4. What does it merely execute?

The HTTP POST (`ureq`), DER encode/decode (`x509-ocsp`, `x509-parser`), and signature verification, which is delegated to `x509-parser`'s `ring`-backed algorithm-agnostic verifier rather than implemented here.

### 5. What does it merely transport?

`OcspError`'s string payloads — every variant carries a diagnostic and every variant is fail-closed, so the strings inform an operator and decide nothing.

### 6. What facts does it reconstruct that another owner already decided?

Three generic X.509 facts, implemented here because no owner offers them: `cert_is_signed_by`, `signature_verifies`, and `sha1_hash` (RFC 6960 `byKey` responder identity). They are correct and small, and they are X.509 facts sitting inside an OCSP module — the same shape as E, one layer down.

### 7. What security relationship exists only through call ordering or local variables?

**The SSRF guard's position.** `OcspChecker::check` resolves the URL, then calls `aia_responder_url_is_safe` or `responder_scheme_allowed` depending on the URL's provenance, then fetches. Nothing in the types prevents a future caller from fetching first: the guard is a free function returning `bool`, the provenance is a private enum, and the pairing of *which guard applies to which provenance* is held by a `match` inside one function. A `FetchableUrl` value carrying its provenance and constructible only through the guard would own it.

The `#[cfg(test)] new_allowing_loopback` constructor disables address vetting. It is correctly test-gated, and it means the production guard is a `bool` field rather than a type — the same relationship expressed as data.

### 8. What public interface exists only because tests need it?

Little, unusually. `extract_ocsp_responder_url`, `responder_scheme_allowed`, `aia_responder_url_is_safe`, `build_ocsp_request_der*`, `build_cert_id`, `map_cert_status`, `verify_and_map_response` and `decide_allow` are all `pub` — but they are the deterministic, network-free pieces the module doc says were factored out *so the unit tests can exercise them with zero network access*, and they are the pieces a future async OCSP would reuse. That is a stated design intent, not test-shaped API.

The one item to classify is `new_allowing_loopback`, which is `#[cfg(test)]` and therefore already correct.

### 9. What branches are unreachable under the current legality model?

**All of them, by two independent gates**, and the distinctions matter:

| gate | effect |
|---|---|
| `#[cfg(feature = "online_ocsp")]` on `pub mod ocsp` | the default build does not **compile** this module at all |
| THM-0013 — `--client-ocsp require` refused at the legality boundary | **no validated deployment**, in any build, is handed a checker |
| the caller is `blocking_mtls_harness`, not the async fleet | even a hypothetical checker would not be consulted on the production plane |

Three gates, in fact, and they are not redundant: the first is a build fact, the second a configuration fact, the third an architectural one. THM-0013's scope sentence already says it establishes *reachability and legality only* and not the correctness of anything in this file.

**The census classifies the code as ADR-061 §5 case B material, not dead code**, and does so along the distinction the issue asked for:

- **excluded by the legality model:** D (fetch orchestration) and C (admission policy) — these exist to serve a posture no deployment may select;
- **reusable protocol mechanism despite unreachability:** A and B — a complete, tested RFC 6960 requester and §3.2 validator, which `serving_capabilities.rs` explicitly says is retained because *"proving the `Require` arm unreachable under today's legality model is not a decision to delete the implementation a future async OCSP would be built from"*;
- **reusable general control despite unreachability:** E — not OCSP at all;
- **test/responder infrastructure:** none in the product. The responder is provisioned by the nightly workflow.

### 10. What facts are represented more than once?

The **public-IP predicate** is stated three times against three input types — `host_is_public` (a host string), `ipv4_is_public`/`ipv6_is_public` (literals), `resolved_ip_is_public` (a resolved `IpAddr`). They agree today and nothing relates them; a fourth caller that reached for the wrong one would compile.

The **fail-closed rule** is stated in `decide_allow` and again in every `Ok(CertRevocationStatus::Unknown)` early return inside `check` — correctly, since those are different decisions, but a reader has to notice that the early returns are *not* bypassing the policy.

### 11. What inconsistent values can callers construct?

**The sharpest instance the census campaign has found so far, and it is not a `pub` field.**

`verify_and_map_response` performs all five RFC 6960 §3.2 checks and returns `Result<CertRevocationStatus, OcspError>`. The success value is a **three-valued `Copy` enum** — `Good`, `Revoked`, `Unknown` — that any code can name. So:

```rust
decide_allow(CertRevocationStatus::Good, false) == true
```

is reachable from anywhere, with no responder, no signature, and no freshness. **The entire §3.2 trust chain collapses into a value that carries no evidence of having been through it.** Compare `EvidenceCommitment` and `AttestedIngressVerified` in the two prior censuses: those had public fields, which is a milder version of the same defect — here there is no representation to seal, because the success product was never given one.

Today the only consumer is `ocsp_rejection_for_chain`, in the same crate, three lines from the producer. The defect is latent, and it is exactly the shape that stops being latent when someone builds the async OCSP this implementation is retained for.

`OcspChecker`'s own fields are private with one public constructor and one `#[cfg(test)]` one — the counter-example, and the model.

### 12. Which test/build/proof lane establishes each claimed property?

See §6. Summary: **46 unit tests that compile in no default lane**, one live-responder test that **self-skips to green** when unprovisioned, and one theorem that is about the module *not running*.

## 5. Theorem inventory

Registry: [`verification/policy/theorems.toml`](../../../verification/policy/theorems.toml). Referenced, not restated (ADR-061 §12).

**Measured: 1 of 33 entries concerns this unit, and it is a claim about the unit's absence.**

| proposition | scope | evidence/unit | status |
|---|---|---|---|
| No validated deployment enables online OCSP client-certificate revocation | configuration legality | THM-0013 · `unit://proxy.online_ocsp_reachability` | **in registry** |
| A `Good` status was produced by a response that passed all five §3.2 checks | local | none — the type cannot express it (Q11) | **gap, and blocked on the representation** |
| A cert-supplied responder URL is never fetched without the full SSRF guard | local | call ordering inside `check` | **structural, no registry entry** |
| Every address the fetch connects to is public | local | `VettingResolver` | **structural, no registry entry** |
| An `Unknown` status denies unless the operator opted into soft-fail | local | `decide_allow` | **structural, no registry entry** |
| A responder-signed `Good` cannot be replayed indefinitely | local | `is_fresh`'s unconditional `thisUpdate + max_age` cap | **structural, no registry entry** |

THM-0013's own scope sentence is unusually careful and worth quoting as the model for the rest: it *"establishes reachability and legality only. It does NOT establish the correctness of the retained RFC 6960 implementation … It says what no deployment can turn on, not that what is turned off would be correct if turned on."*

## 6. Test/evidence inventory

| property | test/evidence | lane | honest? |
|---|---|---|---|
| CertID/nonce construction, status mapping, §3.2 chain, freshness, SSRF predicates, `inet_aton` forms | 46 unit tests in `ocsp.rs` | `cargo test -p mcp-re-proxy --features online_ocsp` · `//mcp-re-proxy:proxy_ext_unit_test` · CI's feature-gated lane | **yes** — 46/46 executed for this census. **Not in `cargo test --workspace` and not in `bazel test //...`**: the module is `#[cfg(feature = "online_ocsp")]`, so both default lanes compile it to nothing |
| Live responder: `Good` and `Revoked` against an independent OpenSSL responder, no restart between | `tests/integration_ext/ocsp_e2e_test.rs` — **1 test** | `live-infra-e2e.yml`, **nightly + manual only** (its `pull_request` trigger fires only when that workflow file changes). Last green run 2026-08-26 03:23 UTC | **conditionally** — see below |
| `--client-ocsp require` is refused however the config was built | `tests/integration/config_legality_characterization_test.rs`, `app_startup_characterization_test.rs` | `//mcp-re-proxy:integration_test`, default lane | yes |

**One row needs flagging, and the issue asked for exactly this.** `ocsp_e2e_test` prints a SKIP notice and **returns success** when `MCP_RE_TEST_OCSP_RESPONDER_URL` is unset. Run anywhere but the provisioned nightly workflow, it is a test that exits 0 having proved nothing — the shape `CLAUDE.md` names ("a command that exits 0 having run no tests is worse than a red one"). It is honest in its own doc comment, and the nightly lane does provision a real responder and is green. But **the live-path property holds in one non-gating nightly lane and nowhere else**, and a PR that broke the live fetch path would go green everywhere a reviewer looks.

**No unit-test row is vacuous.** All 46 were executed under `--features online_ocsp` for this census.

## 7. Implementation map

`mcp-re-proxy/src/ocsp.rs` — **1271 production lines** on `main` @ `68e821b`. Registered `unreviewed` in `config/module-size-debt.toml`.

| lines | region | authority | classification |
|---|---|---|---|
| 1–143 | module doc, imports, protocol constants | — | — |
| 144–211 | `CertRevocationStatus`, `OcspError` | vocabulary | reusable |
| 212–423 | `OcspChecker` — resolve, guard, POST, decode | D | excluded by legality |
| 424–451 | AIA URL extraction | A | reusable |
| 452–787 | scheme allowlist, host/IP predicates, `inet_aton`, `VettingResolver` | **E** | **reusable general control, not OCSP** |
| 788–879 | CertID + nonce construction | A | reusable protocol mechanism |
| 880–1272 | §3.2 trust chain, freshness, nonce echo, `decide_allow` | B, C | reusable protocol mechanism (B) / excluded by legality (C) |

## 8. Outcome — one extraction, one representation, and a §14 exception for the remainder

This census does **not** recommend decomposing the OCSP implementation, and the reason is the distinction the issue asked for. A and B are **one coherent protocol authority**: RFC 6960 request and RFC 6960 §3.2 validation are two halves of one specification, kept together deliberately, and splitting them would scatter a protocol across files to satisfy a number. C and D are thin and belong with them.

Two things should nonetheless leave, and one thing should be recorded.

**1. Extract E — the outbound-fetch network policy (336 lines).** It is not OCSP. It is the control any server-side outbound fetch in this proxy needs, and it is currently unreachable in the default build because it lives behind a feature gate that has nothing to do with it. Moving it to its own module (compiled unconditionally) makes it available to the async OCSP this implementation is retained for, to SCITT registration, and to anything else — and it removes 26% of this file without touching the protocol.

**2. Give the §3.2 chain a success product (Q11).** `verify_and_map_response` should return a value whose existence means the five checks passed — not a bare `Copy` enum anyone can name. This is the same finding as EX-004's `EvidenceCommitment` and EX-005's `AttestedIngressVerified`, in its sharpest form: there is no representation to seal because none was created. It is also the prerequisite for the second theorem row in §5.

**3. Then §14 for the remainder.** With E extracted, the residue is ~935 lines of one protocol authority, over the threshold, and the honest disposition is a **reviewed exception**: RFC 6960 §3.2 is a single security argument whose five conjuncts reference each other, and separating them would damage the reasoning rather than clarify it. That exception should be recorded when the extraction lands — **not now**, because an exception granted over a file that still contains an unrelated 336-line control would be granting it for the wrong unit.

**Disposition recorded as `reviewed-action-required`**, with the action being the extraction and the representation, and a §14 exception as the *expected* end state rather than an assumed one.

**Do not delete, and do not wire up.** Both prohibitions are already the project's standing rulings (`AGENT_INSTRUCTIONS` §9), and this census makes neither move. What it does recommend — extracting a general control and giving a trust chain a success product — is work that makes the retained implementation *better as retained code*, and does not move it one step closer to being selectable.

## 9. Known deviations

| deviation | status |
|---|---|
| A 336-line general outbound-fetch/SSRF control lives inside a feature-gated OCSP module | **this census's finding**; extraction proposed |
| The §3.2 trust chain's success product is a freely-constructible three-valued enum | **this census's finding**; representation proposed |
| The live-responder property holds only in a nightly, non-gating lane; the same test self-skips to green elsewhere | **recorded** — honest in its own doc, and a real evidence limit |
| The public-IP predicate is stated three times against three input types | recorded; would be resolved by the E extraction |
| Generic X.509 facts (`cert_is_signed_by`, `signature_verifies`, `sha1_hash`) implemented inside an OCSP module | recorded; no owner offers them today |
| The SSRF guard's position is held by call ordering, and its enablement by a `bool` field | recorded |
| Unreachable by three independent gates: feature, legality, and serving plane | **not a defect** — deliberate, and THM-0013 states the legality half precisely |

## 10. Completion criteria

- [x] All twelve questions answered in writing
- [x] Blueprint committed under `docs/architecture/components/` and linked from the campaign index
- [x] Implementation map measured with `scripts/module_size_gate.py` on a stated SHA (`68e821b`)
- [x] Theorem inventory distinguishes *in registry* / *structural, no entry* / *gap* — 1 entry, and it is about the unit not running
- [x] Test/evidence inventory names the exact lane per row, and **flags the row whose lane self-skips to green**
- [x] Reachability map records the three independent gates and classifies the code as legality-excluded / reusable protocol / reusable general control / test infrastructure
- [x] Outcome recorded: **extract the network policy, give the trust chain a success product, then §14 for the protocol remainder**
- [x] No code changed
