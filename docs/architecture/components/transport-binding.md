<!-- SPDX-License-Identifier: Apache-2.0 -->

# Component Blueprint: Transport Binding & Ingress Assertions

**Status:** Authority census (ADR-MCPRE-061 §8), MCPRE-140 / issue #576. Investigation only — no code changed by the census.

**Scope split:** this document owns the **target** design for `mcp-re-proxy/src/transport.rs`. Current sealed state lives in [`docs/dev/sealed-owners.md`](../../dev/sealed-owners.md) (ADR-061 §13.1). §9 is the diff. The neighbouring authority is [`components/tls-and-transport-identity.md`](tls-and-transport-identity.md), whose §12 named this unit as separate.

**Measured on `main` @ `dc9f1c1`: 1268 production lines**, 2227 total, by `scripts/module_size_gate.py::production_lines`.

Three figures were in circulation and none of them was this one: the campaign index and issue #576 say **1305**, and the debt registry said **1274** at `c81df3e`. Both predate later shrinkage — ADR-MCPRE-064 Slice 4 removed `MappedBinding`, and the ADR-063 facades moved the asserted-identity vocabulary out. **A census states its own measurement**; the index and the registry are corrected in the same change, so the three stop disagreeing.

## 1. Purpose

Relate the channel a request arrived on to the actor its signature resolved to, and — for deployments that terminate the client's TLS somewhere else — verify an ingress attestor's signed, request-bound assertion about that channel.

## 2. Authority

### Owns

- the **deployment identity policy**: which certificate field is authoritative, with no fallback (`IdentityPolicy`);
- the **binding capability**: which binding modes a validated deployment may enforce (`TransportBinding`, `pub(crate)`, private representation);
- the **routing-header hygiene rule**: `Mcp-Method`/`Mcp-Name` are single-valued and well-formed or the request is refused;
- the **v1 ingress-assertion format** (Mode B) and its verification;
- the **v2 attested-ingress format** (Mode C) and its verification, including the bind-not-interpret rule for the attestor's verdicts.

### Does not own

- the peer-identity **value** rules — ADR-063 Slice 1 owns them; this module re-exports a facade (`facades::asserted_identity`);
- **certificate identity interpretation** — `communication_assurance::certificate_identity_policy` (THM-0024);
- the **binding relation itself** — ADR-064 Slice 4's `bind_request_to_peer`; `ExactMatchBinding` says in its own doc that it is "a COMPATIBILITY facade, and nothing more. … There is no check here to delete";
- TLS termination, chain verification, CRL/OCSP (`tls.rs`, `ocsp.rs`);
- which binding mode is legal (`config_state::transport`).

## 3. Position in the system

```text
                       config_state::transport ──▶ ChannelBindingState (Exact{Uri,Dns}San only)
                                                          │
async_serve ──▶ RequestHeaders ──┬──▶ routing_header_rejection (tls.rs) ──▶ 403
                                 └──▶ assertion_header (tls.rs) ──▶ ServedHttpRequest.assertion
                                                          │
http_profile_serve ──▶ TransportBinding::bind(peer, subject) ──▶ bind_request_to_peer (ADR-064)
```

Everything in the left column is live. `ServedHttpRequest.assertion` is populated only under `PeerIdentityProvenance::IngressAssertion`, which no validated deployment can select — see §4 Q9.

## 4. The twelve questions (ADR-061 §8)

### 1. What single security/control fact does this unit own?

*"A request's actor is related to the channel it arrived on."* That sentence is honest for **355 of 1268 production lines**. For the other 913 the unit owns two wire formats and their verifiers, which is a different fact: *"a trusted attestor said this about this request."*

So question 1 needs one "and" — but it is not the same shape as `scitt.rs`'s sevenfold "and". It is one live authority and one **large deferred capability** that shares its file.

### 2. How many independently describable authorities exist inside it?

**Five**, and the interesting number is not five but the split between live and unreachable:

| # | authority | lines | reachable in a validated deployment? |
|---|---|---:|---|
| A | identity policy + identity value (`IdentitySource`, `IdentityPolicy`, `TransportIdentity`) | 61 | **yes** — `app.rs` maps `ChannelBindingState` onto it |
| B | header view (`RequestHeaders`) | 65 | **yes** — `async_serve` builds one per request |
| C | routing-header hygiene | 54 | **yes** — via `tls::routing_header_rejection` |
| D | binding capability (`TransportBindingPolicy`, `ExactMatchBinding`, `TransportBinding`) | 110 | **yes** — the one live binding |
| E | ingress assertions: Mode B v1 (340) + Mode C v2 (573) | **913** | **no** |

The provider seam (`TransportBindingProvider`, `StaticIdentityProvider`, 36 lines) is a sixth item with no production implementor at all — see Q8.

### 3. What does it decide?

Whether an assertion verifies (E); whether routing headers are well-formed (C); and — through a facade — whether the peer and the subject are the same principal (D, decided by ADR-064).

### 4. What does it merely execute?

Ed25519 signature verification (`verify_ed25519_with`), base64url decoding, length-prefixed preimage framing. The binding relation itself: `ExactMatchBinding::bind` executes `bind_request_to_peer` and maps its refusal to the historical error.

### 5. What does it merely transport?

`RequestHeaders` transports the header block. `AttestedIngressVerified::{cert_verification_result, revocation_result, crl_next_update}` transport the attestor's verdicts for audit — Mode C is explicitly bind-not-interpret, so the node records them and never recomputes them.

### 6. What facts does it reconstruct that another owner already decided?

**None by computation — two by vocabulary.** The asserted-identity rules and the binding relation are both re-exported or delegated rather than re-implemented, which is the right shape and is stated in the code. But `MCP_METHOD_HEADER`/`MCP_NAME_HEADER` are **defined twice**: here, and in `mcp-re-http-profile/src/ids.rs`, whose copies are the ones `mcp_transport.rs` consumes. One vocabulary, two definitions, two consumer sets, nothing relating them. See Q10.

### 7. What security relationship exists only through call ordering or local variables?

The `RequestHeaders` **duplicate-count contract**. `assertion_header` and `validate_routing_headers` both fail closed on a duplicate by calling `headers.count(name) != 1` — a discipline every caller must remember, held by no type. `async_serve` even carries a comment pointing at "the SAME case-insensitive lookup + duplicate-count semantics" it must reproduce. A `SingleValuedHeader` projection would own it; today three call sites remember it.

### 8. What public interface exists only because tests need it?

**`TransportBindingProvider` and `StaticIdentityProvider`.** Both `pub` and re-exported at the crate root. `StaticIdentityProvider` is the only implementor of the trait anywhere in the workspace, its doc says "Useful in tests and as a degenerate provider", and no production path calls `verified_identity`. A seam with one test-only implementor is a seam nothing crosses.

`LbAssertionV2Binding` is also `pub` and crate-root re-exported with no production constructor — but it is a **deferred capability**, not a test artefact, and is classified as such below.

### 9. What branches are unreachable under the current legality model?

**913 of 1268 production lines — 72% of the file.**

`ChannelBindingState` has exactly two inhabitants, `ExactUriSan` and `ExactDnsSan`. `BindingKind::LbAssertion` and `BindingKind::AttestedIngress` are refused by Layer-A validation (`docs/AGENT_INSTRUCTIONS.md` §9), and `TransportBinding` has one constructor, `exact_match()`. So neither assertion verifier can be reached from the serving path even if a configuration named it.

**This is retained deliberately and must not be deleted.** Mode C's verifier is exercised by tests precisely so it stays correct while unreachable, and AGENT_INSTRUCTIONS §9 names both halves of the mistake: do not delete the code behind a refusal as dead, and do not wire one up to make it work. The census records the *proportion*, which is the fact that matters for this unit's authority structure: the file is 28% live authority and 72% correctly-preserved deferred capability, and nothing in its structure says so.

### 10. What facts are represented more than once?

- the **MCP routing-header names**, here and in `mcp-re-http-profile/src/ids.rs` (Q6);
- the **assertion preimage framing**, in `LbAssertion::signing_preimage` and again in `LbAssertionV2`'s v2 layout — deliberately, since v1 and v2 are separately frozen formats and a shared helper would let a v2 change silently alter v1's preimage;
- the **honesty guarantee string**, as `LbAssertionBinding::GUARANTEE` and `LbAssertionV2Binding::GUARANTEE` — two constants stating two genuinely different downgrades.

### 11. What inconsistent values can callers construct?

Two types whose **names are the claim** and whose representations do not hold it:

| type | name claims | actual |
|---|---|---|
| `TransportIdentity` | *"A verified client identity extracted from a successfully-verified mTLS client certificate"* | `pub value`, `pub source`, `pub fn new(impl Into<String>, IdentitySource)` — any string, from anywhere, with any claimed source |
| `AttestedIngressVerified` | the success product of Mode-C verification | all five fields `pub`; constructible with `cert_verification_result: Verified` by anything that can name the type |

`LbAssertion` and `LbAssertionV2` also have fully public fields, but they are **parse products**: `verify` takes the wire string and derives the struct itself, so a hand-built one is not a path into the verifier. `TransportBinding` is the counter-example and the model — private representation, `pub(crate)` constructors, and a doc comment that explains exactly why `pub(crate)` is the right lever here.

`AttestedIngressVerified` is the more serious of the two only in principle: nothing consumes it today (Q9). `TransportIdentity` is live.

### 12. Which test/build/proof lane establishes each claimed property?

See §6. Summary: **45 in-crate unit tests + 14 integration tests across three lanes, all executed for this census and reporting non-zero**, and **zero theorem-registry entries owned by this unit** — THM-0023 and THM-0024 look adjacent but are owned by `proxy.peer_identity_value` and `proxy.certificate_identity`, both in `communication_assurance`.

## 5. Theorem inventory

Registry: [`verification/policy/theorems.toml`](../../../verification/policy/theorems.toml). Referenced, not restated (ADR-061 §12).

**Measured: 0 of 33 entries are owned by this unit.** Two are owned next door and are frequently mistaken for coverage here.

| proposition | scope | evidence/unit | status |
|---|---|---|---|
| Every peer identity value is well-formed, whatever evidence produced it | local | THM-0023 · `unit://proxy.peer_identity_value` | **in registry, owned by `communication_assurance`** — this module re-exports the facade |
| Certificate identity interpretation reads the configured field and refuses rather than falling back | local | THM-0024 · `unit://proxy.certificate_identity` | **in registry, owned by `communication_assurance`** |
| Transport identity is derived only from the verified client certificate | system | none | **gap** — named in the TLS blueprint as open, and it is this unit's boundary that would have to state it |
| Possession of a `TransportBinding` implies the mode was recognised by configuration | local | private representation + `pub(crate)` constructors | **structural, no registry entry** |
| A duplicated routing header is refused before the handler runs | local | `validate_routing_headers` via `tls::routing_header_rejection` | **structural, no registry entry** |
| A v1/v2 assertion binds to the in-hand request hash, or is refused | local | `LbAssertionBinding::verify`, `LbAssertionV2Binding::verify` | **structural, no registry entry — and unreachable** |
| Two distinct field tuples cannot share an assertion preimage | local | length-prefixed framing | **structural, no registry entry** |

The third row is the one to draft first, and it cannot be drafted honestly until Q11 is fixed: a theorem saying identity comes only from the verified certificate is false of a type anyone can build from a string.

## 6. Test/evidence inventory

| property | test/evidence | lane | negative control |
|---|---|---|---|
| Assertion framing, freshness, key lookup, request binding (v1 + v2) | 45 unit tests in `transport.rs` | `cargo test -p mcp-re-proxy --lib` · `//mcp-re-proxy:proxy_unit_test` | forged preimages, unknown key ids, stale and cross-request assertions |
| Mode-A binding through the serving path | `tests/integration/mtls_transport_binding_test.rs` — 3 tests | `//mcp-re-proxy:integration_test` | signer ≠ channel identity refused |
| No fallback between certificate identity fields | `tests/integration/certificate_identity_no_fallback_test.rs` — 8 tests | `//mcp-re-proxy:integration_test` | configured field absent ⇒ refusal, never a weaker field |
| Client-leg mTLS end to end | `tests/integration_async/mtls_client_leg_e2e_test.rs` — 3 tests | `crate_features = ["async_serve"]` · `//mcp-re-proxy:integration_async_test` | — |

**No vacuous row.** Each lane was executed for this census and reported a non-zero count.

**A lane observation worth recording:** this module's in-file tests reach into `communication_assurance::certificate_identity_policy` (line 1306). The tests are therefore partly exercising a neighbour's owner from inside this file — a symptom of the facade relationship, not a defect, but it means "transport.rs is well tested" is a claim about two owners.

## 7. Implementation map

`mcp-re-proxy/src/transport.rs` — **1268 production lines** on `main` @ `dc9f1c1`. Registered in `config/module-size-debt.toml` at a baseline of 1274 (`c81df3e`); re-baselined to the measured 1268 by this census, with `review_ref` EX-005.

| lines | region | authority | reachable |
|---|---|---|---|
| 1–29 | module doc + imports | — | — |
| 30–90 | `IdentitySource`, `IdentityPolicy`, `TransportIdentity` | A | yes |
| 91–155 | `RequestHeaders` | B | yes |
| 156–191 | `TransportBindingProvider`, `StaticIdentityProvider` | — | **no production implementor** |
| 192–245 | routing-header constants, `RoutingHeaderRejection`, `validate_routing_headers` | C | yes |
| 246–355 | `TransportBindingPolicy`, `ExactMatchBinding`, `TransportBinding` | D | yes |
| 356–695 | Mode B v1: `LbAssertion`, `LbAssertionBinding`, rejections | E | **no** |
| 696–1268 | Mode C v2: verdict enums, `LbAssertionV2`, `AttestedIngressVerified`, `LbAssertionV2Binding` | E | **no** |

## 8. Outcome — decompose along the reachability boundary, and seal two types

Question 2 answered five, not seven, and the live authorities are genuinely related: identity policy, header view, hygiene and binding are one story about one request. **This is not `scitt.rs`.** A §14 exception for the live 355 lines would be arguable on its own terms.

It is not arguable for the file as it stands, and the reason is Q9 rather than Q2: **72% of this unit is a deferred capability that no validated deployment can reach, sharing a file with the one binding every deployment does reach.** That is the measurement that decides it. A reader cannot tell from the file's shape which half governs served traffic, the module doc does not say, and the two halves have opposite change rules — the live half is ordinary work, the deferred half must be neither deleted nor wired up.

**Proposed split**, two moves and no more:

```text
transport.rs          A+B+C+D  identity policy, header view, hygiene, binding      ~355
transport/ingress.rs  E        Mode B v1 + Mode C v2, with the retention rule
                               stated at the top of the file                       ~913
```

`ingress.rs` is over the threshold and is then a band-3 unit of its own, to be censused on its own terms rather than hidden. Splitting it further (v1 / v2 / verdicts) is a decision for that census, not this one: v1 and v2 are separately frozen formats and the case for keeping each whole is real.

**Sealing work, which matters more than the file boundary:**

1. `TransportIdentity` — private fields; construct only from a verified certificate interpretation or a verified assertion; a named constructor per provenance so the `source` field cannot disagree with where the value came from. This is also the prerequisite for the open *transport identity is derived only from the verified client certificate* theorem.
2. `AttestedIngressVerified` — private fields, produced only by `LbAssertionV2Binding::verify`. A `Verified`-shaped type anything can construct is the same defect the SCITT census found in `EvidenceCommitment`.
3. `TransportBindingProvider` + `StaticIdentityProvider` — classify. One test-only implementor and no production caller; the ruling in #657 applies by analogy — zero production callers is not by itself a deletion argument, and the right answer may be `#[cfg(test)]`, a test-support feature, or removal once the seam is confirmed dead.
4. The routing-header constants — one definition. `mcp-re-http-profile::ids` already owns the vocabulary and has the production consumer.
5. A `SingleValuedHeader` projection to own the duplicate-count contract three call sites currently remember (Q7).

**Follow-up issues, not this one.** The census recommends and stops.

## 9. Known deviations

| deviation | status |
|---|---|
| 72% of the unit is unreachable deferred capability sharing a file with the live binding | **this census's finding**; split proposed |
| `TransportIdentity` and `AttestedIngressVerified` admit values their names claim are verified | **this census's finding**; sealing proposed |
| `TransportBindingProvider`/`StaticIdentityProvider`: seam with one test-only implementor | recorded; classify before deleting |
| MCP routing-header names defined in two crates | recorded; the http-profile copy has the production consumer |
| Duplicate-count contract held by caller discipline | recorded |
| No theorem entry owned by this unit; two neighbours' entries are easily mistaken for coverage | recorded; §5 is the drafting list, and row 3 is blocked on the sealing work |
| Three disagreeing size figures — index 1305, registry 1274, actual 1268 | corrected in this change; all three now agree |

## 10. Completion criteria

- [x] All twelve questions answered in writing
- [x] Blueprint committed under `docs/architecture/components/` and linked from the campaign index
- [x] Implementation map measured with `scripts/module_size_gate.py` on a stated SHA (`dc9f1c1`), and the stale 1305 figure corrected
- [x] Theorem inventory distinguishes *in registry* / *structural, no entry* / *gap* — 0 owned, 2 adjacent, 1 gap named
- [x] Test/evidence inventory names the exact lane per row; every lane executed and reported non-zero
- [x] Outcome recorded: **decompose along the reachability boundary**, plus the sealing work
- [x] No code changed
