<!-- SPDX-License-Identifier: Apache-2.0 -->

# System assurance completeness audit — 2026-08-31

```text
STATUS:  REVIEW / MEASUREMENT PACKET
         NON-NORMATIVE
         OWNER RULINGS GIVEN 2026-08-31 — see below
```

> **The rulings have been given.** They are in
> [`../rulings/owner-completeness-rulings-2026-08-31.md`](../rulings/owner-completeness-rulings-2026-08-31.md),
> and that record — not this one — is what decides what is in scope and what is bounded out.
> Where the two differ, the ruling record wins: several proposals below were reversed by it,
> including both scope widenings in §2.5. This packet is left as it was measured.

**This document is evidence, not architecture.** It records what was measured, against
which repository state, and what the measurements imply. It is not an authority over
anything: no theorem, unit, assumption, claim boundary or work plan is established here,
and no tool reads it. Where it proposes a decision it is proposing one, and the proposal is
not the decision.

Three layers, and this is the first:

```text
1  RAW AUDIT EVIDENCE      this packet + verification/reviews/r9-dispositions.json
                           kept permanently, never edited into agreement with later rulings
        │ owner ruling pass
        ▼
2  OWNER DECISION RECORD   the eight completeness rulings + the three governance
                           decisions in §11 — a separate, short record
        │ authorizes
        ▼
3  AUTHORITATIVE STATE     ADR-MCPRE-059 · theorems.toml · assumptions.toml ·
                           verification.toml · the current claim boundary
```

Turning layer 1 into layer 3 directly is the mistake this banner exists to prevent. In
particular: **§1's 42% file-coverage figure is not a coverage target**, and **§5's 96
`SURVIVES_AND_MAPPED` rows are not 96 issues**. Both are stated in the sections that
produce them, and both are repeated here because a number lifted out of a packet travels
without its caveat.

**Question asked.** Are the nine declared roots a complete representation of the CURRENT
MCP-RE security claim surface? This is a different question from the one the 84-theorem
closure campaign answered, and it has a different answer.

| | |
|---|---|
| Base | `main @ 8551061c` |
| Date | 2026-08-31 |
| Authority for the exercise | ADR-MCPRE-059 §28; T6 / #542; tracker #544 |
| Roots | 9 |
| Theorems | 84 (3 outside every root closure) |
| Units | 60 (54 V0, 6 V1) |
| Assumptions | 35 (2 withdrawn, 2 ids missing) |
| Verification platform after the §2 correction | `VERIFICATION: PASS` |

No THM ids were allocated. No production architecture was changed. #541's tool capabilities
did not enter any judgment here.

---

## 1. Verdict

> **The nine roots are complete over the authorities they declare, and incomplete as a
> representation of MCP-RE's current security claim surface.**
>
> `9 / 9 declared roots COMPLETE` does not yet imply
> `current MCP-RE security claim COMPLETE`.

The 84-theorem graph is structurally sound: no cycles, no dangling references, no
unresolved internal root closure, no theorem broadened to close a parent.

What is incomplete is the *choice of roots* relative to the current product. Eight coherent
boundary areas have no unit, no theorem, and no explicit out-of-scope declaration — and
each is where a surviving historical cluster landed. §4 lists them; §11 states them as
decisions.

Three findings, kept apart because they call for opposite next actions:

1. **Eight un-rooted boundary areas** (§4). Each needs one owner decision: in the assurance
   roots, or explicitly outside the security promise. Neither is an implementation task.
2. **One root that under-covers its own owner.** THM-0042's statement enumerates the fields
   it compares and *omits `submitted_commitment`* — the field the owner's own code calls
   "the only field that covers the hops AFTER the verified prefix". Six historical clusters
   sit in that omission. This may mean an existing root was declared complete around an
   incomplete proposition (§6).
3. **One security consequence that over-reaches.** THM-0083's consequence claims a document
   that is not an MCP message cannot burn a nonce, spend an approval, or write a retention
   marker. Its *statement* is narrower and true; the consequence generalises past it, and
   the sibling shape refusal `reject_unrepresentable_json` still runs one region late.

### 1.1 A measurement that is not a metric

204 of 482 production `.rs` files (42%) lie inside some unit's `paths`.

**This is not a security-coverage percentage and must never become a target.** A root can
constrain an action through a unit whose `paths` do not enumerate every file involved, and
several do. The figure is useful for exactly one thing: it made the eight un-rooted areas
findable. Raising it for its own sake would produce units that exist to move a number,
which is the failure mode the ADR-MCPRE-061 threshold rules already name in a different
register.

---

## 2. The assumption-graph defect — confirmed, wider than reported, closed

The reported ASM-0037 divergence is real on `8551061c`, and it is **one of nine** instances
of the same class.

### 2.1 Why it is a design defect and not formatting

The two declarations feed different machinery:

- **`[[assumption]].scope`** is what `_fingerprint._trusted_assumptions` puts into a unit's
  `ReviewFingerprint`, and what `check-assumptions` reads for per-unit escape-hatch
  registration. It also feeds `assumption-consumers.md` and `blast-radius.md`.
- **`[[unit]].assumptions`** is what `review-packet` reads to tell a reviewer which
  premises a theorem stands on, and what `owners.md` counts. It participates in **no**
  fingerprint component.

So the system could state one premise graph to a reviewer and invalidate according to
another.

**Severity correction.** The reported symptom was two views disagreeing. The consequence is
a **missed invalidation**. Because `scope` named `http_profile.keyid` and not
`http_profile.keyid_selector`, the selector unit's fingerprint carried *no*
`trusted_assumptions` entry at all — so ASM-0037 could be rewritten, widened or weakened
and **THM-0050, the only theorem that actually rests on SHA-256 collision resistance, would
still read FRESH**. The same held for `proxy.credential_currency` (ASM-0030) and
`proxy.delegated_resolver_materialization` (ASM-0032).

### 2.2 Normative direction under ADR-MCPRE-059

ADR-MCPRE-059 §8 states that *the catalogue SHALL NOT store both directions of the same
relationship* — and then, four lines later, presents `[[unit]].assumptions` beside
`[[assumption]].scope` as the authoritative pair. **That latent duplication is what
produced the divergence.**

Pending an owner ruling (§11.B), the operative reading is the one the machinery already
enforces: `scope` is load-bearing, so a wrong `scope` is the harmful half, and the two must
agree. Three independent statements of intent — `verification.toml`'s comment at the
`keyid` unit, `keyid_selector`'s own comment, and THM-0050's published scope sentence — all
name `keyid_selector`. `assumptions.toml` was the outlier.

### 2.3 The nine disagreements and what was done

| Assumption | Declared by unit | Named in scope | Action taken |
|---|---|---|---|
| ASM-0037 | `http_profile.keyid_selector` | `http_profile.keyid` | scope → `keyid_selector`. The reported instance; three statements of intent agree. |
| ASM-0024/25/26 | none of the five | 5 units | Added to all five units' `assumptions`. Pure under-declaration: the `verus:uninterp` scope is load-bearing for `check-assumptions` and was correct. |
| ASM-0030 | `certificate_identity`, `credential_currency` | `certificate_identity` only | scope widened — **PROVISIONAL, see §2.5** |
| ASM-0032 | `credential_key_correspondence`, `delegated_resolver_materialization` | `credential_key_correspondence` only | scope widened — **PROVISIONAL, see §2.5** |

### 2.4 The negative control

`_manifest.assumption_scope_disagreements()`, called from the `[manifests]` lane before any
other check. It fails the build whenever the two declarations differ in either direction,
when a scope names a unit that does not exist, or when a unit names an assumption the
registry does not contain. Seven tests in `test_measured_inputs.py` pin it, including the
swap that motivated it — a case where *neither half alone would report anything*, because
the premise is declared and is scoped, just to two different units, so any count balances.

Measured: `verify --manifests` reproduces all nineteen messages before the correction and
PASSes after it. Full platform **PASS** (manifests; assumptions 35 registered / 6 hatches;
generated-model; tests; mutations 88 probes; verus 6 units). `check-generated` reports 5
views current. All six verification test suites report 0 failures.

### 2.5 The two widenings are PROVISIONAL and must not be read as ratified

Widening `scope` was chosen as the fail-safe direction: it deletes no stated fact and
strengthens invalidation. **It is not semantically clean, and it does not make the widened
assumption the correct premise for its new consumer.**

```text
ASM-0030 says:                    parser faithfully reports URI SANs, DNS SANs, CN
proxy.credential_currency needs:  issuer/subject Name equality and validity behaviour
                                  (credential_currency/x509_adapter.rs: X509Certificate::from_der,
                                   issuer_der == cert.tbs_certificate.subject.as_raw())

ASM-0032 says:                    parser faithfully reports the leaf's SPKI bytes
proxy.delegated_resolver_
      materialization needs:      the SPKI it uses comes from signer.tls_public_key_spki_der(),
                                  not from a parsed certificate; the shared path is tls.rs
```

The honest repair is to **rewrite or split** these two so each states the actual foreign
contract its consumer relies on, not to leave a broad scope attached to inaccurate wording.
That is an owner-level normalization (§11.A). The provisional status is marked at the two
`scope` entries in `assumptions.toml` so the widening cannot be read out of that file as
settled.

### 2.6 Residual registry-integrity item

**ASM-0016 and ASM-0017 exist nowhere in the tree.** ASM-0015 and ASM-0022 were
deliberately kept as `RESERVED` / `WITHDRAWN` so no later assumption inherits a
justification written for another theorem. The same discipline was not applied to the other
two, and the registry can no longer distinguish "never allocated" from "deleted".

---

## 3. Current claim surface → root crosswalk

Established independently of `theorems.toml`, from `CURRENT_ARCHITECTURE.md`, the
active-profile/legacy-quarantine note, README status and non-claim sections, and
`docs/spec/security-boundary.md` §§9 and 11 — the two sections of that document that *are*
current. §§1–8 and 10 are historical and treated as such throughout (§7).

### 3.1 Current positive promises

| Current positive promise | Root(s) | Status |
|---|---|---|
| RFC 9421 + RFC 9530 is the one carrier; a tampered or unsigned message does not reach the backend | THM-0074 | rooted |
| Freshness, replay admission and continuation approval are spent only for a request that earned dispatch | THM-0074, THM-0078 | rooted, one gap (§1.3) |
| A refusal is terminal and cannot be read as success | THM-0078 | rooted |
| Delegated-required response signing; no direct-root attribution | THM-0075 | rooted |
| The shipped client accepts only an answer to its own request under a signer it trusts | THM-0076 | rooted |
| No deployment serves a posture nobody selected | THM-0077 | rooted |
| The lifecycle record cannot claim a shutdown that did not happen | THM-0012 | rooted |
| A verified SCITT receipt proves registration on the pinned service | THM-0072 | rooted |
| Retained evidence is the evidence the statement was made about | THM-0042 | rooted, **under-covered** (§6) |
| Every reachable in-exchange refusal has typed provenance reaching the record | THM-0071 | rooted |
| ADR-065 authorization: `--authz pdp-decision` is strict, `off` answers who-signed only, transcript names which | THM-0074 → THM-0039/0040/0052/0056 | rooted |
| ADR-066 audit coordinates: a policy denial never renders into Core's `reason` | THM-0071 → THM-0069/0046 | rooted |
| mTLS transport binding: the verified request actor is the identity the channel is checked against | THM-0074 → THM-0034 (via 0023–0033) | rooted |
| **Replay-store durability tier: the fleet fails closed on store unavailability** | — | **FINDING** — THM-0079 claims replay-*key* distinctness, not store behaviour. `async_replay/` (8 files) is in no unit. |
| **Bounded revocation window *T* and CRL-cadence bound, surfaced from real config** | THM-0048 partially | **FINDING** — no theorem states the propagation bound the claim advertises. R9-C125 lands here. |
| **Key custody: HSM/KMS-backed signing, per-node keyset blast radius** | THM-0064, THM-0082 partially | **FINDING** — exposure and provenance are rooted; *acquisition* is not. |
| **The Python and TypeScript SDKs are a supported client path** | — | **FINDING** — THM-0076 is explicitly about "the shipped MCP-RE client proxy". |
| **The client sidecar's local ingress refuses a DNS-rebinding origin** | — | **FINDING** — `mcp-re-client/src/serve/` (10 files) is in no unit. |

### 3.2 Current explicit non-claims

| Non-claim | Claim-boundary authority | Enforcement |
|---|---|---|
| Tool safety / tool-definition signing / method semantics | ADR-MCPS-030 non-goal; v0.5 §A "none, by design" | method-transparency pair + static drift guard banning MCP method literals in Core |
| Kernel/FS/network containment of the inner server | `security-boundary.md` §3 | prose only |
| stdio serving, inner transport or bridging | `CURRENT_ARCHITECTURE.md`; owner decision 2026-07-10 | HTTP-only build surface |
| Native JCS / object-profile evidence | ADR-MCPRE-050; quarantine note | JCS gate over `docs/spec` |
| Ingress / gateway header-mangling survival | `CURRENT_ARCHITECTURE.md` | prose only |
| Attested-ingress (Mode C) and LB-assertion postures | `security-boundary.md` §11 — *current and accurate* | configuration validation refuses both, each naming its own mode |
| Forwarded-header transport identity | README non-claims — capability removed, not refused | no flag, no provider, no code path |
| **The assurance platform itself (`tools/verification/`)** | — | **UNDECLARED** — 28 surviving clusters map here and to no node |
| **Deployment artefacts (Helm chart, CodeBuild, ignore-file parity)** | — | **UNDECLARED** — 11 surviving clusters, including a shipped fail-open (R9-C015) |

### 3.3 Threat → root / out-of-scope

Taken from `docs/spec/threat-coverage-matrix.md`, which self-declares as derived from the
v0.5 matrix over the frozen draft-01 object envelope — a *stale* threat model, used here as
an inventory of threats rather than an authority on coverage. Rows added for the
ADR-063/065/066 threats it predates.

| Threat | Excluding root closure, or claim boundary | Status |
|---|---|---|
| Message tampering in transit | THM-0074 → THM-0014…0022 | rooted |
| Spoofed / unauthenticated signer identity | THM-0074 → THM-0035/0036/0037/0066, THM-0050 | rooted (terminal: ASM-0029) |
| Audience confusion / request redirection | THM-0074 → THM-0079 | rooted |
| Stale-message / freshness-window abuse | THM-0074 → THM-0001 | rooted |
| Replay of captured messages, single node | THM-0074 → THM-0079 | rooted |
| Replay across nodes / failover | — | **FINDING** |
| Response forgery / response-to-request mismatch | THM-0075, THM-0076 → THM-0084 | rooted |
| Forged or caller-injected verified context | THM-0074 → THM-0083 + `ForwardedBody` seal | rooted |
| Stale-trust / delayed credential revocation | THM-0077 → THM-0048/0054, THM-0013 | partial — the bound itself is unclaimed |
| Ingress / transport-identity spoofing | THM-0074 → THM-0028…0034; Mode C refused at validation | rooted |
| Signing-key compromise blast radius | THM-0075 → THM-0062/0063/0082, THM-0064 | rooted |
| Confused-deputy / delegated-authority abuse | THM-0074 → THM-0039/0040/0052/0056 | rooted — the stale matrix still says Partial; ADR-065 changed this and the matrix does not know |
| A policy denial recorded as a Core verdict | THM-0071 → THM-0069/0046 | rooted (post-dates the matrix) |
| Refusal that reads as an ordinary retry after a spent approval | THM-0078 → THM-0044, THM-0081 | rooted (post-dates the matrix) |
| Archivist substitutes an unverified tail under a retained-evidence receipt | THM-0042 | **FINDING** — the root's statement omits the field that defends it |
| Tool poisoning / rug-pull; unsafe tool output; tool sandboxing | ADR-MCPS-030 non-goal + method-transparency guard | out of scope, defended |
| **KMS/STS endpoint re-points a live signing request or IRSA token** | — | **FINDING** — the R9 critical. Fixed in code, still un-rooted. |
| **A browser page reaches the client sidecar by DNS rebinding** | — | **FINDING** |
| **A hostile peer wedges an SDK session by trickling a response body** | — | **FINDING** |
| **A pushed image or upload carries agent/CI credential material** | — | **FINDING** — the parity gate is blind |

Every threat in the inventory has either a root closure or a named claim boundary except
the four in bold, which have neither. Per #542, none of the four is closed here by
manufacturing a theorem.

---

## 4. Boundary action → root crosswalk

| Boundary action | Constraining root | Owning units | Status |
|---|---|---|---|
| Configuration / validation | THM-0077 | trust_composition_root, cross_machine_legality, trust_configuration_state | partial — 23 of `config_state/`'s files are outside any unit |
| Materialization | THM-0077 | tls_listener_state, delegated_resolver_materialization, trust_plan | rooted |
| Listener / ingress establishment | THM-0077, THM-0074 | tls_listener_state, serving_identity_provenance | rooted |
| Request identity and classification | THM-0074 | request_envelope, outstanding_id_provenance | rooted — consequence over-reaches (§1.3) |
| Message verification | THM-0074/0075/0076 | verifier_results, verifier_result_separation, freshness_window, keyid, keyid_selector | rooted |
| Trust / identity | THM-0074, THM-0077 | trust_plan, serving_trust_seam, trust_configuration_state | rooted — terminal is ASM-0029 (§5.2) |
| Admission | THM-0074, THM-0077 | admission_assertion, admission_currency, replay_key | rooted |
| Authorization | THM-0074, THM-0078 | pdp_decision_authentication, pdp_decision_relation, authorization_posture | rooted |
| **Replay / continuation** | THM-0074 | continuation_unbypassability, continuation_binding, replay_key | **GAP** — the *stores* (`async_replay/` 8 files, `continuation_store/`, `redis_*_store.rs`, `etcd_store.rs`) are in no unit. The durability-tier fail-closed claim has no theorem. |
| Backend dispatch | THM-0074 | dispatch_commitment, exchange_lifecycle | rooted |
| Response / refusal emission | THM-0075, THM-0078 | response_signing, response_emission_binding, refusal_provenance, refusal_site_totality, delegated_signing_credential | rooted |
| Client response acceptance | THM-0076 | response_acceptance, trust_manifest_lifecycle, delegation_policy_seal, execution_contract, proxy_request_correspondence | rooted — for the Rust client proxy only |
| **Audit / retained evidence / transparency** | THM-0071, THM-0042, THM-0072 | audit_record_coordinates, audit_delivery, refusal_audit_emission, scitt_* | **GAP** — `mcp-re-proxy/src/transparency/` (6 files, 1,527 lines), the reservation/marker authority, is in no unit. Nothing claims a `.pending` marker exists only for an exchange that crossed the threshold. |
| Runtime lifecycle / shutdown | THM-0012, THM-0071 | runtime_lifecycle, audit_delivery | rooted |
| **Outbound credential acquisition** — KMS/STS endpoint authority, metadata token, IRSA exchange, PKCS#11, remote signer | — | none | **GAP** — `kms_endpoint_policy/`, `kms_keysource/`, `aws_sts.rs`, `gcp_kms_keysource.rs`, `pkcs11_keysource/`, `remote_signer_call/`, `outbound_fetch/`. THM-0064/0082 cover exposure and provenance, not acquisition. The R9 critical lived here. |
| **Client sidecar local ingress** | — | none | **GAP** — `mcp-re-client/src/serve/` (10 files) and `config/` |
| **SDK client exchange** | — | none | **GAP** — THM-0076 names the Rust client proxy; the SDKs are outside every root with no out-of-scope declaration |
| **Deployment rendering** | — | none | **GAP** — plausibly legitimately out of scope, but undeclared; carries a shipped fail-open (R9-C015) |

Two further wholly-uncovered crates worth a decision rather than a finding:
`mcp-re-transport` (9 files) and `mcp-re-policy` (6 files) have no unit at all.
`mcp-re-policy` is where `PolicyError` lives, and ADR-MCPRE-066's whole point is that its
vocabulary is a second authority.

### 4.1 What the R9 re-derivation established about this section

**59 of the 96 surviving historical clusters land in areas with no theorem or root
representation.** That is the strongest single result in the packet, because it is not a
statement about code quality:

```text
old security finding
        ↓
current code still has the relevant behaviour
        ↓
no theorem or root can even express why it matters
        ↓
ASSURANCE-ARCHITECTURE GAP
```

---

## 5. Assumption / TCB closure

Resolved through `scope → unit → theorem → root`. Foreign and primitive assumptions are
**not** flagged merely for being unproved.

### 5.1 Inventory

| Assumption | Class | Scoped units | Roots reached | Note |
|---|---|---|---|---|
| ASM-0001 | MCP_RE_INTERNAL_PROOF_DEVICE | core.time_rfc3339 | none | `external_body` on MCP-RE's own `parse_fixed_digits`. Outside every root because THM-0002 is (§6.2). |
| ASM-0002/3 | TOOL_PROOF_BOUNDARY | core.time_rfc3339 | none | vstd specs for `is_ascii_digit`, `split_last`. |
| ASM-0004 | TOOL_PROOF_BOUNDARY | core.time_rfc3339 | none | `McpReError` nameable without verifying its derived Display. |
| ASM-0005/6/10 | TOOL_PROOF_BOUNDARY | freshness_window | 0074, 0075, 0076 | Saturating i64 arithmetic; `Option::as_deref` totality. |
| ASM-0007/8/9 | MCP_RE_INTERNAL_PROOF_DEVICE | freshness_window | 0074, 0075, 0076 | **FLAG** — `external_body` on MCP-RE's own `VerifierPolicy` accessors. Dischargeable in principle; terminal to three roots today. |
| ASM-0011 | MCP_RE_INTERNAL_PROOF_DEVICE | admission_currency | 0074, 0077 | `AdmissionBinding::matches_state` opaque. |
| ASM-0012 | MCP_RE_INTERNAL_PROOF_DEVICE | admission_currency | 0074, 0077 | **FLAG** — `verify_admission_assertion` is opaque and contributes *no* postcondition. Two roots' admission-currency closure trusts MCP-RE's own assertion verification with no local theorem discharging it. |
| ASM-0013/14 | TOOL_PROOF_BOUNDARY | admission_currency | 0074, 0077 | Opaque datatype; derived `PartialEq` structural. |
| ASM-0015 | UNUSED / WITHDRAWN | — | none | RESERVED — retired rather than reused, correctly. |
| ASM-0016, ASM-0017 | — | — | — | **DEFECT** — present nowhere in the tree (§2.6). |
| ASM-0018/19 | MCP_RE_INTERNAL_PROOF_DEVICE | artifact_typing | 0074 | **FLAG** — `ArtifactBinding::validate` opaque; the typing theorem holds whatever it returns. |
| ASM-0020 | TOOL_PROOF_BOUNDARY | artifact_typing | 0074 | Derived `PartialEq` structural. |
| ASM-0021 | MCP_RE_INTERNAL_PROOF_DEVICE | continuation_unbypassability | 0074 | **FLAG** — `ActorIdentity::actor_id` opaque, NO ensures. Combined with per-file registration granularity (R9-C037/C067/C068), one justified hatch licenses every future site in `verify.rs`. |
| ASM-0022 | UNUSED / WITHDRAWN | — | none | Discharged by `continuation_binding`; kept marked withdrawn, correctly. |
| ASM-0023 | MCP_RE_INTERNAL_PROOF_DEVICE | continuation_binding | 0074 | Deliberately declines to assume domain separation; that refusal stands. |
| ASM-0024/25/26 | MCP_RE_INTERNAL_PROOF_DEVICE | 5 units | 0074, 0075, 0076, 0077 | `verus:uninterp` declarations. Now declared on both sides (§2.3). Widest reach: 13 theorems, 4 roots. |
| ASM-0027/0028 | CRYPTOGRAPHIC_PRIMITIVE | verifier_results | 0074, 0075, 0076 | Ed25519 unforgeability; SHA-256 second-preimage. Correctly not demanded to be proved. |
| ASM-0029 | MCP_RE_INTERNAL_PROOF_DEVICE | verifier_results | 0074, 0075, 0076 | **FLAG — the largest one**, §5.2. |
| ASM-0030 | FOREIGN_IMPLEMENTATION | certificate_identity, credential_currency | 0074 | **PROVISIONAL SCOPE** — §2.5. Owner normalization required. |
| ASM-0031 | FOREIGN_IMPLEMENTATION | ed25519_public_key | 0075, 0077 | SPKI parser faithfulness. |
| ASM-0032 | FOREIGN_IMPLEMENTATION | credential_key_correspondence, delegated_resolver_materialization | 0075, 0077 | **PROVISIONAL SCOPE** — §2.5. Owner normalization required. |
| ASM-0033…0036 | FOREIGN_IMPLEMENTATION | channel_associated_credential, channel_associated_identity, mechanism_verified_credential, authenticated_relationship_peer | 0074 | rustls establishment reporting. Correctly not demanded to be proved. |
| ASM-0037 | CRYPTOGRAPHIC_PRIMITIVE | keyid_selector | 0074 | Corrected (§2.3). The only assumption carrying a `boundary://` coordinate. |

### 5.2 ASM-0029 — the trust seam

"The trust seam answers its SELECTOR correctly" is a behavioural assumption about MCP-RE's
**own** resolver, mechanism `none:trusted-seam`, terminal under **three of nine roots**
(THM-0074, THM-0075, THM-0076). THM-0016's scope names it honestly; **THM-0074's security
consequence does not mention it at all** — so the honesty exists one level down and is lost
at the root a reader quotes.

### 5.3 Graph-integrity defects

1. **Bidirectional declaration drift** — nine instances, corrected, gated. **CLOSED**
2. **ASM-0016 / ASM-0017 missing** — no record of allocation or withdrawal. **OPEN**
3. **ASM-0030 / ASM-0032 scope exceeds wording** — provisional. **OWNER (§11.A)**
4. **A root consequence that does not mention its own terminal** (§5.2). **OPEN**
5. **The duplication ADR-MCPRE-059 §8 forbids is still in the schema.** The gate keeps the
   two halves consistent; it does not remove the second authority. **OWNER (§11.B)**

---

## 6. Theorem-level findings

### 6.1 THM-0042 omits `submitted_commitment` — a root possibly declared complete around an incomplete proposition

THM-0042's statement enumerates what `corresponds_to` compares: request evidence, response
evidence, chain commitment, chain label, bindings commitment, verified-context commitment.
It does **not** mention `submitted_commitment`, which the owner's own code calls "the only
field that covers the hops AFTER the verified prefix" and which exists specifically to stop
an archivist presenting `[h0, h1, h2']` for a statement about `[h0, h1, h2-tampered]`.

Its `scope` sentence does not declare the omission either. Six historical clusters land in
it (R9-C029, C074, C075, C103, C105, C128), covering three distinct residual behaviours:

- the digest folds only status, method, target-URI, request body, response body and headers
  named exactly `signature` — `signature-input`, `content-digest` and `mcp-re-delegation`
  are excluded (`chain/mod.rs:202`);
- `corresponds_to` refuses outright when either side has no verified hop, *before* the
  submission comparison, so the field is unreachable for the records it identifies;
- the both-empty case falls through to `Ok(())`, indistinguishable from a fully bound
  match, while `submitted_commitment` is copied verbatim from the caller-supplied
  reconstruction (`commitment/mod.rs:129`).

This is a statement-completeness question about an existing root, not theorem-count
inflation. It should be examined before T6 is called closed (§11).

### 6.2 The three theorems outside the root closure

None is connected here, and none is proposed for connection merely because it is
unreachable.

**THM-0002 — RFC 3339 parsing is total and range-bounded → `INTENTIONAL_AUXILIARY_CLAIM`.**
`parse_rfc3339_utc` has exactly one production caller in the tree: `aws_sts.rs:728`, parsing
the STS credential expiry. The RFC 9421 profile uses integer `created`/`expires` seconds and
never touches it. Not a missing root edge — a true lemma whose one consumer sits in the
*outbound credential acquisition* area §4 shows has no root. If that root is declared,
THM-0002 joins its closure naturally. It carries ASM-0001…0004, which sit outside every root
closure with it.

**THM-0017 — unbound response-floor verification →
`PUBLIC_API_SECURITY_CLAIM_OUTSIDE_ROOT_SET`.** Characterises the *non-delegated* unbound
operation. The client root reaches unbound receipts via THM-0076 → THM-0059 → THM-0020/0022,
and THM-0022 already covers what both unbound operations share. Response signing is
delegated-required (ADR-MCPRE-052), so no shipped root path reaches it.

**THM-0018 — full bound response verification →
`PUBLIC_API_SECURITY_CLAIM_OUTSIDE_ROOT_SET`.** Same shape one level up. THM-0058 depends on
THM-0016 and THM-0019 (the *delegated* bound operation). THM-0018's statement carries real
content THM-0019 does not restate — the `request_evidence` handle derived at the boundary
rather than supplied as a second operand, so `request A + handle B` is unconstructible —
which is why it should not be folded in.

A true theorem outside the system-root closure is an allowed state. The recommendation is to
record that all three are deliberately outside it, so the graph says so rather than leaving
them looking like an oversight.

---

## 7. Stale and contradictory claim documents

**`docs/spec/security-boundary.md` — the signed honesty gate. Most severe.**

1. §1 caps the claim at "production-hardened for single-node Rust-native deployments"
   because replay protection is a local file-backed cache. The tree ships shared Redis
   replay, a multi-node tier ladder and a live two-node GKE proof. §8 licenses the
   multi-node claim without amending §1, so the document contradicts itself.
2. §2 forbids as NOT PROVIDED four capabilities that now ship — HSM/KMS signing (GCP KMS,
   AWS KMS, PKCS#11), reverse-proxy mTLS / enterprise ingress (ADR-063), horizontal-scale
   replay (licensed by §8 but not struck from §2), client-side remote transport. "None of
   these is partially delivered" sits directly under the table.
3. §4 — "the complete positive claim surface" — **is the JCS/object profile.** It opens
   with Ed25519-over-JCS signing the complete JSON-RPC object, describes the 12-step
   pipeline, and cites ADR-MCPS-003/004/006/009/013/014/015. `CURRENT_ARCHITECTURE.md`
   declares that profile dead. Since §6 says "the only sanctioned positive claim is §1's
   exact wording plus the surface enumerated in §4", the document read literally forbids
   every claim the product currently makes and sanctions claims about a carrier that no
   longer exists.
4. §§9 and 11 **are** current and accurate — audit vocabulary through ADR-066 Slice 2, and
   the strict-mode ingress postures through v0.16 with Mode C honestly marked
   specified-not-delivered. The document is not uniformly stale, which is the worst state
   for an honesty gate to be in.
5. The sign-offs are the live problem. §7 (2026-05-30), §8.1 (2026-06-15) and §10
   (2026-06-23) are owner ratifications of text that no longer describes the product, and
   no later event has re-ratified them.

**`docs/spec/v0.5-claim-matrix.md` — the evidence spine.** Carries a 2026-07-15 currency
banner promising regeneration "next PRD"; that has not happened across
ADR-063/065/066/067. §A still classifies Delegation/authorization binding as "coverage
**Partial** — Core binds, the AuthorizationProfile interprets", citing ADR-MCPS-013 —
superseded by ADR-065, and `--authz reference` is now refused at validation. §B withdraws
the response-signing identity axis correctly and in detail, which shows the file is
maintained *selectively* and makes the unmaintained rows harder to spot. README routes
reviewers here as item 3 of 7.

**`docs/spec/threat-coverage-matrix.md`.** Derived from §A by construction, with a human as
the propagation mechanism; it has not run since 2026-07-15. Still reports the
confused-deputy row as Partial, has no row for any ADR-063/065/066 threat, and four current
threats have no row at all.

**`README.md`.** "Current implementation claim" stops at v0.12.1; ADR-063, ADR-065 and
ADR-066 are absent. "What MCP-RE does not yet claim" states HSM/KMS, CRL/OCSP,
horizontal-scale replay, OS sandboxing and signed tool manifests "are gated on the
`pkcs11_keysource,redis_replay,online_ocsp` cargo features… not linked into the lean
default build" — a build fact stated as a claim boundary, three sections below a paragraph
asserting HSM/KMS-rooted delegated signing as delivered. Two readings of "not claimed",
both in use.

**Correctly handled, as the pattern to copy:** `docs/spec/v0.3-claim-matrix.md` and
`docs/SECURITY_BOUNDARY.md` are redirect stubs that state their own supersession and forbid
claim wording being added.

---

## 8. Proof-strength distribution

| Class | Units |
|---|---|
| V0 | 54 |
| V1 (Verus) | 6 |
| V2 | 0 |
| V3 | 0 |

V1: `core.time_rfc3339`, `http_profile.freshness_window`, `admission_currency`,
`artifact_typing`, `continuation_unbypassability`, `continuation_binding`. The Lean lane is
`NOT_REQUIRED` — no V2/V3 unit is declared, and per the #541 pilot the pinned extraction
image cannot run Lean at all, so V2 is not currently reachable regardless of selection.

**This section is planning input for #541/#543 AFTER completeness is settled.** It is
reported, not acted on. Candidates, ranked by risk reduced rather than by tool reach:

1. **ASM-0029, the trust seam's selector correctness.** Terminal under three of nine roots,
   MCP-RE-owned, today an unproved behavioural assumption. Discharging even part of it
   moves more risk than any other single node, and it is the one whose absence a reader of
   THM-0074's consequence cannot see.
2. **ASM-0012, `verify_admission_assertion`.** Opaque, no postcondition, terminal under
   THM-0074 and THM-0077. `admission_currency` is already V1, so the prover already runs
   over this crate — the smallest step from an existing lane to a materially stronger claim.
3. **`http_profile.replay_key` (THM-0079).** Separator-injectivity is the shape Verus
   handles well, and it carries a root's replay claim at V0 with test evidence only.
4. **`http_profile.keyid` (THM-0055).** Declared `lean-candidate`, carries no assumption,
   pure byte-level argument. The obstacle is the toolchain, not the target.
5. **ASM-0021, `ActorIdentity::actor_id`.** Ranked here because its risk is amplified by a
   *platform* defect (per-file registration granularity) rather than its own content —
   fixing the granularity is cheaper and reduces more.

Deliberately **not** ranked: the four `core.time_rfc3339` assumptions. Already V1, already
proved as far as the pilot goes, reaching no root — ranking them would be selecting a node
because the tool can process it.

---

## 9. Assurance-platform defects

One closed this session, twelve open. These are defects in the machinery that produces
evidence, not in the product.

1. **Bidirectional assumption-declaration drift — CLOSED** (§2).
2. **The bundle survives a failed run** (R9-C023/C071). `verify` returns 1 before
   `write_bundle`, so `attest` reads the previous run's aggregate. This undermines the
   pipeline's central separation — the thing that DECIDES pass is never the thing that
   STAMPS freshness — and is the first one to fix.
3. **`trust-boundaries.toml` is in no fingerprint** (C005/C041). Widening a class cap
   invalidates nothing.
4. **Escape-hatch registration is per (kind, unit), not per site** (C037/C067/C068).
5. **The deleted-specification detector accepts prose** (C002/C038). The sole reader of "is
   the specification still there", satisfied by the word *ensures* in a doc comment.
6. **Prover and solver identity** (C069/C070/C083). A deleted lock table is not an
   unresolved pin; `VERUS_Z3_PATH` is inherited from the environment; `rust_verify`, `z3`
   and `libvstd.rlib` are undigested, the last with its recorded digest in a `note` key the
   fingerprint strips.
7. **Build configuration omits the proof-dependency closure's manifests** (C039/C040).
8. **Boundary cap checked against declared paths, not the measured cone** (C022).
9. **UNAVAILABLE is unreachable from the Verus lane** (C114).
10. **Undeclared `verification/` files are unregisterable** (C120); the FAIL text names a
    remedy that does not exist for them.
11. **Fork PRs: guard in an attacker-writable file; skipped job reports green**
    (C025/C055). Partly an Actions-settings decision.
12. **ASM-0016 / ASM-0017 have no record** (§2.6).
13. **ADR-MCPRE-059 §8's own duplication** (§11.B).

---

## 10. R9 disposition appendix — evidence, not a work plan

All 131 historical clusters from `work/security-audit-2026-08-11-r9` (gitignored),
re-derived against `8551061c`. The round-9 set was `unreviewed` across the board — Stage 3
never ran — so nothing here inherits a prior verdict.

| Disposition | Count |
|---|---|
| `FIXED_AND_COVERED` | 23 |
| `SURVIVES_AND_MAPPED` | 96 |
| `SUPERSEDED_BY_ARCHITECTURE` | 4 |
| `NO_LONGER_REPRODUCES` | 8 |
| `OUT_OF_SCOPE` | 0 |

> **The 96 are not 96 issues, and this table must not become 96 tickets.** They are 96
> clusters whose *claim still holds against the current tree*. Many are duplicate
> descriptions of one defect — R9-C006/C007/C032/C042/C045/C046 are one defect reported six
> times — and others are low-severity observations, documentation inconsistencies, or
> properties that may end up outside the MCP-RE security claim entirely. **The aggregation
> into semantic areas below is the useful output; the rows are the evidence behind it.**

| Area | Surviving + fixed | What the area is |
|---|---|---|
| `assurance-platform` | 28 | §9 |
| `scitt-retained-evidence` | 17 | §6.1 — most land in THM-0042's omission |
| `credential-acquisition` | 12 | §4 GAP — the R9 critical, now fixed in code |
| `tls-listener-and-revocation` | 12 | mostly superseded by ADR-062; CRL reload staleness survives |
| `serving-body-shape` | 11 | §1.3 — one defect, six duplicate rows |
| `deployment-rendering` | 11 | §4 GAP — includes a shipped fail-open |
| `sdk-client-exchange` | 10 | §4 GAP |
| `retention-marker` | 7 | §4 GAP |
| `exchange-lifecycle` | 7 | anomaly latch unread on success terminals |
| `client-proxy-and-sidecar` | 6 | §4 GAP — DNS rebinding, `bound` omission |
| `audit-delivery` | 5 | counter underflow fixed; drain precision survives |
| `cli-boundary` | 3 | two fixed at the validation boundary |
| `retry-contract` | 2 | both no longer reproduce |

**Bounded-coverage admission.** R9-C035 and R9-C065 were re-derived only as far as the
corpus writers. The byte-for-byte comparison between `interop/signed-statement.cbor` and
the committed `s01` statement was **not** performed. They are dispositioned on the strength
of C104, which is independently confirmed; the residual measurement is owed. Silent
truncation would read as completeness, so it is stated.

### 10.1 What this satisfies in #542

#542's criterion "every R9 cluster re-derived against current main with a written
disposition" is met. Three of its named negative controls, explicitly:

- **A cluster that no longer reproduces is recorded with the reason, not silently
  dropped.** Eight; six because a named function or module was deleted, one because the
  gate it named is now green, one because a doc line was corrected.
- **A dependency the audit discovers is a graph defect as well as a code defect.** The 59
  clusters landing in un-rooted areas are recorded in §4.1 as architecture gaps, not only
  as local bugs.
- **A cluster mapping to no node is a finding about the tree.** Every "no THM" node value
  is one, and they aggregate into §4's areas rather than being filed as owner-local.

### 10.2 The table

The record is [`verification/reviews/r9-dispositions.json`](../r9-dispositions.json), and it
is the single authority for which cluster belongs to which workstream — #542 tracks the ten
workstreams and deliberately keeps no second copy of the row map. The table below is
**generated** from the record by `tools/verification/render-r9-dispositions`, which also has
a `--check` mode. Edit the JSON, not the table.

**`Disposition` and `Owner now` are different facts, and the second never rewrites the
first.** A disposition is the measurement taken on 2026-08-31: `SURVIVES_AND_MAPPED` says
the claim *survived that re-derivation*, permanently. Whether the row is *currently
unresolved* is the `Owner now` column — the workstream issue that owns it, or the change
that has since closed it. Rewriting a disposition because later work closed the finding
would destroy the audit's own record of what it found.

A closure is typed (`pr`, `commit`, `note`) and **means merged**: `--check` requires the
recorded commit to be an ancestor of HEAD in the local clone. `R9-C074`/`C075` were once
recorded as closed by a pull request that was green and *open*, and prose could not tell the
difference — the evidence for "merged" was a sentence saying so. They went back to their
owning issue until #736 actually merged, and carry a typed closure now; the round trip is
what the control is for. No network is consulted;
PR state is remote and mutable, while a merge commit reachable from HEAD is the durable
local fact, and it is the one that means the change is in the tree being measured.

<!-- BEGIN GENERATED: r9-dispositions -->

| Cluster | Sev | Area | Round-9 title | Disposition | Node | Re-derivation against current main | Owner now |
|---|---|---|---|---|---|---|---|
| R9-C001 | critical | `credential-acquisition` | GCP Cloud KMS endpoint authority is never checked: userinfo re-points the root-key bootstrap and bearer token | `FIXED_AND_COVERED` | THM-0074 / kms_endpoint_policy | `kms_endpoint_policy::kms_endpoint_authority` is now the single decision, applied at GCP (`gcp_kms_keysource.rs:611`), AWS-KMS, STS and the config boundary. The three-flag asymmetry is gone. | #742 |
| R9-C002 | high | `assurance-platform` | Deleted-specification control accepts prose: SPECIFICATION_TEXT is searched over comments too | `SURVIVES_AND_MAPPED` | assurance platform (no THM) | `check-assumptions:312` still folds comment lines into the attribute block and `SPECIFICATION_TEXT` (`:138`) is still a bare `\bensures\b\|\brequires\b` searched over it at `:360`. A doc comment still satisfies the deleted-specification detector. | closed by #756 (`5164b3944852`) |
| R9-C003 | high | `assurance-platform` | required_lanes widening made every attestation un-issuable: attest refuses all 8 units | `FIXED_AND_COVERED` | assurance platform | `attest` now loads `('test','verus','lean','mutation')`; the test-evidence lane exists and writes records. | — |
| R9-C004 | high | `retention-marker` | NotDispatched leaves a permanent retention marker for a request that never reached a backend | `SURVIVES_AND_MAPPED` | THM-0045 / proxy.dispatch_commitment | `commit_to_dispatch` reserves last, closing the `admit()` ordering — but `dispatch()` still returns `NotDispatched` for the in-flight bound (`http_inner:486`) and all-ejected (`:495`), refused at `inner_plane.rs:99/151` after the reservation, dropping the disposition with no release. | closed by #760 (`6fea87b69734`) |
| R9-C005 | high | `assurance-platform` | trust-boundaries.toml became a gate but participates in no ReviewFingerprint — turning the cap off invalidates nothing | `SURVIVES_AND_MAPPED` | assurance platform | `trust-boundaries.toml` appears in no `_fingerprint.py` component. Raising or deleting `max_class_without_assumption` still invalidates nothing. | closed by #756 (`5164b3944852`) |
| R9-C006 | high | `serving-body-shape` | reject_unrepresentable_json is enforced after the nonce burn and after the continuation is consumed | `SURVIVES_AND_MAPPED` | THM-0083 / http_profile.request_envelope | `reject_unrepresentable_json` still runs inside `body_boundary::prepare` at `forward_body_stage`, i.e. after the nonce burn, after continuation retirement, after `request.accepted`. | closed by #733 (`e6496173fc77`) |
| R9-C007 | high | `serving-body-shape` | The body-representability refusal runs after the nonce burn and the continuation retirement, unlike its sibling | `SURVIVES_AND_MAPPED` | THM-0083 | Same site. `validate_request_envelope` does not call it; the sibling shape refusal is still one region late and still `Refusal::after_admission(e, 500)`. | closed by #733 (`e6496173fc77`) |
| R9-C008 | high | `tls-listener-and-revocation` | chain_issuers_within_validity refuses chains the handshake admits (unused presented certs, pinned-intermediate anchors) | `NO_LONGER_REPRODUCES` | — | `chain_issuers_within_validity` no longer exists in the tree. | — |
| R9-C009 | high | `tls-listener-and-revocation` | chain_issuers_within_validity judges the presented chain, not the built path | `NO_LONGER_REPRODUCES` | — | Same function removed. Certificate currency now has a semantic owner, `proxy.credential_currency` / THM-0032. | — |
| R9-C010 | high | `sdk-client-exchange` | Python mTLS aggregate read deadline never fires: `response.read(64 KiB)` blocks past it | `SURVIVES_AND_MAPPED` | no THM (SDK unrooted) | `_read_bounded` checks the deadline only between `response.read(want)` calls with `want` up to 64 KiB; `http.client` fills to `amt`. The docstring's cap claim is still false. | closed by #792 (`fdc154a82d75`) |
| R9-C011 | high | `sdk-client-exchange` | Python SDK's new "aggregate response read" deadline is inert — http.client read(n) blocks until n bytes | `SURVIVES_AND_MAPPED` | no THM | Same defect, same lines. | closed by #792 (`fdc154a82d75`) |
| R9-C012 | high | `deployment-rendering` | CodeBuild pre_build refuses `.claude`, which `git archive HEAD` always emits (it is tracked) | `SURVIVES_AND_MAPPED` | no THM | `deploy/codebuild/mcp-re-slo-bench.yaml:157` still refuses `.claude`; `git ls-files .claude` still returns tracked files; the documented upload is still `git archive HEAD`. | closed by #749 (`eef0f95271ca`) |
| R9-C013 | high | `deployment-rendering` | CodeBuild guard refuses `.claude`, but `.claude/**` is TRACKED so every `git archive HEAD` upload fails pre_build | `SURVIVES_AND_MAPPED` | no THM | Same guard, same tracked files. Every correctly-produced source zip still aborts pre_build. | closed by #749 (`eef0f95271ca`) |
| R9-C014 | high | `deployment-rendering` | New credential exclusions landed in .gcloudignore only; .dockerignore and the parity gate were not extended | `SURVIVES_AND_MAPPED` | no THM | `.dockerignore` still carries none of `.claude/`, `**/.claude/`, `.vscode/`, `.idea/`, `.verification/`; `REQUIRED_UPLOAD_EXCLUSIONS` still lists none of them, so the parity gate is blind. | closed by #749 (`eef0f95271ca`) |
| R9-C015 | high | `deployment-rendering` | Helm plaintext-Redis de-fleet-gating skipped the admission-currency hop; values.yaml over-claims | `SURVIVES_AND_MAPPED` | no THM | `deployment.yaml:18` still reads `and .Values.fleet …`. The two sibling refusals in `_helpers.tpl:128-135` are fleet-independent and argue in comments that the hazard is independent of replica count. | closed by #749 (`eef0f95271ca`) |
| R9-C016 | high | `tls-listener-and-revocation` | Round-8 'epoch is now live' fix has no live input: anchors are startup-frozen, so republish() always returns None | `SUPERSEDED_BY_ARCHITECTURE` | THM-0048 / proxy.tls_listener_state | ADR-MCPRE-062 replaced epoch advancement with immutable-listener / store-replacement. `tls_listener_state/mod.rs:29` now states proposition 2 as established by *nothing*, and names proposition 3 as the protection. | — |
| R9-C017 | high | `credential-acquisition` | Endpoint userinfo re-point closed only for --aws-kms-endpoint; STS and GCP endpoints still re-point | `FIXED_AND_COVERED` | THM-0074 / kms_endpoint_policy | One authority, three flags. | #742 |
| R9-C018 | high | `credential-acquisition` | validated_kms_endpoint's loopback check is defeated by URL userinfo; the GCP KMS path has no second gate | `FIXED_AND_COVERED` | kms_endpoint_policy | `kms_endpoint_policy/mod.rs:97` refuses userinfo explicitly, before any loopback reading. | #742 |
| R9-C019 | high | `sdk-client-exchange` | Python SDK's new "aggregate" response-read deadline bounds nothing; its test stub ignores the read size | `SURVIVES_AND_MAPPED` | no THM | Unchanged. | closed by #792 (`fdc154a82d75`) |
| R9-C020 | high | `sdk-client-exchange` | Python SDK aggregate response-read deadline is inert; its test uses a reader http.client never behaves like | `SURVIVES_AND_MAPPED` | no THM | Unchanged; the TypeScript twin is still bounded and Python is not. | closed by #792 (`fdc154a82d75`) |
| R9-C021 | high | `retention-marker` | Ladder reorder puts an await between admit() and dispatch(), re-opening the durable-marker leak it closed | `SURVIVES_AND_MAPPED` | THM-0045 | The awaited durable write is now `retention.reserve` between `inner_async.admit()` and `dispatch()`. The capacity check and the permit acquisition are still separated by an await. | closed by #759 (`c83030763d95`) |
| R9-C022 | high | `assurance-platform` | Boundary class cap is checked against declared paths while the proof cone is the whole crate plus its closure | `SURVIVES_AND_MAPPED` | assurance platform | `boundary_class_violations` still decides on `expand_paths(unit['paths'])` while the measured cone is the crate plus its path-dependency closure. | #739 |
| R9-C023 | high | `assurance-platform` | attest gates issuance on a bundle.json no completed run has to have written | `SURVIVES_AND_MAPPED` | assurance platform | `verify:196` returns 1 before `write_bundle` at `:249`. A failed run leaves the previous bundle, and `attest` reads it as the last run's aggregate. | closed by #751 (`07a2df277358`) |
| R9-C024 | high | `assurance-platform` | attest can never issue: required_lanes widened to every scheme, attest still loads only verus/lean | `FIXED_AND_COVERED` | assurance platform | Four lanes loaded. | — |
| R9-C025 | high | `assurance-platform` | Fork-PR guard lives in the file a fork PR controls: pull_request runs the head's verification.yml | `SURVIVES_AND_MAPPED` | assurance platform | The guard is still an `if:` at `verification.yml:322/375` in the file a fork PR's merge ref supplies. Closing it is an Actions-settings decision, not a code one. | #739 |
| R9-C026 | high | `deployment-rendering` | Plaintext-Redis widening skipped the admission-currency hop: deployment.yaml:18 still requires fleet=true | `SURVIVES_AND_MAPPED` | no THM | Same as C015. | closed by #749 (`eef0f95271ca`) |
| R9-C027 | high | `deployment-rendering` | .dockerignore missed round 8's .claude/.verification excludes; Dockerfile.bench is single-stage | `SURVIVES_AND_MAPPED` | no THM | Same as C014. | closed by #749 (`eef0f95271ca`) |
| R9-C028 | high | `serving-body-shape` | Round-8 decimal rule refuses ordinary round-trip f64 values, killing signed replies after the tool ran | `SURVIVES_AND_MAPPED` | THM-0083 (adjacent) | `EXACTLY_CARRIED_DECIMAL_DIGITS = 15` still refuses 16–17-significant-digit shortest-round-trip forms, which are exactly what ryu emits for computed f64s and which round-trip exactly. | closed by #750 (`d34aa49d`) |
| R9-C029 | high | `scitt-retained-evidence` | verify_retained_evidence returns Ok on the both-empty submission case; round-8 vector now pins that path | `SURVIVES_AND_MAPPED` | THM-0042 (root) | `corresponds_to` still falls through to `Ok(())` when neither side identifies a submission, and `submitted_commitment` is still copied verbatim from the caller-supplied reconstruction (`commitment/mod.rs:129`). | closed by #733 (`e6496173fc77`) |
| R9-C030 | high | `tls-listener-and-revocation` | The trust epoch cannot advance in-process; round 8 removed the reload cache flush that replaced it | `SUPERSEDED_BY_ARCHITECTURE` | THM-0048 | See C016. | — |
| R9-C031 | high | `credential-acquisition` | STS endpoint authority is never checked either: userinfo sends the pod's IRSA token to an attacker host | `FIXED_AND_COVERED` | kms_endpoint_policy | `aws_sts.rs:258/461` now call the shared authority. | #742 |
| R9-C032 | medium | `serving-body-shape` | Body-fidelity refusal still runs after the nonce burn and the continuation consume | `SURVIVES_AND_MAPPED` | THM-0083 | Same as C006. | — |
| R9-C033 | medium | `deployment-rendering` | Helm drain invariant is unsound: round 8's 2s post-drain audit flush is not in the arithmetic | `SURVIVES_AND_MAPPED` | no THM | `_helpers.tpl:190` DRAIN INVARIANT is still `pre + proxyDrain < kubelet`, with no budget for the post-serve audit flush. | closed by #749 (`eef0f95271ca`) |
| R9-C034 | medium | `audit-delivery` | Audit occupancy counter incremented after the send: a drain can wrap it to usize::MAX and drop every record | `FIXED_AND_COVERED` | THM-0070 / proxy.audit_delivery | `offer` now reserves the slot before the send and releases it if the send fails, so the counter cannot underflow. | — |
| R9-C035 | medium | `scitt-retained-evidence` | SCITT interop corpus is a stale pre-submitted_commitment statement; the round-8 test asserts a false fact about it | `SURVIVES_AND_MAPPED` | THM-0042 | Re-derived only to the level of the corpus writers; the interop artefact/committed-statement byte comparison is still absent. Treat the residual measurement as owed. | closed by #733 (`e6496173fc77`) |
| R9-C036 | medium | `serving-body-shape` | reject_unrepresentable_json still admits subnormal decimals the composer rewrites inside the signed bytes | `SURVIVES_AND_MAPPED` | THM-0083 (adjacent) | `decimal_survives_the_f64_carrier` still admits any ≤15-significant-digit decimal; `is_finite()` and `value != 0.0` do not exclude subnormals, which carry far fewer digits. | — |
| R9-C037 | medium | `assurance-platform` | Per-unit registration is defeated by over-broad declared paths: ASM-0021 covers all of verify.rs | `SURVIVES_AND_MAPPED` | assurance platform | `is_registered` is still per (mechanism kind, unit) with no site, so one registration licenses every future site in every file the unit declares. | #739 |
| R9-C038 | medium | `assurance-platform` | The only detector for a deleted specification is satisfied by 'requires'/'ensures' in a doc comment | `SURVIVES_AND_MAPPED` | assurance platform | Same as C002. | closed by #756 (`5164b3944852`) |
| R9-C039 | medium | `assurance-platform` | Fingerprint covers dependency source but not dependency Cargo.toml, so the verify feature can change unseen | `SURVIVES_AND_MAPPED` | assurance platform | `_build_configuration` still digests only `WORKSPACE_BUILD_INPUTS` plus the unit's own crates' `Cargo.toml`; the proof-dependency closure's manifests participate in no component. | closed by #771 (`0758ae28fdb7`) |
| R9-C040 | medium | `assurance-platform` | build_configuration omits the manifests of the proof-dependency closure crates | `SURVIVES_AND_MAPPED` | assurance platform | Same measurement. | closed by #771 (`0758ae28fdb7`) |
| R9-C041 | medium | `assurance-platform` | trust-boundaries.toml became a gate but participates in no fingerprint, so widening a cap invalidates nothing | `SURVIVES_AND_MAPPED` | assurance platform | Same as C005. | closed by #756 (`5164b3944852`) |
| R9-C042 | medium | `serving-body-shape` | Duplicate-member refusal still runs at forward_body_stage, past the nonce burn and spent approval, as a 500 | `SURVIVES_AND_MAPPED` | THM-0083 | Same as C006. | — |
| R9-C043 | medium | `exchange-lifecycle` | Reorder decoupled the two ladder events from the work, so the release-active relation cannot see a re-swap | `SUPERSEDED_BY_ARCHITECTURE` | THM-0043 / proxy.exchange_lifecycle | `Established` / `progress.establish` now make the event derive from the value being consumed, so a stage cannot state an event it did not justify. The unconditional-literal shape is gone. | — |
| R9-C044 | medium | `exchange-lifecycle` | Notification arm still mints a signed 202 when the backend answered non-2xx (matches variant, not clause) | `SURVIVES_AND_MAPPED` | THM-0078 (root) | `observe_acknowledgement` still puts all of `InvalidUpstream` in the acknowledging arm, and `http_inner:391` still classifies a non-2xx as `InvalidUpstream`. A notification the backend refused is answered with a signed 202; the bodied arm answers 502. | — |
| R9-C045 | medium | `serving-body-shape` | New request-side body guard is wired after the nonce burn and approval spend, and blamed as a 500 | `SURVIVES_AND_MAPPED` | THM-0083 | Same as C006. | — |
| R9-C046 | medium | `serving-body-shape` | Request body-fidelity guard refuses after the nonce burn and approval spend, and maps a caller fault to 500 | `SURVIVES_AND_MAPPED` | THM-0083 | Same as C006. | — |
| R9-C047 | medium | `tls-listener-and-revocation` | chain_issuers_within_validity exempts on issuer==subject, not on anchor membership | `NO_LONGER_REPRODUCES` | — | Function removed. | — |
| R9-C048 | medium | `tls-listener-and-revocation` | The self-issued exemption is claimable by a cross-signed, non-anchor intermediate | `NO_LONGER_REPRODUCES` | — | Function removed. | — |
| R9-C049 | medium | `sdk-client-exchange` | Python SDK's new aggregate mTLS read deadline never fires — http.client blocks for the whole body in one read() | `SURVIVES_AND_MAPPED` | no THM | Unchanged. | closed by #792 (`fdc154a82d75`) |
| R9-C050 | medium | `deployment-rendering` | `.dockerignore` not updated with `.gcloudignore`'s new exclusions; the parity gate is blind to them | `SURVIVES_AND_MAPPED` | no THM | Same as C014. | closed by #749 (`eef0f95271ca`) |
| R9-C051 | medium | `deployment-rendering` | Plaintext-Redis refusal dropped `.Values.fleet` on two hops but not the admission-currency third | `SURVIVES_AND_MAPPED` | no THM | Same as C015. | closed by #749 (`eef0f95271ca`) |
| R9-C052 | medium | `tls-listener-and-revocation` | Delegated TLS sign budget has no operator surface: rate_per_sec/burst/refused have no callers | `SURVIVES_AND_MAPPED` | no THM | `rate_per_sec`, `burst` and `refused` still have exactly one caller, the unit test at `delegated_tls.rs:439`. No posture line emits a sign-budget field. | — |
| R9-C053 | medium | `assurance-platform` | Verification trigger widened to unit sources but not to the build inputs the fingerprint measures | `FIXED_AND_COVERED` | assurance platform | `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml` and the per-crate manifests are in the trigger set, and `scripts/verification_trigger_gate.py` derives the requirement from the manifest. | — |
| R9-C054 | medium | `assurance-platform` | Verification trigger widening omits the fingerprint's build inputs (Cargo.lock, rust-toolchain.toml, crate manifests) | `FIXED_AND_COVERED` | assurance platform | Same fix. | — |
| R9-C055 | medium | `assurance-platform` | Fork-PR guard is complete against RCE but yields a skipped-job green; no fork-safe verification lane replaces it | `SURVIVES_AND_MAPPED` | assurance platform | A skipped job still reports success, and nothing on the GitHub-hosted side runs any part of the lane for forks. | #739 |
| R9-C056 | medium | `assurance-platform` | verification.yml triggers omit the build inputs ENCODING_VERSION 3 added to every fingerprint | `FIXED_AND_COVERED` | assurance platform | Same fix. | — |
| R9-C057 | medium | `credential-acquisition` | GCP metadata single-flight serializes failing fetches, turning a 5s failure into a growing thread queue | `SURVIVES_AND_MAPPED` | no THM | `gcp_kms_keysource.rs:406` still takes `fetching` across the whole round trip with no negative caching, so waiters serialize their own full-timeout fetches. | — |
| R9-C058 | medium | `credential-acquisition` | New metadata-token single-flight has no failure path: 5s stalls now serialize across the TLS worker pool | `SURVIVES_AND_MAPPED` | no THM | Same lock, same absence of failure caching. | — |
| R9-C059 | medium | `credential-acquisition` | GCP metadata single-flight serializes failing fetches, starving every core's TLS handshake slots | `SURVIVES_AND_MAPPED` | no THM | Same. | — |
| R9-C060 | medium | `credential-acquisition` | Unknown-expiry floor pins a dead GCP token ~240s; doc claims it costs "one failed KMS call" | `FIXED_AND_COVERED` | no THM | `UNKNOWN_EXPIRY_REUSE` is now 120 s and the doc at `:84` states the window a caller actually sees; the revocation path is named at `:163`. | — |
| R9-C061 | medium | `sdk-client-exchange` | New Python `send_notification_verified()` runs outside the concurrency bound its TypeScript twin enforces | `SURVIVES_AND_MAPPED` | no THM (SDK unrooted) | `send_notification_verified`'s whole body is still `await _notify(...)` — no `CapacityLimiter`, no lifecycle or abort check. | #746 |
| R9-C062 | medium | `client-proxy-and-sidecar` | The Rust ambassador drops `bound` from the rejection it hands the local client; both SDKs emit `requestBound` | `SURVIVES_AND_MAPPED` | THM-0076 (root, client side) | `plain_error_from_rejection` still emits exactly wire_code + the four contract members; `bound` is not among them, while both SDKs emit `requestBound`. | — |
| R9-C063 | medium | `client-proxy-and-sidecar` | Ambassador never tells the local client whether a verified rejection was request-BOUND | `SURVIVES_AND_MAPPED` | THM-0076 | Same omission. | — |
| R9-C064 | medium | `audit-delivery` | Audit queue occupancy counter underflows to usize::MAX, opening a window where every audit record is dropped | `FIXED_AND_COVERED` | THM-0070 | See C034. | — |
| R9-C065 | medium | `scitt-retained-evidence` | The SCITT interop corpus is NOT the frozen s01 statement, and a round-8 test now pins the divergence | `SURVIVES_AND_MAPPED` | THM-0042 | See C035. | closed by #733 (`e6496173fc77`) |
| R9-C066 | medium | `exchange-lifecycle` | Release-active anomaly latch is unread on exactly the terminals its invariants can only be violated at | `SURVIVES_AND_MAPPED` | THM-0043 (root closure) | The latch's only production reader is `retry_semantics()`, reached only on refusal paths. Both success terminals still guard with `debug_assert!`, compiled out in release. | — |
| R9-C067 | medium | `assurance-platform` | Per-unit registration still whitelists future escape-hatch sites in every file the unit declares | `SURVIVES_AND_MAPPED` | assurance platform | Same as C037. | #739 |
| R9-C068 | medium | `assurance-platform` | Escape-hatch registration is per mechanism KIND: every declared file already reads 'registered' for external_body | `SURVIVES_AND_MAPPED` | assurance platform | Same as C037. | #739 |
| R9-C069 | medium | `assurance-platform` | An absent toolchain pin is not an unresolved pin: verify-verus runs with [rust] and [verus.z3] deleted | `SURVIVES_AND_MAPPED` | assurance platform | `REQUIRED & set(unresolved_pins(...))` still detects only entries that exist with `state = "unresolved"`; `unresolved_pins` iterates existing tables, so a deleted one is never reported. | #739 |
| R9-C070 | medium | `assurance-platform` | The solver has no measured identity and the lane inherits VERUS_Z3_PATH from the environment | `SURVIVES_AND_MAPPED` | assurance platform | `installed_identity` still digests only `vstd.vir` and `version.json`, and the lane still runs with `{**os.environ}`, so `VERUS_Z3_PATH` selects the solver undetected. | #739 |
| R9-C071 | medium | `assurance-platform` | verify exits before writing the evidence bundle, so attest consumes the previous run's aggregate | `SURVIVES_AND_MAPPED` | assurance platform | Same as C023. | closed by #751 (`07a2df277358`) |
| R9-C072 | medium | `assurance-platform` | Workflow path triggers miss the build inputs the new fingerprint measures, including the verify-feature Cargo.toml | `FIXED_AND_COVERED` | assurance platform | Same as C053. | — |
| R9-C073 | medium | `assurance-platform` | Widened trigger lands on a currently-red gate: most core PRs now fail on an unrelated manifest-policy error | `NO_LONGER_REPRODUCES` | — | `verify --manifests` is PASS on current main (measured this session, including after the ASM-0037 correction). | — |
| R9-C074 | medium | `scitt-retained-evidence` | submitted_commitment covers no header but `signature`, so tail substitution stays open via signature-input | `SURVIVES_AND_MAPPED` | THM-0042 (root) | `submitted_commitment` (`chain/mod.rs:202`) still folds only status, method, target-URI, request body, response body, and headers whose name is exactly `signature`. `signature-input`, `content-digest` and `mcp-re-delegation` are excluded. | closed by #736 (`eef36b63e1dd`) |
| R9-C075 | medium | `scitt-retained-evidence` | submitted_commitment omits every header but `signature`, leaving the tail substitution open | `SURVIVES_AND_MAPPED` | THM-0042 (root) | Same digest. The record's own doc still calls it the identity of what was submitted. | closed by #736 (`eef36b63e1dd`) |
| R9-C076 | medium | `cli-boundary` | --trust-domain non-emptiness is still enforced only in parse_args after its five siblings moved to the boundary | `FIXED_AND_COVERED` | THM-0077 (root) | `config_state/server_identity.rs::coordinate_violations` refuses an empty `--trust-domain` (and `--server-signer`) at the validation boundary. | — |
| R9-C077 | medium | `cli-boundary` | Three semantic refusals are still enforced only in parse_args after the round-8 boundary sweep | `SURVIVES_AND_MAPPED` | THM-0013 / proxy.online_ocsp_reachability | No `ocsp_responder_url` refusal exists in `config_state/`; the dangling-flag refusal is still argv-only, so a programmatic `Config` carries it into serving. | — |
| R9-C078 | medium | `retention-marker` | Both new retention APIs are unwired: nothing enumerates, releases or reclaims a .pending marker | `SURVIVES_AND_MAPPED` | no THM (transparency unrooted) | `release_before_dispatch` is called only from `durability.rs`'s own test; `pending_reservations` only from one proxy integration test. | closed by #760 (`6fea87b69734`) |
| R9-C079 | medium | `retention-marker` | release_before_dispatch() and pending_reservations() have no production caller — both are test-only | `SURVIVES_AND_MAPPED` | no THM | Same. | closed by #760 (`6fea87b69734`) |
| R9-C080 | medium | `retention-marker` | release_before_dispatch() and pending_reservations() have no production caller — R8-C093 is API-only | `SURVIVES_AND_MAPPED` | no THM | Same. | closed by #760 (`6fea87b69734`) |
| R9-C081 | medium | `retention-marker` | Inner-plane saturation still leaves a permanent retention marker when discovered at dispatch | `SURVIVES_AND_MAPPED` | THM-0045 | Same as C004. | closed by #759 (`c83030763d95`) |
| R9-C082 | medium | `assurance-platform` | Both new round-8 verification test files are wired into nothing and will never run | `FIXED_AND_COVERED` | assurance platform | `local_gate.sh:135-139` now runs `test_measured_inputs`, `test_escape_hatches`, `test_theorems` and `test_views`. | — |
| R9-C083 | medium | `assurance-platform` | Prover binaries stay unidentified; the libvstd.rlib digest sits in a note field the fingerprint strips | `SURVIVES_AND_MAPPED` | assurance platform | `rust_verify`, `z3`, `cargo-verus` and `libvstd.rlib` are still undigested, and `_toolchain_identity` still drops every `note` key, where the recorded rlib digest lives. | #739 |
| R9-C084 | medium | `scitt-retained-evidence` | verify_retained_evidence still returns a bare Ok when neither side identifies a submission | `SURVIVES_AND_MAPPED` | THM-0042 (root) | Same as C029. | closed by #733 (`e6496173fc77`) |
| R9-C085 | medium | `scitt-retained-evidence` | ScittServiceTrustPin.position_profile is still serde(default) = Unbound and both committed pins omit it | `SURVIVES_AND_MAPPED` | THM-0068 / http_profile.scitt_service_pin | `position_profile` is still `#[serde(default)]` at `trust_pin/document.rs:85`, defaulting to `Unbound`. | — |
| R9-C086 | medium | `scitt-retained-evidence` | Every trust pin in the tree defaults position_profile to Unbound; the Bound-from-a-pin path has zero coverage | `SURVIVES_AND_MAPPED` | THM-0068 | Same field; the Bound-from-a-pin path still has no committed artefact. | — |
| R9-C087 | medium | `serving-body-shape` | decimal_survives_the_f64_carrier admits subnormal decimals the carrier silently rewrites | `SURVIVES_AND_MAPPED` | THM-0083 (adjacent) | Same as C036. | — |
| R9-C088 | medium | `tls-listener-and-revocation` | max_connection_age doc still claims the age bound forces chain re-validation; async_serve.rs now says the opposite | `FIXED_AND_COVERED` | THM-0048 | `tls.rs:218` now says the age bound *bounds the exposure without ending it* — the chain-re-validation claim is gone. | — |
| R9-C089 | medium | `tls-listener-and-revocation` | Republished TLS auth epoch can never differ, so TB-06 eviction still has no live input | `SUPERSEDED_BY_ARCHITECTURE` | THM-0048 | See C016. | — |
| R9-C090 | medium | `cli-boundary` | --trust-epoch-key with no URL silently mints under the bare label the round-8 refusal names | `FIXED_AND_COVERED` | THM-0077 (root) | ADR-MCPRE-067 made the pair unrepresentable: the key coordinate now travels inside `TrustEpochSource`, and `config_state/trust_revocation.rs:372` records that the clause was deleted because no configuration can state it. | — |
| R9-C091 | medium | `credential-acquisition` | New GCP `fetching` mutex has no poison recovery and is held across I/O — one panic bricks KMS signing | `FIXED_AND_COVERED` | no THM | Both locks now recover poison with `unwrap_or_else(\|p\| p.into_inner())` (`:346`, `:406`). | — |
| R9-C092 | medium | `credential-acquisition` | Endpoint-authority refusal covers only the KMS client; STS and GCP endpoints still accept userinfo | `FIXED_AND_COVERED` | kms_endpoint_policy | See C001. | #742 |
| R9-C093 | medium | `client-proxy-and-sidecar` | `retry_is_refused()` treats an UNRECOGNIZED execution_status exactly like silence | `SURVIVES_AND_MAPPED` | THM-0061 / client.execution_contract | `retry_is_refused` is `!matches!(retry(), Unstated) \|\| matches!(execution(), PossiblyExecuted)`. An `ExecutionStatus::Unrecognized` with no `retry_safety` still returns false — the unknown disposition is resolved to the retry-safe side at the one accessor that decides a retry. | — |
| R9-C094 | medium | `sdk-client-exchange` | The Python test pinning the aggregate read bound uses a fake with short-read semantics http.client lacks | `SURVIVES_AND_MAPPED` | no THM | The fake's short-read semantics still differ from `http.client`, so the test passes over a property the production path lacks. | closed by #792 (`fdc154a82d75`) |
| R9-C095 | medium | `sdk-client-exchange` | TypeScript mTLS now aborts any response whose TOTAL download exceeds `timeoutMs`, not just an idle one | `SURVIVES_AND_MAPPED` | no THM | `timeoutMs` is still both the inactivity bound and the aggregate wall clock — now stated in the module doc at `:27`, so the conflation is honest but unresolved and there is still no second knob. | #746 |
| R9-C096 | medium | `client-proxy-and-sidecar` | `allow_any_host` wired from `allow_non_loopback` disables the rebinding guard even on a loopback bind | `SURVIVES_AND_MAPPED` | no THM (client sidecar unrooted) | `mcp-re-client/src/lib.rs:195` still wires `allow_any_host` from `allow_non_loopback`, and `config/validation.rs:30` still accepts the flag together with a loopback bind. | closed by #753 (`7ce84c95c35b`) |
| R9-C097 | medium | `audit-delivery` | flush_stderr_audit gives up instantly on a full queue — the one case it exists for — never spending its timeout | `SURVIVES_AND_MAPPED` | THM-0070 | `flush` still publishes with `try_send` and returns `OutcomeUnknown` immediately on a full queue, spending none of the timeout. THM-0070 admits *unknown* as its own case, so this is a precision gap rather than a false claim. | — |
| R9-C098 | medium | `scitt-retained-evidence` | SCITT pin guard compares only the key thumbprint, so a re-run silently downgrades position/leaf profile | `SURVIVES_AND_MAPPED` | THM-0068 | `scitt_fetch_service_key.py:423` still compares only `public_key_thumbprint`, so a re-run rewrites `position_profile` / `leaf_profile` with no acknowledgement. | — |
| R9-C099 | medium | `retention-marker` | A failed reserve() can leave a credential-bearing .pending marker no release path can ever clear | `SURVIVES_AND_MAPPED` | no THM (transparency unrooted) | `reserve` still writes the marker durably before returning; a failure or cancellation after the write leaves a credential-bearing `.pending` with no reservation for any release path to consume. | closed by #760 (`6fea87b69734`) |
| R9-C100 | medium | `audit-delivery` | flush_stderr_audit gives up when the queue is full — the exact backlog the shutdown drain was added for | `SURVIVES_AND_MAPPED` | THM-0070 | Same as C097. | — |
| R9-C101 | medium | `audit-delivery` | flush_stderr_audit no-ops on a full queue — the shutdown-under-load case it was added for | `SURVIVES_AND_MAPPED` | THM-0070 | Same as C097. | — |
| R9-C102 | medium | `scitt-retained-evidence` | SCITT pin position_profile made mandatory on the write side only; the verifier still defaults it to Unbound | `SURVIVES_AND_MAPPED` | THM-0068 | Write side requires it; read side still defaults it with no diagnostic. | — |
| R9-C103 | medium | `scitt-retained-evidence` | submitted_commitment is inert on no-verified-hop records; attest_chain now skips the self-check there | `SURVIVES_AND_MAPPED` | THM-0042 (root) | `corresponds_to` still refuses outright when either side has no verified hop, before the submission comparison — so the field that exists to identify such a record is unreachable for it. | closed by #763 (`0bd14469a8bd`) |
| R9-C104 | medium | `scitt-retained-evidence` | The committed SCITT corpus freezes a fabricated submitted_commitment no reconstruction can produce | `SURVIVES_AND_MAPPED` | THM-0042 | `scitt_vectors_test.rs:177` still writes `format!("corpus-submitted-{hops}")`, a literal no digest fold can produce, frozen inside nine signed vectors. | closed by #733 (`e6496173fc77`) |
| R9-C105 | medium | `scitt-retained-evidence` | verify_retained_evidence returns Ok when neither side names a submission; the conformance test asserts that Ok | `SURVIVES_AND_MAPPED` | THM-0042 (root) | Same as C029. | closed by #733 (`e6496173fc77`) |
| R9-C106 | low | `deployment-rendering` | Helm drain invariant does not budget the new 2s post-serve audit flush | `SURVIVES_AND_MAPPED` | no THM | Same as C033. | closed by #749 (`eef0f95271ca`) |
| R9-C107 | low | `credential-acquisition` | Single-flight cannot protect the path its comment names: TLS and signing backends hold separate token sources | `SURVIVES_AND_MAPPED` | no THM | `MetadataServerTokenSource::new` is still constructed per backend (`:1032`), so the coalescing never spans the handshake and issuance paths. | — |
| R9-C108 | low | `credential-acquisition` | Unknown-expiry floor pins a metadata token for 300 s, contradicting the fail-closed clamp its doc describes | `FIXED_AND_COVERED` | no THM | See C060. | — |
| R9-C109 | low | `sdk-client-exchange` | `send_notification_verified` claims TS `send()` parity but skips its concurrency bound and abort checks | `SURVIVES_AND_MAPPED` | no THM | Same as C061. | #746 |
| R9-C110 | low | `sdk-client-exchange` | New Python send_notification_verified() bypasses the concurrency bound the pump and the TS twin enforce | `SURVIVES_AND_MAPPED` | no THM | Same as C061. | #746 |
| R9-C111 | low | `client-proxy-and-sidecar` | Rust ambassador deletes MCP's application-level `result._meta`; both SDKs pass it through | `SURVIVES_AND_MAPPED` | THM-0084 / client.proxy_request_correspondence | `proxy.rs:463` still removes `result._meta`; the behaviour is now pinned by a test, so it is deliberate — but the three shipped clients still deliver the same signed reply differently. | — |
| R9-C112 | low | `scitt-retained-evidence` | Interop test asserts tree_size/leaf_index as facts, but its pin omits position_profile (Unbound) | `SURVIVES_AND_MAPPED` | THM-0068 | The pins still omit `position_profile`, so the interop test still asserts a log position its bytes do not authenticate. | — |
| R9-C113 | low | `retry-contract` | execution_claim duplicates the retry-contract serializer and has already diverged from it | `NO_LONGER_REPRODUCES` | — | `execution_claim` no longer exists in the tree. | — |
| R9-C114 | low | `assurance-platform` | UNAVAILABLE/SKIPPED unreachable from the Verus lane: verify overrides the declared verdict on exit != 0 | `SURVIVES_AND_MAPPED` | assurance platform | `verify:209` still sets FAIL from `returncode != 0` before reading the lane's own `VERDICT:` line, so UNAVAILABLE remains unreachable from the Verus lane. | closed by #771 (`0758ae28fdb7`) |
| R9-C115 | low | `scitt-retained-evidence` | verify_retained_evidence gives its strongest verdict when neither side identifies a submission | `SURVIVES_AND_MAPPED` | THM-0042 (root) | Same as C029. | closed by #733 (`e6496173fc77`) |
| R9-C116 | low | `exchange-lifecycle` | The frozen stage inventory now states a state order the transition relation refuses | `FIXED_AND_COVERED` | THM-0043 | The drifting prose table was deleted and its removal recorded in `request_stages.rs:16-19`. | — |
| R9-C117 | low | `exchange-lifecycle` | validate_request_stage has no ExchangeEvent, so the reorder detector is blind to the new stage | `SURVIVES_AND_MAPPED` | THM-0083 (root closure) | `validate_envelope` still returns a bare `Result` and advances no event, so the reorder detector remains blind to it — but the placement claim is now carried by THM-0083 with declared evidence rather than by nothing. | — |
| R9-C118 | low | `retry-contract` | execution_claim() is a divergent second serializer of the retry contract and drops retention_status | `NO_LONGER_REPRODUCES` | — | See C113. | — |
| R9-C119 | low | `exchange-lifecycle` | The release-active anomaly latch has no production reader: it blocks safe retries and tells nobody | `SURVIVES_AND_MAPPED` | THM-0043 (root closure) | Same as C066: no log line, no audit record, no metric on the success path. | — |
| R9-C120 | low | `assurance-platform` | Escape hatches in undeclared verification/ files are unregisterable and the FAIL text names an impossible fix | `SURVIVES_AND_MAPPED` | assurance platform | `scan_paths` still gives undeclared `verification/` files an empty owner set, `is_registered` still answers false for it, and the FAIL text still names a remedy that does not exist for them. | closed by #771 (`0758ae28fdb7`) |
| R9-C121 | low | `assurance-platform` | Self-hosted verification lane is the only workflow left on actions/checkout@v4 | `FIXED_AND_COVERED` | assurance platform | Both self-hosted jobs are on `actions/checkout@v7`. | — |
| R9-C122 | low | `serving-body-shape` | outstanding_id survives as a pub, permissive second reader of request shape | `SURVIVES_AND_MAPPED` | THM-0083 | `outstanding_id` is still `pub` and re-exported at `lib.rs:160`. THM-0083 honestly bounds its claim to production serving code, so the public weak reader is outside what the theorem covers. | — |
| R9-C123 | low | `serving-body-shape` | forwarded_body_fidelity_test claims byte fidelity the path cannot provide and its control does not test | `SURVIVES_AND_MAPPED` | THM-0083 (adjacent) | The headline sentence — *the bytes the inner server receives are the bytes the client signed* — still stands in `BUILD.bazel:925`, immediately qualified by the re-serialization it does not survive. | — |
| R9-C124 | low | `tls-listener-and-revocation` | Delegated TLS sign-budget sizing rests on 'session resumption is refused by design', which v0.16 does not do | `SURVIVES_AND_MAPPED` | no THM | `delegated_tls.rs:61/82` still state that *session resumption is refused by design*, which ADR-MCPRE-055/062 contradict; the 100/s sizing rests on it. | — |
| R9-C125 | low | `tls-listener-and-revocation` | CRL reload gate mirrors only NoNextUpdate; an already-stale CRL swaps in as a success | `SURVIVES_AND_MAPPED` | THM-0048 | `crl_reload_worker.rs:150` still calls only `crl_next_update_required`; the startup posture additionally handles `Stale`. An already-stale CRL still swaps in over a fresher last-good. | — |
| R9-C126 | low | `tls-listener-and-revocation` | Sign-budget sizing rests on "session resumption is refused by design", which ADR-055 contradicts | `SURVIVES_AND_MAPPED` | no THM | Same as C124. | — |
| R9-C127 | low | `client-proxy-and-sidecar` | Local leg now requires Content-Type and a loopback Host; the contract that defines it was not updated | `SURVIVES_AND_MAPPED` | no THM | `docs/client-sidecar-deployment-guide.md` still documents neither the required `Content-Type` nor the loopback `Host`, and names none of 403/415/421. | closed by #753 (`7ce84c95c35b`) |
| R9-C128 | low | `scitt-retained-evidence` | attest_chain issues zero-verified Signed Statements with no self-check, including of the one binding field | `SURVIVES_AND_MAPPED` | THM-0042 (root) | Same short-circuit as C103, reached from the issuance side. | closed by #763 (`0bd14469a8bd`) |
| R9-C129 | low | `deployment-rendering` | forwarded_body_fidelity_test.rs, round 8's post-verification body-rewrite test, has no Bazel target | `FIXED_AND_COVERED` | — | The test moved to `tests/integration_async/`, which is the Bazel `integration_async_test` glob target. | — |
| R9-C130 | low | `scitt-retained-evidence` | External SCITT cross-verification gate asserts only 'some error' for five of six negatives | `SURVIVES_AND_MAPPED` | THM-0041 / http_profile.scitt_receipt_offline | `external_kat.json` still records only `verify_ok` / `verify_fail`, while the internal corpus pins exact wire codes. | — |
| R9-C131 | info | `exchange-lifecycle` | ContinuationPrep::binding() doc still describes the pre-round-8 store-outage behaviour | `NO_LONGER_REPRODUCES` | — | The store-outage wording is gone from the continuation-preparation contract. | — |

<!-- END GENERATED: r9-dispositions -->

---

## 11. What this packet asks the owner to decide

**It does not ask for a fix pass.** Sending an agent to close the findings would return the
project to haphazard bug fixing and would build a work graph on top of an unratified claim
boundary. The audit has done its job; what is needed next is a small architectural ruling
pass.

### The eight completeness questions

Each has the same shape:

```text
Does MCP-RE claim to protect this?
        │
        ├── YES → it belongs in the assurance architecture
        │
        └── NO  → explicitly declare the boundary
```

1. **Replay / continuation store durability.** THM-0079 claims key distinctness, not store
   behaviour, and stays as it is either way.
2. **Retained-evidence reservation fidelity.** Nothing claims a `.pending` marker exists
   only for an exchange that crossed the execution threshold.
3. **Outbound credential acquisition** (KMS/STS/metadata/PKCS#11/remote signer). Cheapest
   of the eight: the owner already exists and is already sealed (`kms_endpoint_policy`), it
   just has no unit.
4. **Client-sidecar local ingress** and DNS-rebinding protection.
5. **Python/TypeScript SDK exchange semantics.** THM-0076 names the Rust client proxy.
6. **Deployment rendering / Helm / image-context security.** Most likely a clean
   OUT_OF_SCOPE — but it currently carries a shipped fail-open, so declare it deliberately
   rather than by silence.
7. **Whether the verification platform itself belongs inside the system theorem claim.**
   The exclusion is surely intended; nothing writes it down.
8. **THM-0042 omitting `submitted_commitment`** (§6.1). The only one touching an existing
   root's text.

### Three governance decisions to take in the same pass

**A. Are ASM-0030 / ASM-0032 wrong assumptions that need splitting or restatement?**
Their scopes were widened as the fail-safe direction and are marked PROVISIONAL in
`assumptions.toml` (§2.5). Widening a scope does not make an inaccurately-worded assumption
the correct premise for its new consumer.

**B. Should the assumption relationship have ONE authoritative direction**, instead of
permanently maintaining both `[[assumption]].scope` and `[[unit]].assumptions`?
ADR-MCPRE-059 §8 forbids the duplication and its own example contains it. The new gate keeps
the two halves consistent; it does not remove the second authority. Collapsing has a real
cost — `review-packet` and `owners.md` read the unit side.

**C. What is the current authoritative security-claim document?** The existing signed
honesty gate cannot remain half-historical (§7). Until this is answered, "what MCP-RE
claims" has no single answer, and the eight questions above are being asked against a moving
target.

### On closing T6 (#542) and #544

**#542's R9 re-derivation clause is satisfied and can close.** 131 clusters, one written
disposition each, reason recorded for every non-surviving one, residual measurement stated
rather than hidden.

**Its remaining criteria are not.** Child issues for surviving findings do not exist — and
should not be created from the appendix — and `review --require-root-complete` would pass
over a graph this packet measures as an incomplete representation of the claim surface.

**A completeness defect remains, and it is not a mechanical metadata one.** The mechanical
corrections are done and green. What is left is the eight rulings plus A, B and C, each an
owner decision about what MCP-RE promises — the boundary #542 §9 reserves for the
ratification step, and the boundary this packet reports at rather than crosses.

Close #542's re-derivation clause and the corresponding completed portion of #544; hold
#542 itself until the decisions are made. The nine roots become sufficient at the moment
those questions are answered — not before, and not by adding theorems.
