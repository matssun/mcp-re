<!-- SPDX-License-Identifier: Apache-2.0 -->

# Grill decisions — MCP-RE next PRD (Enterprise Authorization Binding and Production Authority Completion)

Session: 2026-07-15. Griller: Claude. Answerer: Codex (`codex-cli 0.142.2`), primed with
`.claude/skills/pp-grill-me/stance-profile.md`. Judge: general-purpose agent, same profile
as sole rubric. Seed: [`mcp-re-v0.13-seed.md`](mcp-re-v0.13-seed.md).

Provenance tags: `[Codex, judge-passed]` = auto-accepted · `[user]` = Mats decided ·
`[Codex, user-confirmed]` = escalated, Mats sided with Codex.

Companion artifacts: the Claude↔Codex Q&A is in
[`mcp-re-next-grill-transcript.md`](mcp-re-next-grill-transcript.md); resolved vocabulary went
into [`CONTEXT.md`](../../CONTEXT.md) inline. **This file is authoritative** — where Mats
overrode Codex, this file wins over the transcript.

> **Note on the "v0.13" name.** The seed and the early transcript say "v0.13". Decision
> A2 removed the version anchor — the PRD is capability-anchored and the release number is
> assigned at ship time. Read every "v0.13" in the seed as historical.

## Findings that changed the plan

Four repo-verified findings contradicted the seed. They are why this grill was worth running:

| # | Finding | Consequence |
|---|---|---|
| C0 | `sign_manifest` signs `serde_json::to_vec(manifest)` — the trust anchor's preimage is "whatever serde does to a Rust struct", guarded by a comment. Landed 2026-07-14: **four days after** its own JOSE/JWS sibling, **three days after** the JCS purge. | The highest-authority object had the least standards-aligned signing → JWS re-base + ADR-053 |
| D3 | `forbidden_claim_guard_test.rs` scans exactly five docs; `docs/PROJECT_STATUS.md` is not one of them. | The guard exists to make over-claiming mechanically impossible, and the real over-claim lived in an unscanned file → document-class rule + typed rules |
| B2 | `aws_kms_live_test.rs` already exists; AWS KMS Ed25519 GA Nov 2025; adapter already uses correct `ED25519_SHA_512` + `MessageType: RAW`. | Codex's "delete ~2,700 lines" collapsed → "no deletion without architectural or maintenance cause" |
| E1 | `artifact.rs` already implements `oauth-dpop` / `oauth-mtls` / `oauth-rar` binding. | EMA needs **no new vocabulary**; the workstream collapsed to docs + vectors + policy mode |

---

## Branch A — Frame & scope · SIGNED OFF 2026-07-15

### A1 — One PRD, all five workstreams `[Codex, user-confirmed]`

The PRD covers all five workstreams as one unit: evidence-spine regeneration,
root-authority lifecycle, production residuals, EMA binding profile, ecosystem readiness.
It ships when all five are green.

Codex's reasoning (adopted): the thesis is not "finish some production chores, then maybe
do EMA" — it is "MCP-RE is production-authority complete and can bind stable enterprise
authorization without interpreting it." EMA is not a separate product direction; it is the
first serious proof that `artifact_bindings[]` and bind-not-interpret survive contact with
the real MCP authorization stack. If the surface is too large, the answer is tighter slice
discipline inside the PRD, not splitting one architectural argument across two releases.

*Judge escalated (Trigger 4 — release scoping is intent; it also flagged that Codex's
"EMA can't be claimed without the spine" is a narrative-honesty argument, not a hard build
dependency). Mats sided with Codex. Per the profile, Trigger 4 escalations are exempt from
the false-alarm rule — escalating was correct even though he agreed.*

### A2 — The PRD is capability-anchored, not version-anchored `[user]`

Title: **PRD: MCP-RE — Enterprise Authorization Binding and Production Authority
Completion**. No version number; the release number is assigned at ship time.

This deliberately breaks #148's version-anchored convention (`PRD: MCP-S 0.5 — …`):
committing a version to work whose size isn't yet known is a guess, and the release number
is an outcome, not an input.

### A3 — The claim matrix is evidence of current capability, not a roadmap `[user]`

**Rule: no green mapped test, no claim-matrix row.**

Codex's `unbacked`-category proposal is **rejected**. It conflated two artifacts:

- **PRD** — planned future capabilities and target claim wording; names the required
  test/evidence. A claim may be *planned* here before its test exists.
- **Claim matrix** — claims the project can *currently substantiate*. A row appears only
  when the implementation exists and its mapped test is green.

Workflow:

```
PRD  → records target capability + intended claim wording + names required test/evidence
         ↓  implementation lands → test exists → test is green
Claim matrix        → row added/updated
Traceability manifest → maps the claim to the real green test
CI                  → verifies the complete evidence chain
```

Ordering: honesty fixes **now**; the spine is regenerated **per-workstream as each lands**
(seed Option C + Option B), with the two-category invariant retained.

Explicitly forbidden: placeholder rows, fake test names, an `unbacked` category, and any
relaxation of the traceability guard.

Immediate actions:
- fix the current over-claims in `docs/PROJECT_STATUS.md` now (it still says
  "Current release: v0.10.1" and still claims a "zero-drop rolling update" that the
  v0.12.1 changelog contradicts with a 2-of-590 in-flight drop);
- keep target/future claims in the PRD;
- add claim-matrix rows only when their real mapped tests exist and pass;
- regenerate the relevant matrix/manifest section incrementally as each workstream lands;
- keep `security_traceability_guard_test` **unchanged**.

*Judge escalated (Triggers 4 + 6) and its finding was verified against the repo before
escalation: `docs/spec/v0.5-claim-matrix.md:36` states the classification invariant
("Every row above is in exactly one of `{unconditional, deployment-dependent; see §B}`" —
"There is no third category"), and `security_traceability_guard_test.rs` fails when any
`test_fn` is absent from the referenced test source on disk. Codex's mechanism would have
broken both. Mats overrode Codex. The griller's own original recommendation (Option A) was
also overturned by this finding.*

**Learning-log candidate → RESOLVED (see the harvest section).** Codex proposed weakening an
existing invariant + guard to accommodate a planning convenience, and framed it as *not*
over-claiming. The candidate's raw form ("a guard that fires means the proposal is wrong") was
**deliberately narrowed** by Mats — it would turn every existing invariant into untouchable
scripture. It landed instead as **Trigger 7 — "weakening the proof system to admit the
proposal"**: escalate and presume the proposal wrong, unless an independent architectural
decision shows the invariant ITSELF is obsolete.

---

## Branch B — Production residuals · SIGNED OFF 2026-07-15

### B1 — Zero-drop is an availability claim; §B stays at four security axes `[user]`

**The §B deployment-tier matrix stays FIXED at its four security dimensions** (replay
durability / trust propagation / key custody / ingress binding). Do not distort the security
claim matrix by inventing a fifth axis just because a property matters operationally.

The separation:

| Security claim matrix (§B) | Operational evidence |
|---|---|
| replay durability · trust propagation · key custody · ingress binding | throughput · latency · graceful drain · rolling-update loss · load-balancer topology · replica convergence |

Zero-drop rolling update lives in: `docs/fleet-deployment-guide.md`, the SLO/benchmark
document, a **named operational deployment profile**, and a reproducible live validation
lane. It MAY be tiered *there* — e.g. `best effort` / `bounded drain` /
`validated zero-drop under declared topology` — but never inside §B.

Codex was right on the narrow point: **increasing `drainPreStopSeconds` does not prove a
general zero-drop property.** It may make the tested deployment green, but the claim must be
bounded to the exact environment:

> Validated zero-drop for: GKE + container-native load balancing/NEG + declared
> readiness/drain configuration + declared load envelope.

**Never claim topology-independent zero-drop.** A NEG-backed/container-native LB path may be
the correct implementation, but the resulting claim stays bounded to the declared topology,
configuration, and load envelope.

*Judge escalated (Trigger 4). Codex proposed a tiered claim without saying where the tier
lived; the judge found §B has exactly four axes, all security properties, each ADR-backed.
Mats sharpened it: tier it, but outside the security matrix entirely.*

### B2 — Keep the AWS KMS adapter; run the existing live lane `[user]`

**Rule: no live proof, no production claim — but also no deletion without architectural or
maintenance cause.**

Codex's "delete the adapter" is **rejected**. Deleting correct, architecturally valid code
solely because its live lane has not yet been run is backwards. The deletion precedent
(stdio / direct-root signing / JCS) does **not** apply: those were **superseded competing
designs**; the AWS adapter has no competing winner.

Verified facts that decided it:
- `mcp-re-proxy/tests/aws_kms_live_test.rs` already exists, mirrors the GCP lane, is
  `#[ignore]`d, and fails loudly if unconfigured ("Compiling is NOT support; this assertion
  against live infrastructure is").
- AWS KMS really supports Ed25519 now — `ECC_NIST_EDWARDS25519`,
  [GA November 2025](https://aws.amazon.com/about-aws/whats-new/2025/11/aws-kms-edwards-curve-digital-signature-algorithm/),
  all regions including GovCloud/China.
- The adapter uses the correct spec and mode: `ED25519_SHA_512` + `MessageType: RAW`
  (PureEdDSA, no pre-hash) — `mcp-re-proxy/src/aws_kms_keysource.rs:7-8,49-50,257-258`.
- `docs/security/google-validation-plan.md:36-50` lists the AWS signer under **"What already
  exists (do not rebuild)"**.

**LocalStack is not enough for this claim.** It is useful for fast CI, but emulating the API
is not proof that the real KMS signing path works — the live-test header already says this.

**Claim wording after the real AWS lane is green** — claim exactly what is proven:

> Native non-exporting delegated-root signing has been validated against Google Cloud KMS
> and AWS KMS.

"Multi-cloud custody" is acceptable **only** as shorthand, and only if the claim matrix
defines it narrowly as *validated support for more than one cloud KMS provider*. It must
**not** imply: equivalent operational maturity · fleet validation on AWS · AWS deployment
automation · AWS IAM/reference architecture · cross-cloud failover · identical revocation
behavior across providers.

*Judge escalated (Triggers 4 + 6) and its refutation was verified end-to-end before
escalation. Mats overrode Codex.*

**Learning-log candidates → ALL RESOLVED (see the harvest section):**
1. *No deletion without architectural or maintenance cause* → **standing**, landed as the
   **S4 refinement**. Must carry both poles: retain AWS (correct code awaiting its lane),
   delete EMA Mode 2 (contradictory mode that must not linger as implied roadmap).
2. *Claim exactly what is proven, never the category* → **standing**, landed as the
   **S14 refinement** (incl. gate-dependent claims, extended by F2).
3. *Security vs operational claims in separate artifacts* → **project-specific, NOT a global
   stance** — landed in `CONTEXT.md` as a documentation invariant.

---

## Branch C — Root-authority production lifecycle · SIGNED OFF 2026-07-15

### C0 — The `TrustAnchorManifest` is re-based on compact JOSE/JWS `[user]`

> **Finding (griller, not Codex).** `sign_manifest` signs `serde_json::to_vec(manifest)`
> (`mcp-re-client-core/src/trust_manifest.rs:135`), so the signature preimage is *"whatever
> this Rust serializer emits for this exact struct definition"* — guarded only by a code
> comment claiming "fixed field order" (`trust_manifest.rs:71-72`). Timeline: `delegation.rs`
> (compact JOSE/JWS, RFC 7515/7519, "no agility, no `none`") landed **2026-07-10**; JCS was
> eradicated **2026-07-11**; `trust_manifest.rs` landed **2026-07-14** — four days after its
> own JWS sibling, three days after the JCS purge — and went ad-hoc anyway. The
> highest-authority object in the system had the least standards-aligned signing.

Mats' ruling:

> The current design is not acceptable for a highest-authority object. That is not a
> protocol. It is an implementation accident.

"Fixed field order" in a comment does not give: a normative serialization · cross-language
reproducibility · independent verification · forward-compatible versioning · protected
algorithm metadata · golden-vector stability.

**Decision — re-base on the same family as the delegation credential:**

```
compact JWS
protected header:
  alg           (Ed25519 / EdDSA, RFC 8037 — no agility)
  kid           (the pinned org/admin manifest-signing key)
  typ           e.g. "mcp-re-trust-anchor-manifest+jwt" (project-owned, precise)
payload:
  versioned TrustAnchorManifest claims
```

The load-bearing reason: **the exact payload bytes ARE the base64url-encoded bytes placed
into the JWS** — producers and verifiers do not independently reserialize a parsed object
and hope to reproduce the signature. JWS defines the signed representation without inventing
another canonical-JSON scheme.

Option 2 (keep serde + add a canonicalization id) was **rejected**: it would formalize the
ad-hoc format and still create a *second* signing construction beside the already-adopted
JOSE/JWS path — unnecessary divergence at the most sensitive layer.

**Golden vectors and an independent non-Rust verifier are mandatory** (S15; also unblocks
Branch F's independent-verifier goal, which the serde preimage made impossible).

### C1 — New ADR-MCPRE-053: Root Authority Lifecycle and Trust-Anchor Transition `[user]`

ADR-052 is already implemented and has a precise subject: delegated signing-key attestation
carried in HTTP evidence. Root-authority lifecycle is now a separate architectural concern —
a different signed object, root trust transition, governance and quorum, publication and
rollback prevention, distribution, fleet propagation bounds, emergency revocation. That is too
much to bolt onto ADR-052 without changing what ADR-052 *means* after implementation.

**Do NOT move §H/§I out of ADR-052 retroactively** if they are needed to understand the
implemented delegation model. Instead:

- leave ADR-052 intact as the implemented delegated-signing decision;
- add a note that root lifecycle is governed by ADR-053;
- let ADR-053 supersede **only** the specific manifest serialization/lifecycle details that
  are changing.

```
ADR-052  defines delegated signing and the credential chain
         references a trusted issuer set / root manifest

ADR-053  defines how that issuer set is represented, governed,
         rotated, revoked, distributed, and audited
```

This preserves history and avoids making an implemented ADR silently mutate into a broader
authority-governance ADR.

### C2 — Mechanism, not staffing — but approval evidence stays OUT of the manifest `[user]`

Codex's core principle is **accepted**: *"fake dual control is worse than honest single
control."* The controller enforces the configured governance policy — solo configures
`quorum = 1` and records one approver **honestly**; enterprise configures `quorum >= 2` with
distinct identities required. `mcp-re-admin rotate-root` is the only normal publication path.
Follows ADR-MCPS-044's "properties not products".

Codex's proposal to bind the full approval record into the signed manifest is **rejected**.
The manifest describes the *resulting trust state*, not the administrative workflow that
produced it.

| In the signed manifest (trust state) | In a separately signed / append-only governance-audit record |
|---|---|
| manifest version / generation | approver identities |
| current issuers | approval timestamps |
| retiring issuers | approval evidence |
| revoked issuers | ticket / change reference |
| `not_before` / `expires_at` | command invocation facts |
| rotation / transition identifier | break-glass reason |
| `governance_policy_id` | operator identity |
| `previous_manifest_digest` / generation linkage | policy evaluation result |

Why they separate:
1. **Different audiences** — every verifier needs trust state; not every verifier should
   receive internal approver identities.
2. **Privacy / disclosure** — approval metadata exposes organizational identities and
   operational structure.
3. **Manifest stability** — trust verification must not depend on the shape of an approval
   workflow.
4. **Different retention** — approval evidence may need long-term audit retention; manifests
   have bounded operational lifetimes.
5. **Cleaner cryptographic responsibility** — the manifest signer attests *"this is the valid
   trust state"*; the governance record proves *"this state change was authorized according to
   policy."*

**"Outside the manifest" must NOT mean "optional":** publication fails unless the external
approval evidence satisfies policy.

**Break-glass** is a distinct command with a distinct audit event. It MAY permit `quorum = 1`
under an explicitly configured emergency policy, but must never masquerade as ordinary
rotation.

*Judge escalated (Trigger 4 — the proposed fields change a signed preimage; current struct is
exactly 7 fields with `deny_unknown_fields`). The judge also flagged an S8 gap Codex never
addressed: **identity-distinctness ≠ human-distinctness** — the mechanism cannot detect one
human holding two approver identities, and that limitation must be documented honestly rather
than left implied.*

### C3 — Reuse the ADR-021 Redis trust-epoch channel + a third Axis-2 sub-bullet `[user]`

**Mechanism:** reuse the existing ADR-MCPS-021 Redis trust-epoch channel. This is
architecturally sound because **the channel is not trusted to establish authenticity** — Redis
transports bytes; the verifier establishes trust by checking the pinned org/root signer, the
manifest signature, expiry, generation monotonicity, rollback linkage, and issuer status. A new
remote resolver is unnecessary merely because the payload is more powerful.

A static ConfigMap is **not** appropriate as the primary mechanism — too slow and awkward for
emergency revocation. It MAY remain a **bootstrap / disaster-recovery source**, never the live
authority channel.

**Axis 2 gains a third explicit sub-bullet** (following `docs/spec/security-boundary.md:291-307`'s
own established pattern — bounds are stated per-mechanism "because the two tiers have physically
different cadences", and are "surfaced from real config at startup… **not asserted in prose**"):

```
§B Axis 2 — Trust propagation
  1. signer/key status propagation
  2. client-certificate revocation propagation
  3. trust-anchor manifest propagation   ← NEW, own declared+tested bound
       e.g. manifest publication-to-fleet acceptance <= 60s
       blast radius: invalidates EVERY descendant credential
```

Reusing Axis 2's existing bound silently was **rejected** — root-manifest changes have a
distinct blast radius.

**Two cases must be distinguished honestly:**

- **Planned rotation** — bounded propagation is acceptable:
  `publish B trust → wait for fleet convergence → switch issuance A→B → drain A credentials → retire A`
- **Emergency root compromise** — a 60s bound means **the old root may remain accepted for up
  to 60 seconds**. State this honestly; never imply instant revocation.

**In-flight requests** are judged at verification time: not-yet-verified fails closed; already
verified and dispatched is not retroactively unsent — exposure is the declared Axis-2 window
plus the request deadline. **`expires_at` failing the fleet closed is correct, not a footgun**
(stale trust material is worse than an outage); the mitigation is operational — republish well
before expiry, page before the renewal window closes, treat failure to republish as an
authority-lifecycle incident.

*Judge escalated (Trigger 6) and verified `PUSH`/`T=60s` are real declared values
(`v0.5-claim-matrix.md:74-78`), not invented — the escalation was about the axis reuse, which
Mats upheld.*

---

## Branch D — Evidence spine · SIGNED OFF 2026-07-15

### D1 — Archive the signed boundary intact; new canonical boundary; new sign-off `[user]`

The old sign-off is **evidence about the system that existed when it was signed**. Editing it
in place would blur that historical fact.

```
docs/archive/security-boundary-v0.5.md      docs/spec/security-boundary.md   ← canonical
  preserved content                           current HTTP-only boundary
  preserved dated sign-offs                   current carrier + trust model
  clear superseded/historical banner          current non-goals + claim limits
  explicitly NON-AUTHORITATIVE                NEW dated owner sign-off
```

This does **not** create two competing boundaries: only the file at the canonical path is
authoritative; the archive is explicitly non-authoritative and records what was previously
attested. (#148's original complaint — "two security-boundary documents that contradict each
other" — was about two *live* docs, not a live doc plus history.)

**ADR-MCPS-036's "no self-approval"** means **an agent cannot approve its own generated
claims**. In a solo-maintainer project the accountable owner may honestly sign as quorum 1 —
the same shape as C2's ruling. Pretending there is independent human review when there is not
would be less honest.

### D3 — The claim guard is rebuilt: classified surfaces + typed rules `[user]`

> **Finding (griller).** `mcp-re-conformance/tests/forbidden_claim_guard_test.rs` scans exactly
> five proposal-facing docs — `security-boundary.md`, `v0.5-claim-matrix.md`,
> `threat-coverage-matrix.md`, `composability.md`, `proposal-scope.md`. **`docs/PROJECT_STATUS.md`
> is not among them**, which is exactly where the stale "zero-drop rolling update" over-claim
> survived. The guard exists to make over-claiming mechanically impossible; the real over-claim
> walked straight past it. The same hole covers `README.md`, `fleet-deployment-guide.md` and the
> SLO doc — the files Branch B just made the home of the bounded zero-drop claim.

**1. Scope by principle, discovered mechanically.** A fixed list of five files has already
failed. The guard applies to all present-tense, reviewer-facing claims about the shipped
system, regardless of file. **Do not rely on natural-language heuristics** to decide whether a
file contains a claim — make files **explicitly declare** their class in front matter, and fail
CI when a public-facing document is unclassified:

```
claim_surface | historical | fixture | internal_working
```

**2. Typed rules, not one flat phrase list.** The guard must distinguish three classes:

```
forbidden absolutely
allowed only with qualification
allowed only as historical/negative wording
```

> **Extended by F2:** a **fourth** class — **gate-dependent** — a phrase that is not
> permanently forbidden but is unavailable until a named gate is satisfied. See F2.

Example rule shape:

```yaml
- phrase: "zero-drop rolling update"
  rule: requires_qualifier
  qualifiers: ["under the declared", "validated on",
               "for the tested topology", "within the tested load envelope"]
- phrase: "multi-cloud custody"
  rule: requires_qualifier
  qualifiers: ["validated against GCP Cloud KMS and AWS KMS", "provider support only"]
```

**Paragraph-level** matching, not line-level — Markdown wraps sentences.

**3. Phrase classification** (Codex's flat ban list was narrowed — the guard must reject the
unqualified claim, not prevent precise language):

| Absolutely forbidden (unless historical/negated) | Qualified-only |
|---|---|
| topology-independent zero-drop | zero-drop rolling update |
| general zero-drop | multi-cloud custody |
| instant root revocation | immediate root revocation |
| zero-window root revocation | two-person approval · staffed dual control · human-distinct approvers |

Legitimate qualified wording:
- "validated zero-drop rolling update under the declared GKE NEG topology and tested load envelope"
- "non-exporting signing validated against GCP Cloud KMS and AWS KMS"
- "the revocation command is immediate; fleet enforcement occurs within the declared propagation bound"
- "two-person approval is required only by the configured enterprise governance profile"

**ANTI-EVASION RULE (load-bearing).** A qualifier must **constrain the same claim**, not merely
appear somewhere nearby — it must grammatically bind the claim. This must still FAIL:

```
MCP-RE provides zero-drop rolling updates.
The benchmark used a declared topology.
```

*Note the implementation tension to resolve in the ADR: qualifiers are matched at paragraph
level (because Markdown wraps), yet a qualifier elsewhere in the paragraph must not excuse a
bare claim. Grammatical binding is the discriminator, and it is the hard part.*

---

## Branch E — EMA composition profile · IN PROGRESS

### E1 — EMA adds NO new `ArtifactType`; it is composition over the existing OAuth types `[Codex, judge-passed]`

> **Finding (griller).** The seed assumed ADR-054 would have to decide "how the client proxy
> receives the token, DPoP vs mTLS, how binding works". The binding primitives **already
> exist**. `mcp-re-http-profile/src/artifact.rs` implements typed artifact-binding
> verification, and its module doc states the three typed OAuth-family proofs "all reduce to
> the same primitive — `base64url-no-pad(SHA-256(credential bytes))` — but over different,
> type-tagged byte sources": `oauth-dpop` → RFC 9449 `ath` (SHA-256 of the access token);
> `oauth-mtls` → RFC 8705 `x5t#S256` (SHA-256 of the DER certificate); `oauth-rar` → SHA-256
> of canonical RFC 9396 `authorization_details`. `verify_dpop_ath` / `verify_mtls_x5t_s256` /
> `verify_rar_details` all exist and are tested. `ArtifactType` is a CLOSED enum.

**Decision: no new `ArtifactType`.** An EMA-issued MCP access token *is* an OAuth 2.0 access
token; binding it is exactly what `oauth-dpop` / `oauth-mtls` already do. Minting
`ema-access-token` would be **dead vocabulary** whose verifier is byte-identical to the
existing one.

Why this is the boundary-correct answer, not merely the cheap one:
- **S13** — the domain-canonical name for this artifact is "OAuth 2.0 access token,
  sender-constrained via DPoP (RFC 9449) or mTLS (RFC 8705)". "EMA" is a *provenance* story
  about how the token was **issued**; it is not a different credential class on the wire.
- **Bind-don't-interpret** — MCP-RE cannot tell, and by its architecture must not care,
  whether the token came from an EMA/ID-JAG exchange or an ordinary OAuth code flow. Needing
  an `ema-*` type would mean MCP-RE is *interpreting provenance* — the exact boundary
  violation the project refuses.
- **The ID-JAG is not a runtime artifact.** It is consumed by the Authorization Server during
  the RFC 8693 token exchange, so there is nothing to bind for it.

**The audience/resource check.** Parsing the token to compare `aud` / `resource` is
authorization-server / resource-server policy work, **not** MCP-RE binding. MCP-RE enforces
its own existing `AudienceTuple` check (`verify.rs` → `mcp-re.invalid_audience`). MCP-RE
binds; the OAuth/MCP authorization layer interprets.

**Net effect: the EMA workstream collapses** from "build a binding profile" to: document the
composition · add positive/negative conformance vectors · add a policy mode requiring a
sender-constrained OAuth binding for EMA deployments.

*Griller and Codex agreed independently, both citing code. No new wire vocabulary is minted,
so Trigger 4 does not fire — the decision is precisely to NOT mint vocabulary.*

### E2 — Mode 2 is CUT completely; Mode 1 only `[user]`

Once the governing rule is that MCP-RE **binds but does not interpret**, the old Mode 2 is
**internally contradictory**. To enforce an EMA-derived token correctly, something must
validate: issuer · signature and JWKS rotation · audience/resource · expiry and not-before ·
scopes or authorization details · revocation/introspection policy · sender constraint (DPoP or
mTLS). That is an OAuth authorization/resource-server responsibility. Putting it into MCP-RE
would turn the evidence layer into an authorization implementation and contradict the
established boundary (and the published non-claims — `PROJECT_STATUS.md:137`,
`MCP-RE-IN-ONE-PAGE.md:53`).

**The distinction that decides it.** Cryptographic binding proves:

> this exact token was attached to this exact request

It does **not** prove:

> this token is valid, authorized, unexpired, or intended for this resource

**A correctly bound stolen or invalid token is still invalid.** Binding alone cannot make it
authorized. So the dangerous alternative — accepting a correctly-bound token with nobody
validating its authorization semantics — is *worse* than removing the mode.

**Mode 2 is removed, not marked experimental.** For a private backend the deployment must
provide one of:

```
MCP-RE proxy → EMA-aware resource server/backend validates token
MCP-RE proxy → authorization-enforcement sidecar/gateway → private backend
```

If no downstream component validates the token, **the deployment is insecure and must be
documented as such** — never presented as an authorization mode.

**Option 3 (cut now, name a trigger) was explicitly rejected:** "a future trigger would
encourage Mode 2 to linger as an implied roadmap item." A separate reference resource-server
project could be considered later, but it would not be MCP-RE Core or an MCP-RE authorization
mode. *(Note: this is a deliberate contrast with the AWS ruling — there, correct existing code
stays; here, a contradictory MODE must not linger as implied roadmap.)*

Mode 1 remains: MCP-RE binds the exact authorization artifact to the exact signed request; an
EMA-aware authorization/resource server or enforcement gateway validates the token semantics;
MCP-RE does not claim the token is valid or sufficient for authorization.

### E4 — Black-box conformance vectors now; real-IdP interop later, OUTSIDE the claim spine `[user]`

Codex was right that a hermetic fake IdP → fake AS flow is **poor conformance evidence**: most
of that test would exercise code invented solely for the test, while MCP-RE's actual behaviour
is only artifact binding. **Do not build a fake IdP and fake authorization server merely to
prove the fake stack works.** *(This overturns the seed, which proposed exactly that lane.)*

**Normative lane — black-box MCP-RE, opaque token bytes. Every assertion terminates on MCP-RE
code:**

- correct OAuth/DPoP `ath` binding accepted;
- token bytes changed after signing → rejected;
- binding detached or spliced → rejected;
- wrong `artifact_type` → rejected;
- required artifact missing → rejected;
- wrong binding mechanism → rejected;
- request/response replay → rejected;
- mTLS thumbprint binding mismatch → rejected;
- multiple artifacts reordered or substituted → rejected (if ordering/identity matters);
- **authorization artifact not leaked into audit output.**

**Real IdP/authorization-server interop lane — later, and OUTSIDE the conformance spine.** It
answers a different question: *can MCP-RE bind artifacts produced by an actual EMA
implementation without format or transport incompatibilities?* It must be: optional or
scheduled · provider-specific · explicitly **integration evidence** · **not required to prove
MCP-RE's core security claims** · **not allowed to claim MCP-RE validated the token semantics**.

A successful real interop lane proves exactly four things: a real EMA flow produced an access
token; MCP-RE bound that token using the specified mechanism; the actual resource server
validated it; the MCP request completed without weakening either boundary. **It does not prove
generic EMA conformance.**

---

## Branch F — Ecosystem readiness · SIGNED OFF 2026-07-15

### F1 — The evidence ladder: package gates everything; the Python verifier is published but never counts as independence `[user]`

Codex conceded the sharp point when pressed: **"same-author second-language verification catches
Rust bugs, not spec ambiguity"** — the same author resolved both ambiguities the same way. A solo
project cannot self-certify independent implementability.

**Three distinct levels of evidence — do not conflate them:**

1. **Specification completeness** — a standalone package containing the normative schemas,
   preimage rules, vectors, expected failures, and versioning.
2. **Cross-language reproducibility** — the project's Python verifier consumes **only** that
   published package and specification, without importing or calling Rust code.
3. **Independent implementability** — a genuine third party implements the profile from the
   published material and passes the package.

**Level 2 is worth doing even though it is not independence.** It exposes: Rust-specific
assumptions · undocumented byte handling · serialization differences · JOSE/JWS interpretation
mistakes · ambiguity between prose and vectors.

**The restriction that makes Level 2 honest:** the Python verifier MUST NOT share hidden
constants, generated Rust artifacts, internal helper libraries, or unpublished assumptions. It
behaves as an **external consumer** of the package.

**Release order:**

```
standalone conformance package
        ↓
project-owned Python verifier consumes ONLY package + spec
        ↓
package and verifier published
        ↓
third-party implementation passes package
        ↓
independent implementability MAY be claimed
```

**Do not defer the package** (it would also conflict with C0, which already mandates golden
vectors + a non-Rust verifier for the JWS manifest). **Do not count the Python verifier as
third-party evidence.** Until step 3, retain an explicit non-claim.

### F2 — Gate-dependent claims: a THIRD rule class beyond D3 `[user]`

> **This extends D3.** D3 established three classes: *forbidden absolutely* / *qualified-only* /
> *historical-or-negated-only*. F2 adds a fourth: **gate-dependent** — a phrase that is not
> permanently forbidden but is **unavailable until a named gate is satisfied**. "Independently
> implementable without importing the Rust code" is not an eternal lie; it becomes legitimate the
> moment a genuine third-party implementation demonstrates it. An eternal ban would be as
> dishonest as an early claim.

**Allowed now:**

> MCP-RE has machine-checked Rust/non-Rust cross-verification for selected wire and credential
> surfaces.

Fuller form (use where independence could be inferred):

> …The non-Rust verifier is maintained by the project and is not evidence of independent
> implementation.

**Allowed after the standalone package is published** (note *intended to support*, never *proves*):

> MCP-RE publishes a standalone conformance package intended to support implementations that do
> not import the Rust code.

**Allowed only after a genuine third-party implementation passes the package:**

> MCP-RE has been independently implemented from the published specification and conformance
> package.

**Qualified-only / gate-dependent class:** `independently implementable` · `independent
implementation` · `cross-language verification` · `non-Rust verification` · `standalone
conformance` · `independent interoperability`.

**Required distinctions:**
- *cross-language* must not imply *independent*;
- a project-maintained non-Rust verifier must be **disclosed** wherever independence could be
  inferred;
- *independently implementable* requires a genuine external implementation;
- **publishing vectors alone does not establish independent implementability.**

**Rejected before the third-party gate** (may appear only as explicit non-claims or future gates):
`independently implementable` · `independently verified` · `implementable from the specification
alone` · `independent cross-implementation interoperability` · `vendor-neutral interoperability
proven` · `third-party conformance proven`.

*Codex's single allowed/forbidden sentence pair was replaced: it was honest but too long for
repeated use and treated the forbidden phrase as eternal. Mats' vocabulary is gate-dependent and
short enough to actually get used.*

---

## Learning-log harvest · CONFIRMED 2026-07-15

Applied to [`.claude/skills/pp-grill-me/stance-profile.md`](../../.claude/skills/pp-grill-me/stance-profile.md)
(human-confirmed, never silent):

| Candidate | Disposition | Landed as |
|---|---|---|
| No deletion without architectural or maintenance cause | **standing preference** | **S4 refinement — deletion requires cause** |
| Claim the demonstrated property, not its category | **standing preference** | **S14 refinement**, incl. gate-dependent claims |
| A guard firing means the proposal is wrong | **standing, but narrowed to an escalation rule** | **Trigger 7 — weakening the proof system to admit the proposal** |
| Security vs operational claims in separate artifacts | **project-specific, NOT a global stance** | `CONTEXT.md` documentation invariant |

Two judgements worth preserving about the harvest itself:

- **Trigger 7 was deliberately narrowed.** The raw form ("a guard that fires means the proposal
  is wrong") was rejected as "turning all existing invariants into untouchable scripture."
  Sometimes an invariant IS obsolete and should change — but that is its own decision on its own
  merits, never a side-effect of something else needing to pass.
- **The S4 refinement must carry both halves or it misfires.** Retain (AWS: correct code awaiting
  its lane) and delete (EMA Mode 2: contradictory mode that must not linger as implied roadmap)
  came from the same session and are the two poles that define "cause".

## Session summary — decisions in resolution order

1. **A1** one PRD, five workstreams `[Codex, user-confirmed]`
2. **A2** capability-anchored title, no version number `[user]`
3. **A3** claim matrix = evidence, not roadmap; no green mapped test, no row `[user]`
4. **B1** zero-drop is availability; §B stays at four security axes; bounded claims only `[user]`
5. **B2** keep the AWS adapter, run the live lane; no deletion without cause `[user]`
6. **C0** re-base the TrustAnchorManifest on compact JOSE/JWS `[user]`
7. **C1** new ADR-MCPRE-053; ADR-052 stays intact with a forward reference `[user]`
8. **C2** mechanism not staffing; approval evidence outside the manifest `[user]`
9. **C3** reuse the Redis trust-epoch channel; third Axis-2 sub-bullet; planned vs emergency `[user]`
10. **D1** archive the signed boundary intact; new canonical doc; new sign-off `[user]`
11. **D3** claim guard rebuilt: document classes + typed rules + anti-evasion binding `[user]`
12. **E1** EMA adds no new ArtifactType `[Codex, judge-passed]`
13. **E2** Mode 2 cut completely; Mode 1 only `[user]`
14. **E4** black-box vectors; real-IdP interop outside the claim spine `[user]`
15. **F1** evidence ladder: package gates all; Python verifier published but never independence `[user]`
16. **F2** gate-dependent claim class + the three-tier claim vocabulary `[user]`

## Open items for the PRD

- **The claim matrix's own name.** It is still `v0.5-claim-matrix.md` while the PRD is
  deliberately capability-anchored (A2). Trigger 4 — Mats' call.
- **ADR-052 §H/§I pointer wording** — the exact forward-reference note that tells a reader which
  ADR governs the trust anchor (C1).
- **D3 implementation tension** — qualifiers match at paragraph level (Markdown wraps) yet must
  grammatically bind the claim. That discriminator is the hard part and belongs in the ADR.
- **C2 honesty gap** — identity-distinctness is not human-distinctness; document it rather than
  leave it implied.
- **Not posted:** the #148 closure note remains a local draft (S12 — Mats controls public moments).
