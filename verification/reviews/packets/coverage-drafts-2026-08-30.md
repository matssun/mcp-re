<!-- SPDX-License-Identifier: Apache-2.0 -->

# Step D — the two coverage holes, drafted

Candidate propositions for the two authorities the registry does not cover. **These are
drafts for the consolidated owner review, not registered theorems**: no `THM-` id is
allocated, nothing is added to `theorems.toml`, and no evidence is claimed for any of them.

The rule followed throughout: *state propositions at semantic-owner granularity, never one
theorem per module.* ADR-MCPRE-065 has five source files and yields **three** candidates;
SCITT has eighteen modules and yields **four**, because its own module documentation already
names seven lettered authorities and several of them compose into one public result.

---

## D1 — ADR-MCPRE-065 / PDP-decision authorization

The registry's real coverage hole: the newest security authority is the one with no theorem
and no evidence, and it is the mechanism that falsified THM-0008.

The chain the implementation itself draws (`pdp_decision/binding.rs`):

```
digest correspondence          <- THM-0008 / THM-0015 already
       ↓
authority trust + JWS authentication      <- D1-A
       ↓
actor relation
action relation                            <- D1-B
audience + validity
       ↓
explicit Allow                             <- D1-B's last conjunct
```

Each step earns the next proposition, and the split between "what did the authority say"
and "is that about this request" is deliberate — it mirrors
`verify_admission_assertion` / `check_admission` exactly.

### D1-A — *An authenticated decision was issued by a trusted authority for this enforcement point*

**Candidate owner:** a new unit over `pdp_decision/{verify,claims}.rs`.
**Public result:** `PdpDecisionClaims` returned by `verify_authorization_decision`.

> If `verify_authorization_decision` returns Ok, then the document is a well-formed compact
> JWS whose `typ` and `alg` are the profile's, whose header and claims agree about the
> issuer kid, whose signature verified under the key the trust seam resolved for that kid,
> which was issued for this evidence profile, which names this enforcement point in its
> audience, whose `[nbf, exp]` window contains `now` within the configured skew, which was
> not issued in the future, and which is no older than this deployment's own cap.

**Security consequence.** A kid never introduces trust: an issuer the deployment does not
configure is refused rather than resolved. A decision issued for another profile or another
enforcement point cannot be replayed here. And the staleness cap is the *verifier's* — a
long-lived decision is the issuer's choice, how long this PEP will act on one is not.

**Scope.** Establishes nothing about the request in hand. A decision may be perfectly
authentic and about a different actor, a different operation, or a different target;
relevance is D1-B. It establishes nothing about whether the authority *should* be trusted —
only that the seam answered for that kid.

### D1-B — *An authorized request was permitted by a decision about that very request*

**Candidate owner:** a new unit over `proxy/authorization/pdp/{relation,policy,refusal}.rs`.
**Public result:** `AuthorizedDecision` returned by `AuthorizationEvaluator::evaluate`.

> If the PDP evaluator returns Ok for an `AuthorizationRequest`, then D1-A holds for the
> decision it consumed; the decision's declared scope equals the scope this deployment
> accepts; the decided actor equals the request's verified actor on every dimension that
> scope names — trust domain and subject always, keyid additionally under credential scope;
> the decided operation equals the operation the SIGNED BODY named and the decided target
> equals the signed target, with *absent* matching neither a named target nor a
> not-applicable one; and the decision's own outcome was `Permit`.

**Security consequence — the one with no registered theorem today.** *A decision is not a
bearer token.* Without the actor relation, anyone whose key the PEP resolves — a
lower-privilege tenant, a compromised sibling workload, anything that read one authorized
request body or request log — could copy an authorized peer's decision into their own signed
evidence block and be authorized by it. The gate would then prove *some principal was
permitted this action*, not *this caller was*. The action relation is the same argument one
axis over: a decision for `tools/list` cannot authorize `tools/call`.

**Scope.** It is authorization and not admission, authentication, or channel binding. It
does not establish that the actor coordinates on the request were correctly resolved — that
is the verified-request claim's (THM-0015 and the communication family). It says nothing
about what happens after the grant.

**Note for the reviewer.** This claim is the closest thing in the registry to a *relation*
theorem, and its honesty depends entirely on `request.actor()` and `request.action()` being
verified facts rather than reconstructed ones. Law A-1 says the action comes from the signed
body; that is what makes D1-B worth stating and what its evidence must actually measure.

### D1-C — *Every refusal names the authority that refused* (candidate, weaker)

**Candidate owner:** the same unit as D1-B, or `refusal.rs` as its own.

> Each refusal renders onto its own frozen `mcp-re.authorization_*` wire token, and no
> refusal is reported as another: an untrusted issuer, a bad signature, a wrong profile, a
> wrong audience, an expired decision, a stale one, a scope the deployment does not accept,
> a different actor, a different action, and an explicit deny are ten distinguishable facts.

**Security consequence.** An operator can tell a rollout problem from an attack. Flattening
them onto one "unauthorized" is how an untrusted issuer during a key rotation reads as a
forged signature — and the reverse.

**Precedent, and the reason it is offered as a candidate rather than a recommendation.** The
registry already has faithful-reporting claims: THM-0024's five distinguishable refusals and
THM-0025's three, both explicitly *"a claim about faithful reporting, not about admission"*.
So the shape is established. What is not obvious is whether it earns a theorem here, given
that issue #637 records that `AuditEvent.reason` has a **fourth producer the drift guard
never scans** and that the ADR-065 product has **zero production readers**. Registering a
faithfulness claim over a vocabulary nothing reads would be a theorem about an unobserved
value.

> **Left for the owner review.** D1-C has two materially different plausible readings —
> a claim about the *refusal algebra* (true today, cheap to evidence) or a claim about
> *what an operator actually observes* (false today, per #637). Both are recorded; neither
> is recommended.

---

## D2 — SCITT / transparency after the authority split

`scitt.rs` is gone; eighteen modules under a facade, with the module documentation naming
**seven lettered authorities A–G**. #657 ruling 6 forbade writing entries over the
monolith and required the boundaries first. They now exist, so drafting is unblocked.

The public surface is small — `verify_receipt_offline`, `verify_retained_evidence`,
`issue_signed_statement` — and that is what the propositions are stated over, not the
modules.

### D2-A — *An offline-verified receipt proves registration, and its root was never supplied*

**Candidate owner:** a unit over `offline.rs` + `receipt/` + `merkle.rs` + `cose_key/` +
`service.rs` (authorities C, D, E and the composition).
**Public result:** a successful `verify_receipt_offline`.

> If `verify_receipt_offline` returns Ok, then: the statement's own `Sig_structure`
> verified under a key resolved for its issuer kid; the receipt is a well-formed RFC 9942
> §5.2.1 receipt; running the RFC 9162 §2.1.3.2 inclusion algorithm over the statement's
> leaf hash at the receipt's leaf index and tree size produced a root that, for an ATTACHED
> receipt, equals the root the receipt commits to and, for a DETACHED one, *is* the payload
> the transparency-service signature was checked against; and both signatures verified under
> keys whose algorithm the protected header names. No network was contacted.

**Security consequence.** The root is **derived from the statement under verification and
never supplied by the caller** — on either payload form. A receipt cannot be made to verify
by handing in a convenient root, and on the detached form a wrong fold produces a different
`Sig_structure` so the signature simply fails. An auditor can check the record existed
without trusting the log to replay honestly and without contacting it.

**Scope.** It establishes registration on *a* service whose key was resolved, not that the
service is honest, append-only, or unique. It says nothing about the call the statement
describes — that is D2-B. It is offline verification, so it establishes nothing about the
current state of any log.

### D2-B — *Retained evidence is the evidence the statement was made about*

**Candidate owner:** a unit over `commitment/` + `retained.rs` (authorities A and F).
**Public result:** a successful `verify_retained_evidence`.

> If `verify_retained_evidence` returns Ok, then the commitment the statement carries
> equals the commitment recomputed from the presented reconstruction and its optional
> binding and verified-context commitments — so the retained bytes are the ones that
> statement committed to, and the `ChainLabel` the statement embeds is the label of that
> reconstruction.

**Security consequence.** Retained evidence cannot be swapped under a receipt, and **a
receipt can never make a truncated call look whole**: the label it commits to says which hop
was missing, so COMPLETE and explicitly-INCOMPLETE records stay distinguishable in the
verified statement. Revealing a receipt discloses nothing, because it carries digests and
not the call.

**Scope.** Correspondence only. It does not establish that the retained bytes are
*themselves* valid evidence, that the call happened, or that the reconstruction is complete
— only that whatever was reconstructed is what was committed to.

### D2-C — *A statement cannot attribute itself to a party that did not sign it*

**Candidate owner:** a unit over `statement/` + `wire.rs` (authority B).
**Public result:** an accepted `SignedStatement`.

> An accepted Signed Statement carries the RFC 9943 §6.1 CWT claims in the PROTECTED
> header with `iss` equal to the signing kid, `sub` equal to `STATEMENT_SUBJECT`, and the
> `STATEMENT_CONTENT_TYPE` content type.

**Security consequence.** A statement cannot attribute call evidence to a party other than
the key that signed it, and **no other `COSE_Sign1` the issuer key produces can be read as
MCP-RE call evidence** — the subject and content type are what separate them.

**Scope.** Attribution and shape only. Nothing about registration (D2-A) or about the
evidence committed to (D2-B).

### D2-D — *Algorithm agreement is decided before any signature is attempted*

**Candidate owner:** `cose_key/` (authority E), possibly folded into D2-A.
**Public result:** a `CoseVerificationKey` accepted for a header.

> Only EdDSA and ES256 are attempted. Any other `alg` is refused rather than attempted, and
> the resolved key's algorithm must equal the one the protected header names.

**Security consequence.** Algorithm confusion is refused rather than attempted — the same
proposition the RFC 9421 floor already carries as THM-0014's algorithm conjunct, here for
COSE.

**Whether this is its own theorem is a granularity decision for the owner.** The precedent
cuts both ways: THM-0025 is separate from THM-0026 on exactly this pattern (a value-level
encoding claim beneath a relation claim), which argues for separating it; but `cose_key` has
no public result of its own outside D2-A's composition, which argues for folding it in.

### The two questions #657 left open, still open

Neither is resolved here, and both must be settled before any D2 unit is registered,
because each changes what a theorem over `prototype` or `receipt` would mean:

1. **`PrototypeTransparencyService`'s classification.** It is `pub` and re-exported at the
   crate root with zero production callers, kept because "zero production callers is not a
   deletion argument" (ruling 4). A theorem over its tree is either a claim about an MCP-RE
   product surface or a claim about a test fixture, and those are materially different
   security meanings. **Recorded, not decided.**
2. **`ReceiptPositionProfile::Bound` selectability.** Unchanged since #657.

Note also that the two RFC 9162 implementations stay two on purpose (ruling 3):
`prototype` builds a tree, `merkle` verifies a path, and they are an independent
cross-check. Any D2 theorem must not quietly assume they are one.

---

## What was deliberately not done

* No `THM-` identifier allocated for any of the seven candidates.
* Nothing added to `theorems.toml`, `verification.toml`, or `mutation-probes.toml`.
* No evidence claimed. Several candidates would need new controls before they could be
  registered at all — D1-B in particular, whose honesty depends on measuring that
  `request.actor()` and `request.action()` are verified rather than reconstructed facts.
* D1-C and the two #657 questions are recorded with both readings and no recommendation,
  because each has two materially different plausible security meanings.
