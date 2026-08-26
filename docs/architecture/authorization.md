<!-- SPDX-License-Identifier: Apache-2.0 -->

# Authorization over Verified Request Evidence — Implementation Blueprint

ADR-MCPRE-065. The companion discussion carries the normative decision; this file is the
working blueprint, as `communication-assurance.md` is for ADR-MCPRE-063/064.

## 1. Why a new ADR rather than another ADR-MCPRE-064 slice

ADR-MCPRE-064 is **closed**. Its chain ends at admission:

```text
communication relationship
    -> authenticated peer
    -> credential current
    -> request <-> peer bound
    -> admission
    ====================================
    AUTHORIZATION   "may this actor perform this action?"
```

Everything above the line is a statement about a **relationship and a request**. Below it is a
statement about **permission**, which no amount of assurance about the first produces. Letting
ADR-MCPRE-064 absorb it would make that ADR a permanent container for everything downstream,
and would blur the one boundary this architecture exists to keep sharp.

## 2. Characterization — measured on `f85ab96`

### 2.1 Where authorization runs on the RFC 9421 serving path

**Nowhere.** `--authz reference` is refused by configuration validation, and the serving PEP
fails closed if a policy is configured. There is no authorization stage in the pipeline.

### 2.2 What the existing evaluator consumes

**There is no evaluator.** It was deleted, deliberately and by name. `mcp-re-policy`'s own
module documentation records it:

> Deferred: the authorization EVALUATOR, the authorization-object PROFILE, and the REFERENCE
> grant profile are not yet built on the RFC 9421 carrier (files retained); they are rebuilt on
> the RFC 9421 request evidence (`VerifiedMcpRequest.request_block.artifact_bindings`) in a
> follow-up.

"files retained" is stale — commit `eafce60` ("delete all deferred object files") removed them.
What survives is profile-agnostic: the decision/error taxonomy, the authorization-block wire
types, revocation, and the JSON-RPC error surface.

### 2.3 There is no Biscuit code — anywhere

`Biscuit` appears in exactly two places in the tree: a doc comment naming it as a later
pluggable profile, and the crate description. **No dependency, no evaluator, no adapter, no
`ArtifactType` variant.**

ADR-MCPS-013 selected Biscuit for the **native/JCS carrier**, which ADR-MCPRE-050 replaced.

> **Decision (supersedes ADR-MCPS-013 for this path).** ADR-MCPS-013's Biscuit
> production-profile selection **does not carry forward as a normative requirement** for the
> RFC 9421 authorization architecture. Biscuit remains an *admissible* future authorization
> mechanism/profile, alongside others, **behind** the ADR-MCPRE-065 semantic boundary.

That is not a rejection of Biscuit. It is a refusal to design the architecture around an
implementation that does not exist. There is no implementation dependency to preserve: the
carrier ADR-MCPS-013 chose it for is gone, and the authorization block it would have travelled
in belongs to the replaced `_meta`/hash model.

**This is not an incompatibility.** The semantic boundary below is mechanism-neutral, and a
Biscuit token is carriable as an opaque-digest artifact. What it does mean is that the first
implementation slice cannot be "adapt the existing Biscuit evaluator": there is nothing to
adapt, and pretending otherwise would put a fictional dependency at the centre of the design.

### 2.4 The RFC 9421 carrier's authorization-artifact model is OAuth/PDP-shaped

`RequestBlock.artifact_bindings[]` is required and non-empty. Each entry is digest-carrying —
**the digest, never the artifact bytes, is the binding** — across two axes:

```text
artifact_type :  oauth-dpop | oauth-mtls | oauth-rar | pdp-decision
                 dtr-approval | classifier-result | human-approval
binding_type  :  opaque-digest | reference-digest
```

`pdp-decision` is the natural carrier for an externally evaluated decision; `oauth-rar` for a
rich authorization request. Neither is Biscuit-shaped. Whether Biscuit arrives as a new
`artifact_type` or behind `pdp-decision` is a **mechanism** question for the adapter, and the
semantic layer must not require an answer to it.

### 2.5 Legacy inputs that must not be reused

`extract_authorization_block(request: &serde_json::Value)` re-extracts a sibling `_meta` block
from a **raw JSON body** and depends on the native opaque `authorization_hash`. That is the
pre-RFC-9421 model twice over: it reaches past the verifier into representation, and it keys
off a carrier that no longer exists. Authorization must consume `VerifiedMcpRequest`, not a
`Value`.

### 2.6 Request facts the verifier already owns

Available without reconstruction, from `VerifiedMcpRequest`:

| fact | source |
|---|---|
| resolved actor: role, trust_domain, subject, keyid | `resolved_actor().identity` |
| verified audience tuple | `request_block().audience` |
| request evidence digest (the attribution key) | `evidence()` |
| artifact bindings | `request_block().artifact_bindings` |
| outstanding id, continuation | `request_block()` |
| signer slot | `resolved_actor().slot` |

From the ADR-MCPRE-064 chain: `RequestPeerBindingFacts` (same principal) and the admission
decision's prerequisites.

### 2.7 The action coordinate — the finding that matters most

A policy decides over *an action*. The signed body's `method` and `params` are verified facts:
the body is covered by RFC 9530 `Content-Digest`, which the RFC 9421 signature covers. The
`Mcp-Method` / `Mcp-Name` **headers are not** the coordinate — they are routing hints the proxy
never trusts for a security decision.

And they need not agree with the body. The MCP transport contract, which makes `Mcp-Name`
mandatory for `tools/call` / `resources/read` and requires it to match `params.name`, is
`Unconstrained` by default and only becomes `Enforced` when a deployment declares
`--mcp-protocol-version`.

> **Law A-1.** The authorization action coordinate is read from the SIGNED BODY. The transport
> contract exists to stop a header and a body disagreeing in front of a human or a router; it
> is not what makes the coordinate authoritative, and authorization must not depend on it being
> enforced.

### 2.8 Admission's relation to authorization

Admission runs before authorization and, since ADR-MCPRE-064 Slice 5, consumes the
request↔peer binding as a prerequisite. It is therefore **ordered before, and available as an
input**. It is not a substitute: admission answers *may this actor be here at all*, not *may it
do this*.

### 2.9 Is any authorization claim made without a typed decision?

No. `--authz off` is the only deployable value and it claims nothing; the reference profile is
refused; the PEP fails closed on a configured policy. There is no false green to remove — the
gap is honest.

## 3. Architecture law

```text
RequestPeerBindingFacts = "request signer and communication peer are the same principal"
AdmissionDecision       = "this actor/request satisfied admission requirements"
AuthorizationDecision   = "this admitted actor may perform this requested action under
                           this policy"
```

None substitutes for another.

- Binding does not grant permission.
- Admission does not grant application authority unless a policy explicitly says so.
- Authorization may **consume** admission facts; it must not **recreate** them.
- Authorization must not reconstruct peer identity from certificate fields, `TransportIdentity`,
  or raw TLS state.
- Authorization must not reconstruct the request actor from strings where the verifier already
  owns the semantic fact.

## 4. The actor coordinate — resolved

**There is no universal authorization actor coordinate.** Choosing globally between `subject`
and `actor_id()` would repeat the mistake ADR-MCPRE-064 Slice 4 escaped: fixing one comparison
operand for every future proposition, and then bending the facts to fit it.

Authorization instead receives the verifier-established actor facts as a **typed semantic
product**:

```text
VerifiedAuthorizationActor
    role
    trust_domain
    subject
    keyid
```

These are not four independently supplied strings. They **originate together** from the
verified `ResolvedActor`, and callers may not assemble them independently — that is the R-SEAL
obligation for this value, and it is what stops a policy input from being partly verified and
partly asserted.

`actor_id()` remains a **derived canonical projection** of that product, for policies that
intentionally bind to the complete signing actor. It is not a second authority.

The **policy** then selects which verified dimensions its grant semantics depend on:

| policy proposition | dimensions it selects |
|---|---|
| principal-level permission | `subject` |
| credential-specific grant | `subject` + `keyid`, or the canonical `actor_id()` |
| trust-domain scoped role | `role` + `trust_domain` + `subject` |

> **Law A-2.** The authorization boundary supplies verified actor facts; the policy semantics
> select the relevant relation. The architecture does not globally declare that every
> authorization grant is principal-scoped or signing-key-scoped.

This preserves — rather than flattens — the distinctions the layers below established:

```text
request <-> peer binding  ->  subject equality
                              question: "same principal?"

admission assertion       ->  actor_id() equality
                              assertion: "issued to this exact resolved signing actor"

authorization             ->  policy-selected verified actor facts
                              question: "what authority does this policy grant?"
```

## 5. Mechanism boundary

The same shape ADR-MCPRE-063 established for communication mechanisms:

```text
verified semantic prerequisites
        v
mechanism adapter  (Biscuit / PDP decision / OAuth-RAR evaluator)
        v
authorization semantic fact
        v
serving decision
```

Token parsing, caveat evaluation and policy-language details stay **behind** the adapter. The
semantic layer must not oblige every future mechanism to expose Biscuit concepts.

The names in the adapter box are **candidates, not commitments** (§2.3). The recurring shape is:

```text
mechanism  ->  verified semantic facts  ->  explicit relation/decision  ->  typed authority product
```

A mechanism occupies the first box. It does not get to dictate the rest of the graph.

## 6. Desired shape of the product

A success product should make clear:

- **who** was authorized;
- for **what** requested operation/resource;
- under **which policy authority/version**, where that survives evaluation;
- **what** decision was reached;
- what **evidence/provenance** makes the decision attributable;
- what **invalidates** it.

Not a bag of optional values. Whether an `AuthorizationInputFacts` aggregate is one semantic
unit or several typed prerequisites is decided by the first slice's characterization, not by
symmetry with the layers below.

## 7. Slice 1 — the boundary and the production control point

Slice 1 establishes the architecture and the place in the serving path where authorization
decides. It does **not** invent a production evaluator in order to reach a green `Allow`.

```text
VerifiedMcpRequest
      |
      +-- VerifiedAuthorizationActor        (typed, originating together)
      +-- VerifiedAuthorizationAction       (from the signed body — Law A-1)
      +-- admission / binding prerequisites (carried whole, not re-decided)
      v
AuthorizationEvaluator boundary
      v
AuthorizedRequestFacts  |  AuthorizationRefusal
      v
dispatch, only from AuthorizedRequestFacts
```

Dispatch must depend on the authorization result **structurally** — the same obligation
ADR-MCPRE-064 Slice 5 met for admission. A result that is computed and then ignored is a
descriptive value, not a control.

### 7.1 Posture must stay honest

`Off` is not `Allow`. Three postures, not two:

| posture | meaning |
|---|---|
| **not configured** | no authorization policy is deployed; the architecture claims nothing |
| **authorized** | a policy evaluated these verified facts and permitted this action |
| **refused** | a policy evaluated these verified facts and denied, or evaluation could not be completed |

This is the same three-state discipline as `CredentialCurrencyOutcome`: "nobody asked" is not
"asked and satisfied", and collapsing them manufactures an authorization claim nobody made.

Where a policy **is** configured and no production evaluator exists for it, the path continues
to **fail closed**, exactly as Layer-A validation already refuses the superseded reference mode.

### 7.2 How dispatch depends on the decision

Not by ordering, and not by a comment. The inner dispatch consumes a `ReadyForDispatch` —
the type ADR-MCPRE-058 §9.3 already defines as *every pre-dispatch prerequisite, in hand* —
and since this slice the body it carries is an `AuthorizedRequestBody`, whose only producer
is `AuthorizationPosture::release`. A pipeline that dropped the authorization stage does not
become a subtly weaker proxy that still compiles; it fails to compile at the dispatch.

The first attempt added an `Authorized` state to the ADR-MCPRE-057 request machine instead.
That is a weaker enforcement — an illegal transition latches an anomaly and degrades the
retry contract, but it does not stop the dispatch — and `exchange_state.rs` is a reviewed
ADR-MCPRE-061 §14 exception already at its debt baseline, which a ratcheted file may not
grow whatever its status. The threshold did its job: it forced the question, and the answer
was a better mechanism rather than a smaller comment.

`release` is consuming, so one decision releases one body: a path cannot take a single
decision and dispatch twice under it.

**What possession does not claim.** `NoPolicyConfigured` releases a body too. The gate is
about the decision having been TAKEN, which is what the ordering is about; the content of
the decision stays in the posture.

### 7.3 The evaluator used to prove the boundary

A reference/conformance evaluator may be used to demonstrate the semantic boundary and to drive
the positive and negative controls through the production request path. It **must not silently
become the accepted production authorization authority** — a test needing an allow path is not
a reason to promote one.

Slice 1 therefore introduces **no** Biscuit, UCAN, OPA, Cedar or PDP protocol. Selecting and
implementing the first production mechanism is the next bounded piece of work, chosen *under*
this architecture rather than defining it.

## 8. Slice 2 — the first production mechanism: carried PDP decisions

Not Biscuit, and not the deleted reference evaluator. An **external authorization authority**
decides; MCP-RE enforces. That exercises the boundary without making MCP-RE a policy-language
product, and it composes with OPA, Cedar, an enterprise PDP or cloud IAM through one shape:
normalized decision evidence in, enforcement before dispatch.

### 8.1 The `artifact_type` × `binding_type` product does the work

`docs/spec/ema-composition.md` had already assigned `pdp-decision`, to the LINKAGE role. It
is not overruled — it is joined by the other form, which is what the two independent axes
were for:

```text
pdp-decision + reference-digest   =  decision LINKAGE
                                     the call names an external decision; MCP-RE neither
                                     authenticates nor interprets it, and an EMA-native
                                     backend remains the enforcement point.
                                     Produces NO AuthorizedRequestFacts.

pdp-decision + opaque-digest      =  decision EVIDENCE
      + inline authorization_decision JWS
                                     the decision travels with the request; MCP-RE
                                     authenticates and enforces it. Mode 2.
```

`ArtifactBinding::validate` has always permitted both combinations. The note simply had one
consumer and tabulated one row.

**One correction to that note.** Its Mode-1 language overstated what a reference binding
buys: MCP-RE cannot say it prevented a forged decision, because it holds no decision artifact
and no authority signature. It can say the reference and digest were integrity-bound into the
signed call.

### 8.2 The chain, and why each link is separate

```text
digest correspondence      exactly these bytes, exactly one applicable binding
        v
authorization-authority trust   its OWN seam, never inferred from request-signer trust
        v
JWS authentication + typed claims
        v
actor relation             at the scope the decision itself declares
        v
action relation            the signed-body coordinate (Law A-1)
        v
explicit Permit
        v
AuthorizedRequestFacts
```

Digest matching is not authorization. A valid signature is not authorization. A matching
actor and action are not authorization until the decision says permit. Collapsing them would
make the failure unreportable, and every link is a different thing for an operator to do.

### 8.3 The scope is a closed, signed choice

```text
principal   ->  trust_domain + subject          survives a signing-key rotation
credential  ->  trust_domain + subject + keyid  voided by one
```

A sum type tagged inside the signed claims, not a struct with an optional `keyid`. So a
principal-scoped decision has no keyid to omit, a credential-scoped one cannot lack it, and
one document cannot mean a principal grant at one deployment and a credential grant at the
next. **Configuration declares what it ACCEPTS; the decision declares what it IS.**

This is Law A-2 exercised by a profile, not a reversal of it.

### 8.4 What a success product means, and what it does not

> A configured and trusted authorization authority permitted this verified actor to perform
> this verified action, and this decision evidence is bound to this request under the
> configured profile.

It does **not** mean transport peer authentication happened (ADR-MCPRE-064 owns that),
admission succeeded (admission owns that), the authority is currently online, or that policy
has not changed since — unless freshness semantics establish it. Carrying the decision rather
than resolving a reference is what keeps *the PDP is reachable* out of the proposition.

### 8.5 Indeterminacy is local, not signed

The decision carries `permit` or `deny` and nothing else. An evaluator that cannot verify a
signature, resolve an authority key, parse claims or determine freshness has produced a LOCAL
refusal — it is not a proposition the authority signed, and inventing an `indeterminate`
outcome for it would put words in the authority's mouth.

### 8.6 A split file must be re-declared to the verification manifest

Extracting `ArtifactBinding` into its own module carried Verus annotations to a path no
verification unit declared. Nothing in the Rust toolchain reports that: the crate compiles,
the tests pass, clippy is clean, and the proved unit silently narrows. The standing rule is
recorded as [`verification/README.md`](../../verification/README.md) rule 16 — moving
formally annotated code moves its verification-unit, fingerprint, and trigger-set ownership
with it.

## 9. Slice 3 — the client/SDK production surface

Slice 2 shipped a mechanism the language SDKs could not conveniently produce evidence for.
The typed Rust producer already owned the invariant; this slice gives Python and TypeScript
the same one, and removes the construction that could only ever be refused.

### 9.1 One semantic operation, two contributions

```text
decision document
      |
AuthorizationDecisionProvider          (Python / TypeScript)
      |  spec: {artifact_type: pdp-decision, form: authorization-decision, material}
      v
build_authorization                    (mcp-re-client-core — ONE implementation)
      |
      v
RequestSigningInputs::with_authorization_decision
      |
      +--> inline `authorization_decision`
      +--> derived `pdp-decision` / `opaque-digest` binding
```

No API anywhere accepts a document together with an independently supplied digest. A caller
able to supply both could commit to one document and carry another, and the digest is the
only thing tying them together.

### 9.2 The generic opaque provider may not mint `pdp-decision`

The distinction is the FORM, never the token:

| form | `pdp-decision` |
|---|---|
| `opaque-bytes` | refused — the binding half of a pair, which a Mode-2 verifier necessarily rejects |
| `authz-system-reference` | legal, unchanged — Mode-1 external decision LINKAGE |
| `authorization-decision` | legal — the document, whose binding the seam mints |

Refusing the *token* would take the reference form with it, so the control is written over
the pair and a structural test pins that.

### 9.3 The enforcement owner is the conversion, not the wrapper

The rule lives in `mcp-re-client-core::binding_spec`, which the PyO3 and N-API layers both
call. The spec JSON is itself a public seam: a guard in the Python or TypeScript wrapper
class alone would be cosmetic, because a caller composing that JSON walks straight past it.
One implementation is also what keeps the two languages from drifting apart on a security
rule — two copies agree only until one is edited.

The wrapper classes still reject early, for ergonomics. Both layers are held by separate
controls, because they are separate routes.

### 9.4 What the narrowing removes

Nothing enforceable. A `pdp-decision`/`opaque-digest` binding with no document is a
composable block — the profile permits it — that a configured decision profile refuses with
the backend never called. The producer now refuses what the enforcement point already
refused; it does not invent a rule.

## 10. Deferred, deliberately

- **ADR-MCPS-035 audit vocabulary** — not widened here. Which authorization facts belong in the
  audit record is decided once a semantic product exists.
- **The verified-context wire schema** — not changed here. Committing a representation before
  knowing which facts downstream consumers need is the mistake this ordering avoids.

Both follow the authorization model; neither precedes it.

## 11. Production wiring — the composition root installs the authority

Sections 7–9 established the boundary, the mechanism and the client surface. None of them
made the mechanism *selectable*: the single production composition root (`app::run_validated`)
never called `with_authorization`, no configuration value named the PDP profile, and the
trust document's `authorization-issuer` slot had a reader for what it EXCLUDED and none for
what it enrolled. Measured on `93a3bd4`, that was the whole remaining distance between the
implementation and a deployment.

```text
--authz pdp-decision
  + --authz-decision-scope        Law A-2: what this deployment ACCEPTS
  + --authz-max-decision-age-secs the enforcement point's own staleness bound
  + --trust  "slots":["authorization-issuer"]
        v
config_state::authorization      Off | PdpDecision { scope, max age }
        v
authorization::capability        reads the slot, builds the resolver, one posture line
        v
app::run_validated               with_authorization(...) + Seam::Authorization
```

### 11.1 There is no permissive mode, and that is §7.1 rather than an omission

A `pdp-decision` deployment refuses a request carrying no applicable decision. §7.1 gives
authorization three postures, and a deployment that has configured an authority has left
*not configured*; letting an undecorated request through would create a fourth —
*policy configured but not enforced for this request* — which is the `Off`/`Allow`
ambiguity the three postures exist to remove. The analogy with admission's
`Optional | Required` does not carry: that optionality was constituted as part of
admission's semantics, and this ADR constituted a different algebra. A migration or shadow
posture, if ever needed, is a separately named non-enforcing posture with its own audit
semantics — never a weaker reading of this one.

### 11.2 What the startup line has to admit

Authorization authorities are read ONCE, at startup. `--trust` has a reload path and this
does not use it, so withdrawing an authority takes effect at the next restart. The ON line
states that rather than leaving an operator to assume the trust-store cadence covers it.
A configured profile whose trust document enrols no authority **refuses to start**: it
would otherwise refuse every call while its transcript announced enforcement.

### 11.3 Mechanism-specific evidence identity is still deferred

ADR-MCPRE-066 Slice 1 records no decision-evidence identity in `Authorized` attribution,
noting that the first production mechanism might supply one. It does not yet:
`BoundDecisionEvidence` is sealed over the decision DOCUMENT and does not retain the digest
its binding committed to, so projecting one would mean recomputing it or reopening the
request's evidence block at the audit site — re-derivation, which invariant 5 forbids. The
authenticated `jti` claim is the honest candidate, and taking it would widen the §5 seam's
success product (`GrantAttribution`). That is an ADR decision, not a wiring one.
