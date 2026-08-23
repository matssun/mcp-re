<!-- SPDX-License-Identifier: Apache-2.0 -->

# Communication Assurance — Implementation Blueprint

**Governing ADR:** [ADR-MCPRE-063](https://github.com/matssun/mcp-re/discussions/601) — ✅ Accepted 2026-08-22; the Discussion is the source of truth.
**Constitutional parent:** [ADR-MCPRE-061](https://github.com/matssun/mcp-re/discussions/567)
**Assurance/evidence framework:** ADR-MCPRE-059
**Current mechanism-specific lifecycle:** ADR-MCPRE-062

## 1. Purpose

This blueprint turns ADR-MCPRE-063 into an executable migration story.

The goal is not to invent a generic security framework and not to complete a flag-day rewrite. The goal is to establish a small set of semantic authorities whose products compose in specific legal positions, then migrate existing code one vertical slice at a time.

The historical `tls.rs` module is an input to the migration, not the target architecture.

## 2. Design vocabulary

The architecture uses semantic names:

- certificate-chain evidence;
- cryptographic peer-key evidence;
- kernel credential evidence;
- hardware-attestation evidence;
- delegated-credential evidence;
- peer-identity evidence;
- verified peer facts;
- relationship facts;
- channel-binding evidence;
- assurance facts;
- admission facts;
- authority decisions.

Specific technologies are implementation mappings. They are documented only where they establish or consume one of these products.

## 3. Target conceptual hierarchy

```text
communication_assurance
|
+-- evidence
|   +-- representation
|   +-- provenance
|
+-- verification
|   +-- evidence validity
|   +-- evidence freshness
|   +-- evidence coherence
|
+-- interpretation
|   +-- peer identity
|   +-- subject / role-neutral facts
|
+-- relationship
|   +-- peer relationship facts
|   +-- channel/link facts
|
+-- assurance
|   +-- strength
|   +-- freshness
|   +-- provenance class
|
+-- binding
|   +-- channel/request binding
|   +-- evidence/fact binding
|
+-- admission
|   +-- relationship admission
|   +-- policy combination
|
+-- mechanisms
    +-- implementation adapters only
```

This is a semantic hierarchy, not a commitment to these exact directories.

## 4. Legal composition model

The normal direction is:

```text
Evidence
  -> Verified Evidence
  -> Interpreted Facts
  -> Relationship Facts
  -> Assurance / Binding
  -> Admission / Authority
```

Not every use case needs every stage, but skipped stages must be deliberate and owned.

Illegal shortcuts include:

```text
raw certificate bytes -> authorization
HTTP header           -> authenticated peer
kernel UID             -> authority decision
public key             -> trusted entity
```

unless a specifically reviewed authority owns exactly that direct proposition.

## 5. Current-code mapping

The current EX-004 census is reinterpreted as migration evidence rather than a list of next refactors.

### Identity extraction

Current location: `mcp-re-proxy/src/tls.rs`

Current proposition:

> Under an explicit certificate identity-field policy, interpret a leaf certificate as one identity value and provenance source; do not fall back to another field when the selected field is absent or malformed.

Target semantic authority:

> certificate-chain evidence -> peer-identity evidence

Mechanism-specific part:

- DER / X.509 parsing;
- SAN / CN representation extraction.

General semantic part:

- selected source is authoritative;
- no fallback;
- peer identity value invariant;
- source provenance preserved.

### CRL posture

Current location: `mcp-re-proxy/src/tls.rs`

Candidate target:

> certificate-chain evidence verification / revocation-evidence evaluation

Do not migrate until its exact input/output proposition is designed. It may be subordinate to a broader verified-certificate-evidence authority rather than a peer module.

### Per-request peer admission

Current location: `mcp-re-proxy/src/tls.rs`

Candidate target:

> verified peer/relationship facts + current evidence/state -> relationship admission

This is not assumed to belong under the certificate mechanism. It is deliberately deferred until lower products exist.

### Delegated resolver validation

Current location: `mcp-re-proxy/src/tls.rs`

Candidate target:

> delegated-credential evidence + cryptographic peer-key evidence -> verified credential/key correspondence facts

Its current Ed25519/X.509 details remain mechanism-specific beneath the general proposition.

### Header hygiene

Current location: `mcp-re-proxy/src/tls.rs` / transport boundary

Candidate target:

> ingress metadata hygiene

This likely belongs outside communication evidence entirely. Do not place it under `communication_assurance` merely because it is currently evaluated near a communication boundary.

### Serving options record

Current location: `mcp-re-proxy/src/tls.rs`

Candidate target:

Split only after ownership analysis. It is likely a composition/configuration vocabulary spanning several semantic authorities rather than one new authority.

## 6. Migration principles

1. Design the semantic product first.
2. Write the contract and refusal algebra before moving implementation.
3. Separate foreign parser/I/O boundaries from the pure semantic transform where useful.
4. Move the semantic ownership, not merely the source lines.
5. Keep compatibility facades only where required by current consumers.
6. Compatibility facades must delegate; they must not retain duplicate semantics.
7. Do not force all downstream consumers to migrate in the same slice.
8. Re-run architectural census after meaningful migrations, but do not use LOC to invent the next slice.
9. Every new product gets an evidence/theorem scope before higher composition relies upon it.

## 7. Slice definition

A slice is vertical when it completes one semantic transformation:

```text
Input product
    -> authority
Output product / refusal
```

A slice is NOT required to:

- start at CLI;
- reach a socket;
- reach an application handler;
- replace every legacy consumer;
- demonstrate a new user-visible feature.

A completed slice must be independently testable and reviewable. Where formal verification is applicable, it must have a precise theorem boundary and explicit external assumptions.

## 8. Slice 1 — Certificate-chain evidence to peer-identity evidence

### 8.1 Objective

Create the first production-quality communication-assurance block:

```text
CertificateChainEvidence
        |
        v
CertificateIdentityInterpreter
        |
        +-- success -> CertificatePeerIdentityEvidence
        |
        +-- refusal -> CertificateIdentityRefusal
```

This slice is the proving ground for ADR-MCPRE-063.

### 8.2 Semantic claim

The authority establishes only this proposition:

> Given certificate-chain evidence and an explicit certificate identity-selection policy, the selected certificate identity field denotes this well-formed peer-identity evidence value with this provenance.

It does NOT establish:

- that the certificate chain is trusted;
- that the chain is unrevoked;
- that the evidence is fresh;
- that the peer is admitted;
- that the peer is authorized;
- that a network channel exists;
- that possession of the output implies any higher assurance product.

### 8.3 Proposed products

Names are provisional but semantics are not.

```text
CertificateChainEvidence
  - leaf representation / leaf bytes
  - optional presented intermediates

CertificateIdentityPolicy
  - URI_SAN
  - DNS_SAN
  - COMMON_NAME_LEGACY

PeerIdentityValue
  invariant:
    - non-empty after normalization
    - bounded length
    - no control characters

CertificateIdentitySource
  - URI_SAN
  - DNS_SAN
  - COMMON_NAME

CertificatePeerIdentityEvidence
  - value: PeerIdentityValue
  - source: CertificateIdentitySource
```

Do not put `trusted`, `authenticated`, or `authorized` in these names.

### 8.4 Refusal algebra

At minimum:

```text
CertificateIdentityRefusal
  - NoLeaf
  - MalformedCertificate
  - SelectedFieldAbsent
  - SelectedFieldMalformed
```

If the parser exposes a distinction between malformed evidence representation and unsupported representation, preserve it only if downstream review/test/assurance needs the distinction.

Do not use `Option` as the authoritative result.

### 8.5 No-fallback invariant

The configured field is authoritative.

Examples:

```text
policy = URI_SAN
URI SAN absent
DNS SAN present
=> SelectedFieldAbsent
```

and:

```text
policy = URI_SAN
first URI SAN malformed
second URI SAN valid
=> SelectedFieldMalformed
```

The implementation must not search for a weaker or later value after the authoritative selected value has failed.

### 8.6 Parser boundary

Do not attempt to prove an ASN.1/X.509 parser merely to prove the selector.

Recommended internal shape:

```text
DER bytes
  -> foreign/mechanism parser boundary
CertificateIdentityFields
  -> pure semantic selector
CertificatePeerIdentityEvidence
```

The parser boundary is recorded as ASSUMED or UNSUPPORTED under ADR-MCPRE-059 as appropriate. The pure selector/value invariants should be formal-verification candidates.

### 8.7 Existing code to migrate

Current semantic source:

- `mcp-re-proxy/src/tls.rs::extract_identity`
- the `IdentityPolicy` / `IdentitySource` semantics currently in `mcp-re-proxy/src/transport.rs`
- the generic value-shape rule currently misleadingly named `validate_asserted_identity_value`

The key architectural correction is that the peer-identity value invariant must be owned once. Certificate-derived evidence and asserted ingress evidence may both consume it; neither provenance owns the generic invariant.

### 8.8 Compatibility plan

During slice 1:

- keep existing public `TransportIdentity` / `extract_identity` APIs where required;
- convert them into compatibility adapters delegating to the new authority;
- no duplicate selector or value-validation implementation may remain;
- do not migrate all transport-binding consumers in this slice.

The legacy facade may map `CertificatePeerIdentityEvidence` to the existing `TransportIdentity` type until a later slice migrates consumers.

### 8.9 Test obligations

Positive controls:

- URI SAN selected and valid;
- DNS SAN selected and valid;
- CN legacy selected and valid;
- provenance source preserved;
- valid boundary-length identity accepted.

Negative controls:

- no leaf;
- malformed certificate;
- selected field absent while another field exists;
- selected field malformed while another field exists;
- first matching selected value malformed while a later matching value is valid;
- empty value;
- over-length value;
- control-character value.

Property tests must assert the refusal or semantic product, not merely a final TLS/request outcome.

### 8.10 Mutation obligations

At minimum mutations should demonstrate that these are load-bearing:

- fallback to another field;
- fallback to a later matching field;
- value validation bypass;
- source provenance substitution;
- selected-policy substitution.

A probe passes only when a declared target-qualified control goes red.

### 8.11 Formal-verification candidates

Pure selector theorems:

1. success source equals configured source;
2. success value satisfies `PeerIdentityValue` invariant;
3. selected-field absence cannot return success;
4. selected-field malformed cannot return success;
5. failure of selected source does not select another source;
6. successful result is deterministic over the interpreted field set and explicit policy.

The theorem must be scoped to successful return from the named selector operation. Do not claim arbitrary possession of a public product proves provenance unless construction closure is separately established.

### 8.12 Dependency constraints

The new semantic block must not depend on:

- MCP request/response types;
- HTTP headers;
- application dispatch;
- `rustls::ServerConnection`;
- listener lifecycle;
- admission policy;
- authorization policy.

A mechanism adapter may depend on the X.509 parser needed to produce the interpreted field representation.

### 8.13 Completion criteria

Slice 1 is complete when:

- one semantic authority owns certificate identity interpretation;
- one canonical peer-identity value invariant exists;
- refusal reasons are explicit;
- no fallback is structurally and behaviorally pinned;
- parser boundary and proof boundary are explicit;
- tests and mutation probes establish the intended properties;
- formal proofs cover the pure semantic selector where feasible;
- existing TLS behavior is preserved by a compatibility adapter;
- `tls.rs` no longer owns the selector semantics;
- no end-to-end migration claim is made.

## 8.14 Slice 1 as built — what the design met, and where it moved

Recorded here rather than only in the issue, because the deltas are the reusable part.

**The products, as they exist.** `CertificateChainEvidence` (the adapter's input),
`CertificateIdentityFields` (the representation seam), `CertificateIdentityPolicy` /
`CertificateIdentitySource` (two types, not one), `PeerIdentityValue` (the sealed generic
invariant), `CertificatePeerIdentityEvidence` (the product), `CertificateIdentityRefusal`
(one algebra, five variants). Registered as `unit://proxy.peer_identity_value` and
`unit://proxy.certificate_identity`; claimed as THM-0023 and THM-0024; the parser is
ASM-0030.

**Three things the design did not anticipate.**

1. **The design said "one algebra"; the code wanted two owners for it.** `NoLeaf` and
   `MalformedCertificate` can only arise in the adapter, and `SelectedFieldAbsent` /
   `SelectedFieldMalformed` only in the pure selector. They are kept in ONE enum per §8.4,
   with each variant documenting which authority produces it. Splitting them would have
   made the caller compose two refusal types to answer one question. The rule this
   suggests for later slices: an algebra follows the QUESTION, not the layer that answers
   each part of it.

2. **`CertificateChainEvidence` carries no intermediates.** §8.3 offered "optional
   presented intermediates" and the slice consumes none: identity is a property of the
   leaf. A field nothing reads is a claim about ownership that no code backs, and
   intermediates are the input of chain verification — an authority that does not exist.
   They enter the representation when that authority does.

3. **The generic value invariant had THREE consumers, not two.** §8.7 named the
   certificate path and the asserted-ingress path. `validate_routing_headers` is a third:
   it applies the identity rules to `Mcp-Method` / `Mcp-Name`, which are not identities at
   all. It still calls the facade, so there is no second implementation, but a routing
   header borrowing the peer-identity invariant is a mis-ownership this slice deliberately
   did not fix. It belongs to ingress hygiene, which §5 already places outside
   communication evidence.

**The measurement that justified the negative controls.** A selector rewritten to skip an
unusable first SAN and take the next left all 93 tests of the plain integration binary
green. The later-value half of the no-fallback law was protected by nothing, because every
existing negative minted a certificate with no other value to fall back to. Controls were
therefore written FIRST, against the unmigrated code, and each was verified to go red under
a deliberate weakening before any ownership moved. That order is the transferable part: a
control written after the migration proves the migration self-consistent, not the property.

**What the slice deleted.** `tls.rs` lost 26 production lines and `transport.rs` 31, and
both debt baselines were ratcheted down. What went is the selector, the value validator's
second implementation, and `tls.rs`'s reach into `x509_parser::extensions::GeneralName` —
the mechanism import that made identity extraction look like a TLS responsibility.

### 8.15 Two implementation laws Slice 1 established

**L-1. A pure semantic helper may be independently testable and formally verifiable
without being a public composition edge. Public visibility is part of the legal authority
graph, not a testing convenience.**

Slice 1's first implementation exported both the field-set type and the pure selector,
because both are unit-tested and both are the proof candidates. That made a second entrance
into the block: a caller could fabricate a field set and interpret it into evidence without
ever presenting a certificate. The theorem survived it — the theorem is scoped over the
selector — but the connector did not, and §5 makes the connector the type, not the prose.
Both are now private to the authority tree, and the one public route is
`CertificateChainEvidence::interpret_identity`.

**L-2. An adapter may not convert "present but uninterpretable" into "absent".**

The refusal algebra a block declares is a claim about what its adapter can tell apart. Slice
1's adapter wrote `.ok().flatten()` over the SAN query — the natural spelling — which turns
every parser error into an empty field list, so a peer whose issuer minted a malformed or
duplicated SAN extension was reported as a peer that presented no such field. Both refuse,
so nothing was admitted either way; what was lost was which fact the refusal RECORDS.

The general form: a refusal algebra more precise than the representation beneath it is not
precision, it is a false claim. Where the mechanism distinguishes `Ok(None)` from `Err`, the
seam must carry that distinction (`FieldReadout::Read` vs `Uninterpretable`) and the
authority must name it. And where the foreign encoder cannot mint the vector — no X.509
encoder here will produce a duplicated SAN extension — the property is pinned at the SEAM,
over an interpreted representation, rather than weakened to what a fixture can express.

## 8.16 Slice 2 as built — the first binary composition

The slice that mattered architecturally: two independently established facts meeting at a
relation.

**Shape.** `CredentialPublicKeyEvidence` and `CryptographicSigningKeyEvidence` are produced
by two adapters from two unrelated representations (a certificate chain; a signer's key
export). The relation sees only those two products and can refuse exactly one way —
`Mismatch`. Everything else failed in the authority that owns it, before the relation was
reached. Registered as `unit://proxy.ed25519_public_key` and
`unit://proxy.credential_key_correspondence`; claimed as THM-0025 and THM-0026; the SPKI
parser is ASM-0031; probes M31–M35.

**Six prose-only failures became a hierarchical typed refusal algebra**, and
characterization found further distinguishable representation facts on the way — an
unreadable key and a well-formed key of another algorithm had been one path, and a
non-canonical Ed25519 encoding was being refused silently. The algebra is deliberately not
counted anywhere: it is a hierarchy whose leaves a later adapter may legitimately extend,
and a record that fixes a number ages into a false one.

**It is hierarchical because the failures are not a flat list.**
`Credential(..) | SigningKey(..) | Mismatch`. Two of the three are a SIDE failing to produce
evidence; only the third is the relation refusing. A flat enum would have made
side-attribution a matter of reading which variant name happened to mention a certificate.

**One legal profile is an invariant, not a one-variant policy.** The required Ed25519
profile is what constructing `Ed25519PublicKeyValue` MEANS. A `RequiredKeyProfile` enum with
a single variant would advertise a choice nobody can make and would put the check back at
the call sites that remembered to consult it. The sum type arrives when a second profile
becomes legal — as a change to the owner, not to its consumers.

**L-3. A classifier added on the refusal path must never become the accepting path.**

The adapter needed to tell three key-representation failures apart, and the only way to do
that was to parse a general `SubjectPublicKeyInfo` — a foreign ASN.1 parser. Accepting
whatever that parse yields would have newly admitted non-canonical encodings that were
refused before: a loosening disguised as better error reporting. So acceptance stays an
exact match against the canonical encoding, and the parse runs ONLY after that match has
failed, only to choose which refusal to report.

That containment is what makes the assumption on the parser (ASM-0031) narrow enough to
take: a wrong parser can change which refusal is reported and can never turn a refusal into
an acceptance. It is a property of the code rather than of the library, so it is pinned by
its own control — `classification_never_widens_acceptance` — rather than trusted to the
refusal tests, all of which would stay green if the classifier started repairing keys.

**What the slice found, again by writing controls first.**

The pre-migration profile controls were **not load-bearing**. Deleting the required-profile
rule and comparing the trailing thirty-two bytes left every one of them green: a P-256 key
was still refused, but by the equality check, because its bytes happened not to match. The
control that reaches the conjunct had to remove the coincidence — a signing key whose SPKI
declares another algorithm and whose trailing bytes ARE the credential's public point. That
is the algorithm-confusion shape, and nothing in the tree reached it before.

The general form, and the reason it keeps recurring: **when two rules can produce the same
outcome, a control that asserts the outcome tests neither of them.** Slice 1 met it as a
fallback that no negative could distinguish from an absence; Slice 2 met it as a profile
rule that no negative could distinguish from an inequality.

**The shared invariant had five consumers.** `ed25519_raw_point_from_spki` lived in the KMS
module and was reached from the delegated TLS path, AWS KMS, GCP KMS and PKCS#11. The owner
now owns both directions — interpretation and the canonical encoding — so no provider
assembles the DER header by hand, and the twelve bytes exist once.

## 8.17 Slice 3 as built — a semantic product gating a runtime capability

The first time the architecture shows a fact gating a concrete **runtime value** rather than
composing with another fact.

**The defect Slice 2 left behind.** Slice 2 established `CredentialKeyCorrespondenceFacts`,
and the production path then discarded the fact and called
`DelegatedCertResolver::with_budget(cert_chain, signer, budget)` — a **public** constructor
taking the same two operands independently. So the relation was established and its terms
were immediately split apart again, and an embedder could skip it entirely. The
characterization test asserted the defect before it was removed: a mismatched credential and
signer materialized a resolver, and the only consequence was an opaque handshake failure
later.

**Facts beside the terms would not have fixed it.** Passing the facts as a third parameter
adds a parameter to the same consistency problem: establish `A ↔ A`, then call with
`facts(A,A)` and material `B, C`. The operands compared and the materialization consuming
the result have to stay inside **one construction closure**, which is what
`DelegatedCertResolver::materialize` is: it establishes correspondence over the very chain
and signer it then moves in, and the facts are never returned to a caller at all.

**The witness is the shape that makes it structural.** The resolver holds the facts in a
private, unprojected field, and the assembling constructor is private and demands one. So
possession of the runtime value proves how it was built — and *skip the check and construct
anyway* is not something a sibling can express, including a sibling added later by someone
who has not read the comment.

**L-4. Do not introduce a bypass seam merely to mutation-test a type-enforced invariant.**

When invalid construction is unrepresentable at the consumer boundary, the ENFORCEMENT is
the compiler-enforced visibility boundary, and the EVIDENCE is that boundary plus successful
compilation of the consumer closure. Mutation moves to the supplying invariant whose
weakening could make the sealed product unsound.

The two must not be conflated, and the first draft of this law did conflate them by saying
that a weakening which cannot be written is stronger *evidence*. It is not evidence at all —
inability to write a mutation is a fact about the mutation, not about the code. What is
stronger is the mechanism: an invalid construction the type system refuses to represent
beats a runtime check every caller must remember. This repository's earlier sealing campaign
already settled that mechanism/evidence split, and settled that module privacy plus
whole-crate compilation is the relevant evidence for same-crate sealing, rather than a
separate-crate `compile_fail` test.

So Slice 3 registers no probe removing the gate from `materialize` — `construct` demands a
`CredentialKeyCorrespondenceFacts` nothing outside the authority can produce, and adding a
seam so that a probe could reach it would be building the bypass the slice exists to remove.
What is probed is the supplying relation: **M36** makes correspondence vacuous and the
resolver's guarantee collapses with it, which is what the `CONTRACT_CONSUMES` edge between
the two units asserts, measured rather than declared.

The runtime controls state what runtime controls can state. A test cannot prove *no other
constructor exists* — that is the visibility boundary's job — so the control that used to
carry that name now carries the property it actually measures: the historical TLS facade
delegates through the gate, for matching and for mismatching material alike.

**Budget continuity was the thing not to break.** Slice 3 gates a construction that also
carries the listener-lifetime signing budget (#597). Correspondence is one relation; budget
continuity across rebuilds is another, and neither authority may reconstruct the other's
semantics. The positive control asserts the budget by `Arc` identity rather than by equal
capacity — a fresh bucket of the same size would pass an equality check and silently turn a
sustained rate limit into a per-interval window. M37 probes exactly that regression.

**The escape hatch stays, and stays honest.**

```text
build_delegated_config(chain, signer, crls)         MCP-RE owns correspondence — guaranteed
build_delegated_resolver_config(resolver, crls)     external mechanism — NOT claimed
```

`build_delegated_resolver_config` accepts an arbitrary `ResolvesServerCert` for custody
arrangements MCP-RE does not model, and THM-0027's scope says in as many words that a
resolver reaching the serving path through it carries no correspondence guarantee. Making
every resolver wear the same guarantee would have destroyed useful extensibility and
replaced an honest boundary with a uniform-looking claim that was false for half its
inhabitants.

## 8.18 Slice 4 as built — a faithful relay, and the seal that makes it worth having

The first block whose entire content is *a mechanism said so*. It verifies nothing and
interprets nothing; what it owns is that the sentence cannot be written by anyone who was
not there when the relationship was established.

**Shape.** `ChannelAssociatedCertificateCredentialEvidence` — private representation,
private constructor — produced only by
`channel_associated_credential::rustls_adapter::associated_credential`, the one module in
the authority that knows a TLS connection exists and now the only place in the crate that
reads `peer_certificates()`. Registered as `unit://proxy.channel_associated_credential`;
claimed as THM-0028; the establishment mechanism's report is ASM-0033; probes M38–M39.

**The producer boundary had to be exact, and `pub(super)` was not.** The first
implementation put the adapter beside the product and made the constructor `pub(super)`,
reading it as *the authority's own producers*. It is not: it publishes construction to
every module of `communication_assurance`, present and future, so a neighbouring authority
could have manufactured the evidence from an arbitrary chain with no relationship behind
it. Slice 1 could live with subtree-owned construction because its claim was about
interpretation *within* one authority tree; here the entire semantic content IS provenance,
so the producer set has to be exactly the mechanism adapter.

The repair is topological rather than a new mechanism — no token, no friend object, no
testing constructor. The adapter became a CHILD of the product's module instead of a
sibling, and the constructor became private:

```text
communication_assurance/                 cannot call the constructor
└── channel_associated_credential/
    ├── mod.rs                           private representation + private constructor
    └── rustls_adapter.rs                the one producer — a descendant, so it can
```

Rust privacy is *the defining module and its descendants*, which is precisely the shape the
claim needs. Both routes were checked to fail from a sibling: the constructor is a private
associated function (E0624) and the field is private (E0451).

**And privacy alone still does not finish the argument** — a point the theorem's own review
caught later, after the mechanism was already right. *The defining module and its
descendants* is a SET, and today it holds three members: the owner, the adapter, and the
owner's `#[cfg(test)]` module, which constructs synthetic inhabitants directly in order to
exercise the refusal at construction. Those two test call sites are counterexamples to a
sentence saying the adapter reaches the constructor and nothing else does. So THM-0028 is
stated as a call-site fact scoped to the production configuration: privacy bounds who
*could* call, the call sites say who *does*, and only the conjunction is the claim. The
general form is the one Slice 1 already used for THM-0024 — quantify over what an operation
returns, not over every inhabitant a build can construct.

**The issue was amended in four places before implementation**, and three of the four came
from the same mistake the earlier slices keep teaching: a contract that looks precise while
claiming more than the mechanism supports.

1. **Establishment is a predecessor, not a refusal of this authority.** The first draft
   required the block to distinguish *no credential* from *no established relationship* —
   but if establishment is a predecessor, the second means the authority never runs, and
   making it a refusal would have made Slice 4 partly responsible for deciding whether
   establishment occurred, which is precisely the boundary the slice exists to draw.
2. **A missing credential is characterized, not assumed legal.** `Option` in the mechanism's
   signature is representation shape, not legality.
3. **The product was renamed.** `AuthenticatedPeerCredentialEvidence` reads as proposition
   B — *the peer identified by this credential has been authenticated* — which is not what
   this establishes. `certificate` in the name is the evidence class, not a TLS spelling.
4. **The Slice-5 sketch was corrected**, which is the part with consequences beyond this
   slice; see below.

**What characterization measured, and what each measurement decided.**

```text
pre-handshake ServerConnection      is_handshaking() == true
full handshake                      Some(chain)
resumption of it                    Some(chain), BYTE-IDENTICAL
peer presenting no certificate      handshake FAILS: "peer sent no certificates"
```

The first says the mechanism will answer the establishment question itself, so the adapter
asks rather than trusting a type that cannot prove it — a `ServerConnection` is constructed
before its handshake, and on the blocking path it is the request read that drives the
handshake to completion. The second decided that the product carries NO full-versus-resumed
provenance: `rustls` can report which path a relationship took, no authority needs the
distinction to establish a later proposition, and a field nothing reads is a claim no code
backs. Had they differed, L-2 would have required the seam to carry which — so this control
is what makes the absence of that field a measurement rather than an omission.

The third is the one that shaped the refusal algebra. *Established with no credential* is
**unreachable** under every supported production path: every serving config is built with a
mandatory `WebPkiClientVerifier`, and the peer is refused DURING establishment, so there is
no established relationship for a credential to be missing from. So the algebra does not
invent a reachable-looking domain state for it. Both refusals — an incomplete establishment,
and an established relationship carrying no credential — are named for what they are,
**mechanism-boundary inconsistencies**, and the control that measured the unreachability is
kept: if client auth ever became optional it goes red at exactly the state it was measured
on, which is the point at which the refusal would have to become a domain state. The one
build that reaches it today is the deliberately-broken `fault_accept_any_client` lane, and
refusing keeps that lane failing closed here too.

**No test seam was added to manufacture either state**, and none was needed: a fresh
connection and a refused handshake are both obtainable from real handshakes.

**The producer boundary is the point, and it is not probed.** M38 and M39 weaken what the
adapter reads from the mechanism. Nothing probes *construct the evidence without a mechanism
report*, because no sibling can express that weakening — it does not compile — L-4, with the
mechanism and the evidence kept apart: the enforcement is the visibility boundary, and the
evidence for it is that boundary plus successful compilation of the crate.

**What THM-0028 claims is ORIGIN, not simultaneous lifetime.** Its first title —
*cannot exist beside a relationship* — overstated in the other direction: the product owns
its bytes and is `Clone`, so it may certainly outlive the connection it came from. What is
proved is that it came from nowhere else. A consumer that needs the relationship to still
exist must establish that separately; this block does not carry it.

**What the slice did NOT do.** `TransportIdentity` is untouched and its consumers are
unmigrated: this slice removes the manufacture route for the CREDENTIAL fact, not for the
identity fact built on top of it. Both serving paths now obtain the credential through the
authority and project the chain for the per-request lifetime and revocation gates, which
still consume a representation. That projection is a compatibility seam and is documented
as one; each later migration removes a caller, and it goes when the last one does.

### 8.19 The composition rule Slice 5 must obey

The rejected Slice-5 shape, and the reason it is rejected, is the reusable part:

```text
ChannelAssociatedCertificateCredentialEvidence + CertificatePeerIdentityEvidence
        -> AuthenticatedPeerIdentityFacts                              # REJECTED
```

Both operands are valid products of authorities that really established them. It is still
wrong: identity evidence interpreted from certificate **B** can be paired with relationship
credential **A**, and the caller does the pairing. That is Slice 3's *facts beside the terms*
defect, reappearing on the evidence-provenance axis rather than the credential/key axis. So
Slice 5 derives the identity from the credential the relationship carries, inside one
construction operation, reusing the Slice-1 interpreter; `CertificatePeerIdentityEvidence` may
be produced internally on that path, and a caller must not supply an independently obtained
one.

Slice 5 measured this and the candidate law became **L-5**.

Two blocks do not legally connect because their types sound compatible.

### 8.20 Slice 5 as built — the first provenance linkage

Slice 5 adds no new identity transformation. Its new semantic content is the provenance
linkage between Slice 4's credential and the result of the existing Slice-1 interpreter,
which it invokes on that credential's own leaf:

```text
ChannelAssociatedCertificateCredentialEvidence
        |
        | the credential's OWN leaf, in one construction operation
        v
   reuse the Slice-1 interpreter, under the caller's policy
        |
        v
ChannelAssociatedCertificatePeerIdentityEvidence
```

The caller supplies a `CertificateIdentityPolicy` and nothing else. There is no parameter
through which a second certificate or a separately obtained `CertificatePeerIdentityEvidence`
could enter, which is what makes the §8.19 substitution unconstructible rather than merely
untaken.

**Characterization decided two things before any code moved.**

| question | measured |
|---|---|
| does the mechanism report intermediates, and in what order? | a real root -> intermediate -> leaf chain is reported **leaf first**, intermediates after, and the Slice-4 projection preserves that order |
| is a rival identity in the chain a real decoy? | yes — an intermediate's URI SAN is in the reported chain, so *identity from the leaf* and *identity from some certificate in the chain* differ on a relationship that establishes normally |

**And it produced a premise, not a result.** *Element 0 of the reported chain is the peer's
own credential* is a property of the mechanism's reporting order, documented by `rustls`
0.23.43 and measured here — but not something ASM-0033 supplies, because *the mechanism
reports the credential it associated* holds under any ordering. It is registered as
**ASM-0034**, scoped to this unit alone: broadening ASM-0033 would widen the blast radius of
a premise THM-0028 does not need. If the order were ever reversed, an ISSUER's identity
would sit under a sentence that says *the peer's*.

That is why the controls establish every relationship with leaf identity **A** and
intermediate identity **B** in the same field. A control that asserted only "interpretation
succeeded" would stay green while the proxy bound the identity of the CA that signed the
peer.

**The refusal surface narrowed, and that is what the predecessor invariant bought.** Slice 1
needs a *no leaf was presented* refusal because arbitrary certificate evidence may carry
none. A channel-associated credential's chain is non-empty by construction, so the state
cannot occur — and rather than keep an unreachable variant, the algebra was split at the
authority it belongs to:

```text
CertificateIdentityRefusal = NoLeaf | Leaf(LeafIdentityRefusal)      the evidence question
LeafIdentityRefusal        = MalformedCertificate | SelectedField*    a leaf that EXISTS
```

Five distinguishable outcomes, as before; each authority now names only the ones it can
produce. Splitting rather than duplicating matters: two enums stating the same four facts
would be one algebra written twice, drifting the moment either gained a variant.

**The seal, measured the way Slice 4's was — and the placement mistake it caught.** The
first layout put the deriving module INSIDE `channel_associated_credential`, next to the
mechanism adapter. It compiled, and that was the defect: Rust privacy is the defining module
and its descendants, so a second child reaches the credential's private constructor. Measured
before the move — the new module compiled a call to `associate` with an arbitrary chain,
which makes THM-0028 false while every control stays green. This is the Slice-4 producer
boundary again, from the other side:

> **A consumer's placement is part of its predecessor's seal.** A sole-producer claim is
> falsified by adding a sibling to the producer just as surely as by widening the
> constructor. What a consumer needs is a named projection, and a projection lives on the
> owner's side.

So the authority is a SIBLING of the credential, consuming a `pub(super)` leaf projection.
Both seals then measure clean — the credential's constructor and the new product's
representation, each probed from where an attacker of the claim would sit:

```text
error[E0624]: associated function `associate` is private            # from the identity authority
error[E0451]: field `identity` of struct                            # from a sibling authority
              ChannelAssociatedCertificatePeerIdentityEvidence is private
```

**What it is still not.** Not authentication. THM-0028 establishes no trust, currency,
revocation status or anchor membership, and THM-0024 establishes only what a representation
denotes; the composition of two deliberately weak facts is not a strong one. The product is
named `ChannelAssociatedCertificatePeerIdentityEvidence` for that reason, and
`AuthenticatedPeerIdentityFacts` stays unbuilt until a trust/authentication premise exists.

**L-5. Two valid facts do not compose into a relation about one underlying object unless
their provenance establishes that they describe the same object.**

The candidate was recorded unnumbered at the end of Slice 4, and Slice 5 measured it — both
the law and, unexpectedly, the first draft of its corollary.

**The law stands as written.** The test for whether a composition needs it is not whether
the operands are true. It is whether a caller holding two of them could pair the wrong ones
with nothing downstream able to tell. `ChannelAssociatedCertificateCredentialEvidence(A)` and
`CertificatePeerIdentityEvidence(B)` are both honest; the pair states something false, and
the only record of which certificate the identity came from is the pairing itself.

**The corollary had to be rewritten, because Slice 5 disproved the first version of it.** It
said to derive the downstream fact *inside the predecessor's construction closure*, and the
implementation took that literally: it placed the successor module inside the predecessor's
Rust privacy tree. That compiled a call to the predecessor's private constructor and
falsified THM-0028. The corollary now reads:

> Where provenance cannot safely be supplied as a second operand, derive the downstream fact
> in ONE construction operation that consumes the predecessor product and only the narrow
> owner projections it needs. A successor must not enter the predecessor's
> producer-privileged privacy subtree merely to obtain those projections.

The distinction the slice produced is between a **semantic construction closure** — one
operation, whose parameter list admits no rival instance of the fact being related — and a
**Rust producer/privacy closure**, the module subtree entitled to construct the predecessor.
The first is what the law asks for. The second is the predecessor's seal, and a successor
that moves inside it to reach a projection pays for a convenience with somebody else's
theorem. Projections travel outward as `pub(super)`; consumers stay siblings.

Slice 3 met the same shape on the credential/key axis — facts beside the terms — and answered
it the same way. Two slices apart, on different axes, is what promoted it from an
observation to a law.

## 9. Slice selection rule

Do not choose the next slice merely because it is physically adjacent to a completed one or
is the largest remaining block. Slice 2 was chosen against adjacency on exactly this rule:
CRL/revocation sits next to Slice 1 in `tls.rs`, and taking it would have dragged in chain
lifetime, current time, revocation snapshots, resumed-session semantics and eventually
ADR-MCPRE-062 — complexity selected by proximity rather than by the graph.

Re-evaluate the authority graph and select a semantic transformation whose predecessor
products now exist, or whose contract can be built independently. Slice 3 was selected on a
second, equally good ground: **a completed block exposed a defect in its own successor
boundary** — correspondence was established and then discarded by the very construction it
was meant to govern. A missing connector immediately downstream of finished work outranks a
larger block that is merely still sitting somewhere.

Candidate directions include:

- certificate-chain evidence -> verified certificate/revocation facts;
- peer-identity evidence + verified evidence -> authenticated peer facts;
- verified peer/relationship facts + binding evidence -> relationship binding facts.

The next issue must state why its predecessor products and authority boundary are real, and
a candidate is not recorded as a decision until it is selected — that would make the graph
look more settled than it is.

Slice 4 was selected on the first ground: a semantic authority carried entirely by control
flow, whose product a public total constructor let anyone manufacture. Slice 5 is named in
§8.19 and it is named for the opposite reason — not because it is next in a list, but
because Slice 4's product is the only legal way to reach it, and the shape it must NOT take
was already measured.

## 10. Relation to #598 / ADR-062

Do not implement #598 before deciding where its session/cache lifecycle product belongs in this architecture.

ADR-062 remains authoritative: one immutable anchor set owns one listener security state and one resumption store; changing anchors creates a new state/store and no resumable session crosses that authority change.

The #598 retirement/re-scope work should later map the dormant live-epoch machinery into the appropriate mechanism-specific assurance block rather than clean it up in a historical location and then move it again.

## 11. Concrete work sequence

```text
PR #600 / MCPRE-138                                                          DONE
  -> close historical blocking-harness extraction

ADR-MCPRE-063 + blueprint                                                    ACCEPTED
  -> ratify semantic architecture, initial graph, migration discipline

Slice 1  (#602)                                                              COMPLETE
  -> certificate-chain evidence -> peer-identity evidence
  -> taught L-1, L-2

Slice 2  (#605)                                                              COMPLETE
  -> credential evidence + signing-key evidence -> credential/key correspondence
  -> the first BINARY composition; taught L-3

Slice 3  (#607)                                                              COMPLETE
  -> correspondence facts gate delegated credential materialization
  -> the first semantic product gating a RUNTIME CAPABILITY; taught L-4
  -> selected because Slice 2 exposed a defect in its own successor boundary

Slice 4  (#609)                                                              COMPLETE
  -> successful establishment -> channel-associated certificate credential evidence
  -> the first FAITHFUL RELAY: a sealed product whose whole content is a mechanism
     report, and which therefore cannot be manufactured beside a relationship
  -> the contract was amended before implementation; §8.18 records the four changes

Slice 5  (#612)                                                              COMPLETE
  -> identity interpreted from the credential the relationship carries, in ONE
     construction operation — never a caller pairing two independently obtained facts
  -> the first PROVENANCE LINKAGE: it adds no transformation, only the fact that two
     established facts are about the same object (§8.19, §8.20)
  -> taught L-5

Later
  -> map ADR-062/#598 session lifecycle into the mechanism-specific assurance branch
  -> compose higher facts
  -> draft #581 theorems only against the architecture/evidence that actually exists
```
