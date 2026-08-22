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

## 9. Slice 3 selection rule

Do not choose the next slice merely because it is physically adjacent to a completed one or
is the largest remaining block. Slice 2 was chosen against adjacency on exactly this rule:
CRL/revocation sits next to Slice 1 in `tls.rs`, and taking it would have dragged in chain
lifetime, current time, revocation snapshots, resumed-session semantics and eventually
ADR-MCPRE-062 — complexity selected by proximity rather than by the graph.

Re-evaluate the authority graph and select a semantic transformation whose predecessor
products now exist, or whose contract can be built independently. Two now exist that did
not before: peer-identity evidence, and credential/key correspondence facts.

Candidate directions include:

- certificate-chain evidence -> verified certificate/revocation facts;
- peer-identity evidence + verified evidence -> authenticated peer facts;
- verified peer/relationship facts + binding evidence -> relationship binding facts.

The next issue must state why its predecessor products and authority boundary are real.
**Slice 3 is deliberately unnamed here.** What the first binary composition taught is an
input to that choice, and recording a candidate as a decision would make the graph look
more settled than it is.

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

Review Slice 2
  -> what a relation between two independently established facts costs and buys
  -> select Slice 3 from the predecessor/product graph, never by adjacency

Later
  -> map ADR-062/#598 session lifecycle into the mechanism-specific assurance branch
  -> compose higher facts
  -> draft #581 theorems only against the architecture/evidence that actually exists
```
