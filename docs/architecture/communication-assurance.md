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

## 9. Slice 2 selection rule

Do not choose slice 2 merely because it is physically adjacent to slice 1 or is the largest remaining block.

After slice 1, re-evaluate the authority graph and select one of the next semantic transformations whose predecessor product now exists or whose contract can be built independently.

Candidate directions include:

- certificate-chain evidence -> verified certificate/revocation facts;
- delegated-credential evidence + cryptographic peer-key evidence -> credential/key correspondence facts;
- peer-identity evidence + verified evidence -> authenticated peer facts;
- verified peer/relationship facts + binding evidence -> relationship binding facts.

The next issue must state why its predecessor products and authority boundary are real.

## 10. Relation to #598 / ADR-062

Do not implement #598 before deciding where its session/cache lifecycle product belongs in this architecture.

ADR-062 remains authoritative: one immutable anchor set owns one listener security state and one resumption store; changing anchors creates a new state/store and no resumable session crosses that authority change.

The #598 retirement/re-scope work should later map the dormant live-epoch machinery into the appropriate mechanism-specific assurance block rather than clean it up in a historical location and then move it again.

## 11. Concrete work sequence

```text
PR #600 / MCPRE-138
  -> close historical blocking-harness extraction

ADR-MCPRE-063
  -> ratify semantic architecture

Blueprint
  -> ratify initial graph and migration discipline

Slice 1
  -> certificate-chain evidence -> peer-identity evidence

Review slice 1
  -> validate products, refusals, proof boundary, compatibility pattern

Slice 2
  -> choose from architecture, not LOC or file adjacency

Later
  -> map ADR-062/#598 session lifecycle into the mechanism-specific assurance branch
  -> compose higher facts
  -> draft #581 theorems only against the architecture/evidence that actually exists
```
