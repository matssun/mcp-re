<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-003: Signing Locus — What signer and a Signature Prove

## Status

Accepted

## Context

Derived from PRD; depends on ADR-MCPS-002. The brief states `mcps-host` signs and "the LLM never manages private keys," and the trust resolver maps `(signer, key_id) → key`. This quietly leaves open *what a signature actually proves* — whether `signer` cryptographically binds a specific agent, and whether `on_behalf_of` (the user) is proven. PRD success criterion #1 originally read "tool calls cryptographically bound to a specific actor identity," which is stronger than the cryptography guarantees unless per-agent keys are mandated.

## Decision

`signer` denotes the identity that controls `key_id`'s private key, and Core proves only that this key signed the canonical preimage — not agent ontology, host-vouching vs self-signing, user consent, `on_behalf_of` truth, `authorization_hash` grant, or binding strength; the key locus is unconstrained by Core, the verified output field is `verified_signer`, and `on_behalf_of` is a signed *assertion* whose independent proof is deferred to a later delegation profile.

## Rationale

MCP-S must not smuggle a stronger identity claim into the word `signer` than the cryptography establishes. Where the key lives (host's own key = vouching; per-agent key custodied by host; agent runtime; HSM; remote signer) is a deployment choice that does not change Core. This mirrors the ATPA `CALLER_ASSERTED_IDP_RESOLVED` vs proof-of-possession distinction but keeps binding-strength classification out of Core's verify path. PRD success criterion #1 is reworded to "bound to a **resolved signer identity**."

## Alternatives Considered

- **Mandate per-agent keys** (signer always binds the named agent): rejected — forces per-agent key provisioning/rotation on every deployment and makes simple host-vouching non-conformant.
- **Fix `signer` = host/ambassador always**: rejected — requires an extra asserted `agent` field and renames "agent attribution" to "host assertion" awkwardly.

## Consequences

### Positive
- Honest, minimal, deployment-flexible; the cryptographic claim matches reality.

### Negative
- Attribution strength varies by deployment and is not provable from the envelope alone (a vouching deployment is weaker than per-agent keys).

### Neutral
- `binding_strength` is a deployment-local annotation in `mcps-proxy`, never a Core field; `TrustResolver` may expose it, but Core's verify path uses only the verification key.

## Compliance and Enforcement

Spec wording and the verified-context field name (`verified_signer`, never `verified_agent`). No Core test asserts agent identity beyond signer-key control.

## Related

- PRD: (author's private monorepo)
- Depends on: ADR-MCPS-002
- Siblings: ADR-MCPS-007 (resolution), ADR-MCPS-008 (verified context)
