# ADR-MCPRE-053 — Admission assertion + §7 admission-state binding

**Status:** Accepted (implementation), 2026-07-17. Issue #433. Derived from
Discussion [#414](https://github.com/matssun/mcp-re/discussions/414) rev 2 §4.3/§5
(authoritative admission state) and
[#415](https://github.com/matssun/mcp-re/discussions/415) rev 2 §7 (binding a call
to admission evidence).

## Context

Layer 1 already has the trust-anchor primitives — `TrustedIssuerSet`, the signed
`TrustAnchorManifest` with anti-rollback, keyset generations. What was absent was a
credential that says *a specific workload is admitted*, and any way for a call to
commit to it. Without that, a PEP verifies that a request is signed by a trusted
key but not that the workload behind that key is still admitted to act — a revoked
or superseded workload keeps signing valid requests.

## Decision

Two artifacts and one check.

### 1. The admission assertion (a compact JWS, §4.3)

Issued from the trust-anchor lifecycle exactly as the ADR-MCPRE-052 delegation
credential is — the authority root signs it through the external-signer seam; the
root key never enters the profile crate. It carries: `mcp_re_admission_id`,
`mcp_re_admission_generation` (the monotonic anti-rollback counter),
`mcp_re_admitted_state_digest` (opaque here — a digest of whatever posture the
authority attests), `mcp_re_admission_status` (`admitted`/`suspended`/`revoked`),
audience, profile, `[nbf, exp]`, and `issuer_kid`. `typ` is
`mcp-re-admission+jws`, distinct from the delegation credential's, so one can never
be presented for the other.

### 2. The §7 binding (in the request evidence block)

An `AdmissionBinding` rides in the request evidence block — protected by
`content-digest` like every other block field, so an attacker cannot swap the bound
generation without breaking the signature. It follows the artifact-binding split:
`opaque-digest` commits to the assertion's `mcp_re_admitted_state_digest` (checkable
offline against the assertion), `reference-digest` names an external authority. The
binding declares `admission_id` and `generation` — the currency check's subject.

### 3. The Layer 4 currency check (§7)

`check_admission` verifies the assertion (signature, `typ`/`alg`, issuer trust,
freshness), confirms the call's binding describes that assertion, and then — the
load-bearing step — compares the **bound generation against the authoritative
state the PEP holds**. A snapshot is not currency: a signed, fresh, "admitted"
assertion is refused when the authoritative generation has advanced, because the
workload's admission was superseded. Status must be `Admitted` in both the
assertion and the authoritative state, so a workload revoked *after* issuance is
refused while its assertion is still within its TTL.

## The freshness budget (§5.2 N/P/TTL)

- **TTL** is the assertion's own `[nbf, exp]` — the issuer's choice.
- **N** (`max_assertion_age`) is the verifier's cap on how stale an admitted-state
  snapshot it will act on, independent of the issuer's TTL.
- **P** (`degraded_propagation_bound`) is the bound within which the PEP may serve
  on the last-known state when the authoritative state is unreachable — and only
  when the deployment explicitly enabled degraded mode. Past P, an unreachable
  authority fails closed, because a revocation could have propagated and the PEP
  would not know.

Degraded mode is **off by default** and marks its verdicts `degraded: true`, so an
auditor distinguishes a live-confirmed admission from one served on a stale
snapshot. Silent, unbounded fallback would turn push-invalidation into a
suggestion.

## Fail-closed taxonomy

| Failure | Wire code |
|---|---|
| Bad assertion / wrong typ/alg / untrusted issuer / not current | `mcp-re.actor_binding_failed` |
| Assertion outside `[nbf, exp]` or older than N | `mcp-re.expired_request` |
| Binding does not describe the assertion | `mcp-re.request_binding_mismatch` |
| Authoritative state unreachable (degraded off / past P) | `mcp-re.actor_binding_failed` |

All reuse frozen `mcp_re_core` tokens (E-11: no parallel namespace).

## Scope and what is NOT here

- **Drift monitoring** (the evidence producer that feeds the authoritative state)
  is out of scope, per #433 — the assertion consumes whatever Layer 1 decides.
- **Cross-replica revocation propagation measured against the declared P bound**
  (#433's fourth criterion) needs a live fleet (GKE), which is HITL-gated in this
  deployment. The P bound is declared, enforced, and unit/vector-tested here; the
  *measurement* of real propagation against it is a fleet exercise, not a code
  change, and remains open.
- The **PEP wiring** (feeding `AuthoritativeAdmission` from a live Layer 1 source
  and calling `check_admission` on the served path) is a deployment integration:
  the check is implemented and tested, but which authoritative source a given
  deployment uses is its own choice, so the serving struct does not hardcode one.

## Proven by

`admission.rs` unit tests (currency, revoked-after-issuance, degraded within/beyond
P, untrusted issuer, binding mismatch), `admission_binding_test` (the binding
through the real request evidence block, and that tampering it breaks the
signature), and frozen vectors `h42`–`h46` — `h43` being the stale-generation case
that a snapshot alone would have let through.
