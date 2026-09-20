<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-078 — R6 ratification packet: a seal that holds, and has nothing to be attached to

**Disposition:** R6, both controls. Nothing of NP-078 landed. Its `[[proposition]]` entry
and record stay in place, with the title and `likely_owner` corrected by measurement.

Measured from the tree at `adr069/px-identity`, 2026-09-20. Both controls appear in
`cargo test -p mcp-re-proxy --lib -- --list`; the default lane is the lane, and neither
`transport/identity.rs` nor anything it uses is feature-gated.

## The probe was written FIRST, and it is the reason this packet exists

ADR-MCPRE-068 §12.1: a passing `cargo check` witnesses no seal. `the_projections_are_the_only_way_to_read_one`
is a `#[cfg(test)]` function INSIDE `transport::identity`, where every private item is
visible — it calls the `pub(super)` constructor and asserts the accessors return what it
passed. It measures the projections; it cannot measure the seal, because it is on the inside
of it. So the hostile constructions were written and compiled before any disposition was
decided.

Four routes, four refusals:

| route | site | rustc |
|---|---|---|
| `TransportIdentity { value, source }` | `mcp-re-proxy/tests/` (separate crate) | `E0451: fields value and source of struct TransportIdentity are private` |
| `TransportIdentity::attested_by_verified_ingress(..)` | `mcp-re-proxy/tests/` | `E0624: associated function attested_by_verified_ingress is private` |
| `TransportIdentity { value, source }` | `mcp-re-proxy/src/`, module declared from `lib.rs` | `E0451` |
| `TransportIdentity::attested_by_verified_ingress(..)` | same | `E0624` |

The in-crate pair is the one that matters. `pub(crate)` seals nothing against this crate's
own composition root, and the injected module was declared from `lib.rs` so the compiler
actually read it — a file no `mod` names compiles to nothing and would have reported "no
error", which is the verdict that means the boundary is OPEN.

The remaining ADR-MCPRE-068 producer paths, answered:

- **module-tree-visibility** — `value` and `source` are bare-private to `transport::identity`,
  and `attested_by_verified_ingress` is `pub(super)`, so privacy admits `transport` and its
  descendants. That set is exactly the documented producer list:
  `transport::ingress::v2`, refused at Layer-A configuration validation.
- **alternate-constructors** — two, both named in the module's own table:
  `extract_identity`, which owns nothing and delegates to the ADR-MCPRE-063 authority, and
  the `pub(super)` one above. No third exists in the crate.
- **generated-or-deserialization** — the type derives `Debug, Clone, PartialEq, Eq` and
  nothing else. No `Serialize`/`Deserialize`, no `Default`, no `From`, no `FromStr`.
- **test-only-construction** — no `#[cfg(test)]` constructor widens anything. The one test
  call site (`identity.rs`'s own module) is inside the set privacy already admits, so it is
  attacked by the in-crate probe rather than exempted from it. RA3-002 deleted
  `transport/mod.rs`'s `spiffe` helper along with the provider fixture that was its only
  caller.

**The seal holds.** That is the measurement, and it is recorded whichever way it went.

## Why it is not registered anyway

A measured seal is not a theorem, and the four-clause subsumption test fails at clause 2 for
every candidate.

THM-0024, scope, verbatim:

> It characterizes values successfully returned by the interpretation operation. It says
> nothing about arbitrary possession of a CertificatePeerIdentityEvidence value, whose
> construction closure is the module boundary rather than a proved postcondition.

Two independent refusals in one sentence. Possession claims are excluded in terms, and the
type excluded is not even this one — `CertificatePeerIdentityEvidence` lives in
`communication_assurance` and is already sealed by `proxy.certificate_identity_authority_boundary`,
which is in THM-0024's `supported_by`. NP-078b is about `TransportIdentity`, a different
type in a different module with a different producer set.

THM-0080, scope, verbatim:

> the historical extractor is a published API with its own X.509 conformance suite over real
> DER, so it cannot be removed to make the wrong call unavailable, and deleting the controls
> leaves a second identity route compiling. What can be held is that the SERVING PATHS do not
> take it, which is a call-site fact.

This names `extract_identity` and says precisely that the claim being held is about the
serving paths, NOT about the extractor. `a_certificate_that_does_not_carry_the_configured_field_yields_nothing`
measures what the extractor returns, which THM-0080 declines to claim.

And the owner has already ruled, in `transport/identity.rs`'s own module note:

> It is deliberately NOT written down as a theorem here. The proposition is an open gap in
> `docs/architecture/components/transport-binding.md`, and closing it in prose ahead of the
> deployment reachability that makes it true is the over-claim ADR-MCPRE-061 exists to
> prevent (EX-005, ruling 5).

Registering a unit for it would be that over-claim arriving through the assurance registry
rather than through prose — the same sentence, written in the place a reviewer of the prose
would not look.

## N4, and why no structural probe was registered

ADR-MCPRE-068 §9 N4 forbids substituting a probe class. NP-078b is `structural`: its
falsifier is a compile refusal, never a mutation, and sweeping it into a `tested` unit
beside `a_certificate_that_does_not_carry_the_configured_field_yields_nothing` to tidy a
count is exactly what N4 names. It was not done.

No `[[probe]]` was added to `verification/policy/structural-probes.toml` either, and the
reason is mechanical rather than a choice: `_structural.load_probes` requires a `unit`, the
orphan check judges probes against declared units, and there is no unit to declare. A probe
whose `unit` named nothing would be a registry row about a claim the graph does not hold.
The constructions are recorded above instead, reproducible in four lines.

## What is missing, precisely

A `[[theorem]]` over the transport identity product — two conjuncts, both already measured:
that the historical facade propagates the authority's refusal rather than falling back, and
that the product cannot be manufactured outside its module. This slice may not add one
(`no new [[theorem]]`), and it may not amend an existing claim field.

The ordinary ADR-069 §5 route applies: the proposition is IDENTIFIED here with its carrier
and its evidence, and stays visible unresolved assurance debt until the theorem architecture
ratifies it. What it must NOT become is an entry in the nearest `supported_by` list.

**Severity:** `critical`.
