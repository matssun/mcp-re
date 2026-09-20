<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-145, NP-186, NP-187 — R6 ratification packet: three residues, three different reasons

**Disposition:** R6 for all three. NP-145 closes in part — two of its five controls landed
as part of `unit://proxy.asserted_identity_delegation` under THM-0023 — and its remaining
three controls are TWO propositions, so one stays under NP-145 and one is separated as
NP-187 under RR-002 C5. NP-186 is NP-075's residue: six of NP-075's seven controls landed as
`unit://proxy.transport_binding_application` under THM-0034, and the seventh is not about
the binding at all.

Measured from the tree at `adr069/px-identity`, 2026-09-20. All controls named here appear
in `cargo test -p mcp-re-proxy --lib -- --list`; nothing in `transport/mod.rs` or
`facades/` is feature-gated, so the default lane is the lane.

## Ids minted

`origin/main` at `f9fe2fd9` reaches NP-185. **NP-186** and **NP-187** are minted here, each
carrying a severity assessed against what it actually claims rather than inherited from its
parent: NP-186 falls from NP-075's `critical` to `medium` because a constant fixture is not
the binding relation, and NP-187 takes `high` rather than NP-145's `medium` because a
conversion that reassigns a case repoints a deployment at another certificate field.

## NP-145's residue: the correspondence RENDERING

**2 controls**, carrier `mcp-re-proxy/src/tls.rs`:

- `lib#tls::delegated_credential_key_correspondence_tests::every_fact_renders_to_a_distinct_sentence`
- `lib#tls::delegated_credential_key_correspondence_tests::an_unsupported_algorithm_tells_the_operator_which_algorithm_was_given`

THM-0026, statement, verbatim:

> If it returns Err, the refusal names which authority failed — the credential side, the
> signing-key side, or the relation.

THM-0026, security consequence, verbatim:

> The failure is refused before any server starts rather than surfacing as an opaque
> handshake failure, and an operator is told which half of the deployment to look at.

Those two sentences are the whole of THM-0026's reach toward an operator, and both stop
short. The first is about the returned refusal VALUE — a three-way attribution over an
algebra a caller matches on — while `every_fact_renders_to_a_distinct_sentence` asserts a
SEVEN-way distinctness over a `String` no clause of THM-0026 mentions. The second says
*which half*; `an_unsupported_algorithm_tells_the_operator_which_algorithm_was_given`
asserts the message carries the OID, which is not a half.

The gap is real rather than pedantic. The facade's own note is explicit that the rendering
is *derived from the fact rather than being the fact*, and THM-0026 owns the fact. A unit
declaring seven distinct sentences under a theorem that states three distinguishable values
would be claiming, in the graph, that the theorem's evidence covers an operator-facing
promise the theorem never made.

**What would close it.** A clause in THM-0026 about the rendered vocabulary, or a separate
theorem over the operator-facing error surface. Neither is available to this slice.

## NP-186: the static identity provider

**1 control**, carrier `mcp-re-proxy/src/transport/mod.rs`:

- `lib#transport::tests::static_provider_yields_its_identity_ignoring_request`

`StaticIdentityProvider` is documented in its own type comment as *"Useful in tests and as a
degenerate provider"*, and the control asserts that a constant function is constant: the
same identity under an empty header set and under a populated one, `None` when built with
none. THM-0034 says nothing about `TransportBindingProvider` or about any provider; its
subject is a binary relation over two semantic products, and this type produces neither.

**Why it is carried as a proposition rather than dispositioned `not-evidence`.** It very
likely is not evidence. But a `not-evidence` row requires a `reason_family` naming a durable
record, and none of the thirteen recorded families covers it. The nearest is ND-009,
*data-structure API robustness with no security proposition* — and this is not robustness,
it is a fixture's constancy. Widening ND-009's scope to absorb it is the same defect at the
disposition layer that widening a unit's proposition is at the registration layer: the row
would read as adjudicated under a reason that does not describe it. Minting a fourteenth
family is excluded from this slice.

## NP-187: the vocabulary conversion, and why it is the sharpest of the three

**1 control**, carrier `mcp-re-proxy/src/facades/asserted_identity.rs`:

- `lib#facades::asserted_identity::tests::the_two_vocabularies_agree_field_for_field`

It enumerates both directions of `IdentityPolicy <-> CertificateIdentityPolicy` and
`CertificateIdentitySource -> IdentitySource`, all three cases each way. The test's own
comment states the stake: *"A conversion that dropped a case would silently repoint a
deployment at another certificate field."*

THM-0024, scope, verbatim:

> Interpretation is total and deterministic over the interpreted field set and the policy.

The policy is an INPUT. Every clause of THM-0024's statement is conditioned on *the field
the policy configures*, and a conversion producing the wrong `CertificateIdentityPolicy`
satisfies the theorem perfectly: the interpreter reads the field it was told to read and
reports that field as the source. The deployment is downgraded and THM-0024 stays true.

So a `critical` theorem's entire guarantee rests on a premise that sits one step upstream of
where the theorem begins, measured by exactly one control, claimed by nothing. It is not
registered under THM-0024 because it is not contained by THM-0024, and saying so is more
useful than a registration that would make the graph look closed at the point it is thinnest.

**What would close it.** A clause in THM-0024 admitting the configuration vocabulary as part
of *the policy*, or a theorem over the configuration-to-authority conversion surface. This
slice may amend no claim field and add no theorem.

## The three that were NOT separated further

`the_two_vocabularies_agree_field_for_field` was separated from NP-145 because it is about
certificate FIELD SELECTION and the other two are about refusal RENDERING — two authorities
in one record, which C5 refuses to file whole. The two rendering controls were not split
from each other: both assert that the historical `String` keeps facts apart, and both fail
the same way.

**Severities:** NP-145 `medium`, NP-186 `medium`, NP-187 `high`.
