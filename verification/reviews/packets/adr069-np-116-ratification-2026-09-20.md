<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-116 residue — R6 ratification packet: the resolver's two NOTHING arms

**Disposition:** R2 in part, R6 for the residue. Five of NP-116's seven controls landed as
`unit://proxy.channel_peer_resolution` under THM-0031, falsifier
`M341-proxy-the-resolver-reads-a-field-the-deployment-did-not-configure`. Two rows remain;
NP-116's `[[proposition]]` entry and record stay in place, with the title narrowed to the
half that remains.

Measured from the tree at `adr069/px-identity`, 2026-09-20. All seven controls appear in
`cargo test -p mcp-re-proxy --lib -- --list`; `channel_peer_resolution_tests` is a plain
`#[cfg(test)]` module with no feature gate, so the default lane is the lane.

## What landed, and the clauses that contain it

THM-0031, statement, verbatim:

> Its identity and source are exactly what interpreting the leaf of V's OWN
> channel-associated credential under P returned, and its establishment path is exactly V's.

That sentence contains four of the five directly. `direct_tls_resolves_the_identity_the_relationship_authenticated_as`
and `an_issuer_in_the_accepted_chain_never_becomes_the_transport_identity` are *the LEAF of
V's own credential* — the fixture puts a decoy URI SAN on the intermediate precisely so that
a route reading any certificate in the accepted chain answers the wrong identity rather than
merely a different-looking one. `a_resumed_relationship_resolves_the_same_identity_as_a_full_handshake`
is *its establishment path is exactly V's*, driven through a real `HandshakeKind::Resumed`.

THM-0031, statement, verbatim:

> pairing the acceptance of relationship A with an identity read from relationship B's
> credential is unconstructible rather than merely untaken

`each_relationship_resolves_its_own_peers_identity` is that, measured at the serving
boundary with two live relationships and one options record.

THM-0031, statement, verbatim:

> The refusal algebra is the leaf interpreter's, unchanged.

`a_leaf_without_the_configured_field_resolves_no_identity` is that: a DNS-SAN leaf under a
URI-SAN policy refuses at the interpreter and reaches the fail-closed core with nothing.

**Why a twin and not an R1.** `proxy.authenticated_relationship_peer` declares
`communication_assurance/authenticated_relationship_peer.rs`; `proxy.serving_identity_provenance`
does declare `mcp-re-proxy/src/tls.rs`, but its declared proposition is the ROUTE — *"one
call to one resolver per path, a resolver signature that admits its predecessor and the
options and nothing else"* — and these five measure what the resolver ANSWERS, which is the
other question. Registering them there is the shape ADR-069 §5 calls strictly worse than
leaving them unregistered. No `paths` was widened.

## The residue

**2 controls**, `mcp-re-proxy`, rust unit test, default cargo lane, carrier
`mcp-re-proxy/src/tls.rs`:

- `lib#tls::channel_peer_resolution_tests::an_absent_acceptance_resolves_no_identity`
- `lib#tls::channel_peer_resolution_tests::an_lb_assertion_deployment_resolves_no_transport_identity`

### Why THM-0031 does not reach the absent arm

THM-0031, statement, verbatim:

> a free function taking a MechanismVerifiedCredentialEvidence by value and a
> CertificateIdentityPolicy, and nothing else

The theorem quantifies over inhabitants produced FROM an acceptance. An absent acceptance is
outside its domain, not a case it decides — `authenticated_peer` never calls the authority at
all on that arm (`accepted?` short-circuits). Claiming this control under THM-0031 would
assert the theorem says something about a call it forbids making.

### Why no theorem reaches the LB-assertion arm

THM-0080, statement, verbatim:

> Neither direct-TLS serving path reconstructs peer identity or credential currency from
> certificate representation

Both clauses of THM-0080 are about what the direct-TLS paths DO. An LB-assertion deployment
is the one where neither path derives a transport identity at all, and no ratified sentence
states that. The nearest is NP-074's — *each ingress format publishes the guarantee it
actually gives* — which is itself an unratified proposition, so it cannot contain anything.

This is the sharp one, and the record says so: under an LB assertion there IS no transport
identity, and producing one would let NP-074's guarantee be read as end-to-end. It is a
deployment-posture claim over `PeerIdentityProvenance`, and it needs an owner for that axis.

### Kept as ONE proposition rather than split

Both controls assert the same thing about the same function — that `resolve_channel_peer`
returns `Ok(None)` where the channel carries no credential-derived identity — and both fail
the same way, by the resolver inventing a peer. Splitting them would produce two records
naming one function's one arm each, which is granularity below the proposition.

**Severity:** `critical`.
