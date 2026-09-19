<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-126 residue — R6 ratification packet: the client-CRL loader's fail-closed

**Disposition:** R2 in part, R6 for the residue. Two controls landed as
`unit://proxy.client_crl_next_update_gate` under THM-0131 (probe
`M326-proxy-a-crl-with-no-expiry-is-not-fresh`). Two rows remain; NP-126's `[[proposition]]`
entry and record stay in place, with the title narrowed to the half that remains.

Measured from the tree at `adr069/px-trust-plane-premises`, 2026-09-19. Every count is
registry- or source-derived, and the lane is the DEFAULT `cargo test -p mcp-re-proxy --lib`
one: both controls appear in `-- --list`, so the battery is not a feature-gated zero.

## What landed, and the clause that contains it

THM-0131, statement, verbatim:

> A set of client CRLs is installable only when every one of them is inside its own
> `nextUpdate` window and states one at all. That is a property of the value, not of a call
> site: the evidence type has a single constructor and the constructor performs the
> classification, so startup and the reload worker run one gate rather than two that agree.

`crl_next_update_tests::a_crl_that_never_falls_out_of_force_is_refused` and
`::a_crl_that_states_its_next_update_is_accepted` are the two directions of that sentence.

## The residue

**2 controls**, `mcp-re-proxy`, rust unit test, default cargo lane, carrier
`mcp-re-proxy/src/client_crl_publication.rs`:

- `client_crl_loading_tests::missing_client_crl_file_fails_closed`
- `client_crl_loading_tests::no_crl_paths_loads_empty_vec`

## Why no existing theorem contains it

THM-0131's own words put it outside: the claim is *"a property of the value, not of a call
site"*, and `load_client_crls` is the call site that produces the bytes a value is later
classified from. A path that cannot be read yields no CRL to classify at all, so the gate
THM-0131 claims never runs — the failure is one layer below the level at which the theorem
quantifies.

THM-0054 is the other candidate and declines it explicitly:

> It does not establish that the CRLs a deployment loads are current or complete

and its subject is the VERIFIER's three postures (deny-unknown, full-chain, expiration) over
a foreign `dyn` trait object, not the loader that hands it a list.

`proxy.client_revocation_currency` already owns
`crl_evidence::tests::no_crls_is_evidence_of_a_deployment_without_them`, which is the same
*configuring no CRL is a posture* fact at the evidence type. The loader row beside it is the
I/O half, and adding it to that unit would make its battery cover filesystem fail-closed while
its declared proposition still says nothing about it — ADR-MCPRE-069 §5's prohibition,
verbatim.

## The proposition, as it would be stated

> A client-CRL path a deployment configured is read, or the listener does not start: an
> unreadable path is a hard error naming the path, never a revocation check silently skipped.
> Configuring no path at all is a different fact and is not an error: it loads as an empty
> list, which is the posture of a deployment without CRLs.

**Security consequence.** The fail-open this closes is the one an operator cannot see. A
listener that started on an unreadable CRL path believes it is enforcing revocation, and every
subsequent posture line is about a list that was never loaded — so the transcript, the digest
and the window all describe a control that is not running. The second clause is the
counterweight and is why this is one proposition rather than "errors on anything unusual": a
deployment that configured nothing must not be refused, or the refusal becomes a reason to
configure a CRL nobody maintains.

**Scope.** The LOAD, not the value and not the verifier. Nothing about whether a loaded CRL is
inside its own `nextUpdate` window (THM-0131), nothing about the verifier's handshake posture
(THM-0054), nothing about the CRLs being the right CRLs, which is an operator decision.

**`direct_consequence_severity`:** `critical`, matching the registry's `NP-126.consequence`.

**`depends_on`:** none obviously required. THM-0131 is the natural consumer rather than the
premise: a value can only be classified once it has been read.

**Supporting unit, if ratified.** One new unit over
`mcp-re-proxy/src/client_crl_publication.rs` — a file already declared by
`proxy.client_crl_next_update_gate`, so the addition is a second unit over an overlapping path
rather than a widening of the first. `tested`, V0, `critical`, two `tested_symbols` verbatim,
and a `mutation://` falsifier: make `load_client_crls` skip an unreadable path instead of
erroring, and `missing_client_crl_file_fails_closed` must go red.

## The fingerprint it would carry

New: `theorem_id`, `theorem_claim`, `theorem_dependencies` (empty, or `{THM-0054, THM-0048,
THM-0103}` if the owner edges it to THM-0054 — the closure is TRANSITIVE). `supported_by` is
not a fingerprint component (`_fingerprint.py:707-727`), so **no existing theorem's fingerprint
moves.** It moves only if the owner makes this a premise of THM-0131 or THM-0054, which would
carry THM-0131's and THM-0054's dependents with it.

## What the owner is being asked

Ratify this statement / consequence / scope under ADR-MCPRE-059 §28, or decline it and say what
the two residue controls are instead.
