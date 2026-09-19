<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-130 — R6 ratification packet: an acknowledgement asserts only what actually happened

**Disposition:** R6, referred whole. Nothing was registered for this item and no
`[[disposition]]` row, `[[proposition]]` entry or record was removed.

## Why no existing theorem contains it

The analysis proposed THM-0101. THM-0101's own scope refuses it:

> The six assembly-owned transitions are EXCLUDED from the correspondence claim: that the
> dispatch, the two continuation facts, retention and the two terminals are stated at the
> right moment is the assembly's own statement, read by hand, and this theorem says only
> that those six are the whole residue and that removing one is detected.

`TerminalResponseServed` and `OpenLegResponseServed` are two of those six, and the 202
acknowledgement is exactly a terminal the assembly states. THM-0101 establishes that the
residue is enumerated; it explicitly does not establish that a member of it is stated
truthfully. That is the proposition NP-130's eleven controls establish.

No other ratified theorem reaches it either. THM-0083's security consequence contains
*a body cannot be dispatched as a request and acknowledged as a notification*, which is the
request-shape half and says nothing about whether the backend received anything. THM-0092,
THM-0093, THM-0096 and THM-0105 each say, in their own words, that what an acknowledged
store write durably establishes is outside their claim. THM-0094 and THM-0095 are the
SDKs' side of the exchange.

## Proposed theorem

**Title.** An emitted acknowledgement asserts only what the serving path knows happened.

**Statement.** Where the serving assembly emits a terminal that ASSERTS something about
execution — the bodyless 202, the retention disposition, the authorization posture carried
to the record, the approval retirement — the assertion is derived from an outcome that
establishes it, and the three outcomes that do not establish it are kept apart from the one
that does. A message the inner plane is not known to have received is not acknowledged; a
timeout is neither a reply nor a definite failure; an unusable answer to a notification
still states that the backend WAS reached, because reaching it is a fact the answer's
unusability does not erase. *No policy is deployed* is carried as a posture and never as a
permit, *retention is not configured* is carried as a disposition and never inferred from
an absent store at the discharge site, and only a real retirement spends an approval.

**Security consequence.** The complement is a signed statement, from the enforcement
boundary, that a backend accepted something no backend is known to have seen — selectable
by a client that simply omits `id`. The same collapse one axis over turns *nobody asked* into
*a policy permitted this* in the audit record, which ADR-MCPRE-066 §1.1 invariant 5 forbids,
and turns *this deployment retains nothing* into a discharged obligation nobody discharged.

**Scope.** The serving assembly's ASSERTING terminals only. It says nothing about which
transition the machine records (THM-0101), which refusal a failure earns (THM-0081), what an
acknowledged store write durably establishes (a foreign per-mechanism premise, THM-0092),
or whether the backend's answer is correct. It is a claim about what MCP-RE says, not about
what the backend did.

**depends_on.** THM-0101 (the transition set), THM-0088 (retention).

**review_requirement.** V0 test battery with a registered mutation falsifier per conjunct
family; the timeout arm is the load-bearing one.

## The unit that would support it

`proxy.acknowledgement_honesty`, `evidence_class = "tested"`,
`direct_consequence_severity = "critical"`, paths = the nine carriers the rows name
(`answering_commitment.rs`, `continuation/mod.rs`, `continuation/open_leg.rs`,
`inner_plane.rs`, `pre_admission/mod.rs`, `pre_admission/action.rs`,
`reply_assembly/accepted.rs`, `reply_assembly/notification.rs`, `retention/mod.rs`),
`tested_symbols` = NP-130's eleven `[[disposition]]` rows verbatim.

## Evidence that already exists

All eleven controls exist, are green in the default `cargo test -p mcp-re-proxy --lib` lane,
and are selected by no unit today. The falsifier is available and unwritten: the timeout arm
in `inner_plane`, weakened to map a timeout onto the definite-failure arm, turns
`a_timeout_is_neither_a_reply_nor_a_definite_failure` and
`a_notification_the_backend_may_not_have_received_is_not_acknowledged` red.

## Fingerprint it would carry

A NEW theorem, so the fingerprint is computed fresh over `encoding_version`, `theorem_id`,
the `theorem_claim` above, `theorem_dependencies = [THM-0101, THM-0088]` and
`theorem_review_requirement`. No existing theorem's fingerprint moves: this packet proposes
no edit to any ratified `statement`, `security_consequence`, `scope`, `depends_on` or
`review_requirement`.

## What granting it needs

An owner. ADR-MCPRE-069 §5 step 2 reserves ratification to the theorem-architecture route,
and this campaign has no authority to state a theorem.
