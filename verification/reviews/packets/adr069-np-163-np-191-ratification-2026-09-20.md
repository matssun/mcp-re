<!-- SPDX-License-Identifier: Apache-2.0 -->
# NP-163 and NP-191 — the authorization serving record, and the theorem that disclaims four of it

**ADR-MCPRE-069 S-09/CO-S1.** NP-163 held seven controls. Four land — under a theorem the plan
did not name — two stay, and one is a separate proposition.

---

## 1. What the record held, measured

| row | control | outcome |
|---|---|---|
| CD-19212 | `an_authorized_request_records_which_policy_permitted_what` | **registered**, THM-0069 |
| CD-19210 | `a_policy_denial_is_recorded_as_a_policy_denial_and_not_merely_as_a_rejection` | **registered**, THM-0069 |
| CD-19211 | `a_request_refused_before_any_policy_ran_is_not_attributed_to_one` | **registered**, THM-0069 |
| CD-19208 | `a_core_verification_failure_still_records_its_frozen_core_reason` | **registered**, THM-0069 |
| CD-19209 | `a_decision_attached_through_the_sdk_producer_is_authorized_end_to_end` | retained, NP-163 |
| CD-19213 | `the_sdk_producer_cannot_build_the_half_pair_this_pep_refuses` | retained, NP-163 |
| CD-19123 | `enforcing_the_transport_contract_does_not_change_which_action_is_authorized` | **NP-191** |

## 2. THE PLAN'S TARGET IS ITSELF THE TRAP THE PLAN WARNED ABOUT

The brief said to register NP-163 against `proxy.authorization_capability` *"not its theorem-less
neighbour"*. Measured on `origin/main` at `f9fe2fd9`: **`proxy.authorization_capability` carries no
theorem.** It is one of the twenty units nothing supports — it appears neither as any theorem's
`owner` nor in any `supported_by` list. It also already holds nine
`tests/integration_async#authorization_serving_test::…` selectors, which is what makes it look
right. Registering there would have closed nothing.

## 3. AND THE THEOREM THE PLAN NAMED DISCLAIMS FOUR OF THE SEVEN IN TERMS

The plan's theorem for this record was THM-0040. Its ratified scope:

> Nor does it establish that a refusal is reported faithfully to an operator; the refusal algebra
> is tested and deliberately carries no theorem, because its vocabulary has no production reader
> today.

Four of the seven rows are exactly that: ADR-MCPRE-066 Slice 1/2 controls over what the AUDIT
RECORD says. They are not THM-0040's, and no amount of choosing a better unit under THM-0040 would
have made them so.

## 4. The corrected home: THM-0069

`proxy.audit_authority_coordinates` resolves to **THM-0069**, whose statement contains each of the
four propositions verbatim:

* *"Every request record states an authorization outcome — not configured, authorized, or refused"*
  → `an_authorized_request_records_which_policy_permitted_what`;
* *"a policy denial's token goes in the authorization coordinate, the two authorization refusal arms
  stay distinguishable, and the arm reached before any policy ran imports no policy vocabulary at
  all"* → `a_policy_denial_is_recorded_as_a_policy_denial_and_not_merely_as_a_rejection` and
  `a_request_refused_before_any_policy_ran_is_not_attributed_to_one`;
* *"The Core verdict and the authorization verdict occupy separate coordinates on one record and
  neither can be read as the other"* → `a_core_verification_failure_still_records_its_frozen_core_reason`.

The unit's own description carries the first and third clauses in lower case, so the appended rows
are strict decompositions of what the unit already says it owns. Its `paths` —
`audit_record/mod.rs`, `audit_record/subject.rs`, `http_profile_serve/authority_verdicts.rs` — are
precisely the production source these four drive; no widening was needed and none was made.

**Lane.** The unit declares no `test_features`, and none is needed: all four appear in
`cargo test -p mcp-re-proxy --test integration_async -- --list` (167 tests, default features).

**What the appended rows add over the seven `lib#` rows already there.** The existing battery
constructs a record and asserts its algebra. These four read a record the PRODUCTION PEP emitted
for a real signed request — so a projection that is correct in the type and wrong at the call site
is visible to them and to nothing above them.

## 5. NP-163's residue — the producer is in another crate

Both retained rows are about `mcp_re_client_core::build_authorization` and
`build_signed_request`. That source is in no proxy unit's `paths`, and a unit's `paths` may not be
widened to reach a control — where controls straddle a source closure the honest resolution is a
twin, and a twin over `mcp-re-client-core` would be a unit over a producer no theorem in the estate
claims. The second row has an independent refusal as well: THM-0040's scope says *"The reference
binding form produces no authorization at all and is outside this claim"*, so the half-pair this
control proves unconstructible is a shape the theorem already declines to reason about.

## 6. NP-191 — the sentence that looks like a home and is not

THM-0040's statement contains *"the decided operation equals the operation the SIGNED BODY named"*,
which is word for word what `enforcing_the_transport_contract_does_not_change_which_action_is_authorized`
measures. It is still not its home. THM-0040 is a claim about `PdpDecisionEvaluator::evaluate` and
an authenticated PDP decision document; this control installs an ADR-MCPRE-065 **Slice 1** policy
and presents no decision at all, under two settings of the MCP transport contract. Its siblings in
that file live in `proxy.authorization_capability`, which carries no theorem, so the only available
R1 closes nothing. Split under RR-002 C5 rather than filed with NP-163, because *the SDK producer
agrees with this PEP* and *an unrelated consistency policy does not move the authorized action* are
two describable propositions.

## 7. What was NOT done

No theorem fingerprint field edited; no new `[[theorem]]`; no unit `description` amended; no unit
`paths` widened; no probe class substituted; no `not-evidence` family created. Units without a
theorem: 20 before, 20 after.
