<!-- SPDX-License-Identifier: Apache-2.0 -->
# Phase-1 split — the verifier's ten propositions, as ten owners

**ADR-MCPRE-068 Phase 1**, executing `verifier-results-decomposition-2026-09-18.md`. That
packet measured the defect and stated the split; this one is what landed, what it cost, and
the two things it found that the measurement could not.

The split order is the campaign ruling's scheduler — *highest semantic fan-out, then highest
effective consequence severity, then greatest number of dependent/root paths* — and this unit
is first on every term: **ten propositions, `critical`, three critical roots' closures.**

---

## 1. What landed

| | before | after |
|---|---|---|
| units | 1 | **10** |
| declared paths | 56, in one list | 22 shared + 3–8 per unit |
| controls | 73, in one battery | 73, partitioned, **no control in two units, none dropped** |
| mutation probes | 30, all naming a different theorem | 30 re-partitioned + **1 new** |
| theorems resolving here | 10 | 1 each, and THM-0065 none |

```
http_profile.request_floor_result            THM-0014  critical  4 probes  11 controls
http_profile.request_full_result             THM-0015  critical  4 probes  11 controls
http_profile.bound_response_shared_facts     THM-0021  critical  2 probes   5 controls
http_profile.bound_response_seam_result      THM-0016  critical  1 probe    1 control
http_profile.unbound_response_shared_facts   THM-0022  high      5 probes   7 controls
http_profile.unbound_response_seam_result    THM-0017  high      1 probe    2 controls   ← new
http_profile.bound_response_full_result      THM-0018  critical  4 probes   6 controls
http_profile.delegated_bound_result          THM-0019  critical  5 probes   5 controls
http_profile.delegated_unbound_result        THM-0020  high      4 probes   4 controls
http_profile.delegated_credential_chain      (none)    critical  1 probe   22 controls
```

**The probes were already labelled**, so this is a re-partition of existing evidence: every
`[[probe]].theorem` field decided which unit its probe went to, and all 30 still turn a
declared control red after the move — re-run and measured, not assumed.

---

## 2. THM-0017 had no falsifier, and writing one found a missing control

The decomposition packet's D1 predicted this and P2-V1 recorded it. What it could not predict
is that the gap was **two deep**.

Splitting made THM-0017's owner a `tested` unit at effective `high` with no `mutation://`
falsifier — merge-fatal under N1, where before it was invisible. So **M71** was written: the
exact twin of M26 on the unbound arm, the same slot resolution one function lower in the same
file, weakened the same way.

**M71 failed.**

```
FAIL M71: THM-0017 claims "the presented keyid resolved through the trust seam for the
Response slot, on the unbound arm too", but removing the check left every expected control
green. The conjunct is NOT load-bearing in the declared battery — write a control, do not
soften the statement.
```

The lane was right. `an_unbound_receipt_whose_root_is_unknown_to_the_seam_is_untrusted` does
not detect the weakening, because a fallback to the Request slot fails for an unknown root
anyway. **The unbound arm had no control for its own slot conjunct at all** — its bound twin
has had one since the beginning.

So the control was written:
`proof_path_test#an_unbound_receipt_signed_by_a_request_only_actor_fails_actor_binding`,
signing an unbound receipt with `client-key-1`, which is trusted for the Request slot only. It
passes; M71 now turns it red.

**That is the whole argument for splitting a unit before discharging its obligations.** The
shared unit did not merely hide a missing probe — it hid a missing *control*, and the only
thing that could find it was a falsifier aimed at the proposition rather than at the unit.

---

## 3. A proposition no theorem states, given an owner

`http_profile.delegated_credential_chain` — 22 controls, `critical`. Eighteen of them are the
`lib#delegation::tests::*` battery over `delegation/verify.rs`: validity, algorithm, type,
root signature, issuer trust, expiry and skew, audience, profile, key use, trust epoch,
rollout window, three revocation identifiers, `cnf` binding, segment count. Four are the
end-to-end chain controls M13 attacks.

They sat inside a unit whose subject was *what a successful verifier operation establishes*,
carried as support for whichever of ten theorems a reader happened to be following.

**No theorem is invented for it.** ADR-MCPRE-069 §5 makes stating a claim a product step, so
the unit exists, THM-0019 and THM-0020 name it as a second leaf — their statements already say
*that credential verified as a chain to a root issuer key the trust seam resolved* — and
P2-V2 stands as the obligation to state the proposition at its own altitude.

**M13 was trimmed as part of this.** It attacks `credential_chain.rs`, which both delegated
paths share, so its old `expect_red` named eleven controls across three propositions. A probe
may only expect a control its own unit declares; trimmed to the three the chain unit holds, it
still turns all three red.

---

## 4. Three premises scoped precisely for the first time

`ASM-0027` (Ed25519 verification), `ASM-0028` (SHA-256 second-preimage), `ASM-0029` (the trust
seam answers its selector) were each scoped to the one wide unit — which is to say, to every
verifier operation, whether or not it used them.

| premise | trusted by, now |
|---|---|
| ASM-0027 | the **eight** propositions that directly assert a signature verified. Not `request_full_result` or `bound_response_full_result`: each rests on a signature through its premise, and a premise reached through a theorem edge is not one this unit trusts |
| ASM-0028 | the **six** that compare a digest and conclude byte agreement — three content-digest, the artifact bindings, and the two that compare a `request_evidence` handle |
| ASM-0029 | the **four** that resolve through the seam: the request slot, the two response slots, and the chain's root issuer |

The five propositions that never query the seam no longer trust it, which is the point of
scoping a premise at all.

---

## 5. Two edges corrected

**THM-0065 loses its edge here entirely.** Its subject is EMISSION — *a response this proxy
signs in the bound form binds the request it answers* — it owns
`http_profile.response_emission_binding`, and it already depends on THM-0021 and THM-0022 for
the verification half. The edge claimed support the argument reaches through its premises.
That also removes one of the two theorems D1 found attacked by nothing.

**A `COMPILE_DEPENDENCY` edge is retargeted.** Its own rationale names the REQUEST verifier's
seam resolution — *the subject bound here IS the one the RFC 9421 verifier resolved through
the trust seam* — which is `request_floor_result`'s proposition. Pointing it at the wide unit
made the prerequisite the whole verifier.

---

## 6. What the split does and does not buy

**Does.** N1 now accounts per proposition here: ten claims, ten answers. An edit to
`delegated/unbound.rs` dirties the two unbound propositions and nothing else, where before it
dirtied all ten. The credential chain has an owner. THM-0017 has a falsifier and a control.

**Does not.** The shared floor machinery — `sigbase.rs`, `digest.rs`, the RFC 9421 component
and parameter readers, the core crypto — is in every unit's `paths`, deliberately: every
operation reads it, so it belongs in every fingerprint that depends on it. An edit there still
dirties all ten, and should.

**Still owed.** The verifier is one of five units that answered for several claims. The
remaining four are `scitt_receipt_offline` (6), `tls_listener_state` (3), `exchange_lifecycle`
(3) and `audit_record_coordinates` (3), in the scheduler's order.

---

## 7. Measured

```
[manifests] PASS — 159 unit(s), 130 theorem(s)
verify-mutations: PASS — 30 re-partitioned probes, each turning a declared control red
verify-mutations: PASS — M71, after the missing control was written
claim-surface gate: OK — 12 roots, every claimed root reviewed at its current fingerprint
check-generated: VERDICT: PASS
21 platform suites: 0 failure(s)
```

Three platform suites used the wide unit as a fixture and were retargeted;
`test_measured_inputs.py`'s assertions were rewritten from magnitudes (`> 50 symbols`,
`> 20 probes`) to equality against the registry, which is strictly stronger and does not
depend on a unit being large.
