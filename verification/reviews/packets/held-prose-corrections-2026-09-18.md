<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-MCPRE-068 Phase 1 — the held prose corrections, and two the table did not hold

When a unit is split, `owner`, `supported_by` and probe `unit` fields retarget freely: none is
in a fingerprint. A unit id inside another theorem's `scope` is different — `theorem_claim =
statement + security_consequence + scope` — so replacing it there moves THAT theorem's claim
digest and the `theorem_dependencies` closure of everything above it.

`residue-units-2026-09-18.md` therefore reverted four such edits and held them as claim
corrections rather than applying them as renames. The splits are now on `main` (#996), the
four sentences name units that no longer exist, and this applies them through the register.

## Measured, not read off the table

The held table listed four. A sweep of every theorem's `statement`, `security_consequence` and
`scope` for a unit id absent from `verification.toml` found **eight occurrences across seven
theorems**:

| theorem | named | now names | why it moved |
|---|---|---|---|
| THM-0126 | `client.response_acceptance` | `client.response_signer_authorization` **and** `client.response_binding_disposition` | #996 |
| THM-0126 *(2nd)* | `client.response_acceptance` | `client.response_signer_authorization` | #996 — **not in the table** |
| THM-0084 | `client.response_acceptance` | `client.response_binding_disposition` | #996 |
| THM-0098 | `proxy.trust_configuration_state` | `proxy.trust_document_locator` | #996 |
| THM-0119 | `proxy.trust_plane_runtime` | `proxy.trust_resolution_window` and `proxy.trust_reload_cadence` | #996 |
| THM-0130 | `proxy.audit_record_coordinates` | `proxy.audit_vocabulary_import` | #996 — **not in the table** |
| THM-0123 | `client.local_ingress_authority` | `client.bind_scope`, `client.accepted_authority`, `client.caller_shape_admission` | #987, pre-existing |
| THM-0127 | `client.config_lattice` | `client.local_leg_declaration` | **never existed** |

Two of the eight were caused by the same split campaign and the table missed them; two predate
it. The table was a record of what one reverting commit had touched, not a measurement of the
defect — which is the argument for sweeping rather than reading a list.

## THM-0127 is a different defect

`client.config_lattice` appears in no version of `verification.toml` in the repository's
history (`git log -S` finds nothing). THM-0127's scope cited an authority that was **never
registered** — not a reference that decayed, but one that was never live. It reads exactly
like the other seven and is the more dangerous kind, because no split will ever break it and
no rename sweep would have found it: only a check against the unit set does.

The bound it attributes is real and locatable: `trust.reload_secs` is bounded at
`mcp-re-client/src/config/validation.rs:67`, which is `client.local_leg_declaration`'s path.

## Two replacements resolved by CONTROLS, not by description

**THM-0130.** `proxy.audit_record_coordinates` was split by #996 into
`proxy.audit_authority_coordinates` and `proxy.audit_vocabulary_import`, and the sentence —
*"whether a given value is a closed token or open text is its owner's decision, measured by
X"* — reads plausibly against either description. Their control sets decide it:

```
proxy.audit_authority_coordinates   7 controls, 0 naming token/text
proxy.audit_vocabulary_import       6 controls, including
    authorization::audit::fields::tests::a_client_named_target_is_classified_as_text
```

The classification is measured by the second. Choosing on description would have been a
coin-flip recorded as a claim.

**THM-0123.** The sentence enumerates three things — the bind scope, the accepted authority,
the head fields — and the dead unit was one owner for all three. THM-0091's `supported_by`
names the successors, and the three map one-to-one rather than needing a judgement.

## What moved, and the two roots that inherit it

Seven premises' claim digests moved, so the `theorem_dependencies` closure of everything above
them moved too. `claim_surface_gate.py` reported exactly that, on two published roots:

```
§2 claims THM-0074 … STALE_DEPENDENCY_CLAIM: changed since review: theorem_dependencies
§2 claims THM-0076 … STALE_DEPENDENCY_CLAIM: changed since review: theorem_dependencies
```

That is the gate working, not a surprise: it is the same signal that caught the first attempt
at these edits when they were made as renames. Both roots are at their reviewed fingerprint on
`main`, so both chains start from the value the owner actually read, and both are recorded as
`theorem_dependencies` corrections.

**No root statement, consequence or scope is touched.** No accepted promise is weakened,
removed or expanded; no product behaviour changes; no severity moves. Every edit replaces a
dead unit id with the live owner of the same proposition.
