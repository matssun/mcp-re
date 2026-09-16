<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-066 Addendum 1 — the admission authority is a third coordinate

**Status:** IMPLEMENTED alongside this document. Authorized by owner ruling on r11 row 9
(`R11-106`), 2026-09-16; the ruling is transcribed in
`work/r11-campaign/RULINGS-OWNER-10.md`.
**Extends:** [ADR-MCPRE-066](audit-composition.md) — audit composition: two authorities, one
record ([#638](https://github.com/matssun/mcp-re/discussions/638)).
**Constrains nothing new.** ADR-MCPS-035's success-event allowlist is untouched, and the
drift guard still reports the success set as exactly two and the key-lifecycle set as exactly
three.

## 1. The finding

`R11-106`. `AdmissionEnforcer::decide` returned `Result<(), _>`, so three facts were dropped
at once:

1. `VerifiedAdmission::degraded` — a serve on a stale snapshot inside P was
   **indistinguishable in audit from a live-confirmed one**;
2. the `Optional` / no-evidence path returned `Ok(())` recording nothing, so *admission was
   checked and passed* and *the call declared no admission and this deployment tolerates
   that* produced **one trace**;
3. `AdmissionSourceError::details` was built and then discarded, so an operator could not
   tell a store outage from a poisoned lock at the point of decision.

The code named the first gap itself and attributed it to the frozen allowlist.

## 2. The ruling, and the design it eliminates

> Live, degraded and not-configured admission are **not Core lifecycle events**. They are the
> VERDICT of the admission authority. Treat this the way ADR-MCPRE-066 correctly treats
> authorization: an independent typed coordinate on the request record.

So the design this addendum exists to reject is **minting a third Core success event**. The
allowlist constrains the **vocabulary**, not the requirement — the same move §1 of the parent
ADR makes for `PolicyError`, applied to a third authority.

This is ADR-MCPRE-066's algebra with one more term, not a new algebra.

## 3. The coordinate

`AdmissionFacet`, owned by `mcp-re-proxy`, closed, and rendered as a single `admission=`
token beside `authz=`:

| variant | means |
|---|---|
| `NotReached` | the exchange ended before the gate was consulted |
| `NotConfigured` | no admission authority is deployed — **not an allow**, and not an examination |
| `LiveConfirmed` | the authoritative current-state relation held |
| `Degraded` | served on a last-known snapshot, inside this replica's own window |
| `Refused` | no admission was established |

`NotReached` is its own answer and not a stand-in for the other four. A refusal that happened
earlier says nothing about admission, and a record reporting one of the gate's verdicts there
would claim a decision nobody took.

**One token, deliberately.** Which workload, which generation and which authority are the
admission EVIDENCE's facts and belong to whatever records those. This coordinate answers
*what did the gate decide about this exchange*; one that also restated the evidence would make
two owners' statements indistinguishable on one line.

## 4. Where it comes from, and why that matters

The facet is the enforcer's own return value, not a reconstruction:

```text
AdmissionEnforcer::decide -> Result<AdmissionFacet, HttpProfileError>
  no enforcer deployed          -> NotConfigured
  AdmissionVerdict::Live        -> LiveConfirmed
  AdmissionVerdict::DegradedCandidate, window unexhausted -> Degraded
  window exhausted / any refusal -> Err, and the record reads Refused
```

`Live` and `DegradedCandidate` are #937's types (`R11-014`). Before them the arm could only
have been re-derived from *it did not refuse*, which is the reconstruction
[`R-COMPOSE`](../../CLAUDE.md) forbids. The facet rides `Exchange::admission` on exactly the
terms `Exchange::authorization` already rides — written by the region that obtains it, read by
the refusal composition, and touched by no stage between.

## 5. Part 3 — the source error's diagnostic — is NOT in this addendum

The ruling is explicit and it is a bound, not a deferral:

> Do NOT log `AdmissionSourceError::details` once per request during an outage. That creates
> an attacker-amplifiable log flood.

During an outage **every** request takes that arm. The diagnostic belongs to the
admission-source health TRANSITION —
`Available -> Unavailable(reason-class + bounded, sanitized diagnostic)` and back — once per
change. That needs state on the enforcer and is separate work; per-request audit carries the
coarse facet only, which is what this addendum delivers.

## 6. What it does not do

It does not widen ADR-MCPS-035. It adds no `event_type`, no `reason` producer, and no
rejection sub-name. A reader of `event_type` sees exactly the tokens they saw before; the
admission verdict is a field beside them, in this crate's own closed vocabulary, exactly as
`authz=` is.

It also does not make the record say whether a degraded serve was CORRECT. That is the
replica's monotonic window's question and `THM-0005`'s scope says the stateless relation does
not establish it. This coordinate reports which arm was taken, so an operator can find them.
