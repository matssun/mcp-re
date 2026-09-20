<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-014 — R6 ratification packet: after close, the Python SDK signs and transmits nothing

**Disposition:** referred WHOLE. Nothing was registered and nothing was removed. All four
`[[disposition]]` rows (CD-1047 … CD-1050), the `[[proposition]]` entry and the record stay
in place.

## The premise the slice arrived with, and why it is false

`ANALYSIS-sdk-asymmetry.md` blocked this record on the claim that adding
`unit://sdk_python.post_close_emission` to THM-0094's `supported_by` republishes the root as
an ADR-MCPRE-059 §28 event. Measured against the code that computes the fingerprint,
`tools/verification/_fingerprint.py::fingerprint_theorem`, it has exactly five components:

```
encoding_version            THEOREM_ENCODING_VERSION
theorem_id                  entry["id"]
theorem_claim               _claim_digest(entry)  = statement + security_consequence + scope
theorem_dependencies        _dependency_closure(entry["id"], by_id)
theorem_review_requirement  entry["review_requirement"]
```

`supported_by` is not one of them. Adding the edge moves no fingerprint, drops no standing
approval and is not a §28 event. That premise is retired.

## The blocker that is real

There is no edge to add. An attachment asserts that the unit is a strict decomposition of a
proposition the ratified theorem already contains, and THM-0094 contains none.

Searched across THM-0094's `statement`, `security_consequence` and `scope`, the only
occurrence of *close* is the idiom *"fails the call closed"*, about an elicitation. The
nearest real clause is:

> A LOCAL failure — a transport deadline, a cancellation, a local I/O or signing failure —
> is reported as a local and ambiguous failure under the SDK's own prefix: never as
> `not_executed`, never as retry-safe, and never as a wire code the peer did not send.

That governs how an aborted exchange is REPORTED. NP-014's four conjuncts are about what is
EMITTED and what is ACCEPTED after `close()`: further work refused, in-flight work aborted
rather than drained, an in-flight notification aborted, nothing delivered to a caller that
has left. A transport that signed and POSTed a queued request after `close()` and then
reported the outcome under the SDK's own prefix satisfies the clause above and violates
every one of NP-014's.

Nor is it in existing subordinate authority. THM-0094's closure is ten units; none states a
post-close emission property. The closest, `sdk_python.correlation_lifecycle`, already
declares `test_close_clears_abandoned_correlation_state` under *"no remotely triggerable
outcome leaves a correlation entry outstanding"* — a claim about the correlation store, not
about emission.

## The asymmetry is at the theorem layer, not the unit layer

THM-0095 states it, in `scope`, verbatim:

> THE ABORT RESTS ON NOTHING TRUSTED, and ASM-0043 is discharged rather than renewed. The
> guard that stops a request still queued at the concurrency semaphore from being signed and
> sent after `close()` reads this transport's own state — assigned synchronously by
> `close()` before anything is aborted — rather than `AbortSignal.aborted`, so it depends on
> this file and not on a runtime semantic.

`sdk_typescript.post_close_emission` is `critical`, attached to THM-0095, and carries twelve
controls. THM-0094 has no counterpart sentence and no counterpart unit. The record's own
finding — *"it is the two system roots promising different things"* — is therefore correct
and is a statement about the two theorems, not about a missing registry row.

## What ratification requires

Amending THM-0094's `statement` or `scope` to carry a post-close emission clause. Both are
`theorem_claim` components, so unlike `supported_by` this DOES republish the root: it moves
THM-0094's fingerprint and drops its standing approval under *Owner security-specification
review*. That is an owner decision about what the shipped Python SDK promises, which is R6.

## Why the two roots differ on the record — a measured provenance, and it reframes the question

The difference between THM-0094 and THM-0095 here has a provenance, and it is neither "intended
product difference" nor "implementation drift". It is an asymmetry in CLAIM-SURFACE PROVENANCE:
which root happened to hold an assumption whose retirement required saying the thing out loud.

Verified at head `5b906abf`:

- `verification/policy/assumptions.toml` ASM-0043:
  `description = "WITHDRAWN — discharged by unit://sdk_typescript.post_close_emission."` Its
  justification records what the premise was: the TypeScript post-queue guard read
  `AbortSignal.aborted`, so the property rested on a RUNTIME semantic.
- `verification/policy/theorems.toml`, THM-0095 `scope`: *"THE ABORT RESTS ON NOTHING TRUSTED,
  and ASM-0043 is discharged rather than renewed."* — the sentence that introduces the
  post-close clause into THM-0095's claim surface.
- `unit://sdk_typescript.post_close_emission` is in THM-0095's `supported_by`; THM-0094's
  `supported_by` is ten units and contains no counterpart.
- The Python side had no comparable premise. Of the 47 assumptions in `assumptions.toml`, the
  only one naming any `sdk_python` unit is ASM-0042
  (`WITHDRAWN — discharged by unit://sdk_python.bounded_read.`), which is about the bounded
  read, not about post-close emission. No assumption mentions a Python post-close guard, so
  nothing ever forced the sentence onto THM-0094.

So THM-0095 speaks because a premise had to be retired there, and THM-0094 is silent because no
premise made anyone speak. The record's silence is therefore not, on its face, evidence of a
decision either way.

**The question the owner must answer, stated exactly:** *does the shipped Python SDK promise
post-close non-emission **on its own account**, independently of the fact that only the
TypeScript root had an assumption whose retirement required stating it?*

Put the other way: THM-0094's silence where THM-0095 speaks may be an intended product
difference, or it may be an accident of assumption retirement. This packet does not decide
that, and neither reading may be taken from the record alone. The four controls pass either
way; what is being decided is whether the product PROMISES it.

## The implementation symmetry — evidence, explicitly not authority

The four Python controls named in *Lane* below exist in `sdk/python/tests/test_transport.py`
and PASS on the prepared lane (re-verified at head `5b906abf`, 4 passed / 63 deselected on
`sdk/python/.venv-cp314`, CPython 3.14.7):

```
test_close_aborts_in_flight_work_rather_than_draining_it     (line 528)
test_close_aborts_an_in_flight_notification_too              (line 548)
test_close_refuses_further_work                              (line 573)
test_close_delivers_nothing_to_a_caller_that_has_left        (line 586)
```

The Python transport therefore IMPLEMENTS and TESTS the guarantee. The divergence between the
two roots is in the claim surface alone, and **the owner should not read this packet as saying
the post-close guard is absent from the Python transport. It is present.**

This is stated as **evidence about the implementation, not as authority about the claim.** The
campaign's governing rule cuts both ways: an implementation difference between the two SDK
roots is not authority for a product difference, and implementation SAMENESS is likewise not
authority for product sameness. Only the owner can decide what the shipped Python SDK promises.
What the symmetry is good for is bounding the work: if the answer is that it promises it, the
behaviour already exists and the ratification is a claim-surface change plus a falsifier, not an
implementation project.

## Proposed shape, if the answer is that it promises it

A clause in THM-0094's `statement` mirroring THM-0095's, plus a new unit
`sdk_python.post_close_emission`, `class = "V0"`, `evidence_class = "tested"`,
`direct_consequence_severity = "critical"`, `paths = ["sdk/python/python/mcp_re_sdk/transport.py"]`,
declaring the four controls, attached to THM-0094 in the same change. Theorem-less units
would be unchanged at 20. A mutation probe over the post-close guard is owed under
ADR-MCPRE-068 at `critical`, and there is none for Python today.

**The model for it is `M282-typescript-nothing-is-signed-after-close`**, in
`verification/policy/mutation-probes.toml` over `unit = "sdk_typescript.post_close_emission"`.
It is not merely an example of the shape; it carries the finding the Python probe must inherit.
M282 is this registry's FIRST COMPOUND falsifier: one primary anchor (`#refuseIfClosed()`
reading the transport's own `#state`) plus two `also` anchors over the per-leg abort checks,
because — in its own note — three sites each enforce the WHOLE conjunct on the paths a closed
transport can still reach, so removing any ONE of them leaves every declared control green. The
one-anchor schema reported the conjunct as unprotected when it was protected three times over.
A Python falsifier written against a single anchor would reproduce exactly that false negative;
the Python guard's own defence-in-depth sites must be enumerated the same way. Note also M282's
distinction between DEFENCE IN DEPTH (one conjunct, several anchors, one probe) and COMPOSITION
(two conjuncts, each taking its own probe) — that is the judgement the Python probe's author has
to make, and it is already worked through there.

## Lane

`sdk/python/tests/test_transport.py` opens with
`pytest.importorskip("mcp", reason="the transport adapter needs the upstream MCP SDK")`. In
the authoritative lane — `sdk/python/.venv-cp314`, prepared by
`scripts/prepare_python_matrix.sh` on the pinned CPython 3.14.7, with the `dev` extra
installed — the import succeeds and the four controls are selected and PASS. Outside it they
select to ZERO and the file reports green having measured nothing. Any ratification must run
the prepared interpreter, never a bare `pytest`.

## N1

Nothing registered. No unit changed. No obligation moves.
