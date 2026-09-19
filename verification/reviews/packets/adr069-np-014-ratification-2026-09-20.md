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

**The question the owner must answer, stated exactly:** *does the shipped Python SDK promise,
as part of THM-0094, that after `close()` nothing further is signed or transmitted — or is
THM-0094's silence where THM-0095 speaks an intended difference between the two roots?* The
four controls pass either way; what is being decided is whether the product promises it.

## Proposed shape, if the answer is that it promises it

A clause in THM-0094's `statement` mirroring THM-0095's, plus a new unit
`sdk_python.post_close_emission`, `class = "V0"`, `evidence_class = "tested"`,
`direct_consequence_severity = "critical"`, `paths = ["sdk/python/python/mcp_re_sdk/transport.py"]`,
declaring the four controls, attached to THM-0094 in the same change. Theorem-less units
would be unchanged at 20. A mutation probe over the post-close guard is owed under
ADR-MCPRE-068 at `critical`, and there is none today.

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
