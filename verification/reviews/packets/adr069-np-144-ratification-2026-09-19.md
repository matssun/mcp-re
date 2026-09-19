<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-144 residue — R6 ratification packet: the per-class refusal latch

**Disposition:** R2 in part, R6 for the residue. Four controls landed as
`unit://proxy.admission_record_addressing` under THM-0129 (probe `M287`). Three rows remain;
NP-144's `[[proposition]]` entry and record stay in place.

## What landed, and the clause that contains it

THM-0129, statement, verbatim:

> The SUBJECT comparison, against the id the record was read under, refuses a genuine record
> MOVED onto another workload's key — a forgery a signature cannot see, because the bytes are
> real. And the CURRENTNESS CEILING refuses a genuine record RESTORED after it was
> superseded ... Store write access without the admission signing authority can deny service
> but cannot mint or indefinitely replay an admission.

*The id the record was read under* is the store key, so *the record is addressed by the
workload's own name* and *a key is readable by an operator* are the key half of that
comparison; the restore and the store-writer controls are the other two conjuncts verbatim.

## The residue

`redis_admission_source::refusal_report::tests::{a_class_is_reported_once_and_then_suppressed,
every_class_has_its_own_latch, one_class_being_reported_does_not_suppress_another}`.

THM-0129 says nothing about how often a refusal class is reported, and its scope is explicit
about what it deliberately leaves out (the publication-sequence floor, Redis ACLs, CAS,
availability). Report-once-per-class is OBSERVABILITY of a fail-closed source: its failure
mode is that one noisy class silences another, so an operator never learns the second one
happened. That is a real security-relevant property and it is not an admission-integrity one.

**Proposed statement.** Where a fail-closed source suppresses repeated refusal reports, the
suppression is per refusal CLASS: the first of each class is reported and every repeat is
suppressed, and no class's latch can silence another's.

**Security consequence.** A shared latch turns a second, different failure into silence. The
deployment still fails closed, so nothing is admitted — what is lost is the operator's only
signal that the cause changed, which is the difference between a store that is down and a
store that is answering with records this deployment refuses.

**Supporting unit.** `proxy.refusal_report_latch`, `tested`, medium,
paths `mcp-re-proxy/src/redis_admission_source/refusal_report.rs`,
`test_features = ["redis_replay"]`, three controls. Falsifier: share one latch across
classes and `one_class_being_reported_does_not_suppress_another` goes red.

This is a candidate for a wider claim than one adapter: the same latch shape exists wherever
this estate suppresses repeated diagnosis. An owner may prefer to state it once over the
diagnosis channel rather than once per source.

## Fingerprint

No ratified theorem's fingerprint moves; the attachment is `supported_by`-only.
