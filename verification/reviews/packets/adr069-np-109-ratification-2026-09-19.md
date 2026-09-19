<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-109 — R6 ratification packet: the residue of the admitted-time-era record

**Disposition:** SPLIT. Three of five controls registered into an existing battery; the two
below referred. Their `[[disposition]]` rows and the narrowed `[[proposition]]` entry stay in
place.

## What landed, and why it needed no packet

`boundary_lowest_admitted_instant`, `boundary_highest_admitted_instant` and
`boundary_a_five_digit_year_is_refused` joined `unit://core.time_rfc3339`'s `tested_symbols`.
THM-0002 does not merely permit this — it CITES them:

> Both bounds are TIGHT: each is attained by an accepted timestamp, so neither can be
> narrowed.

and, in the scope:

> The two endpoints specifically are reachable, and are pinned by boundary controls at their
> exact Unix seconds, but the claim is containment.

"Pinned by boundary controls" named controls that were in no battery. No new unit, no `paths`
change, no new theorem field; the unit is `evidence_class = "proved"` and the R1 half inherits
that, so no new ADR-MCPRE-068 obligation arises.

## Referred control 1 — `admitted_era_round_trips_through_the_formatter`

THM-0002 excludes it by name, in terms:

> It says nothing about the inverse direction: that unix_to_rfc3339_utc round-trips a value in
> this range is a different proposition with its own evidence.

There is no judgement to make. The theorem has already been reviewed and has already declined
to state this, and a §14 record declining an exception is a completed review, not a gap. The
control measures `unix_to_rfc3339_utc` — a function `core.time_rfc3339`'s `proved_symbols` do
not name and whose postcondition no prover has stated.

## Referred control 2 — `fixed_digit_fields_are_total_outside_the_parser_widths`

**The scheduling analysis grouped this with the formatter and the grouping was wrong.** The
control is about `parse_fixed_digits`, the parser's own helper, and touches no formatter. It
was judged on its own, as RR-002 C5 requires, and it is referred for a different reason.

The case FOR registering it is real and should be recorded. Its doc comment says:

> The body is `external_body` to Verus, so the prover checks the CALLER against ASM-0001 and
> never looks inside. These are the checks that stand in its place.

THM-0002's scope locates its own totality evidence — *"Totality is discharged by the absence
of a precondition together with the prover's panic-freedom obligation, not by an ensures
clause"* — and this control is the substitute evidence at the one place inside
`parse_rfc3339_utc` that the prover does not enter. That is a strong containment argument for
part of what the control asserts.

The case against, which decides it: the control asserts six things, and three of them —

```rust
assert_eq!(super::parse_fixed_digits(digits, 100, 2), None);   // start past the end
assert_eq!(super::parse_fixed_digits(digits, 30, 10), None);   // width past the end
assert_eq!(super::parse_fixed_digits(digits, 0, 35), None);    // width that would leave i64
```

— are widths `parse_rfc3339_utc` never issues. Its six call sites use widths 4 and 2 at fixed
offsets, and the control's own NAME says "outside the parser widths". So the proposition the
control states is that `parse_fixed_digits` is a TOTAL FUNCTION for any caller, which is
strictly wider than THM-0002's claim about `parse_rfc3339_utc`. Clause 2 asks for a strict
decomposition of a proposition already contained; a wider proposition is not one, and a
control cannot be split into the half that fits.

Under-registering is recoverable; over-registering puts a false claim in the graph. It stays.

## Proposed shape for ratification

The two controls are two propositions and should not be ratified as one.

1. **The formatter's inverse.** *`unix_to_rfc3339_utc` is total on `i64` and, restricted to
   `[-62167219200, 253402300799]`, is a left inverse of `parse_rfc3339_utc`.* The natural home
   is a theorem `depends_on = ["THM-0002"]`, owned by `core.time_rfc3339` or by a sibling unit
   over `time/format.rs`, at severity `high`: an evidence artifact whose timestamp formats to
   an instant a peer reads differently is the concrete failure. The evidence class question to
   answer first is whether this should be PROVED rather than tested — the era is small, the
   function is already in a Verus-pilot unit, and a round-trip postcondition is the kind of
   thing the prover is there for.
2. **The helper's totality.** *`parse_fixed_digits` returns `None` rather than panicking or
   overflowing for every `(start, width)`, including those no current caller issues.* This is
   the standing-in-for-`external_body` obligation made explicit. It belongs with ASM-0001 and
   is most honestly ratified as part of whatever retires the `external_body` annotation, at
   which point the control becomes redundant rather than unclaimed.

## N1

Three symbols joined a `proved` unit's existing battery, which owes no new falsifier. Nothing
else registered. No obligation moves.
