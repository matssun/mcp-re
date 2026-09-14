-- SPDX-License-Identifier: Apache-2.0
import McpReCore
import Aeneas
import Mathlib.Tactic.IntervalCases
/-!
# `civil_from_days` is total on the domain its caller can supply — THM-0128

The proposition, and the reason it is this one:

> for every `i64` in `[-106_751_991_167_301, 106_751_991_167_300]` — the exact image of
> `i64` under `unix.div_euclid(86_400)` — the model extracted from `civil_from_days`
> evaluates to `ok`. Every intermediate `i64` operation is in range and both narrowing
> `i64 → u32` casts succeed.

`unix_to_rfc3339_utc` stamps `verified_at` and `issued_at` from a caller-supplied
`now_unix`, and `mcp-re-core` never reads a clock itself, so the argument is
attacker-influenced wherever a caller forwards one. Until now the absence of a panic there
was an ARGUMENT — a `#[allow(clippy::arithmetic_side_effects)]` whose justification is a
chain of bounds a reader must follow, checked at two points by
`civil_from_days_is_total_at_the_i64_extremes`. Two points are where a bound argument is
most likely to fail and are still not the domain.

WHAT IS NOT CLAIMED. Not correctness: nothing here says the conversion computes the right
date, only that it computes one. Not the composition with its caller: the link from "any
`i64`" to "a value in this range" runs through `div_euclid`, which the extraction leaves
uninterpreted, so the domain is a hypothesis and a reader checking it against
`unix.div_euclid(86_400)` is doing arithmetic rather than trusting a premise. And nothing
about the TEXT `unix_to_rfc3339_utc` produces — the extraction leaves
`alloc.fmt.format` uninterpreted, so a claim over those bytes is one the model cannot
constrain
(`../../baseline/extraction-pilot-measurement-2026-08-30.md`).

The proof follows the bound chain `format.rs` states in prose — `doe ∈ [0, 146096]`,
`yoe ∈ [0, 399]`, `doy ∈ [0, 365]`, `mp ∈ [0, 11]` — one `step` per operation in the
extracted model, with `omega` on each side condition. Exactly one step needs more than
that, and it is marked below.
-/

open Aeneas Aeneas.Std Result

set_option Aeneas.Deprecated.progressWarning false
set_option maxHeartbeats 4000000

namespace MCPRE.Time

/-- Truncating division by a positive literal, on a non-negative numerator, is Euclidean
division — which is the form `omega` reasons about. Every division in the extracted model
except `era`'s has a non-negative numerator, and this is what lets each bound below be a
one-line `omega` rather than a case split. -/
private theorem tdiv_nonneg_eq {a b : Int} (ha : 0 ≤ a) : a.tdiv b = a / b :=
  Int.tdiv_eq_ediv_of_nonneg ha

/-- The one step of Hinnant's algorithm that linear arithmetic cannot close on its own:
that the year-of-era the model computes really does bracket the day-of-era, so the
day-of-year it derives lies in `[0, 365]`.

`omega` proves each instance and cannot prove the family, because the relation between
`e`'s three divisions and `k`'s two is not linear. There are four hundred instances — the
years of a Gregorian era — and enumerating them is a proof, not an approximation. It costs
about 25 seconds.

This is where the two `i64 -> u32` casts get their bounds, so it is the step the totality
claim actually rests on: without it `d` and `m` are unbounded and the casts may fail. -/
private theorem day_of_year_bound (k e : Int)
    (hk0 : 0 ≤ k) (hk1 : k ≤ 399)
    (he0 : 0 ≤ e) (he1 : e ≤ 146096)
    (h1 : 365 * k ≤ e - e / 1460 + e / 36524 - e / 146096)
    (h2 : e - e / 1460 + e / 36524 - e / 146096 ≤ 365 * k + 364) :
    0 ≤ e - (365 * k + k / 4 - k / 100) ∧ e - (365 * k + k / 4 - k / 100) ≤ 365 := by
  interval_cases k <;> omega

theorem civil_from_days_ok (z : Std.I64)
    (hlo : (-106751991167301 : Int) ≤ z.val)
    (hhi : z.val ≤ 106751991167300) :
    mcp_re_core.time.format.civil_from_days z ⦃ _ => True ⦄ := by
  unfold mcp_re_core.time.format.civil_from_days
  step as ⟨ z1, hz1 ⟩
  split
  · -- z1 >= 0
    rename_i hnn
    have hz1nn : (0 : Int) ≤ z1.val := by scalar_tac
    have hz1hi : z1.val ≤ 106751991886768 := by omega
    step as ⟨ era, hera ⟩
    rw [tdiv_nonneg_eq hz1nn] at hera
    have herann : (0 : Int) ≤ era.val := by omega
    have herahi : era.val ≤ 730692566 := by omega
    step as ⟨ i, hi ⟩
    step as ⟨ doe, hdoe ⟩
    have hdoenn : (0 : Int) ≤ doe.val := by omega
    have hdoehi : doe.val ≤ 146096 := by omega
    step as ⟨ i1, hi1 ⟩
    rw [tdiv_nonneg_eq hdoenn] at hi1
    step as ⟨ i2, hi2 ⟩
    step as ⟨ i3, hi3 ⟩
    rw [tdiv_nonneg_eq hdoenn] at hi3
    step as ⟨ i4, hi4 ⟩
    step as ⟨ i5, hi5 ⟩
    rw [tdiv_nonneg_eq hdoenn] at hi5
    step as ⟨ i6, hi6 ⟩
    have hi6nn : (0 : Int) ≤ i6.val := by omega
    have hi6hi : i6.val ≤ 146096 := by omega
    step as ⟨ yoe, hyoe ⟩
    rw [tdiv_nonneg_eq hi6nn] at hyoe
    have hyoenn : (0 : Int) ≤ yoe.val := by omega
    have hyoehi : yoe.val ≤ 399 := by omega
    step as ⟨ i7, hi7 ⟩
    step as ⟨ y, hy ⟩
    step as ⟨ i8, hi8 ⟩
    step as ⟨ i9, hi9 ⟩
    rw [tdiv_nonneg_eq hyoenn] at hi9
    step as ⟨ i10, hi10 ⟩
    step as ⟨ i11, hi11 ⟩
    rw [tdiv_nonneg_eq hyoenn] at hi11
    step as ⟨ i12, hi12 ⟩
    step as ⟨ doy, hdoy ⟩
    have hkey := day_of_year_bound yoe.val doe.val hyoenn hyoehi hdoenn hdoehi
      (by omega) (by omega)
    have hdoynn : (0 : Int) ≤ doy.val := by omega
    have hdoyhi : doy.val ≤ 365 := by omega
    step as ⟨ i13, hi13 ⟩
    step as ⟨ i14, hi14 ⟩
    have hi14nn : (0 : Int) ≤ i14.val := by omega
    step as ⟨ mp, hmp ⟩
    rw [tdiv_nonneg_eq hi14nn] at hmp
    have hmpnn : (0 : Int) ≤ mp.val := by omega
    have hmphi : mp.val ≤ 11 := by omega
    step as ⟨ i15, hi15 ⟩
    step as ⟨ i16, hi16 ⟩
    have hi16nn : (0 : Int) ≤ i16.val := by omega
    step as ⟨ i17, hi17 ⟩
    rw [tdiv_nonneg_eq hi16nn] at hi17
    step as ⟨ i18, hi18 ⟩
    step as ⟨ i19, hi19 ⟩
    step as ⟨ d, hd ⟩
    split <;> step*
  · -- z1 < 0
    rename_i hneg
    have hz1neg : z1.val < 0 := by scalar_tac
    have hz1lo : -106751990447833 ≤ z1.val := by omega
    step as ⟨ z2, hz2 ⟩
    step as ⟨ era, hera ⟩
    -- The one truncating division whose numerator is negative, and the whole point of
    -- Hinnant's `z - 146096` adjustment: truncation toward zero on the shifted value is
    -- floor division on the original, so `doe` below is the Euclidean remainder.
    have hsign : Int.sign (146097 : Int) = 1 := Int.sign_eq_one_of_pos (by omega)
    simp only [Int.tdiv_eq_ediv, Int.dvd_iff_emod_eq_zero, hsign] at hera
    have hera' : era.val = z1.val / 146097 := by split_ifs at hera <;> omega
    have herahi : era.val ≤ 0 := by omega
    have heralo : -730692558 ≤ era.val := by omega
    step as ⟨ i, hi ⟩
    step as ⟨ doe, hdoe ⟩
    have hdoenn : (0 : Int) ≤ doe.val := by omega
    have hdoehi : doe.val ≤ 146096 := by omega
    step as ⟨ i1, hi1 ⟩
    rw [tdiv_nonneg_eq hdoenn] at hi1
    step as ⟨ i2, hi2 ⟩
    step as ⟨ i3, hi3 ⟩
    rw [tdiv_nonneg_eq hdoenn] at hi3
    step as ⟨ i4, hi4 ⟩
    step as ⟨ i5, hi5 ⟩
    rw [tdiv_nonneg_eq hdoenn] at hi5
    step as ⟨ i6, hi6 ⟩
    have hi6nn : (0 : Int) ≤ i6.val := by omega
    have hi6hi : i6.val ≤ 146096 := by omega
    step as ⟨ yoe, hyoe ⟩
    rw [tdiv_nonneg_eq hi6nn] at hyoe
    have hyoenn : (0 : Int) ≤ yoe.val := by omega
    have hyoehi : yoe.val ≤ 399 := by omega
    step as ⟨ i7, hi7 ⟩
    step as ⟨ y, hy ⟩
    step as ⟨ i8, hi8 ⟩
    step as ⟨ i9, hi9 ⟩
    rw [tdiv_nonneg_eq hyoenn] at hi9
    step as ⟨ i10, hi10 ⟩
    step as ⟨ i11, hi11 ⟩
    rw [tdiv_nonneg_eq hyoenn] at hi11
    step as ⟨ i12, hi12 ⟩
    step as ⟨ doy, hdoy ⟩
    have hkey := day_of_year_bound yoe.val doe.val hyoenn hyoehi hdoenn hdoehi
      (by omega) (by omega)
    have hdoynn : (0 : Int) ≤ doy.val := by omega
    have hdoyhi : doy.val ≤ 365 := by omega
    step as ⟨ i13, hi13 ⟩
    step as ⟨ i14, hi14 ⟩
    have hi14nn : (0 : Int) ≤ i14.val := by omega
    step as ⟨ mp, hmp ⟩
    rw [tdiv_nonneg_eq hi14nn] at hmp
    have hmpnn : (0 : Int) ≤ mp.val := by omega
    have hmphi : mp.val ≤ 11 := by omega
    step as ⟨ i15, hi15 ⟩
    step as ⟨ i16, hi16 ⟩
    have hi16nn : (0 : Int) ≤ i16.val := by omega
    step as ⟨ i17, hi17 ⟩
    rw [tdiv_nonneg_eq hi16nn] at hi17
    step as ⟨ i18, hi18 ⟩
    step as ⟨ i19, hi19 ⟩
    step as ⟨ d, hd ⟩
    split <;> step*

/-- The same fact in the form a reader can check against the Rust without knowing what
`⦃ ⦄` means: the model returns `ok`. `spec` is total correctness — `fail` and `div` are
both `False` under it — so this is a restatement, not a weakening. -/
theorem civil_from_days_total (z : Std.I64)
    (hlo : (-106751991167301 : Int) ≤ z.val)
    (hhi : z.val ≤ 106751991167300) :
    ∃ y m d, mcp_re_core.time.format.civil_from_days z = ok (y, m, d) := by
  have h := civil_from_days_ok z hlo hhi
  cases hr : mcp_re_core.time.format.civil_from_days z with
  | ok r => exact ⟨ r.1, r.2.1, r.2.2, by simp ⟩
  | fail e => rw [hr] at h; simp at h
  | div => rw [hr] at h; simp at h

end MCPRE.Time
