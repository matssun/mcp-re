# ADR-MCPRE-068 Phase 2, slice 33 — the compound falsifier, and an empty ratchet

One probe, `M282`, one mechanism, and the N1 registry reaches **zero open obligations**.

## 1. The lane was reporting a false verdict

`sdk_typescript.post_close_emission` was the last open row, and it was open because the
one-anchor schema could not express the weakening that falsifies it. Three sites each enforce
the whole proposition on the paths a closed transport can still reach:

| site | reads |
|---|---|
| `#refuseIfClosed()` | `#state`, an ordinary field this class assigns |
| the exchange's pre-sign check | `this.#abort.signal.aborted` |
| the pre-prompt check before `answerInputRequired` | `this.#abort.signal.aborted` |

Removing any one leaves every declared control green, so the lane reported *the conjunct is
NOT load-bearing in the declared battery* — **which was false.** It was protected three times
over, and the lane could not say so.

That verdict is the one this lane must never reach dishonestly, so it is what justified
building the mechanism rather than softening the statement.

## 2. Measured, not assumed

Each single site was probed alone before the compound one was registered:

| weakening | verdict |
|---|---|
| `#refuseIfClosed()` alone | **FAIL** — every expected control green |
| the pre-sign abort check alone | **FAIL** — every expected control green |
| all three, atomically | **ok** — the control turns red |

That is the owner's rule applied literally: *one production site removed, property still holds
≠ falsifier failed; all independent sites carrying the proposition removed, property becomes
false = correct falsifier.*

## 3. Narrowly typed, and deliberately not a language

`also` is a list of `(path, anchor, weakening)` triples, each held to the same single-site rule
as the primary anchor. There is no ordering, no conditional, no expression over sites. A probe
using it states that **these sites together carry one conjunct**.

Three properties make it honest, and each has its own control:

- **All or nothing.** Every site is validated before any file is written, so a partial
  application cannot leave a surviving carrier holding the property while the battery runs.
- **Compounding within one file.** Each weakening is applied to the text **as already
  weakened**, because two sites of one carrying set routinely live in one file — applying each
  to a fresh copy of the original would keep only the last.
- **No site named twice.** Weakening one site twice weakens one site, and would report a
  compound falsifier over a carrying set it never removed.

**Composition must not use it.** Where two checks each refuse a shape the other admits they are
two conjuncts, and each takes its own probe; weakening both at once would report one discharge
for two propositions and hide which of them a battery covers. The registry holds many such
pairs — `M181`/`M182`, `M215`/`M216`/`M217`, `M275`/`M277` — and none uses `also`.

## 4. The ASM-0043 note, still attached

The two per-leg checks read `this.#abort.signal.aborted` — the runtime semantic ASM-0043 was
withdrawn to stop trusting. `#refuseIfClosed()` reads `#state`, which is the repair that let the
premise be withdrawn.

This probe measures the carrying set **as it stands**. Ceasing to credit the weaker carrier is a
REMEDIATION question about which sites should remain, not a falsifier question, and it is not
answered here.

## 5. An empty ratchet

`config/assurance-obligation-debt.toml` now holds no rows. Every one it held at the baseline was
discharged by a registered falsifier **measured** to turn a declared control red — never by a
waiver, a reclassification, or a bulk registration. The Phase-1 splits replaced wide propositions
with narrow ones by succession, so the population it bounded grew before it shrank, and it shrank
to nothing.

The file stays, because it is still the ratchet: a proposition that gains an N1 obligation by
being added, reclassified or raised in severity may not be written into it. With no rows left,
that rule now says exactly one thing — **every `tested` proposition at effective Medium or above
names a falsifier, or the gate fails.**

## 6. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `sdk_typescript.post_close_emission` | `M282` | critical, root-reachable |

**N1: 1 -> 0.** The probe registry 303 -> 304.
