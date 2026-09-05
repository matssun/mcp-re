<!-- SPDX-License-Identifier: Apache-2.0 -->
# Owner review packet — THM-0094, the narrowed supported-runtime boundary

**One subject: the supported-runtime conjunct of THM-0094, and nothing else.** ADR-MCPRE-059
§14.7 / §28. Layer 1 — evidence about the tree, not an approval and not authoritative state.

This packet does **not** supersede `thm-0094-final-2026-09-03.md`. That packet's subject was
the whole claim, and every conjunct it carried other than the runtime boundary is unchanged
here, byte for byte. This one exists because exactly one conjunct moved and the standing
record ratified that conjunct by name.

---

## 1. What moved

`requires-python` narrows from `>=3.10,<3.15` to `>=3.14.5,<3.15`, and
`toolchains.lock.toml` `[python].interpreters` from five pinned patches to one.

The theorem's **statement** and **security_consequence** are untouched. The **scope** changes
in one place: the `THE SUPPORTED RUNTIME SET IS PART OF THE CLAIM` paragraph is restated for
the new range, and a `THE SET WAS NARROWED ON 2026-09-05` paragraph is added stating the
change as a withdrawal.

Because `scope` is inside `_claim_digest`, the fingerprint moves. It is not a documentation
edit that the gate happens to notice — it is a change to what the theorem claims.

## 2. Why the standing record cannot carry forward

`verification/reviews/specification/THM-0094.json` ratifies the runtime boundary as an
explicit conjunct:

> THE SUPPORTED-RUNTIME BOUNDARY IS PART OF THE APPROVAL: CPython 3.10, 3.11, 3.12, 3.13 and
> 3.14 … and the REGISTERED root battery executed on **every supported minor**.

A narrower claim is a different claim. The record names five minors; the tree now claims one.
Carrying the record forward would leave an approval standing over a proposition it never read.

## 3. Measured fingerprints

| tree | theorem_claim | fingerprint |
|---|---|---|
| `origin/main` @ `72005913` | `sha256:9848e5d75e6e36f84ccf2c490628410547c3418d81eec3cc31572c3cd5e293ec` | `sha256:ec6f05b3862d0b005102310b432e10cdba3c34613aabe3236fc79f8e40781509` |
| standing review record | `sha256:9848e5d7…` | `sha256:ec6f05b3…` |
| **#813 @ `003ee0e5`** | **`sha256:e28a6eb4304742438d65ed2f6a34413b2069b9b2223d42fa55e86874daac26a7`** | **`sha256:ea2a919168b3aac5200e3985bdea22e0244b0d65c05b3c81462b6c6b96176d31`** |

Main and the record agree exactly, so THM-0094 is `REVIEWED` on main and this PR alone moves
it. Both worktrees were measured at the named revisions, not inferred from the checkout.

## 4. What is being asked, conjunct by conjunct

Everything below is a **narrowing**. Nothing in this delta widens a claim.

1. **The supported set is CPython 3.14 alone**, at pinned patch `3.14.7`.
2. **The floor carries a patch component, and it is load-bearing.** 3.14.0–3.14.4 ship the
   incremental cycle collector CPython reverted in 3.14.5. They are outside the claim as
   surely as 3.13 is. The gate reads the *minor*, so 3.14.7 is the measured representative of
   the claimed 3.14 line exactly as 3.10.20 was of 3.10 before it.
3. **3.10 through 3.13 are outside the claim entirely** — not weakly covered, and not covered
   by inference from an adjacent minor.
4. **The `read1` deadline argument is unaffected in strength but narrower in domain.** The
   scope already records that the read bound rests on stdlib `read1` behaviour, which is a
   per-minor fact. That is now asserted over one minor with one measured battery, rather than
   five minors with five. The claim is smaller and the evidence density per claimed minor is
   unchanged.
5. **This is a support withdrawal, decided on its own merits.** The earlier floor was
   inherited from the upstream MCP SDK's own range, which is not this package's obligation.

## 5. What is NOT in this delta

- The correlation, trust-posture, elicitation, and execution-honesty conjuncts — unchanged.
- `depends_on = []`, the supporting unit `sdk_python.exchange_path`, and the absence of any
  registered assumption — unchanged.
- ASM-0042's discharge — unchanged.
- THM-0095 (TypeScript) — untouched; it carries its own runtime evidence and its own record.

## 6. Evidence

| check | result |
|---|---|
| `scripts/python_runtime_gate.py` | OK — 1 minor claimed, each measured on exactly one pinned interpreter (3.14.7) |
| `verify-tests sdk_python.exchange_path` | PASS — 39 tests on `cpython-3.14.7`, and on no other |
| `check-generated` | 6 assurance views current |
| `claim_surface_gate.py` (lands in #812) | FAIL on THM-0094 only — `STALE_CLAIM: changed since review: theorem_claim` |

The gate's refusal is its first real case and is correct.

## 7. The downloader interpreter, and why it is not a weakening

`downloader — Python maturin wheel` moves 3.12 → 3.14. That job **installs** the built wheel,
so pip refuses an interpreter outside `requires-python`; the observed failure
(`3.12.14 not in '<3.15,>=3.14.5'`) was the correct one.

Its independence is unchanged and was not traded away. What makes that lane independent
evidence is the **second OS, the installed artifact, and directory-based selection of it** —
never the interpreter differing from the one the authoritative matrix pins. Running it outside
the declared support surface would not have been stronger evidence; it would have been
evidence about an unsupported configuration.

## 8. Not part of this review

dev1's uv-managed CPython 3.11.15 lost its stdlib, and the narrowing means the verification
lane no longer needs that interpreter. **That is a consequence of the support decision, not a
reason for it**, and it closes nothing: whatever reaped two independent toolchain stores on a
box with 600 GB free is unexplained, remains an open operational finding, and may recur.

## 9. No record is written here

Minting the specification record alongside the change that invalidated it is the
single-command self-approval §14.7 exists to prevent. If approved, the record is:

- **subject** `THM-0094`, **axis** `specification`
- **reviewed_fingerprint** `sha256:ea2a919168b3aac5200e3985bdea22e0244b0d65c05b3c81462b6c6b96176d31`
- **theorem_claim** `sha256:e28a6eb4304742438d65ed2f6a34413b2069b9b2223d42fa55e86874daac26a7`
