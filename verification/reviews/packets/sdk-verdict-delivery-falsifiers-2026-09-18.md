# ADR-MCPRE-068 Phase 2, slice 3 — verdict delivery, and the conjunct nobody tested

`verdict_delivery` is critical and root-reachable in both SDK roots, and its proposition is
the one an application depends on most directly: **a refusal is never a result.** Four
probes, `M186`–`M189`, and the interesting one is the probe that FAILED.

## 1. The outcome gate

| probe | site | control |
|---|---|---|
| `M186` | `if verified.outcome != "success":` | a verified rejection receipt is delivered as an error, not a result |
| `M187` | `if (verified.outcome !== "success") {` | the TypeScript twin |

This statement is the only gate between a rejection receipt and the result path — everything
below it treats the verified body as a reply to hand the session. Under the weakening, a
receipt the boundary REFUSED arrives as a successful result and the application cannot tell
it was rejected at all.

The signature verification above is not a second carrier of this proposition. It establishes
that the peer really said this, which is what makes the rejection *authentic* rather than
ignorable; it says nothing about which path the verdict takes afterwards.

## 2. M188 failed, and that is what it was for

The TypeScript unit's declaration already stated the conjunct:

> …an **EMPTY** wire code is substituted rather than passed through as an error the
> application cannot act on…

The production check was there. The battery did not cover it. Weakening
`verified.wireCode ? verified.wireCode : "mcp-re.response_sig_invalid"` to a bare
pass-through left **every expected control green**, and the lane refused:

```
FAIL M188: THM-0095 claims "an empty wire code is substituted…", but removing the check
left every expected control green. The conjunct is NOT load-bearing in the declared
battery — write a control, do not soften the statement.
```

So a control was written. `substitutes a wire code the receipt did not carry` drives a
forced rejection verdict for each of `""`, `null` and `undefined` and pins the delivered
`error.message` at `mcp-re.response_sig_invalid`.

**Why `M187` cannot stand in for it.** Passing the raw value through still delivers an
*error* — it is an error whose `message` is the empty string. The refusal-is-never-a-result
conjunct holds under that weakening, which is exactly why it needed its own probe.
`wireCode` is documented as a frozen `mcp-re.*` token an application BRANCHES on, and the
empty string matches no documented token.

## 3. The same gap, mirrored, in the other SDK

`M189` probes the Python site — `verified.wire_code or "mcp-re.response_sig_invalid"` — and
found the defect in its other form. TypeScript **declared** the conjunct and did not test
it; Python **implemented** it and neither declared nor tested it. A production check no
declaration mentions is as unfalsifiable as a declaration no test covers, and both halves
are repaired here: the unit description now states the conjunct and a parametrized control
covers `None` and `""`.

This is worth generalising as a survey question rather than a one-off repair: *where else
does an `x or DEFAULT` in an SDK delivery path carry a security-relevant substitution that
no declaration names?* Not opened here.

## 4. What this slice discharged

| unit | probes | severity |
|---|---|---|
| `sdk_python.verdict_delivery` | `M186`, `M189` | critical, root-reachable |
| `sdk_typescript.verdict_delivery` | `M187`, `M188` | critical, root-reachable |

N1 moves 83 -> 81; the probe registry 207 -> 211. Two new controls, each written because a
falsifier proved the old battery could not see the check. Neither was registered in bulk:
each names the weakening it went red under.
