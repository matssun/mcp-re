# ADR-MCPRE-068 Phase 2, slice 2 — the trust anchor, in both SDKs

The mechanism built in slice 1 is now used for what it was built for. The scheduler put
`trust_anchor_completeness` next on all five criteria at once: effective severity
**critical**, root-reachable in both `THM-0094` and `THM-0095`, one proposition stated in
two ecosystems, a production site already located, and a battery that already existed.

## 1. The unit states three propositions, not one

The obligation is *one registered falsifier attacking this proposition's production
property*, and the honest reading of "this proposition" here is three of them. The unit's
own description says so — completeness **and** denylist shape — and the denylist half is
itself two checks that admit what each other refuses:

| conjunct | production site | fails |
|---|---|---|
| the anchor is complete or construction is refused | `if missing:` / `if (missing.length > 0)` | **closed** — an empty member matches nothing |
| a bare-string denylist is refused | `isinstance(…, (str, bytes, bytearray))` / `!Array.isArray(revoked)` | **open** |
| an entry that cannot match an identifier is refused | `if bad:` / `typeof id !== "string" \|\| id.length === 0` | **open** |

So six probes, `M180`–`M185`, three per SDK.

## 2. These are COMPOSITION, not defence in depth

Slice 1 recorded the distinction against `sdk_typescript.post_close_emission`, where two
sites each independently enforce the *whole* proposition and removing either one leaves the
declared controls green. The denylist pair is the other shape, and the difference is
measurable rather than stylistic:

- delete the bare-string check alone, and iterating `"kid-1"` yields single characters —
  every one of them a non-empty string, so the entry-shape loop below is **satisfied**. The
  denylist is non-empty, reports as configured, and matches no identifier that can exist.
- delete the entry-shape check alone, and a `None` or an empty string sits inside a list
  that `Array.isArray` and the `isinstance` check both **accept**.

Each check refuses exactly what the other admits. Neither is a second carrier of one
proposition, so each gets its own falsifier and each falsifier is a single-anchor
weakening the current schema expresses. The compound-mutation requirement recorded in slice
1 still stands at **one** measured defence-in-depth instance; this slice adds none.

## 3. Why the type system is not the carrier

TypeScript makes every anchor member a required field, and the completeness check exists
anyway. `issuerKeyId: string` says nothing about the string being non-empty, and
`acceptedEpochs` is tested through `?.length ? "set" : ""` precisely because an empty array
satisfies the declared type. `readonly string[]` is erased at runtime and refuses no bare
string at all. The compiler refuses none of the shapes these statements refuse — which is
what makes them production checks rather than restatements of a declaration, and what makes
weakening them a real falsifier.

Python's comment at the same site already said this: *TypeScript makes these required
interface fields; this is where Python states the same requirement, at construction.* The
measurement shows the TypeScript side needed the runtime check just as much.

## 4. Both directions were measured

The campaign rule is that a green test under a weakening is evidence only after proving the
test executed the weakened production artifact, and the converse — a red test is evidence
only if it is green unweakened. Both were run:

| direction | result |
|---|---|
| weakened, all six | every named control **red**; `verify-mutations: PASS — 6 probe(s)` |
| unweakened, same selection | `12 passed` (pytest), the vitest anchor and denylist suites green |

The lane's own `MEASUREMENT FAILURE` arm carries the first half structurally: a control that
is never *reported* by the run is a failure, not a red, so "the weakening broke a test the
lane did not watch execute" cannot be recorded as a discharge.

## 5. What this slice discharged

| unit | probes | severity |
|---|---|---|
| `sdk_python.trust_anchor_completeness` | `M180`, `M181`, `M182` | critical, root-reachable |
| `sdk_typescript.trust_anchor_completeness` | `M183`, `M184`, `M185` | critical, root-reachable |

N1 moves 85 -> 83; the probe registry 201 -> 207. The remaining 23 SDK obligations are
untouched, and nothing here registers a probe against a proposition it did not weaken.
