# ADR-MCPRE-068 Phase 2, slice 17 — the two facts a non-grant can be

Three probes, `M237`–`M239`. The unit under `authorization_posture` exists because *not
authorized* is not one fact, and every weakening here collapses two of them into one.

## 1. Conflated in the direction that matters

*No policy is deployed* and *a policy refused this* are both non-grants, so a reader that only
asks **was this authorized?** cannot tell them apart. `M237` exploits exactly that: a DENY
becomes the posture a deployment with no policy at all reports.

An operator auditing why a request was not authorized is then told the deployment has no
policy — which is false — and the evaluator's own refusal token, the thing that says WHICH
policy refused and why, is discarded.

## 2. The action reader's authority is not the policy's

`M238` weakens the refusal for a request whose action cannot be established. A request whose
ACTION is unreadable is not a request a policy could have been asked about, so answering
`NoPolicyConfigured` for it reports the deployment's posture as the reason a specific request
was unverifiable.

The declared battery already had the control for this — *a denial and a missing coordinate
project to different authorities* — and it goes red with the direct one. Two authorities, one
token, is what the weakening produces.

## 3. A deployment that looks configured

`M239`'s failure mode is the quiet one. With no key enrolled for the `authorization-issuer`
slot, no decision can ever verify, so every request is refused for carrying no valid
decision — which reads as **a policy working correctly and denying everything**, not as a
deployment that was never able to decide.

Refusing at STARTUP is the only point at which the two are distinguishable, because afterwards
the evidence is identical.

## 4. A measurement failure that was not a finding

`M237`'s first weakening fabricated a grant in the no-evaluator branch and **did not compile**
— the decision type has no default. The lane refused it as a measurement failure and reported
nothing about the conjunct, which is the correct answer to a tree that does not build: a
weakened tree that fails to compile measures neither the old code nor the new.

The re-adjudicated weakening attacks the same proposition from the other side, and the
distinction is worth keeping: *this probe demonstrated nothing* has at least three causes now —
the battery cannot see the weakening, the mutation is a no-op, and the mutation does not build.

## 5. What this slice discharged

| unit | probes | severity |
|---|---|---|
| `proxy.authorization_posture` | `M237`, `M238` | critical |
| `proxy.authorization_capability` | `M239` | critical |

N1 moves 45 -> 43; the probe registry 258 -> 261.
