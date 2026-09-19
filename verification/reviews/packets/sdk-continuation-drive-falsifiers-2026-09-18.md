# ADR-MCPRE-068 Phase 2, slice 8 — a pause is not a result

Four probes, `M205`–`M208`, over `continuation_drive` in both SDKs. The unit's claim is one
sentence — *only a terminal verified reply resolves the call* — and the two probed conjuncts
are the two ways a non-terminal reply could wrongly become one.

## 1. The budget is what makes a pause terminate

Without the ceiling a server that keeps eliciting keeps the call alive indefinitely. Each
round costs a signing operation and a correlated entry that stays outstanding, and each round
is an opportunity to prompt the caller again.

The check stands **before the handler runs**, deliberately: a call that has used up its
budget must not prompt for an answer it cannot send. That ordering is what the declared
control names, and it is what the weakening is measured against.

## 2. An elicitation with no handler has no honest resolution

With no `answer_input_required` / `answerInputRequired` installed there is no answer leg to
sign. Falling through would hand the application the elicitation body as though the call had
completed — an `InputRequiredResult` read as a terminal answer, which is precisely the
confusion the unit exists to prevent.

## 3. Two SDKs, and this time no asymmetry

Slices 3, 6 and 7 each found one SDK's battery covering a half the other's did not. This
slice found none: both batteries declare both refusals, in the same replay fixture, and all
four probes turned their named control red on the first measurement. Worth recording as a
negative result — the cross-SDK asymmetry counted at **two** instances, and this slice does
not raise it.

## 4. What this slice discharged

| unit | probes | severity |
|---|---|---|
| `sdk_python.continuation_drive` | `M205`, `M206` | critical, root-reachable |
| `sdk_typescript.continuation_drive` | `M207`, `M208` | critical, root-reachable |

N1 moves 68 -> 66; the probe registry 226 -> 230.
