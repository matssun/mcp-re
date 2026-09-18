# ADR-MCPRE-068 Phase 2, slice 5 — the answerable window, and the message nobody composed

Four probes, `M193`–`M196`, over two units in both SDKs. Both propositions are about a
message arriving somewhere it has no right to be.

## 1. The predicate IS the window

`is_expired` / `isExpired` is consulted by `take`, by the input-required association, and by
reaping. It is therefore **one carrier of several conjuncts** — the shape slice 4 recorded —
and the weakening reaches all of them at once:

- a response is answerable **forever**; the entry never retires on lateness;
- reaping, the thing that BOUNDS the store, drops nothing, so a session of unanswered
  requests grows without limit.

The `_consumed` grace map is **not** a second carrier. It distinguishes a duplicate from an
unbound response among ids that were already consumed, and says nothing about an id that
never expires.

**An asymmetry the measurement exposed, and it is not a defect in the probe.** The same
weakening turns three TypeScript controls red and one Python control red. The TypeScript
battery declares `retires the entry when a response is late` and `reaping > drops only the
dead` as separate controls; Python's declared battery covers the refusal and not the
retirement or the reaping consequence. The conjunct is discharged either way — the probe's
job is to prove the check load-bearing — but the Python battery is measurably thinner about
what a late response does to the STORE. Recorded, not repaired here: repairing it means
writing Python twins of two TypeScript controls, which is its own slice.

## 2. The refusal whose trigger is peer-influenceable

A client→server RESPONSE has no `method`, so the notification path could only carry it by
signing a message the application never composed. That is what makes this a security
conjunct rather than type hygiene, and the trigger is reachable from the wire:

> a verified reply body carrying a `method` parses as a server→client request,
> `ClientSession` answers it with a response, and that answer arrives right here.

Which is the same wire shape `M191`/`M192` weakened from the other end. The rebuild stops
the body being dispatched as a request; this check stops the answer to such a dispatch being
signed. Two independent propositions about one attacker move — **composition**, not defence
in depth, and each is separately falsifiable.

**The SDKs differ in blast radius, not in the refusal.** Python *reports* it on the
diagnostic channel, because the refusal happens in the parent task of the group running
every concurrent exchange and raising would end an entire session over one peer-influenced
reply; TypeScript throws from the one `send()`. Both are probed for the same conjunct, and
the difference is a recorded product decision rather than a gap.

## 3. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `sdk_python.correlation_lifecycle` | `M193` | critical, root-reachable |
| `sdk_typescript.correlation_lifecycle` | `M194` | critical, root-reachable |
| `sdk_python.notification_delivery` | `M195` | critical, root-reachable |
| `sdk_typescript.notification_delivery` | `M196` | critical, root-reachable |

N1 moves 78 -> 74; the probe registry 214 -> 218.
