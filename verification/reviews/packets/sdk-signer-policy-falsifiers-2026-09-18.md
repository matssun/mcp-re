# ADR-MCPRE-068 Phase 2, slice 7 — the policy, and where it is called

Four probes, `M201`–`M204`, over `signer_policy` in both SDKs. The unit states two things
that are established in different places, and separating them is what the probes are for.

## 1. The call site IS the ordering

> the transport does not open unless the signer satisfies the route's policy — **checked
> before anything is signed**

`check` refusing a wrong signer is a property of the policy object, and a `SignerPolicy`
unit test reaches it. *Before anything is signed* is a property of **where it is called**,
and the only thing that establishes it is the statement standing ahead of the stream setup
and every exchange. `M201` / `M203` weaken the call site rather than the predicate: under the
weakening a route with an expected signer opens against any signer at all, and the first
thing that reveals it is a signed request already on the wire.

That is why a probe against `check` alone would not have discharged this unit. Two conjuncts,
two sites, neither redundant with the other.

## 2. M202 failed, and found the asymmetry again

The hardening conjunct weakened cleanly in TypeScript (`M204`) and left every Python control
green. The reason:

| SDK | declared controls for the hardening profile |
|---|---|
| TypeScript | `hardening accepts non-exporting custody` **and** `hardening rejects software custody with mcp-re.actor_binding_failed` |
| Python | `a hardened policy opens with a non-exporting signer` — the accepting direction only |

**A control that only witnesses the accepting direction cannot see a check that stopped
rejecting.** So `test_a_hardened_policy_refuses_software_custody` was written, and what it
refuses is the whole point of the profile: an exportable software key means the private key
is a value in this process's memory, so the actor binding it signs proves possession of
something that can be copied out of the host.

**This is the second measured instance of one shape.** Slice 3 found the wire-code
substitution declared in TypeScript and untested in both; this is the hardening refusal
tested in TypeScript and untested in Python. Two SDKs implement one proposition and their
batteries cover DIFFERENT halves of it. A third instance would justify a systematic
cross-SDK battery diff rather than finding them one probe at a time — recorded here as the
count, not acted on.

## 3. What this slice discharged

| unit | probes | severity |
|---|---|---|
| `sdk_python.signer_policy` | `M201`, `M202` | high |
| `sdk_typescript.signer_policy` | `M203`, `M204` | high |

N1 moves 70 -> 68; the probe registry 222 -> 226. One control written, because a falsifier
proved the battery covered only one direction.
