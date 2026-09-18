# ADR-MCPRE-068 Phase 2, slice 19 — outliving your own trust picture

Three probes, `M242`–`M244`, over the client's three durable trust facts: how wide a window
it will accept, what it does when it cannot refresh, and what it does when two writers
disagree about the floor.

## 1. One number, two windows, and only one of them was bounded

`VerifierPolicy::new` refuses a skew outside the profile bound, so the RFC 9421 freshness
window was always bounded. `DelegationExpectations` carries the same number **straight
through** to `DelegationVerifyParams.max_clock_skew`, which widens the credential's
`nbf`/`exp` with no cap of its own.

So a policy of 604800 accepted a delegated credential a week past its `exp` while the
signature gate silently clamped the same value — one message judged under two different
notions of *close enough*, and the TTL is the primary bound on a compromised delegated key
(DEL-4).

**The seal is the proposition, not the clamp.** The clamp used to live in a
`bounded_clock_skew` helper every reader had to remember to call, and a reader taking the
field directly got the unbounded number. Moving it into the only producer makes the bound a
property of every **inhabitant** rather than of the call sites somebody checked — and `M242`
weakens exactly that producer.

## 2. Two failures that look identical from the refresh's side

A refresh that fails because the publisher is briefly unreachable, and one that fails while
the loaded document has already expired, both arrive as `Err`. Keeping the last good anchors
is right for the first and is *serving on the stale trust picture the expiry check refuses*
for the second.

Under `M243`'s weakening a client outlives its own trust picture **quietly**: every request
keeps verifying against anchors the issuer has retired, and nothing in the transcript
distinguishes that from a healthy client. Publishing the empty set makes it fail closed
**loudly** — every response fails as an untrusted issuer, the refresh keeps retrying, and the
operator gets a signal.

The manifest loader's own expiry refusal is not a second carrier: it refuses to LOAD an
expired document. This branch is about the document already in force when no replacement can
be loaded at all.

## 3. The rollback reached through a race instead of a replay

The floor check happens at LOAD time. If another writer raises the floor between that read and
the record, the accepted document is one the floor has since refused — and reporting success
hands the caller anchors from exactly that document.

The monotone directory is **not** a second carrier here. Its maximum only grows, so the floor
is never walked back; that is a different proposition from the one `M244`'s branch holds, which
is that a caller is never handed anchors the current floor would refuse.

## 4. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `client.delegation_policy_seal` | `M242` | critical |
| `client.anchor_refresh` | `M243` | critical |
| `client.manifest_floor` | `M244` | critical |

N1 moves 41 -> 38; the probe registry 263 -> 266.
