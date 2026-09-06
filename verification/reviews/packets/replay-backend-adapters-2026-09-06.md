# The deployable replay backends — the mechanisms the premises name — 2026-09-06

Item 2 of the ranked remainder the owner's ruling of 2026-09-06 directs continuation through:
*"Shared Redis/etcd stores — 1/5 owned; they are the mechanisms ASM-0040/ASM-0041 name, so
registering them would put the premises' own subjects under an owner."*

Baseline: main `af582442` (#825), stacked on #826 and #827.

## 1. The question these theorems answer, and the one they do not

The premise and the theorem are about different halves of the same seam, and keeping them
apart is most of the work:

| | question | answer |
|---|---|---|
| **ASM-0040 / ASM-0041** | what did an ACKNOWLEDGED insert durably establish? | foreign, per mechanism, unchanged here |
| **THM-0106 / THM-0107** | what happens when there is NO acknowledgement — and what stops the premise being silently invalidated? | local, measured |

Neither theorem is evidence for its premise, neither strengthens it, and neither levels the
two mechanisms. A deployment still obtains the strength of the tier it wired.

## 2. Two units and two theorems, never one union

Two mechanisms, two premises, **two feature lanes** (`redis_replay`, `cpstore_etcd`), and
THM-0092's own scope already insists that *"the two are NOT equally strong and this claim does
not level them"*. A single unit spanning both would additionally need both features at once,
which ADR-MCPRE-061 records as the shape invisible to every single-feature lane.

`redis_store`/`async_redis_store` and `etcd_store`/`async_etcd_store` each pair the sync and
async halves, which is right: the async adapters reuse the sync ones' **pure helpers
verbatim** so the two cannot drift, and splitting them would put one authority's TTL
arithmetic in two units.

## 3. The dependency edge, found top-down

`THM-0092.depends_on` gains both. This is a **genuine missing edge**, not tidiness, and the
test is the one the rule states — ask what the ROOT requires, never what the registry
suggests. THM-0092's security consequence is explicitly:

> a deployment that believes it has cross-replica replay protection and has process-local
> protection, **serving a replayed request as a fresh one because the store it was supposed to
> consult was unreachable**

Its own battery measures that against a **stub** store that errors
(`a_store_that_cannot_establish_the_state_refuses_rather_than_dispatching`). Nothing measured
that the **deployed** adapters error rather than returning `Fresh`. The root's closure now
includes results measured only in feature lanes, which is honest: the root's claim about
fleet-strict deployments genuinely rests on backends that exist only in those lanes.

THM-0092 and THM-0074 take dependency-only re-affirmations. The edge strengthens the support
beneath an existing claim; it does not change the claim, does not widen what earns dispatch,
and introduces no assumption.

## 4. Forty-two controls that were evidence for nothing

Twenty on the Redis side, twenty-two on the etcd side, named by no unit before this slice.
Four conjuncts were held by a green battery while none was load-bearing:

| conjunct | probe | why it matters |
|---|---|---|
| an **unreadable** `maxmemory-policy` is refused, not only an evicting one | M124 | an unverifiable policy is not evidence of a safe one — this is the guard on ASM-0040's own precondition |
| a `WAIT` quorum shortfall **fails closed** | M125 | otherwise the stronger tier is audited and not enforced |
| a failed lease revoke still answers `Replay`, never an error | M126 | cleanup is fail-SAFE; turning a bookkeeping failure into a refusal is a denial of service |
| the per-operation deadline is clamped at **both** ends | M127 | zero fails every insert closed; unclamped is the black hole again |

All four red-verified on this tree. They are also the first probes over **feature-gated**
batteries since #822 fixed `verify-mutations`'s feature blindness — before that fix every one
of them would have returned `MEASUREMENT FAILURE` rather than a result.

## 5. The Redis proposition, and why the unreadable case is the interesting one

`Key present` is the whole replay signal. An admitted nonce that leaves the keyspace before
its TTL is `Fresh` again for the remainder of its freshness window — **on every replica at
once, silently, with the operator's dashboards green**. It is a replay bypass produced by
capacity pressure rather than by an attack. Every replay key carries a `PX` TTL, which makes
it a *preferred* victim under `volatile-*` and an ordinary one under `allkeys-*`, so
`volatile-*` is not the safer half.

So the store asks the server its policy at connect and refuses to open unless the answer is
`noeviction` — case-insensitively, because the reply is a server string rather than a token
this code chose. And it refuses a policy it **could not read**: an empty reply, an error, a
renamed `CONFIG`. A deployment whose premise cannot be checked is not a deployment whose
premise holds.

**Named rather than absorbed:** the policy is read ONCE, at connect. A server reconfigured
underneath a live connection is not detected by this mechanism, and the scope says so. The
connect-time refusal stops a misconfigured deployment from starting; it does not stop one from
being reconfigured.

## 6. The etcd proposition, and two outcomes that are not obviously replay bugs

An **unbounded lease** would leave an admitted nonce in etcd after the proxy that recorded it
died — a resource leak. But a lease TTL computed from an absolute epoch rather than a window
is the mirror image and *is* a bypass, because a clamp to a minimal value is what a negative
window becomes if nothing catches it.

An **unbounded round trip** is a denial of service reachable without sending anything invalid.
The serving path bounds the TLS handshake and the body read but awaits the handler unbounded,
so an awaited future that never completes holds its request and its admission slot forever;
with `--max-in-flight` set, a black-holed endpoint consumes the whole admission budget. The
deadline therefore lives where the round trip is issued, applies to all three POSTs, and is
clamped at both ends.

**Named rather than absorbed:** the protocol is measured against **scripted gateways** and
pure helpers, not a live etcd cluster. What is established is that this adapter sends the
put-if-absent it claims to send, reads the reply it claims to read, and fails closed on
everything else — never that a real cluster answers as the protocol says. A live-cluster
exercise is separate evidence and is not claimed.

## 7. Lane identity

A plain `cargo test --workspace` compiles all four files to **zero tests**. Each unit names
its own `test_features`, and the trigger gate caught the four missing workflow path filters
before this was pushed — a fingerprint input matched by no filter is a unit that gets dirtied
and then never re-measured.

## 8. What remains in this area

`shared_replay.rs` and `replay_tier.rs` — the SYNC tier and its shared helpers — stay unowned.
They are a separate composition with a separate battery, and the async path is the
architecture (ADR-MCPRE-051). Folding them in would make one unit's evidence answer for two
authorities.
