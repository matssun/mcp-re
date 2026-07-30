<!-- SPDX-License-Identifier: Apache-2.0 -->

# Admission-revocation propagation: what was measured, and what it licenses

The fourth ADR-MCPRE-053 acceptance criterion — *cross-replica revocation propagation
measured against the declared P bound* — stayed open from 2026-07-17 to 2026-07-30,
recorded as blocked on a live GKE fleet. It was not. The serving path never performed
the §7 currency check at all, and no authoritative source existed for a revocation to
propagate through, so a fleet run would have measured nothing while producing a number.

This records what now exists, what was measured, and — the part that matters for anyone
quoting it — what the number does **not** license.

## The mechanism

A revocation is a write to a shared authoritative record; every replica reads that
record **live, per request**, and compares the generation and status against the
admission the call is bound to.

```
admission authority ──SET mcp-re:admission:<id> "<generation>:<status>"──> shared store
                                                                              │
replica A ──GET (per request)───────────────────────────────────────────────┘
replica B ──GET (per request)───────────────────────────────────────────────┘
```

There is **no cached copy**. That is a deliberate choice with a cost and a benefit:

- it costs a store round trip on the request path;
- it means there is no staleness window to reason about, so the propagation number is
  store write-to-read visibility plus one round trip — not a cache TTL.

A deployment that cannot pay the round trip wants a bounded cache. **That is a different
claim and must be measured separately**: a cache reintroduces exactly the staleness
window `RevocationTier` (ADR-MCPS-021) exists to keep honest. "Revocation propagates
within P" says nothing without naming the mechanism that produced P.

## The measurement

`mcp-re-proxy/tests/admission_propagation_measure_test.rs`, run with
`MCP_RE_TEST_REDIS_URL` pointing at a real Redis:

```sh
MCP_RE_TEST_REDIS_URL=redis://127.0.0.1:6399 \
  cargo test -p mcp-re-proxy --features redis_replay \
  --test admission_propagation_measure_test -- --nocapture
```

Two `HttpProfileProxy` replicas share one Redis-backed admission source **and nothing
else** — separate delegated signers, separate replay tiers, separate connections. An
authority revokes on a third connection. Measured: the interval from the revoking write
returning to the first request on the *sibling* replica being refused.

| Run | Observed | Requests after the write | Declared P |
| --- | --- | --- | --- |
| 2026-07-30, local Redis 7 (container), macOS | **3 ms** | 1 | 2000 ms |

The baseline is load-bearing: both replicas are asserted to **serve** the workload
before the revocation, so the measurement cannot be passed by a replica that was never
admitting the call. The refused call is also asserted never to have reached the backend
— a currency check that fires after the tool ran is a log line, not a control.

## What this does not license

- **It is not a fleet number.** Measured against a Redis on the same host, it bounds the
  *mechanism*, not a deployment. A real fleet adds network RTT between each replica and
  the store, and replication lag if the store is replicated. Quoting 3 ms as a
  production propagation bound would be dishonest.
- **It is not a push-invalidation measurement.** #414 §5 frames propagation as
  push-invalidation with a bound P. This is a live read. It satisfies the same property
  more strictly, but a deployment that later adds a push channel or a cache has changed
  the mechanism and must re-measure.
- **It says nothing about the degraded window.** With `--admission-allow-degraded`, an
  unreachable authority is served on the last-known state within P. That path is
  exercised by `admission_currency_serving_test`, but its real-world width depends on
  how the store fails, which this does not test.
- **It is one run on one machine.** It establishes that the mechanism propagates at all,
  to a replica with no prior knowledge of the workload, and what the floor looks like
  when the store is not the bottleneck.

## Setting P for a real deployment

P is the window a replica may keep serving on the last-known state when the authority is
**unreachable** — it is not the propagation delay itself. The measurement bounds the
healthy path; P bounds the unhealthy one. Choosing it means deciding how long stale
admission is preferable to refusing traffic, and `--admission-allow-degraded` is off by
default precisely so that stays a decision rather than a default.

## Two gaps, named

- **A degraded-mode serve is indistinguishable from a live-confirmed one in the audit
  stream.** `VerifiedAdmission::degraded` carries the difference; ADR-MCPS-035 §3 freezes
  the success-event allowlist, so recording it needs an ADR.
- **An admission refusal reaches the client as `mcp-re.actor_binding_failed`.** The wire
  taxonomy is frozen and every code is a core token, so a revoked workload, an unknown
  one, and an authority outage are indistinguishable from the code alone. This is why
  the harness measures the served→refused transition under a single changing variable
  rather than keying off the wire code.
