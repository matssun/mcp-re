<!-- SPDX-License-Identifier: Apache-2.0 -->

# Proxy performance: what has been measured, and where the remaining headroom is

Every number here was measured on `apple-m4-pro-14c-dev` with the pinned toolchain, on a
quiet box, with the ADR-MCPRE-051 §7 envelope unless stated otherwise. Claims without a
number are labelled as hypotheses, not findings.

## The one measurement that changes the framing

The §7 anchor envelope is **cold** — a fresh TLS connection per request. That is
deliberate: it is the most sensitive regression detector, because every request pays a
full handshake. It is **not** what a deployment looks like.

| mode (1 core, concurrency 128, 8000 requests) | throughput | p50 added | mean added |
|---|---|---|---|
| `cold` — one handshake per request | 5,482.7 rps | 19,547 µs | 23,245 µs |
| `keepalive` — connection reuse | **10,255.3 rps** | 13,395 µs | 12,362 µs |

**Connection reuse is worth +87% on a single core**, and it is already implemented — the
async data plane serves HTTP/1.1 keep-alive and HTTP/2 at a realised reuse fraction of
1.000. Holding connections open is safe because the peer certificate's validity window and
revocation status are re-checked on **every request**, and since ADR-MCPRE-055 a resumed or
long-lived connection cannot outlive a change to the trusted CA set.

So the first performance lever for an enterprise deployment is not a code change. It is
making sure clients pool connections, and setting `max_connection_age` deliberately rather
than defensively low.

## What the profile says the CPU is doing

Self time, current build, cold envelope, 1 core (samply, 8000 requests):

| bucket | share | note |
|---|---|---|
| kernel (`libsystem_kernel`) | 31.1% | syscalls: accept/read/write/close. Connection reuse removes most of it. |
| curve25519 (X25519 ECDH + Ed25519) | ~21% | per-handshake key exchange, plus request-signature verification |
| malloc | 8.5% | per-request allocation |
| P-256 ECDSA (certificates) | 6.1% | back to anchor levels after ADR-MCPRE-055 |
| `libsystem_platform` (memcpy/memset) | 4.6% | buffer copying |
| SHA-512 | 3.9% | Ed25519 internals |

Two thirds of that is handshake and syscall cost that connection reuse amortises. The
residual per-request work — Ed25519 verification, JSON, header iteration, signature-base
reconstruction — is small: `verify_ed25519_with` is 1.0%, serde_json serialisation 0.6%,
header iteration 0.7%.

**The evidence does not support optimising the verify/sign path.** It has been measured
twice now, in two independent investigations, and it is not where the time goes.

## Measured and rejected

**Swapping the rustls crypto provider `ring` → `aws-lc-rs`.** The hypothesis was that ring
uses a generic aarch64 path for P-256 while aws-lc-rs ships optimised assembly, so a swap
should be free throughput across the ~27% of CPU in crypto.

It is **slower**: 5,095.0 rps against ring's 5,419.2 on the identical envelope, and it
breached the p99 latency ceiling. Rejected on evidence. Worth re-testing on x86-64 Linux
before treating this as universal — the result may be aarch64-specific — but it is not a
win on the declared hardware class, and it would add a large C/assembly dependency to a
security-critical supply chain for a measured regression.

## The measurement rig is the current blocker

Throughput is pinned at **~10.4k rps regardless of proxy cores or client concurrency**:

| cores | concurrency | throughput |
|---|---|---|
| 1 | 128 | 10,008.6 |
| 8 | 128 | 10,080.1 |
| 1 | 512 | 10,456.1 |
| 8 | 512 | 10,387.8 |
| 8 | 1024 | 10,538.0 |

A ceiling that moves with neither cores nor offered load is not the proxy's ceiling. The
harness co-locates everything on 14 cores: the load generator spawns **one OS thread per
concurrent request** (1,024 threads at the widest setting), the inner echo backend runs a
4-worker runtime, and the proxy fleet competes with both.

**No per-core scaling claim can be made from this box, in either direction.** The baseline
file already says the 1→N sweep is non-authoritative for this reason; these numbers confirm
it quantitatively rather than by assertion. Anything measured here is a floor.

This is the highest-value item on the list, because it gates every other item: without a rig
that can saturate the proxy, an optimisation that helps cannot be distinguished from one
that does nothing. It needs a **separate load-generator host** and a backend that is not a
four-thread toy — MCPRE-110's production half and the GKE fleet run.

## Ranked candidates

Ordered by expected value per unit of risk. Every one is a hypothesis until measured on a
rig that can saturate the proxy.

1. **A real load rig** (above). Blocks everything else.
2. **HTTP/2 to the inner backend.** `http_inner.rs` builds its pooled client with
   `build_http()` — HTTP/1.1 only. h2 multiplexing collapses N inner connections into one
   with concurrent streams, cutting inner-side accept and syscall cost. The client is
   already pooled and reused, so this is a small, well-contained change.
3. **Allocator swap** (mimalloc / jemalloc). malloc is 8.5% of self time; a one-line
   experiment with no security surface.
4. **Buffer reuse on the request path.** `libsystem_platform` at 4.6% is memcpy/memset, and
   malloc is adjacent. Pooling body and header buffers targets both at once.
5. **Stateless, epoch-keyed session tickets.** ADR-MCPRE-055 deliberately scoped resumption
   to node-local; a client that lands on another replica behind a load balancer pays a full
   handshake. Ticket-encryption keys derived from the trust epoch, erased on epoch change,
   would extend resumption fleet-wide. This is the largest *security-relevant* design item
   remaining, and it is genuinely harder than what has been built.
6. ~~**Replay-tier round trips.**~~ **Closed — the replay tier is not a bottleneck.** See
   "The replay tier is exonerated" below before spending any effort here.
7. **TLS 1.3 only.** Dropping the `tls12` feature narrows the handshake state machine and
   the attack surface. Small, and a compatibility decision rather than purely technical.
8. **Certificate algorithm and chain depth.** Ed25519 certificates would cut both the ECDSA
   cost and handshake bytes, but the client PKI is usually not ours to choose, and the
   benchmark's P-256 comes from `rcgen`'s default rather than from a deployment decision.
   Explore only with a real PKI in view.

## The replay tier is exonerated

Stage timers (`MCP_RE_STAGE_TIMERS`) attribute 92-94% of every request to `replay_insert`
at every concurrency — 1,500 µs of 1,624 µs unloaded at 4 connections, 50,454 µs of 53,774 µs
saturated. That reads as a bottleneck and is not one.

`mcp-re-proxy/examples/replay_store_bench.rs` drives the SAME store code with no proxy in
the picture, across the same published Redis port, against the same primary + 2 replicas:

| path | concurrency | rps |
| --- | --- | --- |
| `SET NX PX` only | 512 | 421,850 |
| `SET NX PX` + `WAIT 2 2000` | 512 | 463,760 |
| the proxy's exact topology (pool 8, `WAIT 2 2000`, separate 1-worker control runtime) | 512 | 470,245 / 475,630 / 501,019 |
| the same, with 8 control workers | 512 | 391,523 / 416,246 |

Redis itself, measured inside the container with `redis-benchmark` under a concurrent write
stream so `WAIT` blocks on genuinely un-acked offsets: `SET NX PX` 31 µs at c=1 and 202,020/s
at c=512; `WAIT 2 2000` 31 µs at c=1 and 238,095/s at c=512.

The store path sustains ~470k rps against a proxy that sustains ~13k. It is over-provisioned
by more than 30×, so `replay_insert`'s stage time is **scheduling delay attributed to the
sole await point on the request path**, not work. `AsyncReplayTier::check_and_insert` is the
only `.await` of real I/O a request performs, so every scheduling delay in the process has
exactly one place to land — which is also why its *share* stays constant across concurrency,
something a work bottleneck would not do.

### Hypotheses killed by measurement, so nobody re-runs them

| hypothesis | how it died |
| --- | --- |
| `Mutex<redis::Connection>` serialises inserts | that is the *sync* store; `app.rs` wires the async one |
| single Redis connection | pool swept 1/2/4/8/16, flat at ~13k |
| `WAIT` head-of-line blocking on the replication ACK loop | `WAIT` measures 31 µs and 238k/s under real write load, and is *faster* than the bare `SET` in the store bench |
| Redis command execution is single-threaded and saturated | Redis measured 2.8% busy at the ceiling; 202k `SET`/s available |
| Colima's port forwarder is a fixed-rate path | the 470k store bench crosses that exact forwarder |
| cross-runtime wakeups between serving cores and the 1-worker control runtime | split-runtime bench is indistinguishable from single-runtime (475k vs 470k) |
| the control runtime needs more workers | 8 workers measured *slower* than 1, in both the bench and the rig |

Redis parallelism (`io-threads`, cluster sharding, batching `WAIT` across a pipeline) is
therefore moot for this ceiling. None of it can move a component that is already 30× faster
than the demand placed on it.

### Loopback is not the ceiling either

Two independent harnesses converging (~10.2k for the saturation rig, ~10.4k for the §7
lane) with flat scaling across 2/4/8 cores looks exactly like the macOS loopback stack
rather than the proxy. It is not. Measured with the rig's own backend, driven by `ab` over
plain loopback HTTP with keepalive at c=128 — no proxy, no TLS, no pipelining, one request
per socket round trip:

```
Requests per second:  174,481.30 [#/sec]
Failed requests:      0
```

17× the proxy's ceiling. So `lo0` is not the constraint, the M/M+1 `PROXY` verdict stands,
and ~10.2k is the proxy's own number — which is the question an off-host or cloud run
would otherwise have been needed to settle.

The store bench's 470k could NOT settle this on its own, and should not be cited for it:
it pipelines many commands per socket round trip across 8 connections, while the proxy's
HTTP path is one request per round trip across 768. Comparing them conflates throughput
with syscall count.

### Run-to-run variance is large — do not quote single figures

The `multi_thread(8)` split-control store bench returned 21,314 rps in one batch against
470,245 / 475,630 / 501,019 for the identical configuration in others, and the first row
after the Redis containers start has been anomalous twice. Something is cold for the first
measurement in a batch. Every configuration still lands well above the proxy's 10.2k, so
the conclusions here survive, but any individual number needs repeats before it means
anything.

## The ceiling is the per-core runtime shape (5x on the table)

The in-flight gauge shows all ~820 requests are inside `replay_insert` at once
(`replay_inflight` mean 820.1, max 896), so nothing is gated upstream of the store. Yet
the same store at the same concurrency is 13-19x slower inside the proxy than in the
bench, and `inner_dispatch` — which never touches Redis — inflates identically
(91us -> 922us). Everything the proxy AWAITS slows down together while the process burns
0.49 cores.

The cause is ADR-MCPRE-051 §1's `new_current_thread()` per-core runtime: one thread drives
the kqueue I/O driver AND polls every task, so with ~96 TLS connections plus ~100 store
futures per core a cross-runtime wake waits ~10ms to be polled.

Worker-pool sweep at 8 cores, 6 generators, 128 connections/generator:

| workers/core | threads | rps | verdict | p50 | scheduler_latency |
| --- | --- | --- | --- | --- | --- |
| 1 | 8 | 8,636 | CLIENT | 89,026us | 13,468us |
| 2 | 16 | 19,963 | PROXY +0.3% | 36,492us | 46.6us |
| 4 | 32 | 38,730 | PROXY +1.7% | 19,403us | 46.3us |
| 8 | 64 | 44,803 | PROXY +1.1% | 16,277us | 60.3us |
| 16 | 128 | 46,325 | PROXY +3.6% | 15,502us | 82.6us |

Diminishing returns arrive at 8; 16 adds 3.4% and starts raising scheduler latency again.

**Shard count is not the same as thread count, and it is the shards that hurt.** At an
identical 16 total threads:

| layout | threads | rps |
| --- | --- | --- |
| 8 cores x 2 workers | 16 | 19,910 |
| 2 cores x 8 workers | 16 | 44,816 |

2.25x apart. A task readied on an 8-shard/2-worker layout can only be picked up by its own
two workers; a 2-shard/8-worker layout steals work within each pool. And `2 cores x 8
workers` (16 threads) matches `8 cores x 8 workers` (64 threads) at 44,803 — four times the
threads buys nothing once the pools are big enough.

So the per-core sharding is not paying for itself on this workload: fewer, larger pools
reach the same throughput with a quarter of the threads. Changing it is an ADR-MCPRE-051 §1
amendment — the share-nothing property is a stated design choice, not an oversight — so the
knob stays behind `MCP_RE_DIAG_CORE_WORKERS` and off by default until that decision is made.

### What the instrument still cannot see

Nothing on the request path is CPU-bound: at ~10k rps the proxy used 0.44 of 14 cores and
each generator 0.07. Nothing is I/O-bound either, per the above. The rig's M/M+1 probe still
returned `CLIENT` at 6 generators (+18%), so the ~13k figure is a floor and not yet the
proxy's ceiling.

The next instrument needs to separate *work* from *waiting*, which the current stage timers
cannot: they only bracket spans, and one span contains the only await. Measuring scheduler
latency directly — spawn-to-first-poll on each serving runtime — would split "our code is
slow" from "tasks are not being scheduled", and that split is the open question.

## Rules for anyone continuing this

- Measure on a quiet box, and never with `ALLOW_NOISY_BOX=1`.
- Compare against `1cec2bd`-style A/B on the same box within the same session; a number
  measured on a different day against a remembered figure has repeatedly proven worthless
  here.
- A throughput number without its latency percentiles and its concurrency is not a result.
- Prefer a negative result recorded (as with aws-lc-rs above) over an untested plausible
  optimisation carried forward as folklore.
