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
6. **Replay-tier round trips.** Earlier instrumentation put Redis admission at ~6.5 ms of
   wall time per request. Pipelining, batching, or a local negative cache are all plausible;
   none has been measured since the async serving path landed.
7. **TLS 1.3 only.** Dropping the `tls12` feature narrows the handshake state machine and
   the attack surface. Small, and a compatibility decision rather than purely technical.
8. **Certificate algorithm and chain depth.** Ed25519 certificates would cut both the ECDSA
   cost and handshake bytes, but the client PKI is usually not ours to choose, and the
   benchmark's P-256 comes from `rcgen`'s default rather than from a deployment decision.
   Explore only with a real PKI in view.

## Rules for anyone continuing this

- Measure on a quiet box, and never with `ALLOW_NOISY_BOX=1`.
- Compare against `1cec2bd`-style A/B on the same box within the same session; a number
  measured on a different day against a remembered figure has repeatedly proven worthless
  here.
- A throughput number without its latency percentiles and its concurrency is not a result.
- Prefer a negative result recorded (as with aws-lc-rs above) over an untested plausible
  optimisation carried forward as folklore.
