<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-051 §7 — concurrent-TLS-client load-harness benchmark envelope

This is the **declared benchmark envelope** for the ADR-MCPRE-051 §7 proof
obligation: the pinned conditions under which the concurrent-TLS-client load
harness (`mcp-re-proxy/tests/tls_load_harness_bench.rs`) measures the serving
data plane. Per ADR-051 §7 the *architecture* fixes no absolute throughput
number; the numbers live here + with the release profile, and the harness
publishes aggregate throughput and p50/p99/p999 added latency against them.

**The SLO *targets* are declared separately (MCPRE-110, HITL) — this file pins
the measurement CONDITIONS, not the pass/fail thresholds.** A run against the
CURRENT single-threaded proxy produces the Phase-0 baseline input to MCPRE-110.

The machine-readable companion is
[`adr-051-benchmark-envelope.json`](adr-051-benchmark-envelope.json); the harness
emits its measured report as JSON when `MCP_RE_LOADGEN_OUT` is set.

## Pinned dimensions

| Dimension | Value (this envelope, v1) | Notes |
|---|---|---|
| **Hardware class** | operator-declared per run (`MCP_RE_LOADGEN_HW_CLASS`) | recorded verbatim into the report; not fixed in-tree so a CI runner and a bare-metal run are distinguishable |
| **Core count** | operator-declared (`MCP_RE_LOADGEN_CORES`), default = detected | the CURRENT proxy is a single-threaded blocking accept loop (ADR-051 Context), so it utilises **1** core regardless; the per-core scaling curve is flat at 1 until the Phase-2 per-core data plane lands |
| **Payload sizes** | one `tools/call` (`echo`, small JSON body) | the inner echo server returns the argument; representative small-request class. Larger-payload classes are a future envelope revision |
| **TLS mode** | TLS 1.3, **mTLS** (client cert required) | rustls `ring` provider defaults; client presents a trusted URI-SAN leaf, server verified via `AcceptAny` on the client side (the SERVER identity is not under test here) |
| **Cipher / signature suite** | rustls 1.3 default suites; **Ed25519** request + response object signatures | the request is a signed draft-02 object; the response is Ed25519-signed and bound to `request_hash` |
| **Keep-alive vs cold-handshake mix** | selectable (`MCP_RE_LOADGEN_MODE = cold \| keepalive`) | measured **separately**. NOTE: the current wire is one-request-per-connection (`Connection: close`, ADR-051 Context §3), so `keepalive` mode reports a **realised-reuse fraction ≈ 0** on the current proxy — the mode is instrumented now and becomes meaningful with Phase-2 HTTP/1.1 keep-alive / H2 |
| **Replay backend** | in-memory reference (`--replay-cache memory`) | the baseline single-node path; the shared Redis/etcd tiers add a network hop measured under their own envelope |
| **Inner-backend latency** | echo inner, ~0 added latency | isolates the PEP (accept → TLS → verify → sign → respond) cost from inner-server cost; a latency-injecting inner is a future envelope dimension |
| **Concurrency** | `MCP_RE_LOADGEN_CONCURRENCY` (default 64) | number of concurrent client threads; the harness drives ≥ hundreds of concurrent mTLS connections when configured to |
| **Total requests** | `MCP_RE_LOADGEN_REQUESTS` (default 2000) | each request carries a UNIQUE nonce (so replay never fires); success = a verified signed response, not an error object |

## What the harness reports

- **Aggregate throughput** — verified responses / wall-clock second.
- **Added latency percentiles** — p50 / p99 / p999 (plus min / mean / max) of
  per-request round-trip time (connect + handshake + request + verify-on-server
  + response), measured client-side.
- **Per-core scaling (1→N)** — the harness records the declared core count and
  the achieved throughput so a scaling curve can be assembled across runs. On the
  CURRENT single-threaded proxy this is a single point at 1 core (the flat
  baseline); Phase 2 fills in the curve.
- **Cold vs keep-alive** — the two connection modes are measured separately; the
  keep-alive run additionally reports the realised connection-reuse fraction.

## Faithfulness to ADR-051 §7

Unlike `fleet_throughput_bench` (which calls `Proxy::handle` directly on one
thread and structurally cannot measure TLS/handshake/accept cost), this harness
spawns the **real `mcp-re-proxy` binary** and drives its **real listener** over
concurrent rustls mTLS clients — accept → TLS/mTLS → verify → inner → sign →
respond — so every measured number includes the full serving path.

## Versioning

This envelope is **v1**. Any change to a pinned dimension (payload class, TLS
suite, replay backend, inner-latency model) bumps the `envelope_version` in the
JSON companion and is recorded here, so a measured report is always attributable
to the exact conditions that produced it.
