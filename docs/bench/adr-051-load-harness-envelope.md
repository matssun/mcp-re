<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-051 §7 — concurrent-TLS-client load-harness benchmark envelope

This is the **declared benchmark envelope** for the ADR-MCPRE-051 §7 proof
obligation: the pinned conditions under which the concurrent-TLS-client load
harness (`mcp-re-proxy/tests/tls_load_harness_bench.rs`) measures the serving
data plane. Per ADR-051 §7 the *architecture* fixes no absolute throughput
number; the numbers live here + with the release profile, and the harness
publishes aggregate throughput and p50/p99/p999 added latency against them.

**The SLO *targets* are declared separately (MCPRE-110, HITL) — this file pins
the measurement CONDITIONS, not the pass/fail thresholds.** A run drives the
per-core async fleet (`--cores` pins the worker count) and produces the baseline
and per-core scaling input to MCPRE-110. The targets themselves are in
[`adr-051-slo-targets.json`](adr-051-slo-targets.json) and the recorded baseline
in [`adr-051-baseline-local.json`](adr-051-baseline-local.json); how they split
into an active local-regression band and a pending production-SLO block is
described in [§ Baseline, SLO split, and the local-regression
gate](#baseline-slo-split-and-the-local-regression-gate).

The machine-readable companion is
[`adr-051-benchmark-envelope.json`](adr-051-benchmark-envelope.json); the harness
emits its measured report as JSON when `MCP_RE_LOADGEN_OUT` is set.

## Pinned dimensions

| Dimension | Value (this envelope, v1) | Notes |
|---|---|---|
| **Hardware class** | operator-declared per run (`MCP_RE_LOADGEN_HW_CLASS`) | recorded verbatim into the report; not fixed in-tree so a CI runner and a bare-metal run are distinguishable |
| **Core count** | operator-declared (`MCP_RE_LOADGEN_CORES`), default = detected | the proxy serves on the per-core async fleet (SO_REUSEPORT, one worker per core); the harness passes the declared count through `--cores` so the workers actually served equal the reported count and the 1→N scaling curve is reproducible (run at cores=1 then =N) |
| **Payload sizes** | one `tools/call` (`echo`, small JSON body) | the inner echo server returns the argument; representative small-request class. Larger-payload classes are a future envelope revision |
| **TLS mode** | TLS 1.3, **mTLS** (client cert required) | rustls `ring` provider defaults; client presents a trusted URI-SAN leaf, server verified via `AcceptAny` on the client side (the SERVER identity is not under test here) |
| **Cipher / signature suite** | rustls 1.3 default suites; **RFC 9421** HTTP Message Signatures (**Ed25519**) + **RFC 9530** Content-Digest | the request is signed with the audited `mcp-re-client-core` — the signature rides in the `Signature`/`Signature-Input`/`Content-Digest` HTTP headers (no object/JCS `_meta` signature); the response is Ed25519-signed and bound to the request via `;req` |
| **Keep-alive vs cold-handshake mix** | selectable (`MCP_RE_LOADGEN_MODE = cold \| keepalive`) | measured **separately**. The per-core fleet serves HTTP/1.1 keep-alive / H2 (ADR-051 §1); the harness reports the **realised-reuse fraction** so `keepalive` runs are attributable to actual connection reuse rather than assumed |
| **Replay backend** | in-memory reference (`--replay-cache memory`) | the baseline single-node path; the shared Redis/etcd tiers add a network hop measured under their own envelope |
| **Inner-backend latency** | echo inner, ~0 added latency | isolates the PEP (accept → TLS → verify → sign → respond) cost from inner-server cost; a latency-injecting inner is a future envelope dimension |
| **Concurrency** | `MCP_RE_LOADGEN_CONCURRENCY` (default 128) | number of concurrent client threads; the canonical v2 envelope drives 128 concurrent cold mTLS connections — the SAME for local and GKE |
| **Total requests** | `MCP_RE_LOADGEN_REQUESTS` (default 8000) | each request carries a UNIQUE nonce (so replay never fires); success = a verified signed response, not an error object |

## What the harness reports

- **Aggregate throughput** — verified responses / wall-clock second.
- **Added latency percentiles** — p50 / p99 / p999 (plus min / mean / max) of
  per-request round-trip time (connect + handshake + request + verify-on-server
  + response), measured client-side.
- **Per-core scaling (1→N)** — the harness pins the served worker count via
  `--cores` and records it alongside achieved throughput, so the scaling curve is
  assembled by running at `MCP_RE_LOADGEN_CORES=1` then `=N` (each run is one point
  at a truthfully-served core count).
- **Cold vs keep-alive** — the two connection modes are measured separately; the
  keep-alive run additionally reports the realised connection-reuse fraction.

## Baseline, SLO split, and the local-regression gate

MCPRE-110 (#317) splits cleanly, and only the first half is committable without
production hardware:

1. **Committable now — machinery + a provisional local-regression baseline.**
   The harness, this envelope, and a recorded dev-box baseline
   ([`adr-051-baseline-local.json`](adr-051-baseline-local.json)) exist in-tree.
   The baseline is a **provisional local regression anchor ONLY** — it is
   explicitly *not* a production SLO and its 1→N core sweep is *not*
   authoritative. Reason: on a single workstation the load generator is
   co-located with the proxy and contends for the same cores (client-side
   Ed25519/TLS handshake crypto costs as much as the server's), so the run is
   client-concurrency-bound and the scaling curve flattens regardless of how
   well the per-core fleet scales. The active gate is therefore **relative**:
   `local_regression` in [`adr-051-slo-targets.json`](adr-051-slo-targets.json)
   requires a fresh anchor run to hold ≥ 85 % of baseline throughput and stay
   within stated multiples of baseline p50/p99/p999 added latency.
   [`scripts/adr051_slo_gate.py`](../../scripts/adr051_slo_gate.py) is the
   comparator (exit 0 = within tolerance, 1 = regression).

2. **Pending — production SLOs + authoritative scaling.** The `production_slo`
   block holds the absolute per-hardware-class thresholds and the per-core
   linear-scaling acceptance tolerance. Its numbers are `null` until a run on
   the production hardware class with a **dedicated load-generator host** (the
   GKE fleet run) removes the co-location distortion. Those absolute numbers are
   the operator/product declaration — the HITL half of MCPRE-110.

The **replay-race** and **bounded-drain** gates are absolute and
hardware-independent — always required, every release — and are enforced by
their own always-on tests (`//mcp-re-proxy:replay_race_harness_test`,
`//mcp-re-proxy:async_drain_test`), not by the throughput gate above.

To reproduce the baseline anchor and gate a change against it:

```
# fresh anchor run (single served core, moderate concurrency, cold mTLS)
MCP_RE_LOADGEN_CORES=1 MCP_RE_LOADGEN_CONCURRENCY=128 \
MCP_RE_LOADGEN_REQUESTS=8000 MCP_RE_LOADGEN_MODE=cold \
MCP_RE_LOADGEN_HW_CLASS=apple-m4-pro-14c-dev MCP_RE_LOADGEN_OUT=/tmp/fresh.json \
  cargo test -p mcp-re-proxy --release --test tls_load_harness_bench \
    tls_load_harness_bench -- --ignored

python3 scripts/adr051_slo_gate.py --report /tmp/fresh.json
```

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
