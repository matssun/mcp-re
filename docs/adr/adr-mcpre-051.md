<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-051: High-Throughput Serving Architecture — Per-Core Async Data Plane, Stateless Streamable-HTTP Inner Plane, Authoritative Replay Tier, Delegated Signing Custody

## Status

Accepted — ratified 2026-07-09.

The architecture and its Phase 0–4 implementation are in place and the release-gate
machinery is wired and green: the per-core async data plane, the stateless
Streamable-HTTP inner plane with concurrent in-flight dispatch and bounded
pool-exhaustion backpressure (MCPRE-118), the authoritative atomic replay tier
(MCPRE-117), and delegated-signing custody (companion [ADR-MCPRE-052](adr-mcpre-052.md),
ratified) — root-in-HSM/KMS, short-TTL in-memory delegated keys, rotation overlap,
audited lifecycle, fail-closed issuance. The load / replay-race / bounded-drain /
SLO gates run as named required CI lanes (MCPRE-123), and the SLO target framework
is declared in [`docs/bench/adr-051-slo-targets.md`](../bench/adr-051-slo-targets.md)
(status `provisional`).

**One physical step remains before any release may CLAIM specific SLO numbers:** the
representative baseline measurement on the declared hardware class (MCPRE-110, HITL),
which fills the provisional capacity/scaling targets and flips the gate from
correctness-only to full enforcement. This acceptance ratifies the *decision* and the
*mechanism*; per §7 no release ships below its **measured** SLOs — acceptance is not a
capacity claim.

## Context

Through v0.10 the proxy serves on a **single-threaded, blocking `std::net`
accept loop** (`main.rs:857-880`): one connection is accepted, TLS-terminated,
verified, forwarded, signed, and closed — inline, one at a time. This is a
silent regression from ADR-MCPS-014 §1, which specified thread-per-connection;
the loop was narrowed to single-threaded to keep the in-memory replay cache's
interior state unsynchronized and to make the MCPS-88 drain guarantee trivially
exact. Four properties of the current design are disqualifying for a
high-transaction production data plane:

1. **Serial front end.** One request in flight per replica; the accept thread
   blocks on inner I/O, leaving even its one core idle.
2. **Serial inner plane.** The inner MCP server is reached over **stdio to one
   subprocess**, guarded by a single `Mutex<Session>`
   (`persistent_inner.rs:99-102, 237-270`) — or, in the default one-shot mode,
   a `Command::spawn` **per request** (`cli.rs:2778-2828`). No pipelining, no
   concurrency: a hard ceiling of one inner request at a time, independent of
   any front-end model.
3. **Per-request TLS handshake.** The wire is one-request-per-connection with
   `Connection: close` (`tls.rs:12, 1164`) — a full mTLS handshake, the most
   expensive operation in the path, on every request.
4. **Custody on the hot path.** Response signing can require a remote KMS
   round-trip or the single serialized PKCS#11 session
   (`pkcs11_keysource.rs:341-342`) per request.

The product requirement: **high transaction throughput per replica, linear
scaling across cores, bounded tail latency — with every release gated on
measured SLOs, not asserted capacity.** This ADR deliberately fixes no absolute
throughput number; numbers belong to the benchmark envelope (§ Proof
obligation), which pins hardware class, core count, payload size, TLS mode,
keep-alive vs cold-handshake mix, signature suite, replay backend, and inner
latency — and publishes p50/p99/p999 against declared targets. The
*architecture* is chosen so that none of the four ceilings above exists by
construction.

Two facts shape the design space:

- **MCP is going stateless.** Streamable HTTP supports stateless operation and
  the proxy already models it (`InnerSessionKind::Stateless`, `cli.rs:80-90`).
  Statelessness removes session→replica *affinity*. It does not remove the
  *serial* ceiling — that is a property of the stdio-one-subprocess
  *transport*. Cashing in MCP's stateless direction requires making the inner
  transport concurrent and poolable.
- **The security core is already stateless and nearly thread-ready.**
  `mcp-re-core` verification is pure, synchronous, per-request stateless
  (ADR-MCPS-047; proven cross-replica in MCPS-82). The only hard
  interior-mutability blocker to a shared `Proxy` is one field —
  `replay: RefCell<Box<dyn ReplayCache>>` (`proxy.rs:109`); the custody
  backends, trust wrappers, and caches are already `Send + Sync`.

This ADR supersedes ADR-MCPS-014 §1 (blocking, no-async serving path) for the
proxy. `mcp-re-core` remains pure and synchronous — the firewall's real value
is preserved, and the async stack is admitted **only** into the proxy/data
plane.

## Decision

MCP-RE's serving architecture is an **async, thread-per-core, `SO_REUSEPORT`,
HTTP/2-capable L7 security data plane** over a **stateless Streamable-HTTP
inner plane**, with **replay enforced by an authoritative atomic replay tier**
and **custody root keys never on the per-request signing path**. stdio
subprocess mode is **excluded from the production architecture**.

### 1. Data plane — per-core async, no cross-core hot-path locks

- **One worker thread per core, each running its own current-thread `tokio`
  runtime, each owning its own listener via `SO_REUSEPORT`.** The kernel
  distributes connections across cores; there is no shared accept lock, no
  cross-core connection handoff, and no contended cross-core state on the
  request path. Per-core execution is share-nothing **where possible**; the
  explicitly coherent exceptions are enumerated in §4 (replay, trust
  epoch/CRL, delegated-key rotation) and are engineered as bounded, versioned,
  read-mostly or atomically-inserted state — never ambient shared mutability.
- **`tokio-rustls`** drives TLS asynchronously, reusing the existing rustls
  `ServerConfig` construction verbatim — mTLS verification, CRL enforcement,
  and identity extraction are unchanged; only the acceptor becomes async.
- **HTTP/1.1 keep-alive and HTTP/2 multiplexing** (`hyper`). The per-request
  mTLS handshake is amortized across connection lifetime; large client
  populations multiplex over few connections.
- **Bounded per-core admission control**: a per-core in-flight permit ceiling
  with fail-closed backpressure (`503` / connection drop) at saturation,
  generalizing the dormant `max_concurrent_connections` knob and the proven
  fail-closed `ConnectPermit` pattern (`redis_store.rs:86-159`).
- A shared multi-threaded tokio runtime MAY be used as **development
  scaffolding only**. It is not the target, is never the subject of SLO
  claims, and no release ships on it.

### 2. Security core — pure, synchronous, inline (unchanged)

- The pure verification layers run **inline on the async task** —
  sub-millisecond CPU work, no `spawn_blocking`, no runtime coupling. The
  **active production path is the HTTP profile** (`mcp-re-http-profile`):
  RFC 9421 signature bases, RFC 9530 Content-Digest, freshness, replay, and
  profile-specific bindings (ADR-MCPRE-050). `mcp-re-core` retains legacy
  JCS/object-profile verification (Ed25519 over JCS canonicalization +
  freshness) **only for legacy-object-profile compatibility**, not the
  production path. Both layers stay free of networking, async, and fs; the
  firewall test continues to enforce this.
- `Proxy` becomes `Send + Sync`: `ReplayCache::check_and_insert` moves from
  `&mut self` to `&self` (the shared/atomic stores already are —
  `shared_replay.rs:114-116`), the `RefCell` is removed, and the five boxed
  trait-object fields (`proxy.rs:94,97,108,84,111`) gain `+ Send + Sync`.
  Every handler method is already `&self`; each core holds its own `Proxy`
  over the shared coherent stores.

### 3. Inner plane — stateless Streamable HTTP, required for production

- **The production scale path REQUIRES stateless Streamable-HTTP inner MCP
  backends**: a connection-pooled, health-checked, load-balanced async HTTP
  upstream layer (per-core `hyper` client pools, keep-alive/H2 to the
  backends) over a horizontally-scalable fleet of stateless inner servers.
  No affinity, no serial pipe; the inner plane scales out independently of the
  proxy. This is the change that converts front-end concurrency into
  throughput.
- **Outlier ejection and circuit breaking** on the upstream pool: a slow or
  dead inner backend is ejected and cannot stall the plane; pool exhaustion
  fails closed with backpressure, never unbounded queuing.
- **stdio subprocess mode is RELOCATED OUT of the PEP (out of the TCB).**
  The proxy's sole inner plane is the stateless Streamable-HTTP client above;
  the proxy launches no subprocess and carries no sandbox/rlimit/env surface.
  The ~3k-line subprocess/sandbox machinery (subprocess lifecycle, environment
  allow-listing, Landlock fs rulesets, seccomp-bpf egress filters, `setrlimit`)
  — the single most dangerous, most platform-specific code in the system — has
  been MOVED to a separate, un-privileged crate, `mcp-re-stdio-bridge`, an
  out-of-TCB `stdio`↔HTTP adapter. An unmodified local stdio MCP server is
  fronted by the bridge and reached by the PEP over HTTP like any other backend.
  A compromise of the bridge cannot forge a signature or defeat replay — those
  guarantees live entirely in the PEP. This relocation SHRINKS the PEP's Trusted
  Computing Base and removes an entire class of code (subprocess/kernel-sandbox)
  from the cryptographic trust boundary; it supersedes the earlier "stdio remains
  in-tree as a dev/compat mode" position (MCPRE-118).

### 4. Replay — an authoritative atomic tier; L1 is never authoritative

Replay is a **globally coherent admission-control decision at the evidence
boundary**, not a local cache trick. The authoritative replay tier is
**production-critical request-admission infrastructure**: it is deployed,
monitored, and capacity-planned as such, and its unavailability degrades the
service (fail-closed), never the security claim. The rule:

> A request is dispatchable **only** if its replay key is **atomically
> inserted** into the **authoritative replay tier**.

- **Replay key**: the production HTTP-profile replay key is
  `(profile_id, signature_label, actor_id, audience_hash, nonce)`
  (ADR-MCPRE-050). TTL = `expires_at + max_clock_skew`. Legacy object-profile
  replay keys (`(signer/actor, audience, nonce)`) remain confined to legacy
  compatibility code and are **not** part of the production replay profile.
- **Authoritative tier (L2)** — an abstract store contract, not a product:

  ```
  AuthoritativeReplayStore:
      atomic_insert_if_absent(key, ttl) -> Fresh | Replay | Unavailable
  ```

  The requirement is **linearizable (or effectively atomic) insert-if-absent
  per key**. Implementation profiles: Redis `SET NX PX` (single-primary or
  cluster with atomic key routing — the in-tree `redis_store.rs` backend),
  etcd compare-and-put (the in-tree cpstore), DynamoDB conditional put,
  FoundationDB transaction, or a sharded replay service. The existing
  `AtomicReplayStore` seam (`shared_replay.rs:116`, ADR-MCPS-020) is this
  contract; this ADR makes it the **only** authority.
- **Per-core L1 is an optimization only and MUST NEVER answer "fresh"
  authoritatively.** L1 may fast-reject a *known* replay (a key it has seen
  win or lose) and may pre-filter; a "fresh" verdict is only ever the result
  of a successful L2 atomic insert. This preserves exactly the cross-replica
  property proven in MCPS-81 while removing L2 round-trips for the hot
  replay-attack case.
- **`Unavailable` fails closed** (`ReplayCacheUnavailable`, unchanged
  taxonomy): uncertainty is never freshness. The per-core Redis/etcd clients
  are async and pipelined; keys shard by replay-key hash.
- **Release gates**: cross-core and cross-replica replay **race tests** — N
  concurrent submissions of the same signed request across cores and across
  replicas must yield exactly one `Fresh` and N−1 `Replay`, under load, on
  every release.

### 5. Custody — root keys in the HSM/KMS, delegated signing keys on the hot path

**Per-request response signing MUST NOT require a remote KMS/HSM operation on
the hot path.** The custody model:

- The **root/identity key never leaves the HSM/KMS** (ADR-MCPS-028 posture,
  unchanged).
- The HSM/KMS **issues and rotates a short-lived, in-memory Ed25519 delegated
  signing key**; per-request signing uses the delegated key in process
  (microseconds). KMS/PKCS#11 operations run on a bounded `spawn_blocking`
  pool **only at issuance/rotation**, never per request.
- The delegation model is first-class, with these REQUIRED semantics:
  - **Bounded lifetime** (short TTL) and an explicit **rotation overlap
    window** (old key verifies until its `expires_at`; new key signs before
    the old one lapses — no signing gap, no verification gap).
  - **Key identity**: each delegated key has its own `key_id`; evidence names
    the delegated key, never impersonates the root.
  - **Issuer proof**: a root-signed (HSM/KMS-signed) **delegation attestation**
    binding `(delegated public key, key_id, not_before, expires_at, issuer)`,
    so verifiers trust delegated keys **through the attestation chain to the
    root**, not by out-of-band enrollment of ephemeral keys.
  - **Audit trail**: every issuance/rotation/retirement is an audited event.
  - **Revocation & compromise blast radius**: a compromised delegated key is
    bounded by its TTL and revocable via the existing trust-epoch/revocation
    channels; the root is untouched.
  - **Fail-closed issuance**: if the HSM/KMS cannot issue/rotate, the proxy
    serves only until the current delegated key expires, then **stops signing**
    (fails closed) rather than extending a stale key.
- The **wire-level delegation evidence format** (how the attestation is
  carried and verified — certificate-shaped vs signed-object-shaped, resolver
  integration, taxonomy) is standards-relevant and is specified in a dedicated
  companion custody ADR (ADR-MCPRE-052), authored as part of this program —
  the *decision* to adopt delegated signing is made here and now; only its
  wire format ratification is delegated. **ADR-MCPRE-052 is BLOCKING for any
  production delegated-signing release**: no release signs with delegated keys
  before that ADR is ratified.

### 6. Lifecycle

- **Graceful drain**: flip `SHUTDOWN`, stop accepting on every per-core
  listener, and **join all in-flight requests within a bounded grace window**
  (sized under the k8s `terminationGracePeriodSeconds`), each request already
  bounded by the `ServerLimits` deadlines. This replaces MCPS-88's
  "exactly ≤1 inline request" guarantee with an explicit bounded-drain
  guarantee, proven by a drain test (zero abandoned requests).
- **Config hot-swap** (CRL reload — MCPS-66, key rotation, trust updates):
  atomically-swapped versioned snapshots (`ArcSwap`-style) read per-request by
  every core; writers are the background rotation/reload tasks. No lock on the
  read path.

### 7. Proof obligation — benchmark-first, SLO-gated releases

- A **concurrent-TLS-client load harness driving the real listener** is a
  prerequisite deliverable — built and baselined against the *current* system
  **before** the new data plane lands, so every architectural claim is
  measured, not argued. (The existing `fleet_throughput_bench` calls
  `Proxy::handle` directly on one thread and structurally cannot measure any
  of this.)
- The harness pins a **declared benchmark envelope**: hardware class, core
  count, payload sizes, TLS mode and cipher/signature suite, keep-alive vs
  cold-handshake mix, replay backend, inner-backend latency distribution.
- **Release gates**: aggregate throughput, p50/p99/p999 added latency, and
  **per-core linear-scaling tolerance (1→N cores)** against declared SLO
  targets; plus the replay race gates (§4) and the drain gate (§6). No
  release ships below its declared SLOs; the SLO numbers live with the
  harness and the release profile, not in this ADR.

## Rationale

This is the linkerd2-proxy/Envoy-class Rust data-plane architecture applied to
MCP's actual backend reality, plus the custody discipline every high-throughput
signing system uses. Thread-per-core with `SO_REUSEPORT` (rather than a shared
work-stealing runtime) is chosen for **predictable tail latency and linear
scaling**: the hot path holds no contended cross-core state, so p999 does not
degrade with core count. The target is built directly — not approached through
intermediate half-steps that would themselves need superseding — because the
project is pre-release, navigating a standards process where the reference
implementation should demonstrate the ceiling of the design, and every
intermediate architecture iteration has real cost.

Statelessness plus a pooled Streamable-HTTP inner plane removes the serial
ceiling; keep-alive/H2 removes the per-request handshake; the delegated-key
custody model removes the per-request HSM round-trip; the authoritative replay
tier keeps the fleet's security claim intact at speed. Each is independently
load-bearing. `mcp-re-core` stays pure, so the genuinely valuable half of the
ADR-MCPS-014/018 firewall — an embeddable, networking-free verification core —
is preserved exactly.

## Alternatives Considered

- **Bounded thread pool in blocking `std::net`.** Rejected: wastes cores
  blocked on inner I/O, cannot do H2 fan-in or efficient keep-alive at
  population scale, and leaves the inner serial ceiling untouched.
- **Shared multi-threaded tokio runtime as the target.** Rejected as target
  (dev scaffolding only): work-stealing and shared scheduler state degrade
  tail latency under load relative to per-core share-nothing, and adopting it
  first means paying for the same migration twice.
- **Per-request HSM/KMS signing.** Rejected: a remote signing round-trip on
  the hot path is disqualifying for this throughput class and serializes on
  device sessions.
- **stdio inner plane in production (pooled or not).** Rejected: even pooled,
  it is process-manager-shaped local IPC with per-worker serial pipes —
  the wrong transport for a scale path MCP itself is moving away from;
  keeping it in the production architecture diffuses focus. Its subprocess/
  sandbox surface is RELOCATED to the out-of-TCB `mcp-re-stdio-bridge` adapter
  (MCPRE-118), so a stdio-only server is still protectable — fronted by the
  bridge and reached over HTTP — WITHOUT that surface entering the PEP's TCB.
- **L1-authoritative replay (per-core caches, best-effort sync).** Rejected:
  violates the cross-replica replay guarantee (MCPS-81) the fleet posture is
  built on; freshness must be a linearizable insert, full stop.
- **`io_uring` runtimes (monoio/glommio).** Deferred, recorded as a future
  lever: highest ceiling, but Linux-only and less proven against the rustls
  stack; the per-core tokio design must be benchmark-proven first.
- **Fixed TPS targets in this ADR.** Rejected: capacity claims without a
  pinned benchmark envelope are marketing, not engineering. The ADR fixes the
  architecture and the *obligation* to declare and meet SLOs per release
  profile.

## Consequences

### Positive
- No known single-request architectural serialization ceiling in the target
  profile: front end scales with cores, inner plane scales with backends,
  handshakes amortized, custody off the hot path.
- Bounded tail latency by construction (no cross-core hot-path contention).
- The security core is untouched, pure, and embeddable; all security claims
  (replay coherence, revocation bounds, custody) are preserved or sharpened.
- A reference implementation that demonstrates the standard at production
  class.

### Negative
- A substantial build: async data plane, net-new HTTP inner transport, async
  replay-store clients, delegation attestation model (companion ADR), and a
  real load harness. Staged and benchmark-gated, but not small.
- `tokio`/`hyper`/`tokio-rustls` enter the proxy dependency closure
  (superseding ADR-MCPS-014 §1). The core firewall is unchanged.
- The drain guarantee weakens from "exactly ≤1 request" to "bounded join
  within grace" — still exact within the window, proven by test.
- Deployments with genuinely stateful or stdio-only inner servers are
  explicitly outside the high-throughput profile.

### Neutral
- Horizontal fleet scaling (ADR-MCPS-049) is unchanged and complementary; the
  fleet gates (shared replay tier under `--fleet`) now sit on top of an
  efficient per-node design.
- The CRL hot-reloader (MCPS-66) is subsumed by the versioned-snapshot
  config-swap mechanism (§6).

## Migration (benchmark-first; each phase gated)

- **Phase 0 — proof harnesses + baseline.** Build the concurrent-TLS-client
  load harness and the replay race harness; measure and record the current
  system's baseline. No architecture changes ship before the instruments
  exist.
- **Phase 1 — thread-readiness.** `ReplayCache` → `&self`; remove the
  `RefCell`; `Send + Sync` bounds → `Proxy: Send + Sync`. Mechanical, no
  behavior change, ships independently.
- **Phase 2 — target data plane.** Per-core tokio runtimes + `SO_REUSEPORT` +
  `tokio-rustls` + `hyper` keep-alive/H2 + per-core admission + bounded
  drain + versioned config snapshots. Built directly as the target; a shared
  runtime may exist transiently in development but is never a release.
- **Phase 3 — stateless Streamable-HTTP inner plane.** Pooled, health-checked,
  outlier-ejecting upstreams; the production profile switches to it.
- **Phase 4 — delegated signing custody.** Companion ADR-MCPRE-052 (wire
  evidence format) + implementation: root-in-HSM/KMS, short-lived in-memory
  delegated keys, rotation overlap, audit, fail-closed issuance.
- Every phase must hold the Phase-0 harness green against its declared SLOs
  and the replay/drain gates before the next begins.

## Compliance and Enforcement

- The load harness + SLO gate, the replay race gates (cross-core and
  cross-replica: exactly one `Fresh` under N-way concurrent submission), and
  the bounded-drain test are CI release gates.
- The firewall test is updated: `mcp-re-core` MUST remain pure (no
  networking/async/fs); the proxy serving path MAY use the async stack.
- The production deployment profile asserts Streamable-HTTP inner backends.
  The proxy has NO stdio inner mode: a stdio-only server is fronted by the
  out-of-TCB `mcp-re-stdio-bridge` and reached over HTTP (MCPRE-118).
- Delegated-key issuance, rotation, and retirement are audited events;
  fail-closed issuance is covered by a deterministic test.

## Related

- Supersedes: ADR-MCPS-014 §1 (blocking, thread-per-connection, no-async
  serving path); the serving-path half of the "ADR-MCPS-018 lean-sync
  firewall" convention. The pure-core half of both is retained and enforced.
- Builds on: ADR-MCPS-020 (`AtomicReplayStore` durability contract — promoted
  here to the sole replay authority), ADR-MCPS-047 (stateless MRT
  continuation; MCPS-82 cross-replica proof), ADR-MCPS-049 (fleet posture),
  ADR-MCPS-028 (KMS/HSM custody — root retained, hot path delegated),
  ADR-MCPRE-050 (HTTP profile).
- Companion: [ADR-MCPRE-052](adr-mcpre-052.md) — delegated signing-key attestation:
  wire evidence format, verifier trust chain, rotation overlap, revocation, audit,
  taxonomy (Proposed; BLOCKING for any production delegated-signing release).
- Prior art: linkerd2-proxy / Envoy data-plane model; thread-per-core
  share-nothing high-transaction designs; php-fpm-class process management
  (rejected for production here, informative for the dev-mode stdio pool).
- Follow-up issues: Phases 0–4, the io_uring evaluation.
