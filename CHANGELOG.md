<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to MCP Runtime Evidence (MCP-RE, formerly MCP-S) are
recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until
1.0 the public surface is explicitly unstable: minor versions may break API
or wire-format compatibility while the design lines from
[`docs/adr/`](docs/adr/) settle.

## [Unreleased]

### Added

- **`mcp-re-stdio-bridge` — the out-of-TCB stdio↔HTTP adapter (ADR-MCPRE-051,
  Phase B, MCPRE-118, part 1).** A new binary crate that fronts an unmodified,
  sandboxed local stdio MCP server behind a plain HTTP endpoint, so the proxy PEP
  can protect a stdio-only server via its stateless HTTP inner plane **without**
  the subprocess/sandbox/env/rlimit attack surface (~3k lines: subprocess
  lifecycle, environment allow-listing, Landlock fs rulesets, seccomp-bpf egress
  filters, `setrlimit`) entering the signing PEP's Trusted Computing Base. The
  bridge accepts a `POST` of an already-verified JSON-RPC body from the PEP,
  relays it to the sandboxed child over stdio (blocking subprocess I/O kept off
  the async workers), and returns the child's JSON-RPC response as the HTTP body;
  non-`POST` is `405`, over-cap bodies `400`, a panicked dispatch `502`. A
  compromise of the bridge cannot forge a signature or defeat replay — those
  guarantees live entirely in the PEP. Phase A reuses the proven hardened
  subprocess inner (`SubprocessInner` / `PersistentSubprocessInner` +
  `InnerLaunchConfig` + the Landlock/seccomp `SandboxProfile` + `RLimits`) from
  `mcp-re-proxy` with secure launch defaults; a later commit of this phase
  physically moves those modules into this crate and cuts the dependency so the
  PEP links none of them. Arg-parse unit tests + an end-to-end HTTP→stdio→HTTP
  relay smoke path.
- **Async authoritative replay tier — seam + L1-never-Fresh (ADR-MCPRE-051 §4,
  Phase 2, MCPRE-117, part 1).** The async data plane checks replay without blocking a
  runtime worker: a new `async_replay` module defines `AsyncAtomicReplayStore` — the
  async analogue of `shared_replay::AtomicReplayStore`, one server-side-atomic
  `atomic_insert_if_absent` awaited on the request path — with an in-memory reference
  impl (`InMemoryAsyncAtomicReplayStore`). The per-core `L1FastRejectStore` sits in
  front of the shared authoritative L2: it may fast-reject a key it already knows is
  present (returning `Replay` with no L2 round-trip) but **can never answer `Fresh` —
  `Fresh` is produced only by a winning L2 insert.** The property is enforced BY
  CONSTRUCTION (the L1 lookup returns `Some(Replay)` or a miss — a type that cannot
  express `Fresh`) and BY TEST. L1 is bounded per core with FIFO eviction that is
  always safe (an evicted known key costs an L2 round-trip, never a false `Fresh`); an
  L2 outage fails closed (`ReplayCacheUnavailable`) and recovers clean. A deterministic
  suite (`async_replay_test`) proves L1 fast-reject-without-L2, eviction safety, outage
  fail-closed + recovery, and **cross-core EXACTLY-ONE-`Fresh`** (many per-core tiers
  over one shared L2 under concurrency). Concrete async Redis (`SET NX PX`) / etcd
  (CAS) backends implement the same contract next; their live cross-replica proofs run
  in the skip-when-absent infra lane. Conformance target count 79 → 80.
- **Bounded graceful drain across cores — zero-abandoned (ADR-MCPRE-051 §6, Phase
  2, MCPRE-115).** On shutdown, each per-core `async_serve` loop stops accepting and
  then waits up to a bounded grace window (`ServerLimits::drain_grace`, default 30s)
  for its IN-FLIGHT requests to finish before the runtime is dropped — so a request
  already being served **completes rather than being abandoned**, while a stuck
  request cannot delay process exit past the grace (bounded exit). In-flight requests
  are tracked by a per-core RAII counter (`InFlightGuard`, incremented once a request
  is admitted, decremented on every return path); idle keep-alive connections carry no
  in-flight request and so do not extend the drain — an idle drain returns promptly.
  Because each request is also bounded by `request_deadline`, sizing
  `request_deadline <= drain_grace < terminationGracePeriodSeconds` guarantees a clean,
  zero-abandoned drain under a k8s rollout (documented on `drain_grace`). This replaces
  MCPS-88's single-process "≤1 inline request" guarantee with an explicit
  bounded-drain guarantee for the per-core fleet (each core drains before its worker
  thread joins). A deterministic suite (`async_drain_test`) proves an in-flight request
  drains cleanly (200, not abandoned), idle + saturated drains return within bound, and
  a request stalled in the body-read phase cannot delay exit past the grace. The
  SIGTERM/SIGINT → shutdown bridge is CLI wiring (a tracked follow-up); the mechanism
  is driven by the shared shutdown flag. Conformance target count 78 → 79.
- **Per-core bounded admission control + fail-closed backpressure (ADR-MCPRE-051
  §1, Phase 2, MCPRE-114).** The async serving path now enforces a **per-core
  in-flight-request ceiling** (`ServerLimits::max_in_flight_requests`): once a core is
  serving that many requests, the next request is rejected with `503 Service
  Unavailable` **before its body is read or the handler runs** — fail-closed
  backpressure that bounds tail latency under overload instead of queuing work without
  bound. The ceiling is a per-core `tokio::sync::Semaphore` acquired at the top of
  request handling and released on return (RAII, the same fail-closed permit idiom as
  `redis_store`'s `ConnectPermit`), so it stays lock-free ACROSS cores. Config surface
  is both per-core and fleet-global: `FleetConfig::max_in_flight_total` is divided
  evenly into per-core ceilings (`ceil(total / cores)`, at least 1; an explicit
  per-core ceiling wins) — no shared cross-core semaphore on the hot path. `None`
  leaves in-flight unbounded (the historical default). A deterministic suite
  (`async_admission_test`) drives `serve` on a multi-thread runtime with blocking
  handlers to prove over-cap requests get 503 (handler never reached), that the
  uncapped default admits all, and the global→per-core division. **Saturation latency
  bounded-at-cap is measured on the load harness (MCPRE-108) in the SLO lane.**
  Conformance target count 77 → 78.
- **Per-core async serving fleet — SO_REUSEPORT + thread pinning (ADR-MCPRE-051
  §1, Phase 2, MCPRE-113).** A new `mcp-re-proxy` module (`async_fleet`, behind the
  non-default `async_serve` feature) stands up the target data plane: **one worker
  thread per core, each a current-thread `tokio` runtime with its own `SO_REUSEPORT`
  listener and (on Linux) `sched_setaffinity` CPU pinning, running one
  `async_serve::serve` loop over one `Proxy` per core.** The kernel's `SO_REUSEPORT`
  group load-balances accepted connections across the per-core listeners, so there is
  no shared accept lock, no cross-core connection handoff, and no contended cross-core
  hot-path state — the only cross-core sharing is the coherent replay/trust store
  (server-side-atomic, ADR-MCPS-020) and the immutable `Arc<ServerConfig>` /
  `Arc<ServerOptions>` snapshots (a module-level cross-core-sharing audit documents
  this, satisfying the "no cross-core locks on the request path" criterion). Core
  count is configurable (`0` = `available_parallelism`); listeners share one port
  (`:0` resolves on the first bind and is reused). `SO_REUSEPORT` + `bind`/`listen`
  are done via `libc` directly (set before `bind`, which `std::net` cannot express) —
  no new crate, no crate-universe repin; the raw socket is wrapped in an `OwnedFd`
  for fail-closed RAII. This supersedes the MCPRE-112 single-shared-runtime
  scaffolding (never a release). An always-on suite (`async_fleet_test`) proves N
  independent per-core runtimes serve the full mTLS pipeline correctly, that a missing
  client cert fails closed on every core, configurable/auto core counts, and clean
  shutdown+join; on Linux it also asserts `SO_REUSEPORT` distributes connections
  across ≥2 cores. **Near-linear 1→N throughput scaling is measured on the load
  harness (MCPRE-108) in the SLO/CI lane (MCPRE-110/123), not this deterministic
  suite.** Bounded graceful drain across cores is MCPRE-115; per-core bounded
  admission control is MCPRE-114. Conformance target count 76 → 77.
- **In-process CRL hot-reload + versioned serving-config snapshots (ADR-MCPRE-051
  §6, MCPRE-116; subsumes MCPS-66).** The serve loop now reads the current rustls
  `ServerConfig` per connection from a `ServerConfigSnapshot` (a dependency-free
  `RwLock<Arc<ServerConfig>>` swap seam) instead of a fixed `Arc`. A new opt-in
  `--client-crl-reload-secs N` spawns a background task that every `N` seconds
  re-reads the `--client-crl` files and atomically swaps in a rebuilt verifier — so
  a **refreshed CRL is honored without a restart**, removing the old
  "restart-before-nextUpdate" requirement. A failed reload keeps the last-good
  config (which still fails closed once its CRL passes `nextUpdate`, via rustls'
  `enforce_revocation_expiration`), so a bad reload never widens what is accepted;
  every reload outcome is logged. The swap/keep-last-good decision (`reload_once`)
  is pure and deterministically tested (no wall clock), and an in-flight handshake
  keeps serving on the config it captured. **Default behavior is byte-identical**
  (no `--client-crl-reload-secs` → the snapshot is never swapped). Direct-TLS path
  in this increment; delegated-TLS reload is a tracked follow-up. The snapshot seam
  is also what the per-core async data plane (ADR-051 §1) reads from.
- **Opt-in async serving path (ADR-MCPRE-051 §1, Phase 2, MCPRE-112).** A new
  `mcp-re-proxy` module (`async_serve`, behind the non-default `async_serve`
  feature) serves over `tokio` + `tokio-rustls` + `hyper` with HTTP/1.1 keep-alive
  and HTTP/2 — killing the one-request-per-connection `Connection: close` wire. It
  is a THIN transport swap: the rustls `ServerConfig` (mTLS verifier + CRL), the
  verified-identity extraction, the per-connection cert-lifetime + routing-header
  rejections, and the request handler are the EXACT SAME ones the blocking
  `serve_once` uses (shared leaf-DER helper cores), so every mTLS fail-closed
  behavior is byte-identical — only the I/O framing is async. `ServerLimits` map
  onto the async stack: the aggregate read deadline bounds the handshake + body
  read (slow-loris), `hyper`'s header-read timeout bounds the header read,
  `max_body_bytes` caps the body (`http_body_util::Limited`), and
  `max_concurrent_connections` is a fail-closed `Semaphore`. A parity suite
  (`async_serve_parity_test`) proves mTLS rejection (missing/untrusted cert),
  identity extraction, keep-alive (N requests / one handshake), 32-way concurrency
  over one shared `Proxy` (`Send + Sync`, MCPRE-111), and the body-cap fail-closed.
  **The default/production closure is unchanged** — it links no `tokio`/`hyper` and
  stays the blocking `std::net` path (ADR-MCPS-018 lean-sync firewall); only the
  `:mcp_re_proxy_async` flavor + its test link the async stack. A shared runtime is
  dev scaffolding only (per-core `SO_REUSEPORT` is MCPRE-113); CLI wiring, an HTTP/2
  client test, load-harness (#313) integration, and online-OCSP-on-async are the
  tracked follow-ups. Conformance target count 73 → 74; 22 async crates enter the
  `async_serve`-only closure (validated by the CI `cargo-deny` gate).
- **Concurrent-TLS-client load harness driving the real listener (ADR-MCPRE-051
  §7, MCPRE-108).** A new harness (`tls_load_harness_bench`) spawns the real
  `mcp-re-proxy` binary and hammers its listener with many concurrent rustls
  **mTLS** clients — accept → TLS/mTLS → verify → inner → sign → respond — so
  every number includes the full serving path (unlike `fleet_throughput_bench`,
  which calls `Proxy::handle` on one thread). It reports aggregate throughput and
  p50/p99/p999 added latency, measures the cold-handshake and keep-alive
  connection modes SEPARATELY (keep-alive reports a realised-reuse fraction ≈ 0 on
  the current `Connection: close` wire), and records the per-core-scaling point.
  The **declared benchmark envelope** is committed alongside it
  (`docs/bench/adr-051-load-harness-envelope.md` + `adr-051-benchmark-envelope.json`):
  hardware class, core count, payload, TLS/signature suite, connection mode,
  replay backend, inner latency. The full run is `#[ignore]` (the §7
  manual/dispatch lane, scaled by `MCP_RE_LOADGEN_*`, optional JSON via
  `MCP_RE_LOADGEN_OUT`); an always-on smoke test self-verifies the harness at tiny
  scale on every battery run. Run against the current single-threaded proxy it
  produces the Phase-0 baseline for the SLO declaration (MCPRE-110). Conformance
  target count 72 → 73.
- **Replay race harness — the authoritative tier admits exactly one `Fresh`
  under concurrency (ADR-MCPRE-051 §4, MCPRE-109).** A new always-on test
  (`replay_race_harness_test`) fires N barrier-released threads at the SAME
  replay key on one shared `AtomicReplayStore` and asserts EXACTLY ONE `Fresh` +
  N−1 `Replay` — cross-core (many threads, one store) and cross-replica (per-
  replica store clones over one backend) — plus the fail-closed path (store
  unavailable ⇒ ZERO `Fresh`). Deterministic: a `Barrier` maximises contention
  and the assertion is an exact count, so there is no timing/sleep flake. The
  in-memory reference tier runs on every `bazel test //...`; the Redis and etcd
  lanes race the same harness on the live store (skip-when-absent; hard-fail
  under `MCP_RE_REQUIRE_LIVE_INFRA`). The full-stack serving-path variant arrives
  with the async data plane (ADR-051 Phase 2). Conformance target count 72 → 73.
- **HTTP standards profile — minimal proof path (ADR-MCPRE-050, seed Work
  Item 3)**: new pure crate `mcp-re-http-profile` implementing the RFC 9421
  HTTP Message Signatures + RFC 9530 `Content-Digest` carrier with the ratified
  covered-component sets, profile tag `mcp-re-http-v1`, labels `mcp-re` /
  `mcp-re-response`, split-form `request_evidence` handle, and fail-closed
  verification (body tamper, response splice, wrong digest, missing covered
  component, stale window, wrong keyid, foreign tag, `Content-Encoding`
  rejection). Wire-code verdicts reuse the frozen `mcp-re.*` taxonomy — no new
  tokens. Independent oracle: RFC 9421 Appendix B.2.6 known-answer test
  (byte-exact signature base; deterministic Ed25519 `sig-b26` byte-match).
- **HTTP-profile conformance corpus seed (Work Item 4)**:
  `mcp-re-conformance/tests/vectors/http-profile/` — 8 frozen fixtures with a
  static oracle (signature base, `Content-Digest`, Ed25519 signature bytes,
  evidence handle) plus a regenerating drift guard; draft-01/draft-02 corpora
  untouched.
- **Standards issue tracker (Work Item 5)**:
  `docs/spec/http-profile-open-questions.md` — grill-resolved questions vs.
  open items with named triggers (wire-code mapping ratification, third-party
  RFC 9421 CI cross-verification, artifact-binding/rejection/MRTR slices).
- **HTTP standards profile — full profile + parity gate green (ADR-MCPRE-050,
  MCPRE-92…103)**: the full profile is implemented and integrated — active
  `se.syncom/mcp-re.http.request` / `.response` body evidence blocks
  (audience + strict DPoP/mTLS/RAR artifact bindings, `server_signer` +
  `request_evidence` response binding), resolved-actor trust seam, the
  five-tuple replay key `(profile_id, signature_label, actor_id, audience_hash,
  nonce)` packed onto the existing replay-cache tiers, signed rejection
  receipts, and MRTR continuation rebased onto three standards-derived handles
  (previous-request / input-required-response signature-base digests + a
  `requestState` digest). A pure profile-level dispatcher seam
  (`mcp-re-http-profile::dispatch`) drives replay admission and continuation
  binding over verified evidence, failing closed and refusing a single-process
  reference replay cache under fleet-strict. ADR-MCPRE-050 is **Accepted**: the
  parity gate is declared green on the integrated-path battery
  (`full_profile_parity_test`, MCPRE-103) composed with the third-party RFC 9421
  cross-verification CI no-merge gate (MCPRE-99).
- **Fleet proof (c) — MRT continuation survives a mid-continuation replica
  switch (ADR-MCPS-049 W1, MCPS-82).** Completes the three ceiling-lifting
  proofs (alongside replay MCPS-80/81 and revocation MCPS-86): a new always-on
  e2e (`fleet_mrt_replica_switch_e2e_test`) drives an elicitation continuation
  across two independent serving-proxy replicas — leg 1 to replica A, the signed
  continuation leg to a fresh replica B — and B completes it without any shared
  server-side continuation state, because the `continuation` binding rides the
  signed draft-02 preimage (ADR-MCPS-047). Runs in the normal Bazel battery
  (not the Redis live lane): replica-independence of the continuation requires
  no shared cross-node store. No production code change.

### Changed

- **BREAKING — async/HTTP is the sole proxy serving path; sync serving + stdio
  inner are deleted/relocated (ADR-MCPRE-051, MCPRE-118).** The `mcp-re-proxy`
  binary now serves ONLY on the per-core async fleet (SO_REUSEPORT + one tokio
  runtime per core) forwarding to a stateless Streamable-HTTP inner backend; the
  blocking single-threaded serve loop and the synchronous in-memory `Proxy::handle`
  / `handle_with_transport` / `InnerServer` seam are removed. `Proxy::new` no longer
  takes an inner argument — wire the async inner via `.with_async_inner(...)`; the
  async replay tier defaults to in-memory and is swapped for a durable store via
  `.with_async_replay_tier(...)`. **The proxy no longer launches a subprocess:** the
  ~3k-line stdio subprocess/sandbox/rlimit/env surface (Landlock, seccomp-bpf,
  `setrlimit`, subprocess lifecycle) is REMOVED from the PEP's TCB and relocated to
  the out-of-TCB `mcp-re-stdio-bridge` crate. The `--inner-command` flag and all
  `--inner-*`/sandbox/rlimit stdio flags are gone; `--inner-http-url` is now required
  (front a local stdio server with `mcp-re-stdio-bridge` and point `--inner-http-url`
  at the bridge). The async serving path links tokio/hyper unconditionally,
  superseding the ADR-MCPS-018 §1 lean-sync firewall for the proxy serving path.
- **Durable/distributed replay is served by the async fleet (ADR-MCPRE-051 §4,
  MCPRE-118).** `--replay-cache shared` selects an AWAITED async authoritative
  store — `--replay-durability-tier linearizable` → a new async etcd backend (hyper
  over the etcd v3 JSON gateway), otherwise the async Redis backend (`SET NX PX` via
  the tokio client; its `ConnectionManager` reconnect task runs on a process-lifetime
  control runtime distinct from the per-core serving runtimes). `--replay-cache file`
  is not offered on the async fleet (a single file cache does not fit the per-core
  share-nothing data plane; use `shared` for durable cross-replica replay or `memory`
  for single-replica dev). *Follow-up: re-establish the persistent-inner / sandbox
  e2e coverage against the bridge topology (the bridge carries the unit coverage; the
  proxy's old proxy-wraps-subprocess e2e tests were removed with that topology).*
- **Thread-readiness: `Proxy` is now `Send + Sync` (ADR-MCPRE-051 §2, Phase 1,
  MCPRE-111).** Mechanical, no behavior change — the groundwork for the target
  per-core async data plane where a single `Proxy` serves concurrently across
  cores. `ReplayCache::check_and_insert` moved from `&mut self` to `&self`; the
  in-memory reference cache and the file-backed `DurableReplayCache` gained
  interior `Mutex` synchronization (each check-and-insert stays atomic — the
  lock spans check+insert, so a race still yields exactly one `Fresh`); the
  shared/atomic stores were already `&self`. The proxy now holds its replay
  cache directly (the `RefCell` on the serving path is gone), and the boxed
  custody/trust/inner/replay/policy trait-object seams carry `+ Send + Sync`. A
  compile-time assertion (`proxy_is_send_and_sync`) locks the property. The
  `ReplayCacheUnavailable` fail-closed taxonomy is unchanged; `mcp-re-core`
  stays pure (the interior lock is `std::sync`, not I/O/async).
- **Project renamed: MCP-S / MCPS → MCP Runtime Evidence (MCP-RE)** (#289,
  Stages 2–4). A full identity rename, including the wire format:
  - Crates and directories: `mcps-*` → `mcp-re-*`; Rust lib/module names
    `mcps_*` → `mcp_re_*`; types `Mcps*` → `McpRe*`.
  - **Wire format (BREAKING, pre-1.0):** envelope `_meta` namespaces
    `se.syncom/mcps.*` → `se.syncom/mcp-re.*`, error tokens `mcps.*` →
    `mcp-re.*`, canonicalization id `mcps-jcs-int53-json-v1` →
    `mcp-re-jcs-int53-json-v1`, and the response-preimage domain-separation
    tag. All conformance vectors and SDK oracle fixtures regenerated; peers
    speaking the old vocabulary do not interoperate.
  - Environment variables: `MCPS_*` → `MCP_RE_*`.
  - Bazel module `mcps` → `mcp-re`; crate-universe hub `crates_mcps` →
    `crates_mcp_re`; Helm chart `mcps-proxy` → `mcp-re-proxy`; SDK packages
    `@mcps/sdk` → `@mcp-re/sdk` (npm) and `mcps-sdk` → `mcp-re-sdk` (PyPI,
    Python module `mcp_re_sdk`).
  - Preserved as historical record: `ADR-MCPS-NNN` / `MCPS-NNN` work-item
    IDs and dated ADR filenames, grilling-seed docs, dated security scans,
    prior CHANGELOG entries, and the published demo-video sources under
    `demo/video/mcps-intro/`.

## [0.10.1] — 2026-07-05

Horizontally-scaled fleet deployment posture (ADR-MCPS-049) — lifting the
single-node ceiling over proven cross-replica coherence — plus a hermetic PKCS#11
test provider. No wire-envelope or public-API changes; the frozen v0.3 envelope is
unchanged.

### Added

- **Horizontally-scaled fleet posture (ADR-MCPS-049).** MCP-S may now run as N
  identical replicas behind a load balancer without weakening any security claim,
  gated behind an explicit `--fleet` flag (orthogonal to `--strict`):
  - `--fleet` rejects node-local replay caches — a replica must use a shared,
    cross-replica ReplayCache (Redis) so a nonce a second verifier could accept is
    never silently allowed (MCPS-79).
  - `--inner-session` self-declared statefulness field, so a stateful inner server
    is pinned/handled correctly under fan-out (MCPS-83).
  - Redis-backed trust-epoch invalidation source for the ADR-021 Push tier, so a
    revocation propagates across replicas (MCPS-84), with per-tier cross-replica
    revocation-lag bounds (MCPS-85).
  - Graceful `SIGTERM`/`SIGINT` shutdown for rolling fleet deploys (MCPS-88).
  - Cross-replica replay- and trust-revocation-coherence e2e proofs
    (MCPS-80/81/86) and a fleet PEP throughput / added-latency benchmark harness
    (MCPS-89).
  - Kubernetes/Helm fleet deployment reference + guide (MCPS-87).

### Changed

- **PKCS#11 e2e now runs against a hermetic in-tree mock provider.** The
  `pkcs11_keysource` sign+verify and delegated-TLS end-to-end tests
  (`tests/pkcs11_keysource_e2e_test.rs`) previously exercised the token path only
  in a nightly lane backed by an external SoftHSM2 software token; under plain
  `cargo test` they self-skipped. They now build and load a small test-only
  Cryptoki `cdylib` (`tests/mock-pkcs11/`, deterministic in-memory Ed25519 keys)
  that implements exactly the surface the client calls, so the full FFI /
  `C_Sign` (`CKM_EDDSA`) / delegated-mTLS-handshake path runs for real in the
  blocking `cargo` job — no external token or tooling. The mock is a test double,
  not a shipped key store; the vendor-neutral PKCS#11 client interface is
  unchanged. Removed the SoftHSM2 provisioning from the live-infra CI lane.

## [0.10.0] — 2026-07-04

**Mode C — attested ingress.** v0.10 adds the second strict-mode ingress posture:
a controlled ingress attestor terminates or receives validated client mTLS, checks
certificate revocation, and Ed25519-signs a request-bound assertion the
`mcps-proxy` node verifies over a pinned attestor→node channel. Mode C is
*attested delegation*, an explicit opt-in — **not** end-to-end client↔node mTLS
(the load balancer witnesses proof-of-possession and stays in the trusted computing
base). It never widens the wire: **zero draft-02 preimage change** — every Mode-C
fact rides the assertion, never the request. Built on top of v0.9.0
(ADR-023 §C, epic #245).

### Added in v0.10

- **`mcps/lb-ingress-assertion/v2` assertion format + node verifier**
  (`mcps-proxy`). A new frozen, domain-separated, length-prefixed assertion
  (the Tier-3 v1 preimage is untouched). v2 binds a distinct ingress identity,
  the audience/route, the attestor's opaque certificate-verification and revocation
  verdicts (explicit enums — a stale attestor CRL is an explicit `StaleCrl` verdict,
  never a sentinel), a recorded-only CRL `nextUpdate`, and an optional `expires_at`.
  The verifier is **bind-not-interpret** (§C3): it checks signature, freshness,
  `request_hash`, audience, and ingress identity, and admits the attestor's opaque
  verdicts by fail-closed policy — performing no certificate-path validation and no
  CRL-freshness computation of its own. No nonce, no assertion-replay cache.
- **`--transport-binding attested-ingress`** (`mcps-proxy`,
  `BindingKind::AttestedIngress`). Wires Mode C through proxy dispatch with
  fail-closed configuration guards: missing attestor keys, trusted ingress
  identity, audience, or the explicit `--ingress-pinned-mtls` acknowledgement each
  refuse to start (§C2 — the pinned attestor→node channel is load-bearing). Mode C
  is strict-**admitted** (explicit opt-in), unlike Mode B (`lb-assertion`, Tier-2
  header) which remains strict-**rejected**. The node records the three §C2 audit
  trust facts (`delegated_client_identity`, `ingress_internal_hop`,
  `backend_channel_binding = pinned_mtls`) and `revocation_mode = delegated_attestor_crl`.
- **Offline conformance spine** (`mcps-proxy` / `mcps-conformance`). Serve-level
  node-side rejection of a v2 assertion carrying `revocation_result = revoked`, a
  stale-CRL verdict, a bad signature, a cross-request `request_hash`, an untrusted
  ingress identity, a mismatched audience, or a missing header — plus a
  **preimage-invariance** proof that the forwarded draft-02 request is byte-identical
  to Mode A. Eight GREEN-OFFLINE entries added to the traceability manifest.
- **Non-normative Google Cloud cookbook** (§C4,
  [`docs/mode-c-attested-ingress-gcp-cookbook.md`](docs/mode-c-attested-ingress-gcp-cookbook.md)).
  The operator guide for building the attestor on GCP: the Envoy signing filter, GCLB
  `client_cert_*` headers with public-side stripping, CAS CRL lookup keyed on the cert
  serial, and the side-door-closing topology (internal ALB + Private Service Connect;
  Cloud Run `internal-and-cloud-load-balancing`).
- ADR-023 §C (attested ingress) is promoted to Accepted for v0.10; the
  `security-boundary.md` §11 two-posture (Mode A / Mode C) statement is added.

### Not in v0.10 (gaps / deferred)

- **Optional v0.10 tail** — live revocation, an OCSP response cache, cross-cloud
  attestors, and FIPS-140-2 L3 via PKCS#11 — stays deferred / HITL (MCPS-63, #243).
- **Live-cloud attestor QA is supporting-only.** Presenting a genuinely revoked
  client certificate and watching the GCP attestor reject it is operator QA of your
  build, outside the offline MCP-S evidence spine.
- Carried over from v0.9: the live-GCP HSM Ed25519 fact-check (MCPS-59, #239) and the
  in-process CRL hot-reloader (MCPS-66, #246) remain open.

## [0.9.0] — 2026-07-04

**Enterprise hardening — KMS key custody + Mode-A revocation honesty — on a
generated-first build graph.** v0.9 hardens the strict-mode operational envelope
(short-lived-cert Mode-A revocation, offline KMS-lifecycle-vs-trust-policy
custody semantics) with offline-provable evidence, and rebuilds the dual
Cargo/Bazel build so the Bazel graph is generated from the Cargo manifests and
CI-gated against drift. Built on top of v0.8.0.

### Added in v0.9

- **Mode-A strict cert-lifetime ceiling** (`mcps-proxy`). Strict mode now rejects
  a `max_client_cert_lifetime` above 3600s (previously strict only rejected
  none/0), tightening the short-lived-cert revocation posture (ADR-023 §A1).
- **Static CRL fail-closed-on-stale** (`mcps-proxy`). `--client-crl` enforces
  revocation-list expiration (rustls `enforce_revocation_expiration()`; the prior
  default was fail-open `Ignore`), plus a pure `crl_freshness()` startup gate
  (strict = refuse-start on a stale CRL; otherwise warn) and explicit
  OCSP-no-AIA → Unknown honesty. This is the restart-before-nextUpdate path; the
  in-process hot-reloader is deferred (MCPS-66).
- **Offline KMS-lifecycle custody negatives** (`mcps-proxy`, gcp/aws features). A
  fault-injecting FakeGcp backend + offline negatives proving the ADR-028/021
  custody sentence: KMS disable → sign-fail; destroy → construct-fail; a disabled
  KMS key is NOT verifier revocation (trust-policy-driven, no live KMS at verify);
  trust revocation rejects an otherwise-valid signature; rotation overlap.
- **Honest KMS protection-level labeling** (`mcps-proxy`, gcp feature). The native
  GCP Cloud KMS adapter documents software-vs-HSM protection precisely; FIPS-140-2
  L3 routes via PKCS#11 (CKM_EDDSA); Ed25519-only. (The live-GCP HSM protection
  fact-check remains HITL / open, #239.)
- ADR-021 / ADR-023 / ADR-028 gain v0.9 delta addendums recording these decisions;
  ADR-028 §C (KMS key custody) is promoted to Accepted for v0.9.

### Tooling

- **Generated-first build graph (ADR-048).** The Cargo/pyproject/package.json
  manifests are the sole human-authored dependency truth; first-party Bazel BUILD
  targets/edges are generated (gazelle_rust) and a **semantic drift gate**
  (`scripts/bazel_gazelle_gate.py`) fails CI on divergence — killing the #220
  Bazel/cargo parity-rot class. gazelle is the drift detector, not the byte-owner.
- **Blocking Bazel CI parity job.** `bazel test //...` + the drift gate now run on
  every push/PR (Bazel was previously ungated — the root cause of #220). The zig
  hermetic toolchain is scoped to darwin cross-compiles so the Linux runner builds
  every target with the native cc toolchain.
- **Downloader-artifact CI** (no Bazel). The maturin wheel (Python SDK) and napi
  package (TypeScript SDK) are built and smoke-installed in clean environments,
  proving the cargo/pip/npm downloader path.

### Not in v0.9 (gaps / deferred)

- **Mode C attested ingress** (`mcps/lb-ingress-assertion/v2` + attestor +
  `BindingKind::AttestedIngress` + offline rejection conformance) is v0.10
  (epic #245).
- **Live-cloud KMS fact-checks stay HITL** — the GCP HSM Ed25519 protection-level
  verification (MCPS-59, #239) and live revocation lanes are not part of the
  offline-provable v0.9 gate.
- **In-process CRL hot-reloader** deferred to MCPS-66 (#246).

## [0.8.0] — 2026-07-02

**Stateless multi-round-trip continuation + the TypeScript SDK.** v0.8 folds
request-associated elicitation into strict MCP-S as signed multi-round-trip (MRT)
continuation evidence (ADR [047](docs/adr/adr-mcps-047.md)), and ships a second
client SDK — TypeScript — bound to the SAME audited `mcps-client-core` as the Python
SDK and the proxy. Built on top of the released v0.7.0.

### Added in v0.8

- **Stateless MRT continuation evidence** (`mcps-core` / `mcps-client-core` /
  `mcps-client-proxy`). A signed `InputRequiredResult` is verified as an ordinary
  server response and classified non-terminal; the client answers with a fresh signed
  continuation request bound to it (`previous_request_hash` +
  `input_required_response_hash`), verified server-side by the ordinary draft-02
  request path (the continuation object rides inside the signed preimage — no bespoke
  proxy code). Non-terminal correlation is associate-without-consume; the client proxy
  drives the elicitation → continuation round trip transparently. Shared conformance
  vectors **d12–d15**.
- **TypeScript SDK** (`sdk/typescript`, NEW). A `napi-rs` binding to the audited
  `mcps-client-core` — the exact analog of the Python PyO3 binding, so the canonical
  signed preimage is byte-identical across every SDK and the proxy by construction.
  Transport adapters (stdio + one-POST-per-request mTLS), authorization-binding
  providers, non-exporting (KMS/HSM) custody, and MRT continuation. Verified against
  the same independent oracle vectors as the Python SDK.
- **Python SDK** conformance driver gains MRT continuation support (parity with
  TypeScript), so the interchangeable-driver matrix stays a true parity harness.
- **Cross-SDK MRT parity matrix.** A safe, deterministic `delete_files` elicitation
  tool on `mcps-demo-fileserver` (a dry-run that carries its pending state in the
  opaque `requestState`) drives the elicitation → continuation SECURITY SHAPE end to
  end through the real four-hop across the **Rust reference, Python, and TypeScript**
  drivers.
- **`McpsHttpTransport` MRT coverage in both SDKs.** The continuation path through the
  request/response transport (record on the `InputRequiredResult` leg, bind on the
  answer leg) is covered three ways: always-run hermetic transport tests, the
  primitives-level four-hop matrix, and a **live** `delete_files` elicit → answer round
  trip driving the transport against the real `mcps-proxy` + fileserver — added for both
  the Python and TypeScript SDKs.
- **Transport hardening (message-boundary correctness).** `serverName` is validated
  against CR/LF before it reaches the HTTP `Host` header (header-injection guard); the
  stdio reader fails closed per message so one malformed line can't tear down the
  transport; the request/response transport delivers exactly one outcome per request id
  (no contradictory success-then-failure on interleaved server messages); and empty-vs-
  malformed inbound-payload handling is byte-for-byte matched across the two SDKs.

### Tooling

- **Two-tier security scanning.** CodeQL moved from default setup to an advanced-setup
  workflow that runs off the per-push inner loop (`push: main` / merge queue / weekly)
  and excludes the test-fixture `hard-coded-cryptographic-value` false positives; a
  `.pre-commit-config.yaml` adds a fast local hygiene + Semgrep tier.
- **Draft-02 corpus pinned by content.** The v0.8.0 draft-02 conformance corpus is
  pinned by digest, not only by Git tag: `scripts/corpus_digest.py` deterministically
  recomputes a `manifest.json` SHA-256 and a whole-directory file-hash-list digest from
  the checked-in bytes, so a reviewer can confirm they are recomputing against the same
  corpus object. The script's output is the normative pin; the scope and values live in
  the [Conformance Guide](docs/conformance-guide.md#v080-draft-02-conformance-corpus-pinning).

### Not in v0.8 (gaps / deferred)

- **Arbitrary server push stays out of strict MCP-S** and fails closed under
  `require_mcps` (ADR-047 / D9); `allow_unverified_server_initiated` remains a
  degraded migration opt-out only, audited as no-evidence.
- **ADR-MCPS-044 (Client-Side Integration Model) stays Proposed.** Both SDKs realize
  it, but its full scope is not yet claimed complete — not overclaiming.
- **ADR-MCPS-046 (Signed Rejection Receipts) stays deferred / design-only.**
- **The TypeScript conformance driver's Cloud KMS path signs via a synchronous
  `curl`** (Node has no native synchronous HTTP, and the napi non-exporting sign
  callback is synchronous); the offline/software path is fully in-process.

## [0.7.0] — 2026-07-02

**End-to-end walkthrough — the v0.7 persona ladder.** v0.7 closes the
"prove v0.7 end-to-end" gap with a real, multi-process MCP-S path: an ordinary
plain-MCP client → `mcps-client-proxy-cli` (signs draft-02, dials mTLS) →
`mcps-proxy` server PEP (verifies draft-02, strips, injects verified context,
serves) → an unmodified inner MCP server, organized as a persona ladder of
runnable tiers (ADR [045](docs/adr/adr-mcps-045.md)).

### Proven in v0.7

- **The real four-hop MCP-S path, offline.** T0/T1/T3 run the full topology as
  separate OS processes over mTLS-on-loopback (`mcps-walkthrough`); the server PEP
  now verifies AND serves draft-02 end to end (version-branched forward +
  protected response; draft-01 path untouched).
- **Scoped authorization, deny-before-dispatch.** A reader's `write_file` is
  refused with `authorization_scope_denied` before the inner server is ever
  reached (T2; the inner's own received-log confirms it across processes at T3).
- **Transport-identity binding (T3).** `--transport-binding exact` ties the
  verified mTLS client identity to the request signer; a mismatched identity is
  denied before dispatch (proven by the inner's own append-only log + zero inner
  spawns), while the same cert passes with binding off — isolating the binding as
  the cause.
- **Client Cloud KMS signer (offline + ignored live lane).** A non-exporting
  `KmsClientSigner` (feature `gcp_kms`) signs through GCP Cloud KMS
  (`EC_SIGN_ED25519`, no algorithm substitution); proven OFFLINE against the
  unmodified `mcps-core` verifier via a no-network fake backend, plus an
  `#[ignore]` live lane.
- **Server Cloud KMS support (existing live lane).** `mcps-proxy --key-source
  GcpKms` continues to sign responses from a non-exporting Cloud KMS key
  (feature `gcp_kms_keysource`, live lanes).
- **Integrated Cloud KMS four-hop — Tier T4 (live, #218).** A single live run
  with the client request signer AND the server response signer BOTH non-exporting
  in Cloud KMS (two distinct keys), over the real mTLS socket. The walkthrough
  harness (`FourHop::launch_kms`, feature `gcp_kms`) fetches both KMS public keys
  to wire trust and drives a signed round-trip end to end; `#[ignore]`d, run from
  the cloud script (command 5). PROVEN against a real Cloud KMS project.
- **Secret-hygiene guard.** A tracked-file leak guard
  (`mcps-walkthrough` `no_tracked_secrets`) asserts no real account/project
  identifier is committed; the live-cloud script stays gitignored behind a
  sanitized committed placeholder.
- **Python SDK — request-side slice (#199).** `mcps-python-sdk` gains request
  signing + custody/signer-policy binding (request side only;
  ADR [044](docs/adr/adr-mcps-044.md)).
- **Multi-SDK test architecture — pluggable client leg.** The four-hop harness's
  client leg is a `ClientDriver` seam: every MCP-S SDK is an interchangeable client
  behind one stdio + CLI contract (`mcps-client-proxy-cli` is the reference), and
  the `sdk_driver_matrix` runs the tiers against each configured driver (skip-not-
  fail). Ready for the upcoming TypeScript/Rust SDKs (`MCPS_DRIVER_*`).
- **Python SDK — live four-hop interop, software AND Cloud KMS.** `mcps_sdk.driver`
  makes the Python SDK a live client leg: it signs via the SDK's audited core, mTLS-
  POSTs to the real `mcps-proxy`, and verifies the server-signed response. Proven
  green in the matrix; and with `--key-source gcp-kms` the Python client signs every
  request with a NON-EXPORTING Cloud KMS key (`Signer.non_exporting` → `asymmetric
  Sign`) across the integrated four-hop (`t4_python_kms_custody`, live, #[ignore]).
  Both the happy path AND the untrusted-server negative are proven cross-language
  through the four-hop: every driver must fail closed when it cannot verify the
  server's response. Surfaced (and fixed) a real cross-language cert defect: the demo
  TLS leaves lacked an Authority Key Identifier — tolerated by rustls, rejected by
  OpenSSL (Python).

### NOT yet claimed in v0.7

- **Signed rejection reasons across the wire.** A client that fails closed cannot
  yet surface the remote's specific reason (e.g. `transport_binding_failed`) — it
  rides an unsigned error body the client rightly distrusts. The fix (signed
  rejection receipts) is designed, not built: ADR
  [046](docs/adr/adr-mcps-046.md).

### Build & test

The **Cargo** workspace is the authoritative, maintained test gate and is fully
green (1104 tests across the workspace, 0 failures). The Cloud KMS lanes and the
live cross-language KMS four-hop are intentionally `#[ignore]`/manual (they require
live cloud credentials). The **Bazel** build has
known, pre-existing **non-gating** `BUILD`-file parity rot — unrelated to this
release — e.g. `//mcps-proxy:mcps_proxy_cli` missing a `//mcps-core:mcps_core`
dep (present already before this epic) and `pkcs11` test-dep gaps; tracked
separately and NOT mixed into this line.

## [0.6.0] — 2026-06-30

**Runtime-evidence preimages — a `draft-02` wire-envelope change.** v0.6
introduces the `draft-02` profile alongside the released `draft-01`/v0.5.1
baseline: two protected envelope identifiers (`version: "draft-02"` and a
self-describing `canonicalization_id`), an explicit canonical-preimage exclusion
predicate, a typed `authorization_binding` object (both `opaque-bytes` and
`authz-system-reference` base forms), nine new fail-closed wire codes, a dual
verifier with strict version dispatch and a required expected-version policy, and
a separate frozen conformance corpus with a static interop oracle.
`draft-01`/v0.5.1 stays byte-for-byte and verdict-for-verdict unchanged.
Resolved in the v0.6 grill (2026-06-29);
ADRs [037](docs/adr/adr-mcps-037.md)–[042](docs/adr/adr-mcps-042.md).

**Scope.** v0.6 ships the draft-02 profile, verifier, authorization-binding
policy wiring, and conformance corpus (including a live Cloud KMS draft-02
envelope lane). The `mcps-host`/`mcps-proxy` production paths still emit and
serve `draft-01`; adopting the draft-02 signing/serving path end-to-end is a
follow-up. The dual verifier exists so both profiles coexist at the verification
boundary during that migration.

### Documented limitation — integer-only canonicalization (`mcps-jcs-int53-json-v1`)

The first `draft-02` canonicalization scheme keeps the integer-only JSON number
domain (±(2^53 − 1)), named `mcps-jcs-int53-json-v1`. **MCP-S v0.6 does NOT
protect a signed payload that contains JSON fractional numbers** —
`{"temperature":0.7}`, `{"price":19.99}`, a latitude — such messages fail closed
with `mcps.canonicalization_failed` unless the value is carried as a string. This
is an intentional, named, machine-checked scope boundary (a required honesty
conformance vector proves `0.7`/`19.99` are rejected), not a defect: full
RFC 8785 fractional-number serialization is the highest-risk cross-implementation
interop surface and is **deferred to a future, separately-named, separately-
vector-hardened `mcps-jcs-…-v2` scheme** admitted through the canonicalization
allowlist — never by widening v1 ([ADR-MCPS-037](docs/adr/adr-mcps-037.md)).

## [0.5.1] — 2026-06-24

**Live Google Cloud KMS validation release.** No wire-envelope changes: this
release proves the already-shipped GCP Cloud KMS adapter against **real** Cloud
KMS and adds a one-command reproduction harness. It is evidence and test surface,
not new protocol mechanism (see
[`docs/security/google-validation-plan.md`](docs/security/google-validation-plan.md)).
The `draft-01` request/response envelopes are unchanged.

### Added

- **Live GCP delegated-TLS test lane**
  (`mcps-proxy/tests/gcp_kms_delegated_tls_live_test.rs`). Proves the proxy's TLS
  *server* private key can live entirely in Cloud KMS and never leave it: the
  server leaf is minted over the KMS **public** key (rcgen `RemoteKeyPair`, no
  private key), and a fully-validating rustls mTLS handshake completes only
  because a live `asymmetricSign` produced the `CertificateVerify`. Negative
  lanes: a leaf not bound to the KMS key is rejected at config construction
  (`DelegatedKeyMismatch`), and an untrusted client certificate is rejected at the
  handshake (fail closed).
- **Object-signing negative lanes** in `gcp_kms_live_test.rs`: wrong-identity (a
  signature must not verify under a foreign key), bad-token fail-closed (an
  invalid access token must fail backend construction), and non-Ed25519 rejection
  (a provisioned RSA key version is rejected at construction, variant-matched).
- **One-command reproduction harness**
  (`docs/security/gcloud-kms-validation.sh`): sanitized, no secrets, `PROJECT_ID`
  placeholder-guarded; enables the KMS API, idempotently provisions the keys, and
  runs both live lanes.
- **First-time Google Cloud onboarding** in the validation plan ("Reproducing
  Stage 1 locally"): the account, billing, project, and `gcloud auth` steps a
  brand-new user needs before running the harness.

## [0.5.0] — 2026-06-23

**Proposal-readiness release over the frozen `draft-01` wire envelope.** 0.5 adds
**zero** wire-envelope fields; request and response envelopes are unchanged. The
work is documentation, conformance, and claim hardening — making every security
claim reviewable and traceable to a green test — not new protocol mechanism. Any
claim `draft-01` cannot support is ejected to a future `draft-02` ADR rather than
smuggled in as a field addition (ADR-MCPS-031, [`docs/spec/proposal-scope.md`](docs/spec/proposal-scope.md)).
Proposal-readiness is gated twice: mechanical CI **and** owner HITL sign-off over
one evidence spine (ADR-MCPS-036; [`security-boundary.md`](docs/spec/security-boundary.md) §10).

### Added — proposal-readiness artifacts

- **ADR-MCPS-031..036 (Accepted).** 031 frames 0.5 as proposal-readiness over a
  frozen `draft-01`; 032 consolidates docs to one canonical boundary + docs root;
  033 defines the two-section v0.5 claim matrix (NSA/threat-coverage matrix
  derived from §A, one evidence spine); 034 makes method-transparency
  CI-enforced; 035 derives the audit-evidence vocabulary from the frozen error
  taxonomy; 036 defines the dual proposal-readiness gate (mechanical CI + owner
  HITL).
- **v0.5 claim matrix** ([`docs/spec/v0.5-claim-matrix.md`](docs/spec/v0.5-claim-matrix.md),
  supersedes the v0.3 matrix): §A per-capability reviewer-facing claims, §B the
  four-axis deployment-tier composition (AND of declared tiers, bounded by the
  weakest).
- **New spec briefs:** [`proposal-scope.md`](docs/spec/proposal-scope.md) (draft-01
  freeze + bind-not-interpret authorization), [`composability.md`](docs/spec/composability.md),
  [`threat-coverage-matrix.md`](docs/spec/threat-coverage-matrix.md); glossary and
  v0.5 grilling seed.
- **Method-transparency is CI-enforced (ADR-MCPS-034):** a behavioral-equivalence
  test plus a static drift guard in `mcps-conformance` (`method_transparency_test`,
  `method_name_drift_guard_test`, `security_traceability_guard_test`,
  `forbidden_claim_guard_test`, `audit_vocabulary_guard_test`).

### Security

- **OCSP DNS-rebinding fix (#128).** The OCSP fetch is pinned to the vetted
  resolved IPs, closing a rebinding window between resolution and connection.
- **OCSP freshness when `nextUpdate` is absent (#136).** Acceptance age is bounded
  by `thisUpdate` + a `max_age` cap instead of being accepted unbounded.
- **Verify-before-return at the remote-signer seams (#137, #138).** PKCS#11 and
  KMS response signing now verify the produced signature before returning it,
  centralized at the response-signer seam.
- **Per-method key-reference scope (#133).** A key reference scopes its target
  per-method; empty-tool grants are rejected.
- **LB-assertion fails closed without a transport binding (#135).** A wired
  load-balancer ingress assertion with no transport binding now fails closed
  rather than admitting.
- **Replay-cache growth bounded (#140).** The file and in-memory replay paths are
  growth-bounded, and durable inline-prune is anchored on a real clock rather than
  request expiry.
- **Non-positive-TTL replay rejected pre-store (MCPS-08, #142).** Requests with a
  non-positive TTL are rejected before the store write, on the etcd backend too.

### Note

Internal version (`VERSION`, workspace `Cargo.toml`) advances from 0.3.1 to 0.5.0.
0.4.0 (below) was tagged retroactively from the hardening-epic history; it carried
no separate release commit, so the source tree at the v0.4.0 tag still declares
0.3.1.

## [0.4.0] — 2026-06-22

**Hardening-epic release (#68).** 0.4 wires the v0.3 tiered multi-node profile from
declared tiers into enforced backends, lands the full audit-remediation cluster
from the v0.4 Stage 1–2 audit round, and purifies MCP-S Core. *Tagged
retroactively* at the first-parent tip of the epic (`09f3250`, just before the 0.5
proposal-readiness work) — the tag was created after the fact, so no release commit
bumps `VERSION`/`Cargo.toml` at this point in history.

### Added — four-axis multi-node profile, wired

- **Axis 1 — LINEARIZABLE CP replay backend (#69).** An etcd-backed CPStore
  replay backend, the concrete realization of the v0.3 `LINEARIZABLE` tier.
- **Axis 2 — near-zero revocation tiers (#70).** Live + push revocation tiers
  wired into the trust resolver, with an injective trust-cache key.
- **Axis 4 — Tier-3 LB-signed ingress assertion (#71).** A request-bound,
  load-balancer-signed ingress assertion, wired into the serve path with
  serve-level acceptance.

### Security & hardening — v0.4 audit remediation

- **Seccomp egress (#98).** `io_uring` egress is denied in the `DenyAll` seccomp
  posture.
- **Production-surface sealing (#81, #83).** Test nonce/clock fixtures are
  feature-gated off the production surface; `VerifiedResult`/`VerifiedResponse`
  are sealed against out-of-band construction.
- **Strict-mode replay durability (#78, #90).** Replay caches self-declare a
  type-level durability class; strict mode rejects a non-durable in-memory cache
  and forbids `inherit-env` together with an env key source.
- **Reference-authz acknowledge gate + epoch-clock diagnosis (#94).**
- **Signed-manifest canonicalization & identity (#85, #87).** Duplicate keys in
  signed manifest bytes are rejected, `key_id` is cross-checked, the validity
  window is skew-tolerant, and inverted windows / unknown wire members are
  rejected.
- **Server read-path deadline (#100).** An aggregate wall-clock deadline on the
  server read path closes a slow-loris exposure.
- **Redis handshake watchdog (#97).** Abandoned Redis connect-handshake watchdog
  threads are bounded.
- **Working-dir TOCTOU (#93).** An explicit `--inner-working-dir` is hardened
  against symlink/TOCTOU with an explicit `O_RDONLY` no-follow open.
- **Key custody (#76).** The unused `Clone` on `SigningKey` is dropped and the
  custody boundary documented.
- **OCSP SSRF guards (#130).** Redirect-follow and empty-label-host SSRF bypasses
  on the OCSP fetch path are closed.
- **Centralized Ed25519 alg gate (#131).** The Ed25519 envelope algorithm gate is
  centralized in Core.

### Changed — Core purification (ADR-MCPS-030)

- The tool-catalog **signed-manifest subsystem is removed from MCP-S Core**; the
  manifest-enforcement design (formerly ADR-MCPS-029) is relocated to MTCI. Core
  is once again pure verification.

### Added — security process

- **Cross-round finding ledger** ([`docs/security/finding-ledger.jsonl`](docs/security/finding-ledger.jsonl)):
  durable per-finding disposition memory so a later audit round verifies only what
  is genuinely new and flags regressions loudly.

## [0.3.1] — 2026-06-21

Security-hardening patch release. No API or wire-format change relative to
0.3.0 — every change is a defensive fix or documentation correction surfaced by
the **Stage 1–2 security-audit funnel** (deterministic pre-scan + 3-lens review,
without the verify gate). Findings were triaged file-by-file: 10 fixed with
regression tests, 3 closed as false positives, and the remaining cluster
deferred to the v0.4 hardening epic (#68) as intentional ADR-MCPS-017
single-node-ceiling posture. The full verified (3-skeptic) scan is scheduled for
v0.4.

### Security

- **OCSP delegated-responder validity window (#95, RFC 6960).** A delegated
  responder certificate presented outside its `notBefore`/`notAfter` window is
  now rejected instead of trusted.
- **Authorization-grant timestamp taxonomy (#88).** An unparseable RFC 3339
  expiry on a delegated grant now fails as `AuthorizationMalformed` rather than
  being misclassified as `AuthorizationExpired`.
- **JCS duplicate-key invariant (#74).** A hand-built `JcsValue::Object`
  containing duplicate keys now fails closed (`CanonicalizationFailed`) rather
  than producing an ambiguous canonical form.
- **Injective trust-resolver composite key (#79).** `InMemoryTrustResolver`
  composes its lookup key with a length-prefixed encoding, removing a
  delimiter-collision class across `(signer, key_id)` pairs.
- **Bounded KMS response reads (#89, #92).** The AWS-KMS response body is read
  under an explicit byte cap (reject only when the length exceeds the cap), and
  GCP-KMS token-expiry arithmetic saturates on overflow instead of panicking.

### Fixed

- **Freshness-window overflow (#82).** Freshness-window expiry uses
  `checked_add`, failing closed instead of panicking on `i64` overflow.
- **Replay prune boundary (#91).** Durable-replay pruning is now inclusive at
  `retain_until` (`>=`), matching the in-memory store and removing a one-tick
  off-by-one retention gap.
- **Response taxonomy precision (#77).** `verify_response` rejects batch and
  notification shapes *before* canonicalization, restoring symmetry with
  `verify_request`.

### Documentation

- Corrected a stale `shared_replay` module doc and documented the
  `sandbox_linux` `try_clone` async-signal-safety caveat (#99, #98).

## [0.3.0] — 2026-06-16

This release adds the **tiered multi-node profile within one trust domain**
(epic #7). v0.2 was production-hardened for single-node deployments; v0.3
makes a *bounded, honest* multi-node claim: each of four security axes declares
a tier, and the composed claim is the **conjunction of the four declared tiers,
bounded by the weakest**. The proxy can never surface a claim stronger than its
configured tier. The enforcement artifacts are
[`docs/spec/v0.3-claim-matrix.md`](docs/spec/v0.3-claim-matrix.md),
[`docs/spec/v0.3-claim-boundary.md`](docs/spec/v0.3-claim-boundary.md), and
[`docs/spec/security-boundary.md`](docs/spec/security-boundary.md), backed by
the conformance manifest and `mcps-conformance` drift guard.

### Added — tiered multi-node claim matrix (the four axes)

- **Axis 1 — replay-store durability (ADR-MCPS-020).** Tiers `REDIS_ASYNC`,
  `REDIS_WAIT_QUORUM`, `LINEARIZABLE` (named; CP backend deferred), and
  `SINGLE_STORE_FAIL_CLOSED`, each surfacing its own honest guarantee.
  Strict-production deployments must declare `REDIS_WAIT_QUORUM` or stronger.
- **Axis 2 — trust propagation / revocation window `T` (ADR-MCPS-021).**
  Bounded-cache eventual trust: revocation enforced fleet-wide within `T`
  (default 60s), fail-closed on store outage past `T`. Zero-window revocation
  is a forbidden claim in v0.3.
- **Axis 3 — signing-key custody (ADR-MCPS-022 / ADR-MCPS-028).**
  `per_node_keyset` (default; tight blast radius) or `shared_remote_signer`
  (one non-exporting KMS/HSM identity). Copying a private key across nodes is
  normatively forbidden in every mode.
- **Axis 4 — ingress / transport binding (ADR-MCPS-023).** `end_to_end_mtls`
  (peer bound to the request signer end-to-end) or `trusted_ingress_asserted`
  (explicitly weakened; ingress in the TCB, authenticated LB↔node hop).

### Added — native cloud-KMS + delegated TLS key custody (ADR-MCPS-028 §B–§G)

- **Native cloud-KMS Ed25519 response signers** — AWS KMS
  (`ECC_NIST_EDWARDS25519`, `ED25519_SHA_512`, `MessageType=RAW`) and GCP Cloud
  KMS (`EC_SIGN_ED25519`), each over a blocking, hand-audited transport
  (SigV4 / OAuth2 + `ureq`), **not** the async vendor SDKs — the ADR-MCPS-018
  lean-sync firewall is preserved. The private key never leaves the KMS.
- **Delegated TLS-server-key custody (§G)** — the TLS server key can also stay
  non-exporting, via the `RawEd25519TlsSigner` seam and a delegated rustls
  certificate resolver, wired across PKCS#11, AWS KMS, and GCP KMS backends.
  Cross-cutting invariants enforced fail-closed: Ed25519-only, cert↔signer
  public-key match at config construction, a TLS credential distinct from the
  object-signing key, and delegated-XOR-exported mutual exclusion.
- **Cloud-KMS live CI lanes** — nightly-real-only (no faithful Ed25519 KMS
  emulator exists), secret-gated and non-blocking, with an anti-gaming hard
  fail; the load-bearing proof is `mcps-core` verifying the signature over the
  exact canonical preimage, never the provider's own `Verify`.

### Added — MCP SEP composition and trust hygiene

- **Replay safety under MCP multi round-trip requests (ADR-MCPS-024, SEP-2322).**
- **Untrusted transport routing headers (ADR-MCPS-025, SEP-2243)** — `Mcp-Method`
  / `Mcp-Name` never assert identity and never influence a security decision, in
  every ingress mode.
- **Signing scope vs. stateless per-request `_meta` (ADR-MCPS-026, SEP-2575).**
- **Extension-identifier reassignment to `se.syncom/mcps` (ADR-MCPS-027).**

### Known limitations — forbidden claims (tracked for v0.4, epic #68)

The composed claim licenses none of the following; each is a deferred tier
named in its ADR and tracked as v0.4 axis-hardening:

- Linearizable / unconditional replay safety (Axis 1 — needs the `CPStore`
  backend).
- Zero-window / instantaneous revocation (Axis 2 — needs live or push tiers).
- Smaller-than-per-node blast radius for a shared signer (Axis 3).
- End-to-end binding under `trusted_ingress_asserted` (Axis 4 — needs the
  LB-signed, request-bound Tier 3 assertion).
- Multi-tenant isolation between distrusting operators, and a hostile-shared-store
  threat model, both remain explicitly excluded from v0.3.

### Build

- Workspace version bumped to `0.3.0` across all crates. Cargo + Bazel still
  coexist; every crate carries both a `Cargo.toml` and a `BUILD.bazel`.

## [0.2.0] — 2026-06-05

This is the **initial public release** of MCP-S. v0.1 existed only inside the
authoring monorepo and was never published as source; it is captured here for
historical accuracy because both the architecture and the security review
process span it.

### Public-release scope

- Apache-2.0 licensed Rust workspace, ten crates:
  `mcps-core` (pure verification), `mcps-host` (client-side ambassador),
  `mcps-transport` (verifying mTLS client), `mcps-proxy` (server-side sidecar
  with TLS termination, OCSP, sandbox, Redis replay, PKCS#11 key sources),
  `mcps-policy` (delegated-authorization profiles, Phase 5),
  `mcps-conformance` (black-box conformance harness), three demo crates
  (`mcps-demo`, `mcps-demo-server`, `mcps-demo-fileserver`), and the test-only
  `mcps-test-paths` helper that lets the same integration tests run under
  Bazel runfiles OR a plain Cargo build.
- 19 architecture-decision records under [`docs/adr/`](docs/adr/) covering the
  trust model, core invariants, transport layering, authorization profile
  abstraction, and Phase 7 external backends.
- Specification briefs under [`docs/spec/`](docs/spec/) including the core
  spec, security boundary, and the upstream-proposal brief intended for an
  eventual MCP SEP submission.
- Two multi-agent Claude Opus 4.8 security audits and a per-finding
  remediation log under [`docs/security/`](docs/security/).

### Added — Phase 6 transport hardening

- **mTLS transport (`mcps-transport`)** — a blocking rustls client that
  presents a client certificate AND verifies the proxy's server certificate +
  identity against a configured server CA, including
  per-socket DoS hardening (read/write timeouts) and an aggregate
  response-read deadline that bounds slow-trickle peers
  (ADR-MCPS-015, [`mcps-transport/src/lib.rs`](mcps-transport/src/lib.rs)).
- **Server-side mTLS termination + identity verification** in `mcps-proxy`
  with configurable identity policies (SAN URI / SAN DNS / CN-legacy),
  exact transport-binding enforcement, and short-lived-cert posture
  (ADR-MCPS-014).

### Added — Phase 5 delegated authorization

- **`AuthorizationProfile` abstraction** with the Reference Signed
  Authorization Profile as the first implementation; policy evaluator runs
  AFTER core verification and BEFORE dispatch
  (ADR-MCPS-013, [`mcps-policy/src/`](mcps-policy/src/)).
- **Per-profile conformance vectors** under
  [`mcps-policy/tests/vectors/`](mcps-policy/tests/vectors/) covering every
  documented allow / deny code (12-token coverage).

### Added — Phase 7 external backends (feature-gated, off by default)

- **`pkcs11_keysource`** — vendor-neutral PKCS#11 backend for the
  response-signing key; key material never leaves the token.
- **`redis_replay`** — Redis-backed shared atomic replay cache for
  horizontally-scaled deployments, with bounded connection/read/write timeouts
  and TTL aligned to clock skew.
- **`online_ocsp`** — RFC 6960 §3.2 OCSP client-cert revocation, including
  full responder-signature trust chain
  (signature + responder identity + CertID binding + freshness + nonce).
- **Linux sandbox enforcement** (Landlock fs allowlists + seccomp egress
  filter), fail-closed on platforms without a kernel backend
  (ADR-MCPS-016 / ADR-MCPS-017).

### Security

This release is the product of two independent multi-agent Claude Opus 4.8
audits, totalling **282 agents and ~14.55M tokens** of review across both
rounds. The full audit reports are committed under
[`docs/security/`](docs/security/), alongside a per-finding remediation log.

- **v0.1 audit (2026-06-01)** — 3 High / 14 Medium / 36 Low / 53 Info,
  0 Critical. Overall residual-risk rating at audit time: **MODERATE**.
- **v0.2 audit (2026-06-02)** — 4 Critical / 15 High / 30 Medium / 59 Low /
  254 Info on the hardening branch. Overall residual-risk rating at audit
  time: **HIGH**.
- **Remediation in this release**: all 4 Critical, all 15 High, and 28 of 30
  Medium findings are **Addressed** with regression tests. The remaining 2
  Mediums (M01/M02 in [`docs/security/remediation-v0.2.md`](docs/security/remediation-v0.2.md))
  are **Deferred to v0.3**; their fail-mode is fail-closed and does NOT admit
  unauthorized requests.

Notable cross-cutting fixes folded in:

- OCSP responder verification rebuilt to enforce signature + identity +
  CertID + freshness + nonce per RFC 6960 §3.2; the single OCSP defect
  surfaced by four audit lenses is closed
  ([`mcps-proxy/src/ocsp.rs`](mcps-proxy/src/ocsp.rs)).
- Manifest pin atomicity (audit H-1) — repository now writes the pin file
  atomically via rename
  ([`mcps-policy/src/manifest_verifier.rs`](mcps-policy/src/manifest_verifier.rs)).
- Redis replay backend (audit H-8 / H-9 / H-10) — bounded connect, read, and
  write timeouts so the single-threaded serve loop cannot hang
  ([`mcps-proxy/src/redis_store.rs`](mcps-proxy/src/redis_store.rs)).
- `--strict` / `--production` postures now reject group/world-readable key
  files and disabled client-cert lifetime enforcement
  ([`mcps-proxy/src/main.rs`](mcps-proxy/src/main.rs),
  [`mcps-proxy/src/cli.rs`](mcps-proxy/src/cli.rs)).

### Build

- Cargo and Bazel coexist by design: every crate carries both a `Cargo.toml`
  and a `BUILD.bazel`, and the workspace is buildable with **either**
  toolchain. Cargo is the public-facing default for OSS contributors;
  Bazel remains the hermetic build path the maintainer uses internally.
- A small `mcps-test-paths` dev-dependency lets the same integration tests
  resolve child-process binaries and data fixtures under Bazel runfiles OR
  a plain Cargo build — see
  [`mcps-test-paths/src/lib.rs`](mcps-test-paths/src/lib.rs).

### Known limitations

- Two Medium findings (`M-01`, `M-02`) remain deferred to v0.3; both relate
  to fail-closed correctness gaps that do NOT admit unauthorized requests.
- Sandbox kernel enforcement (Landlock + seccomp) is Linux-only; on
  macOS / Windows / older Linux the proxy fails closed if
  `--inner-sandbox enforce` is requested (ADR-MCPS-017).
- The crate names and wire formats are explicitly unstable until 1.0; the
  ADR set names the surfaces most likely to evolve.

---

## [0.1.0] — 2026-06-01 (unpublished)

v0.1 is the internal pre-public baseline. It is NOT released as a public
crate or source archive; this entry is recorded so the v0.2 changelog,
audit, and remediation documents have an unambiguous predecessor to refer
to. The v0.1 audit report at
[`docs/security/audit-v0.1.md`](docs/security/audit-v0.1.md) captures the
state of the codebase at this point.

### Highlights

- Pure `mcps-core` verification crate with canonicalization, signature
  verification, replay detection, and the verified-context contract.
- `mcps-proxy` server-side sidecar with stdio transport, response signing,
  and verified-context propagation to an unmodified inner MCP server.
- `mcps-host` client-side ambassador for request signing and bound
  response verification.
- Black-box `mcps-conformance` harness (object + stdio targets).
- 18 ADRs covering the trust model, core invariants, and Phase 1-5 design
  decisions.

### Audit summary

- 3 High / 14 Medium / 36 Low / 53 Info, 0 Critical.
- Residual-risk rating at audit time: **MODERATE**.
- Four findings were partial carry-overs into the v0.2 hardening branch;
  all are closed in v0.2.0 per the
  [v0.2 remediation log](docs/security/remediation-v0.2.md).

[0.3.1]: https://github.com/matssun/mcps/releases/tag/v0.3.1
[0.3.0]: https://github.com/matssun/mcps/releases/tag/v0.3.0
[0.2.0]: https://github.com/matssun/mcps/releases/tag/v0.2.0
[0.1.0]: https://github.com/matssun/mcps/releases/tag/v0.1.0
