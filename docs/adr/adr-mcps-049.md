<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-049: Horizontally-Scaled Fleet Deployment Posture — Lifting the Single-Node Ceiling Over Proven Coherence

## Status

Proposed

## Context

Through v0.10.0 the load-bearing security claim is *"production-hardened for
single-node Rust-native deployments"* — the ceiling set by
[ADR-MCPS-017](adr-mcps-017.md). That ceiling deferred a named list of
enterprise capabilities, each to its own ADR and threat model. Most have since
landed: enterprise key custody (ADR-MCPS-028, live GCP Cloud KMS), online and
offline certificate revocation (Mode A static-CRL + OCSP, v0.9), and
reverse-proxy / ingress mTLS ([ADR-MCPS-023](adr-mcps-023.md) Mode A/C, v0.9 /
v0.10). The remaining deferral from ADR-MCPS-017 is **horizontal scale** — the
one qualifier that no feature removes and that a chokepoint PEP cannot be
deployed without, because no enterprise puts a single, un-redundant policy
enforcement point in the request path.

Three prior ADRs sketched the sub-problems but were each marked "v0.3 sketch"
and none proved a composed, running fleet:

- [ADR-MCPS-020](adr-mcps-020.md) fixed the **durability contract** for the
  shared replay store (`AtomicReplayStore` / `SharedReplayCache`, Redis
  `SET NX PX` and etcd linearizable backends, the `ReplayDurabilityTier` gate).
- [ADR-MCPS-021](adr-mcps-021.md) sketched **cluster trust-state propagation**
  (revocation/rotation across nodes).
- [ADR-MCPS-022](adr-mcps-022.md) sketched **per-node key custody at scale**.

This ADR is the consolidating decision. It does not re-open those contracts; it
defines the **deployment posture** that composes them across every piece of
node-local state, and it fixes the **proof obligation** that must be discharged
before the single-node ceiling of ADR-MCPS-017 is lifted.

A fresh node-local-state audit of `mcps-proxy` grounds the decision. The proxy
is per-request stateless apart from a small, enumerable set of stateful
subsystems; the audit ranked their fleet-coherence hazards:

1. **Replay cache — CRITICAL, fix already in-tree.** The default cache is the
   in-memory reference (`proxy.rs:109`, `proxy.rs:172`); the single-node durable
   file cache (`durable_replay.rs`) is explicitly *not* shareable across
   processes. A nonce admitted on replica A therefore replays successfully on
   replica B unless the operator selects the shared tier — `--replay-cache
   shared` over Redis (`redis_store.rs`, `SET NX PX`) or the etcd cpstore
   (`etcd_store.rs`). The mechanism exists and is proven at unit level
   (`cross_instance_insert_via_a_is_replay_via_b`); what is missing is making the
   shared tier the *enforced fleet minimum* rather than an opt-in.
2. **Persistent inner MCP server — HIGH, structural.** `PersistentSubprocessInner`
   (`persistent_inner.rs:95`) holds a per-node `session: Mutex<Session>` — the
   one-time `initialize` handshake, and whatever inner-server session state a
   given wrapped server keeps (cursors, subscriptions, the MRT D5 `requestState`
   cross-check). Each replica has an independent inner subprocess; there is no
   shared or push mechanism for arbitrary inner state, and none is proposed.
3. **Trust / key-status revocation propagation — HIGH.** The shipping trust
   store is node-local: a JSON keyset loaded at startup (`cli.rs:2359`) plus
   offline revocation-list files (`cli.rs:2476`). The Tier-2 "live"
   (`live_trust.rs`) and Tier-3 "push" (`push_trust.rs`) resolvers are real
   abstractions but ship over an in-process `InMemoryInvalidationChannel` with no
   networked event source (`cli.rs:2413`–`2424`), so a revocation applied on one
   node does not propagate fleet-wide except by restart or by waiting out each
   node's independently-configured bounded window `T`.
4. **Client-cert CRL — MEDIUM.** CRLs are loaded once per node into the rustls
   `WebPkiClientVerifier` (`main.rs:566`, `tls.rs:252`); refreshing a CRL
   requires a process restart. MCPS-66 (issue #246) is the deferred in-process
   reloader and remains per-node even once delivered.
5. **Per-node-keyset response signing — LOW, by design.** Under the
   `per-node-keyset` posture (`authorized_keyset.rs:188`, ADR-MCPS-022) replicas
   sign *responses* with distinct keys; the response audience must be provisioned
   to trust every node's key. Not an inbound-verification hazard.

Confirmed non-hazards: the proxy's MRT/continuation handling is genuinely
stateless — the `continuation` object rides inside the signed draft-02 preimage
([ADR-MCPS-047](adr-mcps-047.md)), so a mid-continuation request re-issued to a
different replica still verifies; the OCSP per-request nonce is ephemeral; and
the KMS/PKCS#11 caches and the inner `next_id` are node-local operational or
internal-correlation state that never crosses the client boundary.

The draft-02 wire envelope is frozen (v0.6.0) and unchanged by this ADR. This is
control-plane and deployment work only — **zero preimage change**.

## Decision

Define a **fleet strict-production profile** for the MCP-S PEP, and lift the
single-node ceiling of ADR-MCPS-017 only for deployments that satisfy it and are
covered by a full-stack multi-replica proof lane. The profile has four
non-negotiable clauses:

1. **Shared replay tier is the fleet minimum.** In fleet strict-production the
   replay cache MUST be a `SharedReplayCache` whose declared `ReplayDurabilityTier`
   meets `meets_strict_production_minimum` (≥ `REDIS_WAIT_QUORUM`, per
   `replay_tier.rs`). Any single-node cache (in-memory or file) MUST fail the
   fleet gate rather than degrade silently.
2. **Inner-server statefulness is declared, and stateful inners require
   affinity.** The proxy carries a self-declared `inner_session` config field
   with values `stateless` (any replica may serve any request) or `stateful`
   (the deployment MUST route a logical session to a stable replica — sticky
   routing). The field **defaults to `stateful`**: absent an explicit operator
   assertion that the wrapped server is session-stateless, MCP-S assumes affinity
   is required and fails toward correctness. The field is auditable and is what
   the deployment reference (W3) keys its routing guidance off. MCP-S ships no
   cross-replica inner-session replication and does not claim it.
3. **Trust/revocation propagation is either networked or a stated bound, and the
   bound is stated per tier.** Fleet strict-production MUST either (a) run a
   networked trust-invalidation backend behind the ADR-MCPS-021 push/live tiers,
   or (b) declare explicit, operator-visible **cross-replica revocation-lag
   bounds — one per tier**. The two tiers have physically different cadences and
   are bounded separately: the **trust key-status bound** equals the
   trust-epoch poll interval (or, without a networked backend, each node's
   bounded window `T`); the **client-cert CRL bound** equals the CRL rollout /
   reload cadence (gated by MCPS-66). When the networked backend is run, it MUST
   be the ADR-MCPS-021 tier trait with **Redis as the first shipped backend using
   a versioned, monotonic trust-epoch key that replicas watch/poll** — not
   fire-and-forget pub/sub (a reconnecting or restarted replica would silently
   miss a one-shot message; an epoch key is pull-based and self-healing). The
   backend reuses the Redis already required for the shared replay tier — no
   second infrastructure dependency — while the tier trait keeps it pluggable, so
   Redis is the first practical backend, not the definition of correctness (the
   ADR-MCPS-020 stance for replay, applied to trust). Zero propagation lag is NOT
   claimed on either tier.
4. **The ceiling lifts only behind proof.** The word "single-node" is removed
   from `PROJECT_STATUS.md` and the one-pager only once a full-stack e2e lane —
   ≥ 2 `mcps-proxy` replicas behind a load balancer over one shared replay store
   — proves, as CI-gated tests: (a) cross-replica replay rejection, (b) a
   trust/revocation change taking effect on a sibling replica within the stated
   bound, and (c) an MRT continuation surviving a mid-continuation replica switch.

Delivery is scoped into four workstreams, which become the issue backlog:

- **W1 — Multi-replica e2e proof lane** (the load-bearing artifact): the
  ≥2-replica + shared-store topology and the three proofs in clause 4.
- **W2 — Close the node-local coherence gaps**: land MCPS-66 (in-process CRL
  reloader) and either a networked trust-invalidation backend or the explicit
  revocation-lag non-claim of clause 3.
- **W3 — Deployment reference + operability**: k8s/Helm reference at N replicas
  with the shared store wired, readiness/liveness probes, graceful connection
  drain on rollout, and a throughput/latency benchmark so the eventual claim
  carries a number, not just a topology.
- **W4 — Retire the non-claim**: update `PROJECT_STATUS.md` and the one-pager to
  state the proven fleet topology, the durability tier, and the revocation-lag
  bound, once W1–W3 land.

## Threat Model

The adversary is unchanged from ADR-MCPS-020/011 (forgery, replay,
authorization stripping, response tampering, channel confusion) with one
scale-specific amplification: **cross-replica replay**. A load balancer that
spreads a captured, already-signed request across replicas defeats replay
defense entirely if replay state is node-local — the classic
"admitted-on-A, replayed-on-B" break (hazard 1). Clause 1 closes it by making the
shared, quorum-durable tier the enforced minimum and failing closed on any
single-node cache. Trust/revocation lag (hazard 3) is a *window*, not a break:
during the stated bound `T`, replicas may disagree on whether a signer is still
trusted; clause 3 makes that window explicit and bounded rather than unbounded
(restart-only). Inner-session affinity (hazard 2) is a correctness/availability
property of the wrapped server, not an MCP-S authenticity property — MCP-S keeps
verifying every call identically on every replica; only application session
continuity depends on routing.

## Rationale

The expensive part — a server-atomic, quorum-durable shared replay primitive
with an honest failure contract — already exists and is proven (ADR-MCPS-020).
The remaining work is composition, coherence closure, and *proof*, not new
cryptographic architecture, which is why a consolidating deployment-posture ADR
(rather than re-opening the sub-contracts) is the right instrument. Making the
shared tier the enforced fleet minimum, rather than a documented option, is the
single change that converts "can be deployed safely" into "cannot be deployed
unsafely" — the honest posture the security-boundary document demands. Declaring
inner statefulness and requiring affinity for stateful inners is the honest
alternative to claiming a cross-replica session-replication feature MCP-S does
not have. Stating a revocation-lag bound, rather than implying zero-window
propagation, matches the project's existing revocation honesty (Mode A/C never
claim zero-window revocation).

## Alternatives Considered

- **Do nothing; stay single-node.** Rejected: leaves the PEP undeployable as a
  redundant enterprise chokepoint — the one gap that caps deployment topology
  regardless of feature completeness.
- **Fold horizontal scale into the existing sketch ADRs (020/021/022).**
  Rejected: those fix sub-contracts; none owns the composed deployment posture or
  the cross-cutting proof obligation, and none can lift the ADR-MCPS-017 ceiling
  on its own.
- **Ship cross-replica inner-session replication.** Rejected for this ADR:
  replicating arbitrary wrapped-server session state is a per-server, unbounded
  problem outside the MCP-S trust boundary; sticky routing is the bounded,
  honest answer.
- **Claim zero-window fleet revocation via a mandatory networked backend.**
  Rejected as a *requirement*: it would over-claim and force infrastructure on
  small deployments; offered as clause-3 option (a), with the explicit bound as
  the honest default (b).
- **Let the shared tier stay opt-in with documentation only.** Rejected: a
  silent default to a single-node cache in a multi-replica deployment is exactly
  the CRITICAL hazard; the fleet gate must fail closed.

## Consequences

### Positive
- The claim can honestly become *horizontally-scaled production-hardened* with a
  stated durability tier and a stated revocation-lag bound — retiring the
  "single-node" qualifier that has capped the project since ADR-MCPS-017.
- No wire change: draft-02 preimage is untouched, so existing clients, SDKs,
  conformance vectors, and the four-hop matrix are unaffected.
- The critical cross-replica-replay hazard becomes un-triggerable in strict
  production (fail-closed gate), not merely documented.

### Negative
- Stateful inner servers are affinity-bound: deployments must run sticky routing,
  a real operational constraint MCP-S does not remove.
- Fleet strict-production requires external infrastructure (a quorum-durable
  shared store; optionally a networked trust-invalidation backend), raising the
  minimum deployment footprint above single-node.
- Revocation is not zero-window across the fleet; operators inherit a bounded lag
  they must configure and accept.

### Neutral
- MCPS-66 (CRL reloader) and the trust-invalidation backend graduate from
  "someday" to scoped W2 issues.
- The `per-node-keyset` response-signing posture (ADR-MCPS-022) is unchanged; the
  audience-trusts-all-node-keys requirement is restated, not altered.

## Compliance and Enforcement

- **Fleet gate (clause 1):** a strict-production fleet configuration MUST reject
  any replay cache whose declared tier fails `meets_strict_production_minimum`;
  this is a fail-closed startup check, not a warning.
- **Proof lane (clause 4):** the ≥2-replica e2e lane and its three assertions
  are CI-gated tests; the "single-node" non-claim may not be edited out of
  `PROJECT_STATUS.md` / the one-pager until they are green (mirrors the
  ADR-MCPS-017 security-boundary release gate).
- **Honesty (clause 3):** the security-boundary document states the
  cross-replica revocation-lag bound verbatim, alongside the existing
  zero-window-revocation non-claim.
- Inner-session affinity (clause 2) is documented in the deployment reference
  (W3); there is no code-level enforcement of sticky routing — that is a known,
  stated operator responsibility.

## Related

- Supersedes the single-node ceiling of [ADR-MCPS-017](adr-mcps-017.md) for
  deployments meeting the fleet strict-production profile (ADR-MCPS-017 remains
  authoritative for single-node deployments).
- Consolidates: [ADR-MCPS-020](adr-mcps-020.md) (replay durability contract),
  [ADR-MCPS-021](adr-mcps-021.md) (cluster trust propagation),
  [ADR-MCPS-022](adr-mcps-022.md) (per-node key custody).
- Composes with: [ADR-MCPS-023](adr-mcps-023.md) (ingress Mode A/C),
  [ADR-MCPS-047](adr-mcps-047.md) (stateless MRT continuation — the property that
  keeps continuations replica-independent).
- Code: `mcps-proxy/src/{proxy,shared_replay,redis_store,etcd_store,replay_tier,
  live_trust,push_trust,trust_cache,persistent_inner,tls}.rs`.
- Follow-ups: MCPS-66 (issue #246, in-process CRL reloader); Redis-backed
  trust-epoch invalidation behind the ADR-MCPS-021 tier trait (W2); multi-replica
  e2e lane (W1); k8s/Helm deployment reference + benchmark (W3).

## Resolved Design Questions

The three questions raised in review are resolved as follows and folded into the
Decision above.

- **Backend for W2 trust invalidation — pluggable trait, Redis first, epoch not
  pub/sub.** The ADR-MCPS-021 tier trait remains the contract; Redis is the first
  shipped backend, reusing the replay Redis (no second dependency). The mechanism
  is a versioned, monotonic **trust-epoch key** that replicas watch/poll, chosen
  over pub/sub because pub/sub is fire-and-forget — a reconnecting or restarted
  replica would silently miss an invalidation, whereas an epoch key is pull-based
  and self-healing (on any doubt a node reads the current epoch and reconciles).
  This mirrors the ADR-MCPS-020 stance: Redis is the first practical backend, not
  the definition of correctness.
- **Revocation-lag bound — per tier, two numbers.** Trust key-status and
  client-cert CRL have physically different cadences (seconds via epoch poll vs
  the CRL `nextUpdate`/reload cadence), so each is bounded and stated separately.
  A single knob would either loosen the trust bound artificially or over-promise
  CRL freshness.
- **Sticky-routing declaration — yes, a self-declared `inner_session` field,
  default `stateful`.** The field is auditable and drives the deployment
  reference's routing guidance; defaulting to `stateful` fails toward correctness
  (affinity assumed unless the operator asserts a stateless inner).
