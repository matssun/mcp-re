<!-- SPDX-License-Identifier: Apache-2.0 -->

# Root-family design packet — the five ruled-in completeness areas

```
STATUS:  DESIGN PACKET — ADR-MCPRE-059 §28
         NON-NORMATIVE. Proposes a decomposition; establishes nothing.
         Temporary node identifiers only. No THM allocated, no root declared.
```

**Authority.** Owner completeness rulings 1–5 of 2026-08-31
([`../rulings/owner-completeness-rulings-2026-08-31.md`](../rulings/owner-completeness-rulings-2026-08-31.md)),
under the security-claim boundary ratified 2026-09-01
([`../../../docs/spec/security-boundary.md`](../../../docs/spec/security-boundary.md) §4).

**Measured against** `main @ e6496173`.

Node names `D1`, `D1.1`, … are handles for this review and appear nowhere else. A node that
earns permanent identity gets a `THM-NNNN` only after ratification, and only then.

---

## 0. Altitude first: the ruling named five areas, not five roots

The ruling asked for the five areas; it did not say each needs a root. Determining altitude
before proposing nodes is the whole of §1, because the failure it prevents is the expensive
one: a new root is a new top-level security promise, and one minted where a child would do
makes the root set look like a list of subsystems rather than a set of independent promises.

The test applied to each area, in order:

1. **Is there a proposition here that no existing root's statement already quantifies over?**
   If an existing root's promise is simply *false* in a case this area covers, the area is a
   child of that root, not a peer of it.
2. **Can a deployment run this area without the candidate parent, or the parent without it?**
   Mutual independence is what makes two propositions peers. THM-0075 and THM-0076 are
   separate roots for exactly this reason — a deployment may run either side alone.
3. **Does an honest semantic owner exist for it in the tree today?** An architecture gap is
   a claim to *measure*, not to assert. Two of the five turned out to have real authorities
   that merely lack a `[[unit]]`.

### Verdict table

| # | area | altitude | why |
|---|---|---|---|
| 1 | Replay / continuation store durability | **EXISTING_ROOT_EXTENSION** (two children: THM-0077, THM-0074) | not independent of either parent — a store is *selected posture* and *a dispatch precondition*; a deployment cannot run "the store promise" alone |
| 2 | Retained-evidence correspondence | **REOPENED_BRANCH** (THM-0042) | the root exists and is declared; its statement is corrected and its review is `STALE_CLAIM`. Nothing new is minted |
| 2b | Retained-evidence reservation fidelity | **EXISTING_ROOT_EXTENSION** (THM-0074, with a refusal-side relation to THM-0078) | a marker's legality is a fact about the *execution threshold*, which is the dispatch root's subject |
| 3 | Outbound credential acquisition | **EXISTING_ROOT_EXTENSION** (THM-0077) | materialization: the deployment reaches only the authority it selected. Not a peer promise — it is what "the posture it selected" *means* for a credential |
| 4 | Client-sidecar local ingress | **NEW_ROOT** | passes test 2 in both directions: the sidecar runs with no MCP-RE proxy in the deployment, and every existing root holds with the sidecar absent |
| 5 | Python / TypeScript exchange paths | **ROOT_FAMILY_MEMBER** ×2, under a family whose Rust member is THM-0076 | independently implemented boundaries; a common implementation theorem would be a claim about neither |

**Three of five need no new root.** That is the result of the altitude pass, not a shortcut
through it.

---

## 1. Area 1 — replay / continuation store durability

Two propositions, not one, and they belong under different parents. Folding them would
produce a node whose answer to *what single security fact does this own?* needs an "and".

### D1 — the materialized tier is the tier that was selected

`EXISTING_ROOT_EXTENSION` — child of **THM-0077** (no unselected posture).

- **Proposition.** For every started deployment, the replay and continuation stores the
  serving path uses are the tier the validated configuration selected, at the durability the
  tier advertises; a tier that cannot be established prevents startup rather than being
  silently substituted.
- **Security consequence.** An operator who selected a shared, durable replay tier cannot be
  served by a local in-memory one. The failure this excludes is not a crash: it is a
  deployment that believes it has cross-replica replay protection and has per-process
  protection, which is the exact shape of the single-node claim ceiling the historical
  boundary was written around.
- **Scope / non-claim.** Says nothing about whether Redis or etcd is *itself* correct, or
  about availability. Tier fidelity, not tier quality.
- **Owner.** `mcp-re-proxy/src/replay_plane/` — a real authority today, with a documented
  materializer contract, and no `[[unit]]`. `continuation_store/` is its sibling for the
  continuation half.
- **Parent / dependencies.** THM-0077; consumes THM-0037 (trust plan) and THM-0013 shape.
- **Reusable.** `replay_tier.rs`, `shared_replay.rs`, the `async_replay` backends and their
  existing tests; the ADR-MCPRE-056 §6 materialization argument already written in the
  module doc.
- **Required new proposition.** That the plan→plane relation is total and injective on the
  selected tier — today the argument is prose in the materializer, not a stated claim.
- **Assumptions.** Will need a registered premise over the Redis/etcd client libraries'
  reported success, in the shape of ASM-0033 (a mechanism faithfully reports what it did).
  None exists yet.
- **R9 disposed.** None directly; this closes an *omission*, which is why the audit found it
  by boundary-action enumeration rather than by finding.

### D2 — a store that cannot establish its state prevents dispatch

`EXISTING_ROOT_EXTENSION` — child of **THM-0074** (no unearned dispatch).

- **Proposition.** Where the selected tier is unavailable, or cannot durably establish the
  replay or continuation state a request requires, the exchange does not dispatch.
- **Security consequence.** Replay admission cannot degrade to *fail-open on infrastructure
  trouble*. This is the direction that matters: an unavailable store must not become an
  admitted request.
- **Scope / non-claim.** Not availability, not latency, not a retry policy. It says the
  refusal happens, not that the deployment stays useful.
- **Owner.** `proxy.dispatch_commitment` already owns the pre-dispatch commitment; the store
  arm is the new part and sits with the replay plane's projection.
- **Parent / dependencies.** THM-0074; relates to THM-0045 (retention reservation ordering).
- **Reusable.** THM-0009, THM-0053 and the admission chain under THM-0074.
- **Required new proposition.** The fail-closed direction, stated over the *tier*, not over
  a particular backend's error type.
- **Assumptions.** Shares D1's mechanism premise.
- **R9 disposed.** None open; recorded because the ruling put it here.

---

## 2. Area 2 — retained evidence: one reopened branch, one extension

### D3 — retained-evidence correspondence (REOPENED)

`REOPENED_BRANCH` — **THM-0042**, already a declared root. No new node.

The statement was corrected on `main` and the specification review is consequently
`STALE_CLAIM`. What remains before it can return to boundary §2:

- **Residual gap, measured and still open: R9-C074 / R9-C075.**
  `submitted_commitment` digests method, target URI, status, both bodies, and *only the
  `signature` header*. `signature-input` is not covered. For the UNVERIFIED tail — the only
  part this field exists to bind — two hops differing solely in `signature-input` (a
  different `created`, a different covered-component set, a different keyid) produce the
  same submission identity. Nothing verifies those hops, so nothing else catches it. **The
  tail substitution the field was added to close is therefore still open in one dimension.**
  This must be fixed before the branch closes; widening the digest is a change to what an
  identity *is*, so it is a proposition, not a patch.
- **Evidence gap.** The `s01` corpus cannot evidence this claim at all (its artefact records
  handles, not messages). A corpus from a real signed multi-hop exchange is required. This
  is corpus generation, not verifier work, and it is the long pole.
- **R9 disposed by work already merged:** R9-C029, R9-C084, R9-C105, R9-C115 (both-empty
  `Ok`) — closed by the statement correction; R9-C035, R9-C065, R9-C104 (corpus fabrication
  and staleness) — closed by `from_retained_handles` plus the in-place demotion.
- **R9 still open here:** R9-C074, R9-C075, R9-C103, R9-C128 (zero-verified-hop records
  issued with no self-check).
- **Not in this branch:** R9-C085/C086/C098/C102/C112 are THM-0068 (pin `position_profile`),
  a different claim under THM-0072.

**No node is proposed.** Reopening is not redesign, and the ratification established nothing
here by declaration.

### D4 — a retention marker exists only under its execution threshold

`EXISTING_ROOT_EXTENSION` — child of **THM-0074**, with a refusal-side relation consumed by
**THM-0078**.

- **Proposition.** A `.pending` retention marker exists at an instant only if the exchange it
  names has crossed the execution threshold its semantic owner defines; a pre-dispatch
  failure leaves no marker readable as executed work.
- **Security consequence.** A durable marker is an assertion that the deployment became
  answerable for a call. A marker for a call that provably never reached a backend makes the
  retained record a source of false positives exactly where an auditor trusts it most —
  and unlike a missing record, a spurious one cannot be distinguished from a real one after
  the fact.
- **Scope / non-claim.** Not that the record's *contents* are correct (that is
  `retained_record`'s and THM-0042's), and not that the write succeeded (that is the
  durability barrier). Existence and threshold only.
- **Owner.** `mcp-re-proxy/src/transparency/durability.rs` — a real authority with an
  explicit "WHEN responsibility has been durably established" contract, and no `[[unit]]`.
  `retained_record.rs` is the separate WHAT owner and stays separate.
- **Parent / dependencies.** THM-0074; THM-0045 (reservation is the last pre-dispatch
  refusal) is the existing edge to reuse; the rescind relation is consumed by THM-0078.
- **Reusable.** THM-0045 and the ordering argument in `durability.rs`'s module doc; the
  bounded-queue argument in `durability_bounds.rs`.
- **Required new proposition.** The *release* half. Today the ordering is established and
  the undo is not: `release_before_dispatch()` and `pending_reservations()` exist and have
  **no production caller**. A proposition that a marker is rescinded is not evidenced by an
  API that could rescind it.
- **Assumptions.** A filesystem durability premise will be needed for the barrier; none is
  registered.
- **R9 disposed.** R9-C004 and R9-C021 (high — `NotDispatched` and ladder-reorder marker
  leaks), R9-C081 (inner-plane saturation at dispatch), R9-C078/C079/C080 (both retention
  APIs unwired), R9-C099 (a failed `reserve()` can leave a credential-bearing marker no
  path can clear). **Seven, including two High.**

---

## 3. Area 3 — outbound credential acquisition

### D5 — a credential-bearing outbound call reaches only the selected authority

`EXISTING_ROOT_EXTENSION` — child of **THM-0077** (materialization).

- **Proposition.** Every outbound request that carries a credential, a bearer token or a
  workload identity — KMS, STS, instance metadata, remote signer — is issued to the
  authority the validated configuration selected for that capability, where the authority is
  the one the client will actually reach, not the one the configured text appears to name.
- **Security consequence.** The threat is not misconfiguration, it is *redirection*: an
  endpoint whose literal spelling names one host and whose machine interpretation names
  another sends the pod's IRSA token, or the root-key trust bootstrap, to an attacker. R9's
  single Critical was exactly this.
- **Scope / non-claim.** Says nothing about what the remote authority does with the
  credential, nothing about token lifetime or refresh correctness, and nothing about
  availability of the acquisition path.
- **Owner.** `mcp-re-proxy/src/kms_endpoint_policy/` — a real, fully documented authority
  that already states the invariant ("accepted only when its literal human-readable
  representation and the machine interpretation used by the client agree") and owns the rule
  rather than its callers. **It lacks a `[[unit]]` and nothing else.** This is the clearest
  case of the audit's "an architecture gap needs a measurement" result.
- **Parent / dependencies.** THM-0077; THM-0064 (custody exposure) is adjacent and must not
  be re-derived here.
- **Reusable.** `authority.rs`'s `check_host` / `check_port` predicates and their tests;
  `config_state/kms_endpoint.rs`.
- **Required new proposition.** Coverage: that *every* credential-bearing egress consults
  this authority. Today the rule is owned but its application is per-call-site, which is the
  R-SEAL shape — the check is a deletable statement at each site.
- **Assumptions.** A premise over the HTTP client's authority resolution matching the
  policy's interpretation. None registered; this is the load-bearing one and it should be
  narrow.
- **R9 disposed.** R9-C001 (**critical**), R9-C017, R9-C018, R9-C031, R9-C092 — already
  FIXED, but currently mapped to a node that does not exist as a unit, so the fix is
  unrooted. Bringing the owner into the graph is what makes those five *covered* rather than
  merely *fixed*.
- **Deliberately excluded.** R9-C057/C058/C059/C107 (metadata single-flight stalls) are
  availability, not this proposition. They are real defects and belong to ordinary
  engineering, not to this branch. Naming them here so the exclusion is a decision rather
  than an omission.

---

## 4. Area 4 — client-sidecar local ingress

### D6 — the local ingress admits only a caller the operator selected

`NEW_ROOT` — the only one proposed.

- **Proposition.** A security-bearing outbound MCP-RE exchange is initiated by the sidecar
  only for a local request whose origin the deployment selected; a request reaching the
  listener from an origin the operator did not select does not become a signed outbound
  exchange.
- **Security consequence.** The sidecar signs with the agent's key. An unrelated web page
  in the user's browser that can reach the loopback listener — via DNS rebinding, or simply
  because the listener answers any `Host` — obtains signed, attributed MCP-RE calls made
  under someone else's identity. No existing root excludes this: THM-0076 is about what a
  client *accepts as an answer*, and the attack is complete before any answer exists.
- **Scope / non-claim.** Not authentication of the local caller (there is none, and none is
  claimed); not confidentiality of the local leg; not a claim about anything the sidecar
  does after admission, which is THM-0076's.
- **Why NEW_ROOT and not a THM-0076 child.** Both directions of the independence test pass.
  The sidecar runs against a deployment with no MCP-RE proxy at all, so its ingress
  proposition holds where THM-0076's producer side is absent; and every current root holds
  in a deployment with no sidecar. Folding it under THM-0076 would also put an *ingress*
  fact under a root whose subject is *response acceptance* — two authorities under one
  promise, which is the shallow boundary the twelve questions exist to catch.
- **Owner.** `mcp-re-client/src/serve/head_fields.rs` (the caller-shape and loopback-`Host`
  check) with `serve/request.rs`. A real authority; no `[[unit]]`.
- **Parent / dependencies.** None — it is a root. Consumes `client.trust_manifest_lifecycle`
  for what the sidecar is configured to be.
- **Reusable.** The existing `is_loopback_host` check and `local_leg_e2e_test.rs`.
- **Required new proposition, and the defect it must fix.** **R9-C096 is a live conflation:**
  `allow_any_host: config.local.allow_non_loopback` makes one operator flag govern two
  independent facts — *where the listener binds* and *whether the rebinding guard runs*. An
  operator who legitimately binds non-loopback thereby disables the `Host` guard, and a
  deployment that sets the flag for the bind reason gets the guard removed silently. Two
  facts, one input: the proposition cannot be stated honestly until they are separated.
- **Assumptions.** None foreign expected; this is MCP-RE-owned throughout.
- **R9 disposed.** R9-C096 (the conflation), R9-C127 (the local-leg contract not updated
  when `Content-Type` and loopback `Host` became required). R9-C062/C063 (`bound` dropped
  from the rejection handed to the local client) sit on the THM-0076 side and are named here
  only so the split is explicit.

---

## 5. Area 5 — the supported-client root family

### D7 / D8 — the Python and TypeScript exchange paths

`ROOT_FAMILY_MEMBER` ×2. The family's existing member is **THM-0076** (Rust `ClientProxy`).

- **Proposition (per member).** For the shipped `<language>` SDK, an application is not
  handed, as this call's answer, a response from another exchange or signer, or one that
  verified only unbound — and is not led to repeat a side effect by reading silence as *it
  did not run*.
- **Security consequence.** Identical in words to THM-0076 and *not* implied by it. The
  boundary is implemented independently in each language, so the Rust proof establishes
  nothing about the Python or TypeScript path.
- **Scope / non-claim.** Per-implementation. A member says nothing about its siblings.
- **Why two members and not one language-neutral theorem.** A single implementation theorem
  would be a claim about no shipped artefact. The measured evidence for this is direct: the
  byte-level parity fixtures are green while the implementations *diverge behaviourally* —
  Python's `send_notification_verified()` runs outside the concurrency bound its TypeScript
  twin enforces (R9-C061, C109, C110), and the two disagree about what a response deadline
  bounds (R9-C095 total download vs idle). A theorem quantifying over "the SDK" would be
  true of neither.
- **Owner.** No Rust `[[unit]]` can own these; the source is `sdk/python/python/mcp_re_sdk/`
  and `sdk/typescript/src/`. **This is the one area where the unit model itself is the
  obstacle**, and it is a real one: a review unit's fingerprint is built from Cargo packages
  and Rust test selectors. Resolving that is a prerequisite, not a detail — see §6.
- **Parent / dependencies.** Family peers of THM-0076; each depends on the profile-level
  claims THM-0057…THM-0061 that are language-independent facts about the wire.
- **Reusable.** `test_parity.py` and the TypeScript twin; the existing per-language transport
  and correlation suites.
- **Required new proposition.** For each member, that its deadline and concurrency semantics
  are the ones its claim rests on — the divergences above are not incidental, they are the
  claim.
- **Assumptions.** Per-language runtime premises: `http.client`'s read semantics for Python
  (R9-C010/C011/C019/C020/C049 all turn on `read(n)` blocking until `n` bytes), and the
  `AbortSignal`/fetch semantics for TypeScript. Neither is registered.
- **R9 disposed.** All ten `sdk-client-exchange` clusters, including four High, plus
  R9-C093 (`retry_is_refused()` treating an UNRECOGNIZED `execution_status` as silence,
  which is THM-0061's neighbourhood).

---

## 6. What must be settled before any of this is encoded

Stated because a design packet that hides its own prerequisites produces a work plan that
stalls at the first one.

1. **The SDK members need a unit model that can hold them.** A `[[unit]]` today is measured
   through Cargo packages, Rust test selectors and `crate_features`. D7/D8 have none of
   those. Either the manifest grows a non-Rust unit kind with its own fingerprint components,
   or the family's non-Rust members cannot be evidenced at all — and an unevidenceable root
   is worse than an absent one, because it reads as coverage.
2. **Five of the six proposed nodes have owners with no `[[unit]]`.** Four of those owners
   are real, documented authorities today (`replay_plane`, `transparency/durability`,
   `kms_endpoint_policy`, `mcp-re-client/src/serve`). Declaring the units is mechanical;
   deciding their `paths` and evidence is not.
3. **Three new assumption families will be needed** — store-mechanism reporting, filesystem
   durability, and per-language runtime semantics. Each should be narrow and separately
   registered; none should be widened from an existing entry, which is what ruling A already
   had to undo once.
4. **D6 cannot be stated until R9-C096 is fixed.** The conflated flag makes the proposition
   unstatable, not merely unproven.
5. **THM-0042's branch is gated on corpus generation**, which is the longest single item
   here and is not verifier work.

## 7. What this packet does not do

No `THM-NNNN` is allocated. `root_theorems` is untouched. No specification-review record is
written. No graph is implemented. Nothing here is established, and the §4 rows of the
ratified boundary stay exactly where the ratification left them.

The next boundary is an owner ruling on §0's altitude table and on the six proposed nodes.
