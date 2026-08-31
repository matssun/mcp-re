<!-- SPDX-License-Identifier: Apache-2.0 -->

# Root-family design packet — the five ruled-in completeness areas

```
STATUS:  DESIGN PACKET — ADR-MCPRE-059 §28
         NON-NORMATIVE. Proposes a decomposition; establishes nothing.
         Temporary node identifiers only. No THM allocated, no root declared.
         Altitude table RATIFIED 2026-09-01; node statements corrected below.
```

**Authority.** Owner completeness rulings 1–5 of 2026-08-31, and the owner ruling of
2026-09-01 that ratified this packet's altitude pass and corrected six node statements.
Under the claim boundary ratified 2026-09-01
([`../../../docs/spec/security-boundary.md`](../../../docs/spec/security-boundary.md) §4).

**Measured against** `main @ 11a3a83f`.

Node names `D1`…`D10` are handles for this review and appear nowhere else.

---

## 0. Altitude — ratified

| # | area | altitude |
|---|---|---|
| 1 | Replay tier fidelity | **EXISTING_ROOT_EXTENSION** — D1a under THM-0077 |
| 1 | Continuation tier fidelity | **EXISTING_ROOT_EXTENSION** — D1b under THM-0077 |
| 1 | Replay establishment fail-closed | **EXISTING_ROOT_EXTENSION** — D2a under THM-0074 |
| 1 | Continuation establishment fail-closed | **EXISTING_ROOT_EXTENSION** — D2b under THM-0074 |
| 2 | Retained-evidence correspondence | **REOPENED_BRANCH** — THM-0042. No node minted |
| 2b | Retention reservation state relation | **EXISTING_ROOT_EXTENSION** — D4 under THM-0074, rescind relation consumed by THM-0078 |
| 3 | Credential egress authority | **EXISTING_ROOT_EXTENSION** — D5 under THM-0077 |
| 4 | Sidecar local ingress | **NEW_ROOT** — D6 |
| 5 | Python exchange path | **ROOT_FAMILY_MEMBER** — D7 |
| 5 | TypeScript exchange path | **ROOT_FAMILY_MEMBER** — D8 |

### One new root SHAPE, three new declared roots

Stated because the earlier revision of this packet blurred it. If D6, D7 and D8 are
established as designed, **all three become entries in `root_theorems`** — the declared root
set goes from nine to twelve.

Only **D6 is a new root shape**: a top-level security promise of a kind the system did not
previously make. D7 and D8 are two new *implementation-specific members* of the
supported-client family whose shape THM-0076 already established. "One new root" is true of
the shape and false of the count, and the count is what `root_theorems` holds.

---

## 1. Area 1 — four leaves, not two

The parent may quantify over replay and continuation together. A leaf may not, because
`replay_plane/` and `continuation_store/` are sibling authorities and neither owns the
other's facts. Putting the joint on whichever leaf existed first is the shallow-boundary
move the twelve questions exist to catch.

There is a second split inside each leaf, and it is the one that decides where an external
premise is needed:

```text
selected tier IS what was materialized          ← configuration projection. MCP-RE-owned.
                                                   needs NO external mechanism premise.
that mechanism's reported success establishes   ← external fact. Needs a narrow,
its advertised durable effect                      mechanism-specific premise.
```

D1a/D1b claim only the first. The second is a separate obligation, and it is where Redis and
etcd stop being interchangeable.

### D1a — the materialized replay tier is the selected replay tier

`EXISTING_ROOT_EXTENSION` — child of **THM-0077**.

- **Proposition.** For every started deployment, the replay store the serving path uses is
  the tier the validated configuration selected; a tier that cannot be established prevents
  startup rather than being substituted.
- **Security consequence.** An operator who selected a shared replay tier cannot be served
  by a per-process one. The excluded failure is not a crash — it is a deployment that
  believes it has cross-replica replay protection and has process-local protection.
- **Scope / non-claim.** Projection only. Says nothing about whether the backend's
  acknowledgement means what the backend documents, nothing about availability.
- **Owner.** `mcp-re-proxy/src/replay_plane/` — real authority, documented materializer
  contract, **no `[[unit]]`**.
- **Parent.** THM-0077. Consumes THM-0037 (trust plan).
- **Reusable.** `replay_tier.rs`, `shared_replay.rs`, the ADR-MCPRE-056 §6 argument already
  in the module doc.
- **Required new proposition.** That the plan→plane relation is total and preserves the
  selected tier. Today it is prose in the materializer.
- **Assumptions.** **None.** This is the point of the split: a configuration-projection
  claim does not need a backend-behaviour premise, and giving it one would widen a blast
  radius the claim does not use.
- **R9 disposed.** None. Closes an omission the boundary-action enumeration found.

### D1b — the materialized continuation tier is the selected continuation tier

`EXISTING_ROOT_EXTENSION` — child of **THM-0077**. As D1a, owned by
`mcp-re-proxy/src/continuation_store/`, with `redis_continuation_store.rs` as the shared-tier
arm. Separate node because separate owner; identical shape, no shared representation.

### D2a / D2b — a store that cannot establish required state prevents dispatch

`EXISTING_ROOT_EXTENSION` ×2 — children of **THM-0074**, one per mechanism family.

- **Proposition (per store).** Where the selected tier cannot durably establish the replay
  (resp. continuation) state a request requires, the exchange does not dispatch.
- **Security consequence.** Replay admission cannot degrade to fail-open on infrastructure
  trouble. An unavailable store must not become an admitted request.
- **Scope / non-claim.** Not availability, not latency, not retry policy.
- **Owner.** The dispatch-side owner is `proxy.dispatch_commitment`; each store's
  establishment projection is its own plane's.
- **Reusable.** THM-0009, THM-0053 and the admission chain under THM-0074.
- **Assumptions.** **Here** the external premise is needed, and separately per mechanism:
  what a Redis `WAIT` acknowledgement establishes is not what an etcd transaction success
  establishes, and neither is what a filesystem `fsync` establishes. Three narrow premises,
  registered only where a root actually consumes the fact. No "the client library reports
  success faithfully" umbrella.
- **R9 disposed.** None open.

---

## 2. Area 2 — retained evidence

### D3 — THM-0042, reopened. Identity, not a field list

`REOPENED_BRANCH`. No node minted; the root is declared and its review is `STALE_CLAIM`.

The measured gap: `submitted_commitment` digests method, target URI, status, both bodies,
and **only the `signature` header**. `signature-input` is absent. For the unverified tail —
the only part the field exists to bind — two hops differing solely in `signature-input` (a
different `created`, a different covered-component set, a different keyid) share a submission
identity.

**This is not closed by appending `signature-input` to the recipe.** A hand-maintained field
checklist has already failed once; the same defect recurs the next time a security-bearing
field is added and nobody remembers the digest. What is missing is the semantic value:

```text
SubmittedHttpHop
    method / status
    target
    body
    signature-input
    signature
    the header values Signature-Input's covered components NAME
    every other retained fact the correspondence claim treats as part of the hop
          ↓  closed canonical representation
SubmittedHopCommitment
```

The invariant to establish:

> Two retained submitted hops that differ in any fact the correspondence claim treats as
> part of the submitted hop have distinct commitment preimages.

Note the recursive obligation the ruling names: `signature-input` *names covered components*.
If those components refer to header values not otherwise represented in the commitment, those
values are part of the hop's identity too. A digest over `signature-input`'s text alone does
not discharge it.

**Omission must be mechanically hard.** Adding a field to the canonical representation has to
force the commitment implementation and its controls to account for it — a struct the digest
destructures exhaustively, not a function that reads the fields it remembers. Mutation
controls then alter every field of the closed representation and require the commitment to
move.

**The corpus must be a NEW artefact, not a regenerated `s01`.** Measured while planning the
execution order, and it changes what step 1 means. `interop/manifest.json` records
`produced_by: "@transmute/cose 0.3.0 + node crypto Ed25519"`, and the test's own framing
states the point: *"No MCP-RE code produced any of it."* That is the entire value of an
interop vector. Regenerating `s01` to carry submitted messages would replace a third-party
artefact with this project's own opinion and destroy the receipt/statement/pin
interoperation it genuinely does evidence — while gaining nothing, since a corpus MCP-RE
produced cannot demonstrate that a foreign implementation reads our statements.

So: `s01` stays exactly as it is, demoted in place and evidencing what it evidences. THM-0042
needs a **separate, MCP-RE-produced multi-hop corpus** from a real signed exchange, written
by an explicit golden writer in the established `--ignored` pattern
(`write_http_profile_fixtures`, `write_delegation_fixtures`) so the committed bytes and the
regenerated bytes are compared rather than assumed.

**THM-0042 stays out of boundary §2 until all four hold:**

1. the semantic submitted-hop identity is corrected as above;
2. the zero-verified-hop and self-check findings are disposed (R9-C103, R9-C128);
3. a real signed multi-hop retained corpus reproduces the commitment;
4. the corrected statement receives independent specification review.

- **Disposed by work already on `main`:** R9-C029, R9-C084, R9-C105, R9-C115 (both-empty
  `Ok`); R9-C035, R9-C065, R9-C104 (corpus fabrication and staleness).
- **Still open here:** R9-C074, R9-C075 (the identity gap), R9-C103, R9-C128.
- **Not this branch:** R9-C085/C086/C098/C102/C112 are THM-0068 under THM-0072.

### D4 — the retention reservation state relation

`EXISTING_ROOT_EXTENSION` — child of **THM-0074**; the rescind relation is consumed by
**THM-0078**.

The earlier revision of this packet stated D4 as *a marker exists only after execution*.
**That was wrong**, and wrong in the direction that would have damaged the architecture: the
reservation is deliberately taken *before* irreversible dispatch, precisely so that lack of
retention capacity can still refuse safely. THM-0045 already establishes that the reservation
is the last pre-dispatch refusal. A proposition forbidding pre-dispatch reservations would
contradict the design it is supposed to protect.

The honest model is a transition relation:

```text
NoReservation
      ↓
Reserved                     pre-dispatch. NOT evidence that execution occurred.
      ├─ refusal before dispatch ──→ Released
      └─ dispatch commitment crossed ──→ DispatchedPending ──→ retained terminal state
```

- **Proposition.** An exchange that never crosses the dispatch commitment cannot terminate
  holding a retention artefact readable as evidence of execution or of retention
  responsibility beyond what the reservation itself earned. And: a pre-dispatch reservation
  is rescinded on every path that terminates before dispatch.
- **Security consequence.** A durable artefact is an assertion that the deployment became
  answerable for a call. A spurious one cannot be told from a real one after the fact —
  unlike a missing record, which announces itself.
- **Scope / non-claim.** Not what the record contains (that is `retained_record` and
  THM-0042). Not that the write succeeded (that is the durability barrier). **Do not collapse
  WHAT was retained with WHEN execution responsibility was acquired.**
- **Owner.** `mcp-re-proxy/src/transparency/durability.rs` — real authority, explicit "WHEN
  responsibility has been durably established" contract, **no `[[unit]]`**.
- **Reusable.** THM-0045; the ordering argument in `durability.rs`; the bounded-queue
  argument in `durability_bounds.rs`.
- **Required new proposition — and the representation defect behind it.** Measured: the
  release half does not exist in production. `release_before_dispatch()` and
  `pending_reservations()` are reachable **only from tests** (`durability.rs:887-899` and one
  integration test). More fundamentally, if the current `.pending` representation cannot
  distinguish *reserved but not dispatched* from *dispatch occurred, retention pending*, then
  no cleanup discipline can make the invariant true — the two states are the same artefact.
  **Treat that as a representation defect and give the states distinct types or
  representations**, rather than relying on a caller remembering to release. This is the
  R-SEAL test applied to a state machine: can the release call be deleted and still leave the
  forbidden state unconstructible?
- **Assumptions.** A narrow filesystem-durability premise for the barrier, stated as what
  `fsync` on this platform establishes — not a general "the filesystem is correct".
- **R9 disposed.** R9-C004, R9-C021 (**High** — `NotDispatched` and ladder-reorder marker
  leaks), R9-C081, R9-C078, R9-C079, R9-C080, R9-C099. Seven, two High.

---

## 3. Area 3 — credential egress. The owner was remeasured

`EXISTING_ROOT_EXTENSION` — child of **THM-0077**.

The ruling refused to let `kms_endpoint_policy` become the generic owner of KMS + STS +
metadata + remote-signer egress merely because useful predicates live there. Remeasuring
found something better and worse than expected.

**A mechanism-neutral destination authority already exists**: `mcp-re-proxy/src/outbound_fetch/`.
Its stated fact is *a destination has passed the guard its PROVENANCE requires*, it is
explicitly not RFC-6960-specific, and — the part that matters here — `VettedDestination::agent`
hands out the configured HTTP client rather than a boolean, **so the connect-time half of the
guard travels with the value that earned it.** Its subordinates are `url` (scheme/host),
`address` (is this outside our network) and `resolver` (every connected address passed the
guard).

**And no credential-egress path consumes it.** Measured across `mcp-re-proxy/src`, the only
consumer of `VettedDestination` is `ocsp.rs`. It has no `[[unit]]` either.

So the shape is:

```text
D5   credential-sensitive outbound capability
       → validated semantic destination        ← outbound_fetch, the generic authority
       → actual connect-time authority         ← resolver, guard travels with the value
     ├─ D5.1  AWS KMS
     ├─ D5.2  GCP KMS
     ├─ D5.3  STS / workload credential
     ├─ D5.4  instance metadata
     └─ D5.5  remote signer
```

- **Proposition.** Every outbound request carrying a credential, bearer token or workload
  identity reaches only the authority selected and validated for that capability — where
  *reaches* means the authority actually connected to, not the one the configured text
  appears to name.
- **Security consequence.** The threat is redirection, not misconfiguration: an endpoint
  whose literal spelling names one host and whose machine interpretation names another sends
  the pod's IRSA token, or the root-key trust bootstrap, to an attacker. R9's only Critical
  was exactly this.
- **Scope / non-claim.** Nothing about what the remote authority does with the credential;
  nothing about token lifetime, refresh or availability.
- **Owner.** `outbound_fetch/` for the generic relation. `kms_endpoint_policy/` stays the
  **KMS-specific leaf**, which is what it actually owns — a config-time agreement between
  literal spelling and machine interpretation. **It is not renamed and its authority is not
  widened.**
- **The honest gap.** `kms_endpoint_policy`'s proof ends at configuration parsing. Under a
  rebinding-capable threat model a config-time host-string check cannot establish
  *actual-destination* safety; that needs the connect-time vetting `outbound_fetch/resolver`
  already implements. **D5 may not claim actual-destination safety until credential egress
  consumes that authority.** Do not duplicate the SSRF/DNS logic into the KMS paths.
- **Reusable.** All of `outbound_fetch`; `authority.rs`'s `check_host`/`check_port` and their
  tests; `config_state/kms_endpoint.rs`.
- **Assumptions.** One narrow premise that the HTTP client's authority resolution is the one
  the resolver vetted. `outbound_fetch`'s design already minimises this by handing out the
  agent rather than a verdict.
- **R9 disposed.** R9-C001 (**Critical**), R9-C017, R9-C018, R9-C031, R9-C092 — fixed but
  currently unrooted.
- **Deliberately excluded.** R9-C057/C058/C059/C107 (metadata single-flight stalls) are
  availability. Real defects, ordinary engineering, not this proposition.

---

## 4. Area 4 — sidecar local ingress

### D6 — ingress authority, NOT caller identity

`NEW_ROOT`. The only new root shape.

The earlier revision said *a local request whose origin the deployment selected*, while also
saying there is no local-caller authentication. Those cannot both hold: any local process
that can reach the listener and supply an acceptable `Host` still calls it. "Origin" is also
ambiguous where no HTTP `Origin` is authenticated.

- **Proposition.** A request reaching the shipped sidecar outside the deployment-selected
  listener and HTTP-authority policy cannot cause the sidecar to initiate a signed MCP-RE
  exchange.
- **Explicit non-claim.** **This does not identify or authenticate which local process
  originated an otherwise admissible local request.** Nor is the local leg confidential.
- **Security consequence.** The sidecar signs with the agent's key. A web page in the user's
  browser that reaches the loopback listener — by DNS rebinding, or because the listener
  answers any `Host` — obtains signed, attributed MCP-RE calls under someone else's identity.
  No existing root excludes it: THM-0076 concerns what a client *accepts as an answer*, and
  the attack completes before any answer exists.
- **Why NEW_ROOT.** Independence holds both ways: the sidecar runs against deployments with
  no MCP-RE proxy, and every current root holds where no sidecar exists.
- **Owner.** `mcp-re-client/src/serve/head_fields.rs` (caller-shape and loopback-`Host`
  check) with `serve/request.rs`. Real authority, **no `[[unit]]`**.
- **Required prerequisite — R9-C096, and it blocks registration.** Measured at
  `mcp-re-client/src/lib.rs:195`: `allow_any_host: config.local.allow_non_loopback`. One
  operator input governs two independent facts. Separate them into distinct semantic values:

  ```text
  BindScope                      where the listener is exposed
  AcceptedHttpAuthority          which HTTP authority names may reach signing
  ```

  Permitting a non-loopback bind must **not** disable `Host`-authority validation. One
  boolean with two meanings makes the proposition unstatable, not merely unproven, so this
  is fixed **before** the root is registered.
- **Reusable.** `is_loopback_host`, `local_leg_e2e_test.rs`.
- **Assumptions.** None foreign expected.
- **R9 disposed.** R9-C096, R9-C127. (R9-C062/C063 sit on the THM-0076 side; named so the
  split is explicit.)

---

## 5. Area 5 — the supported-client root family

### D7 / D8 — Python and TypeScript members

`ROOT_FAMILY_MEMBER` ×2, beside **THM-0076** (Rust `ClientProxy`). Both become declared
roots.

- **Proposition (per member).** For the shipped `<language>` SDK, an application is not
  handed, as this call's answer, a response from another exchange or signer, or one that
  verified only unbound — and is not led to repeat a side effect by reading silence as *it
  did not run*.
- **Why two members, never one language-neutral theorem.** A theorem quantifying over "the
  SDK" would be a claim about no shipped artefact. The boundary is implemented independently
  per language and the Rust proof establishes nothing about either.

### What is and is not theorem material

The earlier revision said the deadline and concurrency divergences "are the claim." **That
was too wide.** The security root concerns response↔request correlation, signer and trust
acceptance, bound-vs-unbound verification, execution-status interpretation, and safe-retry
interpretation. A concurrency ceiling is resource management. Widening a security root into a
general availability theorem by accident is exactly the drift these rulings exist to stop.

Each SDK finding, classified:

| finding | classification | why |
|---|---|---|
| R9-C061, C109, C110 — `send_notification_verified()` outside the concurrency bound its TS twin enforces | **ORDINARY ENGINEERING** | a resource ceiling. Does not change what the client concludes about authenticity, correlation or execution |
| R9-C095 — TS aborts any response whose TOTAL download exceeds `timeoutMs`, not just an idle one | **SECURITY-ROOT RELEVANT** | the client aborts a request the server may have executed. If that surfaces as a clean failure rather than ambiguous execution, safe-retry interpretation is wrong |
| R9-C010, C011, C019, C020, C049 — Python aggregate read deadline inert (`http.client` `read(n)` blocks) | **ORDINARY ENGINEERING, conditionally security-relevant** | an inert deadline yields *no* conclusion rather than a wrong one. It crosses into the root only if a caller's outer timeout then produces a retry whose execution status the SDK never determined — state that condition rather than assuming it |
| R9-C094 — the Python test pins the bound with a fake `http.client` never behaves like | **EVIDENCE DEFECT** | not a claim defect: a control that cannot fail. Belongs to the member's evidence, and it is why C010's classification cannot currently be settled by that test |
| R9-C093 — `retry_is_refused()` treats an UNRECOGNIZED `execution_status` like silence | **SECURITY-ROOT RELEVANT** | execution-status interpretation, directly. Rust client-proxy side, THM-0061's neighbourhood |

- **Owner.** No Rust `[[unit]]` can own D7/D8 — see §6.
- **Assumptions.** Narrow and exact: the specific `http.client` read semantics D7 rests on;
  the specific `AbortSignal`/fetch semantics D8 rests on. **Not** "the Python runtime is
  correct" or "fetch is correct".

---

## 6. Prerequisite: generalize the unit model, do not special-case a language

A `[[unit]]` is meant to be *the smallest semantic authority whose source, assumptions,
evidence and review can be fingerprinted*. That concept is not inherently Cargo. Today's
implementation is: `_unit_packages` splits paths on the crate directory, `test_package` names
a Cargo package, selectors are Rust test paths, and `crate_features` is a fingerprint
component.

**Do not bolt on `kind = "python"` / `kind = "typescript"`.** Generalize:

```text
semantic unit
    owned source closure
    dependency / configuration inputs
    typed evidence providers
    registered assumptions
    review fingerprint
        ↑ adapters
  Cargo/Rust   ·   Python/pytest   ·   TypeScript/npm
```

The platform slice must demonstrate, with negative controls:

1. changing owned Python/TS source dirties the unit;
2. changing the relevant dependency manifest or lockfile dirties it;
3. stale evidence cannot establish it;
4. an unknown evidence provider fails closed;
5. a non-Rust unit with no executed evidence cannot become established;
6. owner, dependency and assumption views derive identically;
7. root-completeness treats a non-Rust member exactly as a Rust member once evidence is
   valid.

This belongs to the Assurance Platform Integrity layer. **The SDK roots may not be claimed
before the platform can honestly measure them** — an unevidenceable root reads as coverage
while being none.

---

## 7. Execution order

1. **THM-0042 corpus** — a NEW, MCP-RE-produced signed multi-hop retained corpus with a
   golden writer. Started first: longest pole, and not verifier work. **Do not regenerate
   `s01`** — it is third-party-produced and that is its value.
2. **Generalize the unit model** for non-Rust semantic units, with the §6 negative controls.
3. **Register the existing-authority units** — `outbound_fetch`, `kms_endpoint_policy`,
   `replay_plane`, `continuation_store`, `transparency/durability`, `mcp-re-client/src/serve`.
   Mechanical; the owners already exist.
4. **Close D1a/D1b projection and D2a/D2b fail-closed.**
5. **Repair the retention reservation state machine** (typed states, production release path)
   and close D4's relations.
6. **Split `BindScope` from `AcceptedHttpAuthority`**, then register D6.
7. **Close D7/D8** on the generalized unit model.
8. **Close THM-0042** once identity and corpus are ready.
9. **Whole-system missing-edge pass and root completeness.**

No §4 boundary row moves to §2 until its root or member is established **and independently
reviewed**.

## 8. What this packet does not do

No `THM-NNNN` allocated. `root_theorems` untouched. No specification-review record. No
implementation. Nothing established.
