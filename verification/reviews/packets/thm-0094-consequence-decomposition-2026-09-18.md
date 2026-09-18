<!-- SPDX-License-Identifier: Apache-2.0 -->
# Phase-1 decomposition packet — THM-0094, the shipped Python SDK root

**ADR-MCPRE-068 Phase 1**, consequence-first. One subject: the root THM-0094 and the
smallest set of independent propositions that must be true for it to hold. Layer 1 under
ADR-MCPRE-059 §14.7 — evidence about the tree, not an approval and not authoritative state.

Its predecessors are `thm-0094-python-sdk-root-2026-09-03.md` (the ratification packet),
`thm-0094-final-2026-09-03.md` and `thm-0094-runtime-narrowing-2026-09-05.md`. This one asks
a question none of those asked: *is the obligation attached to the right propositions at
all?* The answer is no in four measurable ways, and this packet is the correction.

**The statement itself is NOT changed by the commit that lands this decomposition.**
`scripts/claim_surface_gate.py` refuses a published root claim whose `theorem_claim` has
moved since the owner's specification review, and that refusal is correct: a claim nobody has
approved in its present form must not be published. So the decomposition lands — units,
owners, carriers, classes, batteries, and this root's `supported_by` — and the CLAIM
CORRECTIONS §2 establishes are batched for owner review. §10 states them as exact edits.

---

## 1. The root consequence, stated before anything is decomposed

| | |
|---|---|
| **root theorem** | THM-0094 |
| **current statement** | "The shipped Python SDK accepts only an answer to its own request" |
| **declared root severity** | `critical` |
| **worst credible failure consequence** | an application driving MCP through this SDK repeats a side effect that already ran — it is told an operation did not execute when the SDK does not know that — or it acts on an answer that belongs to another exchange, another signer, or no request at all |
| **externally visible security failure** | a tool call with real-world effect (a payment, a deletion, a deploy) executes twice, on the strength of a verdict the peer never gave; or an application acts on a result produced by someone the deployment does not trust |

Severity is taken from the consequence, not from the evidence. Nothing below lowers it.

---

## 2. Falsifying the root statement before decomposing it

Six of the nine questions §2 of the Phase-1 method asks return findings.

### F1 — the statement is STRONGER than production guarantees, on its own headline sentence

The statement opens:

> Every reply is taken from the correlation entry the request created, and a reply binding
> to nothing outstanding, arriving late, or repeating one already answered is refused rather
> than delivered.

Measured against `transport.py::_exchange`. The correlation id handed to
`CorrelationStore.take()` is `signed.evidence_digest_value` — the value `record()` returned
for **this leg, three statements earlier in the same loop iteration**. It is not derived
from the reply. MCP-RE is HTTP-profile only, one signed POST per request, and the reply is
the return value of `await poster(...)`: there is no inbox, no demultiplexer, and no lookup
by anything the peer controls.

So on the shipped path:

| clause | reachable from `_exchange`? |
|---|---|
| "binding to nothing outstanding" | **no** — the entry was just recorded |
| "repeating one already answered" | **no** — `record()` would have raised first |
| "arriving late" | **yes** — `take()` raises `mcp-re.expired_request` when the response lands past the request's own TTL |

Two of the three named refusals are unreachable branches under the current legality model
(ADR-MCPRE-061 question 9). They are real properties of `CorrelationStore` *as a value*,
exercised at its own API by `tests/test_correlation.py::TestFailsClosed::*` — which is a
different proposition from the one the root states, at a different altitude.

**What actually binds a reply to its request is not in this sentence at all.** It is the
audited core: `sdk/python/src/lib.rs` builds a `ResponseExpectation` from the request bytes
and `verify_delegated_response` decides binding cryptographically. The root's own promise
rests on THM-0058/THM-0059 and on the SDK handing the verifier *this transmission's* bytes —
neither of which the statement names.

**Correction, and it is a claim correction rather than a guarantee withdrawal.** The
correlation sentence narrows to what the shipped path enforces (freshness, and the store
never left holding a remotely-triggerable entry), and the binding promise moves to where it
is actually decided: a dependency on the core theorems, plus a leaf saying the SDK gives the
core the bytes it signed. The system promise — *an application is not handed another
exchange's answer* — is **better** supported after the correction than before, because it
now names a cryptographic binding instead of a store lookup that cannot fail.

### F2 — `depends_on = []` is false

THM-0094 declares no premises. Its promise rests entirely on `mcp_re_client_core`:
`verify_delegated_response` (trust, revocation, epoch, audience, request binding),
`DelegationPolicy` (the clamped skew), `ExecutionContract` (what a receipt stated) and
`continuation_state` (terminal vs. non-terminal). Those are MCP-RE's own code with
registered units and ratified theorems — **not** an external boundary, and not something
this root establishes for itself.

A root whose whole cryptographic argument is unstated reads as a self-contained claim over
five Python files. It is not one.

### F3 — the theorem is about a composition whose middle layer is in NO unit

`sdk/python/src/lib.rs` (770 lines) and `sdk/python/src/trust.rs` (46) are the PyO3 binding.
They are production code on the root's critical path: they construct the pinned root
resolver from the configured anchor, build the `DelegationPolicy` and the
`StaticRevocationList`, call the core, and **project the core's verdict into the Python
object** whose `bound`, `execution_status`, `retry_safety`, `continuation_status` and
`retention_status` members leaf C3 then reports to the application verbatim.

They are in **no unit's `paths`**. Three consequences, all measured:

1. no `[[unit]]` states any proposition about them;
2. they are outside every fingerprint, so editing the trust-anchor construction invalidates
   no attestation and drops no evidence;
3. `sdk/python/src` contains **zero** `#[cfg(test)]` modules, against the repository standard
   that every file carries one.

This is the twelfth-question #10 case as well: `verified_outcome.rs` in `mcp-re-client-proxy`
already owns "a verified reply is not a completed call" (THM-0126) and the PyO3 binding
derives the same fact independently.

**No unit is invented for it here.** The packet README's rule governs: *a proposition with no
semantic authority that can honestly own it is an architecture gap, not a manifest
inconvenience*. Registering the binding as `tested` against a pytest battery in which no
control names it would be exactly the dishonesty ADR-068 exists to remove. It is recorded as
**Phase-2 obligation P2-A** below and as a typed `review-obligation` premise.

### F4 — two stated conjuncts are NOT in the root's consequence chain

The Phase-1 inverse falsifier — *is there a child whose failure does not affect the root
consequence?* — returns two.

- **The aggregate read bound** (`mtls._read_bounded`). Remove it and a trickling peer holds a
  worker until the byte ceiling; the application is not handed a wrong answer. That is
  availability. What the root legitimately takes from the deadline is that it fails the
  exchange as a **local** condition carrying no execution verdict — and that is leaf C4's
  proposition, not the bound's. The bound keeps its own unit and its own severity, outside
  this chain; the root's scope keeps its sentence about the worst case as a stated non-claim.
- **Signer/route policy at open** (`custody.SignerPolicy.check`). Remove it and the SDK signs
  under an identity the route did not expect. The peer refuses, or it does not — but the
  answer the application receives still binds to the request that was sent. It is a
  request-side attribution proposition, not a response-acceptance one.

Both stay registered. Neither is in THM-0094's `supported_by`.

### F5 — the Python and TypeScript members state DIFFERENT claims over the same controls

THM-0095 states *"a complete configured trust anchor — an incomplete one is refused at
construction rather than defaulted — and only outside the revocation denylist, whose shape is
checked so a bare string cannot spread into a per-character list."* THM-0094 states nothing
of the kind — and the Python SDK has all four controls
(`test_an_incomplete_trust_anchor_fails_at_construction`, and three denylist-shape controls),
none of them registered. The asymmetry was in the claims, not in the implementations.

Leaf C13 states it for Python.

### F6 — what the falsification did NOT find

- The claim is not true only under a configuration subset: the runtime-support narrowing
  (`requires-python = ">=3.14.5,<3.15"`, `scripts/python_runtime_gate.py`) already scopes it
  and that scoping is correct.
- No caller bypasses the named owner in a way the root does not already exclude: the scope
  sentence about an application that bypasses the adapter stands.
- The statement does not combine two authorities with an "and" that hides one — it combines
  **eleven**, which is what §3 separates.

---

## 3. The decomposition

Ten propositions in the chain, three registered beside it. Each has one semantic
proposition, one owner, one production carrier and one honest evidence class.

```
THM-0094  the shipped Python SDK accepts only an answer to its own request     critical
│
├── depends_on ─ THM-0058  accepted only under a signer the trust configuration authorizes
│                THM-0059  an unbound receipt is never a success, never another's answer
│                THM-0060  the clock skew is bounded at construction and read once
│                THM-0061  a receipt that says nothing is not one that says nothing ran
│
└── supported_by
    C1  sdk_python.exchange_binding            the verifier is given THIS transmission
    C2  sdk_python.verdict_delivery            a non-success is never an acceptance
    C3  sdk_python.execution_report            only what the receipt carried is reported
    C4  sdk_python.local_failure_provenance    a local condition wears no peer vocabulary
    C5  sdk_python.reply_envelope              what reaches the session is rebuilt, not edited
    C6  sdk_python.continuation_drive          only a terminal reply resolves the call
    C7  sdk_python.correlation_lifecycle       answerable only inside its window; nothing leaks
    C8  sdk_python.nonce_floor                 no request is signed under a sub-floor nonce
    C11 sdk_python.notification_delivery       delivered only against a verified bound 202
    C13 sdk_python.trust_anchor_completeness   an incomplete anchor is refused at construction

    registered, NOT in this chain (§2 F4):
    C9  sdk_python.signer_policy               request-side attribution
    C10 sdk_python.bounded_read                availability of the response read
    C14 sdk_python.authorization_binding       which artefacts a request is bound to
```

### Per-leaf record

Every leaf is `tested`; none is honestly `proved`, `structural` or `measured`, and §4 says
why. `existing evidence` is the battery the predecessor unit declared;
`target evidence` adds the falsifier N1 requires.

**C1 — `sdk_python.exchange_binding`** · direct `critical` · effective `critical`
- **proposition** — the verdict is computed over the exact request bytes this exchange
  signed and transmitted; nothing is re-derived, re-serialized or reconstructed for the
  verifier.
- **semantic owner** — the exchange driver. **Production carrier** —
  `transport.py::_exchange` and `::_notify`: one `signed` value is both POSTed and passed to
  `_core.verify_response` / `_core.verify_accepted_202`.
- **composition consumers** — every other leaf: each reads a verdict this one made honest.
- **why it is the composition proposition** — the core owns request↔response binding, and
  the core is only correct about the request it is *given*. A re-serialized body would
  verify cleanly against bytes the peer never saw.
- **evidence class** `tested`. Existing: `test_the_signed_body_is_the_request_the_caller_described`,
  `test_the_stubbed_verdict_shape_is_the_cores_own`. Registered here from the ADR-069 census:
  `test_a_tampered_response_fails_closed_and_never_reaches_the_app`,
  `test_an_unsigned_response_fails_closed`,
  `test_authorization_bindings_reach_the_core_which_digests_the_real_bytes`.
- **Phase-2 gap** — falsifier: re-serialize the body at the verify call site; at least one of
  the above must go red.

**C2 — `sdk_python.verdict_delivery`** · direct `critical`
- **proposition** — a verdict whose outcome is not `success` reaches the application as a
  correlated JSON-RPC error and never as a result, and the receipt's request-binding fact
  travels beside the frozen token rather than inside it.
- **carrier** — the `verified.outcome != "success"` branch of `_exchange`, `_error_message`.
- **class** `tested`. Battery: the six replay controls (untrusted root, stale epoch, wrong
  audience, revoked key, appended byte, recorded session) plus the unbound-receipt and
  rejection-delivery controls.
- **depends on** THM-0058, THM-0059 — those decide *what* a non-success is; this leaf decides
  what the SDK then does with it.

**C3 — `sdk_python.execution_report`** · direct `critical`
- **proposition** — the application is told exactly the execution / retry members the
  verified receipt carried, and no member it did not carry is invented for it.
- **carrier** — `transport.py::_rejection_data`.
- **class** `tested`. Battery: `test_a_post_dispatch_rejection_reports_its_execution_and_retry_contract`,
  `test_a_transport_deadline_does_not_synthesize_what_the_peer_never_said`.
- **This is the leaf the whole root family exists for.** A byte-level parity fixture cannot
  reach it: fixtures pin what the SDK emits, and this is about what it reports upward.
- **depends on** THM-0061 (`Unstated` and `NotExecuted` are distinct inhabitants).

**C4 — `sdk_python.local_failure_provenance`** · direct `critical`
- **proposition** — a condition this SDK originated (a transport deadline, a cancellation, a
  local signing or I/O failure) is reported under the SDK's own prefix, never as a
  `mcp-re.*` token the peer did not send and never as an execution or retry verdict.
- **carrier** — `transport.py::_peer_wire_code` and `_one`'s exception ladder; `_notify`'s
  `ValueError` arm.
- **separate from C3 deliberately** — C3 is about what a PEER verdict may be reported as; C4
  about what a LOCAL condition may be reported as. C3's failure invents a peer fact; C4's
  borrows the peer's vocabulary. Two authorities, two leaves.
- **class** `tested`. Battery: four existing controls plus four registered from the census
  (`..._is_delivered_as_the_bare_token`, `..._is_labelled_a_local_condition`,
  `test_a_notifications_wire_code_is_the_bare_token_too`,
  `test_the_cores_own_fail_closed_error_is_delivered_rather_than_hanging`).

**C5 — `sdk_python.reply_envelope`** · direct `critical`
- **proposition** — what reaches the MCP session is REBUILT from the one member the verified
  reply carried plus the session's own id; a verified reply that is not a JSON-RPC response
  — one carrying a `method`, one with neither `result` nor `error` — is refused rather than
  dispatched.
- **carrier** — `transport.py::_plain_response_object`, `::_plain_mcp_reply`.
- **why rebuilding rather than editing is the proposition** — editing left every other
  top-level key in place, and a body carrying both a legal `result` and a `method` then
  re-parsed as a server→client REQUEST. The rebuild removes the class.
- **class** `tested`.

**C6 — `sdk_python.continuation_drive`** · direct `critical`
- **proposition** — only a terminal verified reply resolves the call; a non-terminal one
  pauses it and its answer leg signs over the verified handles of the leg before it; an
  elicitation with no handler, a declined one, a non-object answer, or one past the
  continuation budget fails the call closed rather than resolving it.
- **carrier** — `_exchange`'s continuation loop, `_answer_leg_id`,
  `correlation.record_input_required`.
- **class** `tested`. Registered from the census:
  `test_the_continuation_round_ceiling_is_enforced_before_the_caller_is_asked`.
- **depends on** THM-0061 — the *classification* of a reply as terminal, and the refusal of an
  unrecognised `resultType`, is the core's, not this leaf's.

**C7 — `sdk_python.correlation_lifecycle`** · direct `high` · effective `critical`
- **proposition** — a request is answerable only inside the window it declared, and no
  remotely-triggerable outcome leaves a correlation entry outstanding.
- **carrier** — `correlation.py::CorrelationStore` (`take`, `abandon`, `_retire`,
  `expire_before`, `prune_consumed`) and `_exchange`'s `finally`.
- **This leaf carries the F1 correction.** Its scope says explicitly that `CorrelationStore`'s
  mismatch and replay refusals are properties of the value at its own API and are NOT
  reachable from `_exchange`; what the shipped path enforces is freshness and bounding.
- **class** `tested`. Registered from the census:
  `test_every_concurrent_reply_is_correlated_to_its_own_request`,
  `test_a_completed_chain_leaves_no_correlation_entry_outstanding`,
  `test_an_unanswered_elicitation_leaves_no_correlation_entry_outstanding`,
  `test_correlation_state_belongs_to_the_transport_not_the_config`,
  `test_an_injected_clock_and_ttl_are_honoured`.

**C8 — `sdk_python.nonce_floor`** · direct `high` · effective `critical`
- **proposition** — no request and no notification is signed under a nonce below the
  128-bit floor, and freshness is generated per leg rather than taken from the caller.
- **carrier** — `transport.py::_checked_nonce`, `_default_nonce`.
- **in the chain because** a guessable nonce makes a captured response replayable against a
  NEW request — the application is then handed an answer that is not to its own request,
  which is the root consequence exactly.
- **class** `tested`. **The predecessor unit declared NO control for this at all**; all seven
  come from the ADR-069 census (`tests/test_nonce_floor.py`'s five,
  `test_a_sub_floor_nonce_override_is_refused_before_a_notification_is_signed`,
  `test_freshness_is_generated_here_so_a_caller_cannot_repeat_a_nonce`). A conjunct of the
  root with no declared evidence is the sharpest single result of this census.

**C11 — `sdk_python.notification_delivery`** · direct `high` · effective `critical`
- **proposition** — a notification is treated as delivered only against an acknowledgement
  that verified as bound to THAT transmission; a failure to verify one is contained — the
  message is not delivered, is reported on the diagnostic channel, and unrelated exchanges
  are untouched.
- **carrier** — `_notify`, `send_notification_verified`, `_one_notification`,
  `_report_undeliverable`.
- **in the chain because** telling an application its `notifications/cancelled` reached the
  enforcement boundary when nothing acknowledged it is the same failure shape as reporting an
  execution fact the peer never stated.
- **class** `tested`. Six controls registered from the census, including the client→server
  response refusal and its containment.

**C13 — `sdk_python.trust_anchor_completeness`** · direct `critical`
- **proposition** — a trust anchor is complete or the transport is refused at construction,
  and the revocation denylist's SHAPE is checked, so a bare string cannot spread into a
  per-character list.
- **carrier** — `transport.py::McpReConfig.__post_init__`.
- **NEW leaf, ADR-069 `new-proposition` disposition.** Four controls exist, none registered,
  and the proposition they establish is stated by the TypeScript member and by no Python
  claim (§2 F5).
- **class** `tested`.

### The three registered beside the chain

**C9 — `sdk_python.signer_policy`** · direct `high`, effective `high` (NOT-ROOT-REACHABLE).
The transport does not open unless the signer satisfies the route's identity and custody
policy, checked before anything is signed. Carrier `custody.py::SignerPolicy.check`,
`Signer`, `SigningDevice`. Four controls.

**C10 — `sdk_python.bounded_read`** · direct `medium`, effective `medium`
(NOT-ROOT-REACHABLE). The response read is bounded by the aggregate deadline plus at most one
per-recv timeout and by a byte ceiling; exceeding either fails the exchange. Carrier
`mtls.py::_read_bounded` and the connect helper. Eighteen controls.

**C11's sibling, C14 — `sdk_python.authorization_binding`** · direct `medium`
(NOT-ROOT-REACHABLE). The binding specs a request carries are the ones the policy permits,
serialized canonically, and the retained digest identifies which artefacts the request was
bound to without ever being re-interpreted. Carrier `authorization.py`,
`transport.py::_bindings_json` / `_authz_binding_digest`.

NOT-ROOT-REACHABLE is a graph fact and not a lower obligation: all three keep their direct
severity, and C9 and C14 owe falsifiers under N1 exactly as the in-chain leaves do.

---

## 4. Why every leaf is `tested`, and none of the other three classes

- **`proved`** — nothing here is a mathematical property of code semantics suitable for Verus
  or Aeneas/Lean. The propositions that *are* — request/response binding injectivity, the
  execution-status lattice — belong to `mcp-re-client-core` and are already this root's
  premises (THM-0058, THM-0059, THM-0061). Proving them there is a Phase-2 target for THOSE
  units and would be claimed here through the dependency edge, not restated.
- **`structural`** — the class requires a construction the compiler refuses. Python refuses
  nothing at compile time. Every seal-shaped sentence in this root ("nothing is
  reconstructed", "the envelope is rebuilt") is a data-flow discipline in a dynamic language,
  which is a runtime fact however carefully it is written. **The one place a structural
  witness is available in this root's composition is the PyO3 binding, which is Rust — and it
  is not a unit (§2 F3).** That is the strongest argument for P2-A below.
- **`measured`** — nothing here is scoped to a corpus or an environment. The runtime matrix
  is close, but it scopes the WHOLE claim rather than being a proposition of its own, and it
  already has its mechanism (`scripts/python_runtime_gate.py`, the pinned interpreter in the
  fingerprint).

---

## 5. Premises, boundaries and obligations

**Typed premises reached transitively** through the dependency edges to THM-0058/0059/0060/
0061 and their units: no new theorem→assumption edge is created here, per Ruling 2 — the
authoritative direction stays `[[assumption]].scope` → unit.

**New `review-obligation` premise, P2-A** — the PyO3 binding as an unregistered carrier. It
is a review obligation and not an `assumed` premise because it WILL be discharged at a named
event, and not an `external-boundary` because the code is MCP-RE's own.

**External boundaries this root genuinely ends on**, recorded as such rather than silently
assumed:

| boundary | why it is outside |
|---|---|
| CPython's `http.client.HTTPResponse.read1` short-read semantics | C10's bound rests on it; the stdlib owns it, and the claim is scoped to the pinned interpreter set |
| the upstream `mcp` package's `ClientSession` / pydantic parse | C5 hands it a rebuilt envelope; what it then does is its own |
| the OS CSPRNG behind `secrets.token_urlsafe` | C8's floor is about length at emission, not about entropy quality |

---

## 6. ADR-MCPRE-069 dispositions

The census is run here for the first time over a **Python** project: ADR-069 §2's measurement
counted `#[test]` / `#[tokio::test]` only, so this population was structurally invisible to
it. Measured over `sdk/python/tests/`, by function:

| | count |
|---|---|
| control functions in the predecessor unit's paths | 109 |
| registered by the predecessor unit | 39 |
| registered after this decomposition | **85** |
| newly registered here | **46** |
| dropped | 0 |

| disposition | functions | what landed |
|---|---|---|
| `register` | 42 | the symbol joins the leaf whose proposition it establishes, named there |
| `new-proposition` | 4 | C13 — the trust-anchor and denylist-shape controls (§2 F5) |
| `reattribute` | 0 | no control here belongs to another unit's battery |
| `not-evidence` | 22 | reasons below |
| **blocked** | 5 | `tests/test_transport_e2e.py` — §6.1 |

**Four declared symbols expand.** `test_a_sub_floor_override_is_refused_at_sign_time` (4),
`test_an_incomplete_trust_anchor_fails_at_construction` (7),
`test_a_denylist_entry_that_cannot_match_an_identifier_is_refused` (3) and
`test_a_bound_that_would_refuse_everything_is_refused` (2) are parametrized, and each is
declared as the ids the runner REPORTS rather than as the bare function. The lane compares
names verbatim, so a bare name would read as controls that never ran — and for the anchor
case the distinction is substantive: the claim is that NONE of the seven members is
defaulted, and one id would establish it for whichever member ran first. 85 functions, 97
declared ids, 97 passing.

`not-evidence`, with reasons:

- **`tests/test_parity.py` (11)** — the frozen-oracle byte fixtures. They establish cross-SDK
  EMISSION parity, which is a different proposition from this root's — and the one issue #746
  measured as insufficient for it. They are evidence for a parity claim no unit holds;
  recorded as a second `new-proposition` candidate, deferred to the THM-0095 packet where the
  same fixtures sit on the other side of the same comparison.
- **`tests/test_smoke.py` (3)** — import and non-empty-string checks over the binding
  surface. Local sanity, not a security proposition.
- **`tests/test_transport.py` lifecycle and concurrency (8)** — `close()` semantics and the
  `CapacityLimiter` bound. Resource and lifecycle properties; this root's scope excludes
  concurrency and throughput in terms.

### 6.1 The five that are not a disposition at all — `test_transport_e2e.py` does not run

`tests/test_transport_e2e.py` holds the strongest controls in this project for C1 and C9: a
tampered response and an unsigned one, failing closed against the real `http_profile_proxy`
and a real MCP backend, and the hardening profile refusing a software key before connecting.
None of the five is registered, and registering them would have been a false green.

**Measured**: the file's module-level guard is `pytest.importorskip("httpx")`, and the
locked resolution provides **`httpx2`** — `mcp` 2.0 moved. So the whole file skips:

```
SKIPPED [1] tests/test_transport_e2e.py:34: could not import 'httpx': No module named 'httpx'
1 skipped in 0.32s
```

This is the repository's oldest failure class, one layer over: not a filter selecting zero
tests, but a lane whose tests are all guarded away. Five live controls over the root's own
claim have been running nowhere, and nothing said so — because nothing claimed them, which
is exactly what ADR-069 exists to surface.

**They stay unregistered on purpose.** A declared symbol that does not run is a lane FAILURE,
and it would be one here for a second reason even once the import is fixed: the file also
needs a built `http_profile_proxy` example, which the measured lane does not build. Recorded
as **P2-E**; the fix is a port to `httpx2` plus a decision about whether the e2e lane is a
registered battery or an independent one.

## 7. Adequacy — why the children jointly establish the root

Read forward: a reply arrives; C1 guarantees the verdict was computed over the bytes this
exchange actually sent; THM-0058/0059 guarantee what that verdict MEANS about signer and
binding; C2 guarantees a non-success never becomes a result; C5 guarantees what does reach
the session is a rebuilt response and nothing else; C6 guarantees only a terminal reply ends
the call; C3 guarantees the execution facts reported are the receipt's own and THM-0061
guarantees silence is not "it did not run"; C4 guarantees a local condition never borrows the
peer's vocabulary; C7 guarantees the window; C8 guarantees the request was fresh enough that
a captured answer cannot be aimed at it; C13 guarantees the trust configuration the whole
chain is evaluated against is complete; C11 carries the same honesty onto the leg that has no
reply to ride back on.

**What they deliberately do NOT establish**: that anything is served (every leaf is
one-directional); that the SDK is fast, concurrent or available; that a caller's own retry
policy is safe; that an application bypassing the adapter is protected; that the OTHER two
members of the root family hold; that the PyO3 binding does what §3 assumes it does — which
is P2-A, stated as debt rather than assumed away.

---

## 8. The Phase-1 falsifier, run against the decomposition itself

*If one child were removed, could the remaining graph still claim the root ESTABLISHED?*

| removed | the root's consequence then reachable by |
|---|---|
| C1 | a re-serialized body verifies against bytes the peer never saw |
| C2 | a signed REJECTION receipt is handed up as this call's result |
| C3 | `not_executed` is synthesized for a receipt that stated nothing; the caller retries a tool call that ran |
| C4 | a local deadline is reported as a peer wire code, and read as the peer's verdict |
| C5 | a reply carrying `result` AND `method` is re-parsed as a server-initiated request |
| C6 | an elicitation nobody answers surfaces as the call's answer |
| C7 | a response past the request's TTL is accepted; a peer grows the store for the session's life |
| C8 | a guessable nonce makes a captured answer replayable against a new request |
| C11 | an unacknowledged notification is reported as delivered |
| C13 | a defaulted anchor or a per-character denylist evaluates the whole chain under a trust picture the operator did not configure |

Ten NOs. The inverse question returned C9, C10 and C14, which is why they are registered
beside the chain and not inside it (§2 F4).

---

## 9. Phase-2 obligations this decomposition creates

| id | obligation | severity |
|---|---|---|
| **P2-A** | register the PyO3 binding (`sdk/python/src/lib.rs`, `trust.rs`) as production carriers: a cargo-native battery inside the binding crate, `#[cfg(test)]` modules per the repository standard, and the unit(s) whose propositions those controls establish. Until then the binding is outside every fingerprint and outside every claim. | critical |
| **P2-B** | the falsifier lane has **no Python or TypeScript ecosystem**: `verify-mutations` runs `cargo test` only, so not one of these thirteen `tested` leaves can discharge N1 today. The lane needs the pytest/vitest adapters `_ecosystems.test_argv` and `parse_results` already provide, plus a runtime graft for the prepared environments the scratch copy does not carry. | critical — it blocks every SDK leaf |
| **P2-C** | ADR-069's census tooling covers `#[test]`/`#[tokio::test]` only. §6 was measured by hand. A Python/TypeScript census is owed, or the 626 figure is a count over part of the estate. | high |
| **P2-D** | THM-0126's proposition is derived a second time in the PyO3 binding rather than consumed from `mcp-re-client-proxy`. Twelfth-question #10. Remediation belongs with P2-A. | medium |
| **P2-E** | `sdk/python/tests/test_transport_e2e.py` skips entirely — `importorskip("httpx")` against a resolution that provides `httpx2` — so five live controls over this root's own claim run nowhere. Port it, and decide whether the e2e lane is a registered battery (which needs the example built in the measured lane) or independent evidence that says so. §6.1. | high |

None is discharged here. Phase 1 states the graph; Phase 2 discharges it.

---

## 10. The claim corrections requested, and not taken

`theorem_claim` is `statement + security_consequence + scope`, and `theorem_dependencies` is
the transitive `depends_on` closure. Each edit below moves one of them, so each is the
owner's. **None weakens or withdraws the promise**; §2 argues that C1 strengthens its support.

**C1 — narrow the correlation sentence to what the shipped path reaches** (§2 F1). Replace
*"Every reply is taken from the correlation entry the request created, and a reply binding to
nothing outstanding, arriving late, or repeating one already answered is refused rather than
delivered"* with a sentence that says the verdict was computed by the audited core over the
exact bytes this exchange signed, that a request is answerable only inside the window it
declared, and that `CorrelationStore`'s unbound and duplicate refusals are the store's own at
its own API. The promise — *not handed another exchange's answer* — is unchanged and better
supported, because the corrected text names the cryptographic binding instead of a store
lookup that cannot fail.

**C2 — add `depends_on = ["THM-0058", "THM-0059", "THM-0060", "THM-0061"]`** (§2 F2). The
present `[]` is false: the SDK's whole cryptographic argument is `mcp_re_client_core`'s.
THM-0126 is deliberately excluded — the PyO3 binding derives that fact independently rather
than consuming it, which is P2-D.

**C3 — a scope paragraph recording the PyO3 binding as uncovered** (§2 F3): that this claim
assumes the binding's projection is faithful rather than establishing it, and that the
assumption is a recorded review obligation.

**C4 — move the read bound from the claim to a stated non-claim** (§2 F4). The bound is
availability; what the root takes from the deadline is the honesty of the local outcome,
which is `sdk_python.local_failure_provenance`'s. The existing worst-case paragraph stays, as
a statement about a proposition registered beside the chain.

**C5 — a scope sentence excluding request-side attribution**, naming
`sdk_python.signer_policy` and `sdk_python.authorization_binding` as the units that hold it.

**C6 — state the trust-anchor completeness conjunct** (§2 F5), which the TypeScript member
states and this one does not, and which `sdk_python.trust_anchor_completeness` now carries.

Proposed text for all six is drafted; applying it is one edit to the entry followed by
`tools/verification/review --fingerprint THM-0094` for the record the review names.
