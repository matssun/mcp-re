<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-061 §14 review dispositions

The durable records that `config/module-size-debt.toml`'s `review_ref` fields point at.

A §14 record adjudicates a unit. It does **not** necessarily grant it an exception — this
register holds declined censuses too, because:

> **Investigation status and disposition are separate facts.** A completed census must stay
> distinguishable from an unperformed one, even when its disposition is *decompose before
> any exception*.

So a registry entry says one of three things about a unit over the 200-line threshold:

| status | meaning |
|---|---|
| `unreviewed` | over the threshold and **nobody has investigated it** |
| `reviewed-action-required` | investigated under ADR-061 §8; **specific architectural work identified**, and the record below names it |
| `reviewed-exception` | investigated under ADR-061 §8 and **deliberately kept intact**, with the record below saying why |

The lifecycle, enforced by `scripts/module_size_gate.py` against `origin/main`:

```text
unreviewed
    ├──> reviewed-exception
    └──> reviewed-action-required
              │  remediation + re-census
              ├──> reviewed-exception
              ├──> reviewed-action-required   (the re-census found more)
              └──> entry removed, once the unit is <= 200 production lines
```

Every permitted move preserves or increases what is known. **Nothing returns to
`unreviewed`** — that would tell the next reader nobody had looked.

Record IDs keep the `EX-` prefix. It is stable identity vocabulary — it names the record,
not its disposition — and identities are not churned because our understanding of the
register improved.

**Review granularity equals exception granularity.** A function-level exception does not
make its file a reviewed exception, and a ruling about one aspect of a unit does not close
the census of the rest of it. Each record below names exactly what was reviewed.

The register only records outcomes. The investigation procedure is ADR-061 §8; the campaign
order is [`README.md`](README.md).

## What a record must contain

`CLAUDE.md` states the B-case obligation: why decomposition would damage the reasoning,
what invariant requires locality, why the subordinate responsibilities cannot be separated,
and what tests or review evidence compensate for the size. **"It is complicated" is not an
exception.** A record that cannot answer those in concrete terms is a census that has not
finished, and its unit stays `unreviewed`.

---

## EX-001 — `mcp-re-proxy/src/exchange_state.rs`

**Status:** reviewed exception. **Measured:** 789 production lines on `main` @ `a735e8c`.
**Component blueprint:** [`components/exchange-lifecycle.md`](components/exchange-lifecycle.md) §10.

### §8 question 1 — what single fact does it own?

**Which exchange states are legal, and which transitions produce them.** The answer needs
no "and": the vocabulary, the relation over it, and the projections that read a position in
it are one fact stated once.

### §8 question 2 — how many independently describable authorities?

**One.** The module's contents are the relation and nothing else:

| item | role |
|---|---|
| `ExchangeState`, `ExchangeEvent`, `ContinuationState`, `BackendState`, `ResponseOrigin`, `OpenLeg`, `RetrySemantics` | the vocabulary the relation is defined over |
| `transition()`, `ExchangeEvent::establishes()` | the relation itself |
| `ExchangeProgress` + its projections (`state`, `continuation`, `origin`, `open_leg`, `retry_semantics`, `anomaly`, `invariant_violation`) | reading a position in the relation |
| `Established<T>` | the witness that a stage performed the work its event names |

None of these is describable without the others. A `RetrySemantics` that did not read a
state is not a projection of anything, and a vocabulary with no relation over it is a list
of names.

### Why decomposition would damage the reasoning

Splitting the relation from the vocabulary it ranges over produces two files that **must
agree**, with nothing enforcing that they do — a relation stated twice, which is ADR-061
§2's defect class 1 and the precise thing this module was created to remove. The module
doc records the history: each state used to be a position of the program counter, its name
existing only in a comment above the code that entered it, and one reachable combination
was unrepresented — a continuation consumed to enforce one-shot, followed by a refusal
before dispatch, where the approval is destroyed, the action never ran, and the retry-safe
reading is wrong in a way no local check could see.

Every subsequent split of this module re-opens the same seam.

### What invariant requires locality

`transition()` is **total over `(state, event)`**, and its totality is what makes
`invariant_violation()` and the anomaly latch meaningful — an illegal pair has a decided
outcome rather than a fallthrough. Totality is a property of one match over one pair of
enums. Distributing the arms across modules keeps the behaviour and destroys the ability to
see, in one place, that the relation is total.

### Why the subordinate responsibilities are not separable

They are already separated in the only direction that matters: this module decides
**nothing about a request**. It executes no I/O, transports no payload, and reconstructs no
fact another owner decided. Its consumers — the serving assembly, the stages — hold the
facts; it holds only what follows from them. There is no subordinate here to extract,
because there is no subordinate: the file is deep, not wide.

### What compensates for the size

| evidence | lane |
|---|---|
| `RELATION` and `PIPELINE` tables + `every_state_event_pair_has_a_decided_outcome` — totality is asserted, not assumed | `//mcp-re-proxy:proxy_unit_test` |
| End-to-end legality of the pipeline path and the open-leg path | `//mcp-re-proxy:proxy_unit_test` |
| Illegal `(state, event)` latches an anomaly | `//mcp-re-proxy:proxy_unit_test` |
| Tests derive from the same transition authority rather than a second table | `tests/integration/exchange_transition_ownership_test.rs` · `//mcp-re-proxy:integration_test` |
| A stage cannot emit a transition the work did not earn | `Established<T>` is `#[must_use]`; `establish()` is the only opener — compile time, every lane |

### What this record does **not** close

- The §7 **correspondence theorem** is still unwritten, and with it the scope sentence
  naming the five assembly-owned transitions the mechanism does not cover — issue #583.
- Nothing here is an exception for `http_profile_serve.rs`, which is a separate unit with
  a separate census (#586, #587).

---

## EX-002 — `mcp-re-proxy/src/app.rs` — **census complete, disposition: decompose first**

**Status:** `reviewed-action-required` — the census is complete and the disposition is
*decompose first*. **Remediation:** [#592](https://github.com/matssun/mcp-re/issues/592).
**Measured:** 1037 production lines on `main` @ `a735e8c`.

This record exists because the registry may not be changed on the strength of a
function-level ruling. `app.rs` carries a well-substantiated **function** exception for
`run_validated` (`#[allow(clippy::too_many_lines)]`, 531 lines, with the invariant, the
locality argument, and the compensating evidence stated at the item). That exception is
about `run_validated`. It says nothing about the other 500 production lines, and the
file-level census below is what those needed.

### §8 question 2 — how many independently describable authorities?

**Seven.** Five of them are thin, and the distinction is what decides this record.

| # | unit | decides | verdict |
|---|---|---|---|
| A | `run` / `run_validated` — the assembly | the order of effects, and the scope in which failure reclaims | the composition root itself; case-B, substantiated at the item |
| B | `build_actor_resolver` | which resolver answers which `SignerSlot` | composition — it wires owner-provided seams; R-COMPOSE permits it |
| C | `check_key_file_perms` / `process_gids` | nothing — `KeyFileAccessPolicy::violation` decides; this performs the `stat` and supplies the process gids | I/O the owner cannot perform; stays |
| D | `key_files_read_from_disk` | nothing — a pure projection over `CustodyState` + `TlsCustodyState` | stays; already pure and separately tested |
| E | `faulted_clock_refusal` | nothing — composes `CrlRevocationState::is_enforced()` with `startup_plan::host_clock_is_faulted` | composition; stays |
| F | `channel_binding_effects` | nothing — a total function of the recognised `ChannelBindingState` | stays |
| **G** | **`drain_audit_stream` / `audit_drain_line` / `AUDIT_FLUSH_TIMEOUT`** | **how long teardown waits, and whether the outcome is "drained" or "nobody can say"** | **separable — see below** |

### Why the census does not grant the exception

Authority **G** is not composition. It owns a bounded-teardown timeout, and it owns the
distinction between *every record reached stderr* and *the acknowledgement never came, so
neither outcome can be claimed*. That second property is the execution-certainty rule this
project holds elsewhere: a seam must preserve did-not-run vs unknown-if-ran until something
downstream has consumed it. Collapsing them into one "shutdown complete" line would destroy
exactly what an audit stream exists to preserve — and the code says so, in its own doc
comment.

An authority with its own constant, its own two-valued semantics, its own tests, and an
existing owner next door (`crate::audit_sink`, which already owns the flush) is not a unit
being *deliberately kept intact*. It is a unit nobody has moved yet.

ADR-061 §14 records a decision to keep something whole. It is not a place to park work. So
`app.rs` does not become `reviewed-exception`, and this record states precisely what
remains: **relocate authority G to the audit-sink owner, then re-run this census.**
Authorities B through F are closed by it and need not be re-argued.

Its status is `reviewed-action-required`, not `unreviewed`. Those are different facts and
the next agent must be able to tell them apart: nobody having looked, and having looked and
found named work, call for opposite next actions.

### The measurement worth keeping

`run_validated` is 531 of the file's 1037 production lines, and its own comment records
that 290 of those are code and the rest is the exception argument. A file-level number is
therefore a poor proxy for a file-level authority count here — which is ADR-061 §7 in one
unit: **size ordered this investigation; it did not decide it.**

---

## EX-003 — `mcp-re-http-profile/src/verify.rs` — **census complete, disposition: decompose first**

**Status:** `reviewed-action-required` pending owner security-specification review of the
theorem family. **Remediation:** ~~#571~~ and ~~#572~~ implemented (THM-0014 … THM-0022);
the disposition may move to `reviewed-exception` only once that review lands and this
census is re-run. **Measured:** 1360 production lines after the #572 review round (the two
delegated paths had verbatim copies of the credential-chain resolution, now one
`chain_to_root`); 1388 after #571; 1598 after #570; 1640 before any of them. **Component blueprint:**
[`components/evidence-verification.md`](components/evidence-verification.md).

Required by ADR-061 §5.3 before the work in [#570](https://github.com/matssun/mcp-re/issues/570):
a band-3 unit gets an authority census *before* substantial new functionality, not after.

### §8 question 2 — how many independently describable authorities?

**Four axes, multiplied into a flat public function list.** The interface answers the
question without reading the body:

| axis | values |
|---|---|
| assurance | cryptographic floor · full MCP-RE profile |
| direction | request · response |
| binding | bound · unbound |
| policy | default · explicit `VerifierPolicy` |

plus a delegated variant of three response forms — seventeen public items over one module.

### §8 questions 3–5 — decides, executes, transports

It **decides** two things: whether the cryptographic floor holds, and whether the full
profile's bindings hold. It **executes** signature-base reconstruction, digest comparison
and trust-seam resolution, all of which have owners (`sigbase`, `digest`, `keyid`, the
caller-supplied resolver). It **transports** nothing.

Two decisions, so question 1 needs an "and" — which ADR-061 §8 names as evidence of a
shallow authority boundary.

### §8 question 10 — facts represented more than once

The assurance level was represented **twice and inconsistently**: once in the name of the
function called, and once in whether three `Option` fields were populated. Nothing related
them, so a consumer that received the product could not recover which had run without a
runtime probe — and one did exactly that (`prepare_http_dispatch` failed closed on a
missing `audience_hash`, commented *"minimal-path evidence reached the dispatcher"*).

### §8 question 9 — branches unreachable under the current legality model

That probe. Its case is now unconstructible, so it is deleted rather than moved — the
ADR-061 §11 operational test applied to a real check.

### Disposition

The request half is done in #570 and the response half, with the `_with_policy` axis, in
#571 — `verify.rs` fell from 1640 to 1388 production lines and its public surface is now
one `Verifier`. The composition theorems the split makes expressible are #572.
`verify.rs` stays `reviewed-action-required` until that closes and this census is re-run:
the disposition records that work remains, not that nobody looked.

The #572 review round removed one more §8 question-10 duplicate: `delegated_bound_response`
and `delegated_unbound_response` carried **verbatim copies** of the credential-chain
resolution — the same `DelegationVerifyParams`, the same root-issuer closure, the same
outage/wrong-slot capture, and the same 10-line comment explaining it. Two copies of a
trust-resolution rule are two places for it to drift, and the mutation probe made that
concrete: a single slot mutation in the shared `chain_to_root` now breaks all 12 delegated
controls at once, where before it took two mutations to reach the same set.

### What the census found that the issue did not anticipate

- The Verus postcondition for THM-0009 was **guarded by the assurance ambiguity**:
  `request_block matches Some(block) ==> …` is vacuously true for a floor-verified request.
  The type split removes the guard, so the obligation is now unconditional.
- The verification unit's `paths` did not include the new product module, so a change to
  the type the proof reads would not have marked the theorem dirty. Corrected in
  `verification/policy/verification.toml`.
- Sealing the products is **not available**: Verus rejects private fields on a transparent
  datatype and cannot call accessors from verified code. Recorded in
  [`docs/dev/sealed-owners.md`](../dev/sealed-owners.md) as the second measurement of a
  rule that already existed — a proved postcondition outranks a seal.

---

## EX-004 — `mcp-re-proxy/src/tls.rs` — **census complete, disposition: decompose first**

**Status:** `reviewed-action-required`. **Remediation:** [#573](https://github.com/matssun/mcp-re/issues/573)
(the listener-lifetime security-state owner) then
[#574](https://github.com/matssun/mcp-re/issues/574) (the blocking HTTP/1 harness).
**Measured:** 1907 production lines on `063a0f8`, re-measured rather than carried over from
the issue text — an ADR-061 §5.3 **band-3** unit (>1,000), so this census is required before
the work, not after it. **Component blueprint:**
[`components/tls-and-transport-identity.md`](components/tls-and-transport-identity.md).

### §8 question 1 — what single security fact does it own?

There is no single answer, and the shortest honest one needs six "and"s: *the file owns the
serving TLS configuration **and** the client-verifier posture **and** the resumption-epoch
binding **and** offline CRL evidence **and** identity extraction from a leaf certificate
**and** the classification of why a connection was refused **and** a blocking HTTP/1
harness.* ADR-061 §8 names an answer needing an "and" as evidence of a shallow authority
boundary; this one needs six.

### §8 question 2 — how many independently describable authorities?

Eight. Size ordered the investigation; this count decides the outcome.

| # | authority | what it decides | ~prod lines |
|---|---|---|---:|
| A | **Listener security state** — `new_resumption_state`, `epoch_bound_resumption`, `NoStatelessTickets`, the four builders and their `_resuming` twins | whether a stored session is still a shortcut under current trust | ~230 |
| B | Client-verifier construction (`build_client_verifier`, the `fault_accept_any_client` bypass) | what a valid client certificate is | ~40 |
| C | Offline CRL evidence and freshness posture (`CrlFreshness`, `crl_freshness`, `CrlPosture`, `load_client_crls`) | whether revocation evidence may be relied on | ~230 |
| D | Identity extraction (`extract_identity`, `resolve_identity*`, `leaf_facts`) | which certificate field IS the peer's identity | ~180 |
| E | Connection-rejection classification (`connection_rejection*`, `cert_lifetime_rejection*`, `chain_issuers_*`, `ocsp_rejection`, `routing_header_rejection`, `assertion_header`) | the refusal token a peer is told | ~330 |
| F | Serving limits and options vocabulary (`ServerLimits`, `ServerOptions`, `IdentityStrategy`) | the DoS ceilings and the identity strategy | ~230 |
| G | **The blocking HTTP/1 harness** (`serve*`, `serve_connection`, `DeadlineStream`, `read_http_request`, `write_http_response`, framing helpers) | nothing security-relevant — it is a test harness | ~420 |
| H | Wall clock (`wall_clock_unix`) | the instant every validity check reads | ~28 |

A and G are the two the campaign already ruled on, and they are the two with the clearest
seams. This record closes the census; #573 and #574 are the work it identifies.

### §8 question 7 — security relationships existing only through call ordering

**This is the defect #573 exists to remove, and the code states it against itself.**

`tls_plane.rs` calls `tls::new_resumption_state(&client_ca)` once and holds the result
across every rebuild, so *the listener lifetime is the resumption authority*. Nothing says
so at a type. Meanwhile `RustlsDirectProvider::build_server_config_with_crls` — and both
delegated one-shot builders — call `new_resumption_state` **internally**, and
`new_resumption_state`'s own doc comment admits the consequence:

> A state created per build pairs a fresh epoch with a fresh empty cache, which discards
> every resumable session on each rebuild and leaves the epoch unable to move.

Two builders whose names differ by the suffix `_resuming` differ in whether ADR-055's epoch
is a live lever or a constant. The relationship holds today only because `tls_plane.rs`
happens to call the right one.

There is a second ordering relationship inside the surviving path. A rebuild passes
`state.client_ca.clone()` **and** `&state.resumption` as separate arguments, which must
agree — the anchors are the epoch's only input. Nothing but the call site relates them.

### §8 question 8 — public interface that exists only because tests need it

**The entire one-shot builder family.** No production code calls
`RustlsDirectProvider::build_server_config`, `build_server_config_with_crls`,
`build_server_config_delegated_with_crls` or `build_server_config_delegated_validated`.
Every caller is a test, including cross-crate ones in `mcp-re-transport/tests/`. Production
reaches TLS only through `tls_plane.rs` → the `_resuming` variants.

So the API surface that carries the degenerate epoch behaviour is also the surface with no
production consumer. That is what makes #573's ambiguity removable rather than a
compatibility problem: there is one production capability, not two.

Authority G is the same finding at file scale — `serve_once`'s own doc says *"the shipped
proxy does not use it"*.

### §8 question 9 — branches unreachable under the current legality model

`epoch_bound_resumption`'s `if let Some(previous) = resumption.republish(epoch)` branch, and
the operator log line inside it, are **unreachable in production today**. Within a listener
the anchor set is fixed at `TlsRebuildState::new`, and every rebuild republishes the same
digest; a trust-anchor change produces a new plane with a new store, which discards the
cache wholesale rather than moving the epoch. The mechanism that actually prevents stale
resumption across an anchor change is store replacement, not epoch advance.

The epoch-mismatch eviction is still exercised, but only by
`tls_listener_state::resumption_acceptance` (an integration test at census time; moved
inside the owner's seal by #573), which drives `SharedTlsAuthEpoch::store` directly. **That is a claim about the store, not about the plane**, and #573 must not
quietly convert it into a claim about the plane.

This is recorded, not acted on. Deciding whether the epoch should become a live
listener-lifetime lever (an anchor-reload path) or an acknowledged construction-time
constant is an ADR-055 question and needs owner review; #573's scope is ownership, not
epoch lifecycle.

### §8 question 10 — facts represented more than once

The trusted client-CA set is held by `TlsRebuildState.client_ca` **and** digested into the
epoch the store publishes, with only the call site relating them. Both `_resuming` builders
recompute `TlsAuthEpoch::compute(&client_ca)` from the anchors they were handed rather than
reading the epoch the store already holds.

### §8 question 11 — inconsistent values a caller can construct

`TlsAuthEpoch`, `SharedTlsAuthEpoch` and `EpochBoundSessionStore` are `pub` with `pub`
constructors, so a caller can assemble a store under any epoch and hand it to any build.
`new_resumption_state` is `pub(crate)`, which binds nothing inside this crate. The forbidden
combination — a fresh cache paired with an epoch unrelated to the verifier installed beside
it — is constructible today, and is what #573 must make unconstructible rather than
detectable.

### §8 questions 3–6, 12

It **decides** the resumption gate, the verifier posture, the identity field, and the
refusal token. It **executes** rustls configuration and socket I/O. It **transports** the
extracted identity to the handler. It **reconstructs** nothing another owner already
decided, except the epoch, which it recomputes per build from anchors the store's owner
already holds (question 6, and the question-10 duplicate above). The lanes that establish
its properties are `cargo test -p mcp-re-proxy` for the unit tests,
`//mcp-re-proxy:integration_test` for the epoch-resumption control, and
`//mcp-re-proxy:fault_injection_test` for the deliberately-broken client-auth control
(question 12).

### Disposition

`reviewed-action-required`. Eight authorities, two with identified owners next door: the
listener-lifetime security state (#573) and the blocking harness (#574). A §14 exception is
declined — this record does not grant one, and the file stays in the debt registry until
those land and this census is re-run.

### What #573 changed, measured

`tls.rs` **1907 → 1565** production lines; `tls_plane.rs` 679 → 623. The owner's tree is
measured in EX-005, which is the record that owns those numbers.

Authority A left the file entirely, into a module TREE under the owner
(`assembly`, `auth_epoch`, `client_verifier`, `resumption_binding`,
`resumption_acceptance`), every member `pub(super)`. Authority B — the client verifier —
went with it, since after the move its only callers were there.

The first attempt left those as `pub(crate)` in `tls.rs` and kept `tls_auth_epoch` a `pub`
sibling, while claiming the pairing was unconstructible. Review caught it: `pub(crate)`
seals against nobody when every consumer lives in the crate, so any module could assemble a
verifier over anchors A, build a store over epoch B, and pair them. The subordinates moved
INTO the owner rather than being described as subordinate. The residual limit is foreign
and is now stated rather than papered over — `rustls::ServerConfig::session_storage` is a
public field of a type this project does not own.

Each question above, answered by the change:

- **Q7 (both instances).** A build is now a method on `TlsListenerSecurityState`. The
  anchors and the store are never separately passable, so neither ordering relationship
  survives.
- **Q8.** The one-shot family is deleted, along with the `RustlsDirectProvider` marker it
  hung off, which held nothing else. Nineteen call sites across five crates migrated to
  the owner; every one was a test, which is the census finding confirming itself.
- **Q9.** Untouched, deliberately. `republish` stays under the owner and is now called with
  the epoch the store already holds, so it is a visible no-op rather than a recomputation
  that might look like a live lever. Whether the epoch SHOULD be one is an ADR-055
  lifecycle question, recorded separately.
- **Q10.** The anchors are held once; the epoch is derived once, in the constructor. The
  mutation probe found this mattered: while `bind_resumption` recomputed the digest, a
  corrupted constructor epoch was silently CORRECTED by the first build, so the constructor
  looked load-bearing only until a config was built through it.
- **Q11.** `EpochBoundSessionStore` is still publicly constructible — the real-handshake
  acceptance test builds one, and a store in isolation is not an illegal value. What is now
  unconstructible is the illegal value: *a serving config whose cache is unrelated to the
  anchors its verifier was built from*. No public path installs a store on a config.

The ownership is measured rather than asserted. `proxy.tls_listener_state` is a class-V0
review unit carrying `test://` and `mutation://` evidence, so it cannot be attested without
a mutation PASS at its exact fingerprint, and FOUR registered probes each turn a declared
control red: a store created per build (T01), an epoch derived from anything but the owner's
anchors (T02), an enabled stateless ticketer that would resume outside the store at all
(T03), and a signing budget created per delegated rebuild (T04).

T04 exists because review found the budget named among the four things "established
together" while nothing asked what breaks if a rebuild recreates it — a conjunct asserted in
prose on a V0 unit. Making it load-bearing needed the delegated seam to return the CONCRETE
resolver, since `DelegatedCertResolver::budget()` is the only handle on which budget a build
actually used.

The unit's `paths` reach `tls.rs`, `tls_plane.rs` and `delegated_tls.rs` as well as the
owner's tree. The first version named the owner and the epoch module only — and T03 mutates
`tls.rs`, so an edit there could have weakened the resumption binding while the fingerprint
stood still. Same false-freshness class as the one #596 closed.

The eviction property itself did not move. It is a claim about the STORE, asserted by
`tls_listener_state::auth_epoch`'s unit tests and by
`tls_listener_state::resumption_acceptance` driving real rustls handshakes — both now
inside the owner's privacy boundary, because keeping the acceptance test outside would have
kept the subordinates `pub`. `tls.rs`'s `epoch_binding_tests` had been asserting the same
thing a third time through the builder, and that duplicate is gone rather than relocated.

**The lifecycle question this census raised is now ruled.**
[ADR-MCPRE-062](https://github.com/matssun/mcp-re/discussions/599) supersedes ADR-055 and
selects immutable listener / store replacement. #573 conforms to it structurally and does
not retire the dormant machinery; that is #598, deliberately a separate diff. Question 9
above stands as the census finding that produced the ruling.

---

## EX-005 — `mcp-re-proxy/src/tls_listener_state/mod.rs` — **reviewed exception**

**Status:** `reviewed-exception`. **Measured:** 223 production lines, of which **85 are
code**; the remaining 138 are the module note and the item documentation. Created by
MCPRE-137 / #573; the parent census is EX-004.

### Why this is a B-case and not a shave

The unit is what is LEFT after five extractions, not a unit that was never examined. The
listener-state authority was decomposed into siblings first, and each of them is under the
threshold:

Measured by `scripts/module_size_gate.py::production_lines` on this head — re-rendered from
the counter rather than carried forward, because a stale number in a durable review record
is how a census stops being reliable:

| module | prod | what it decides |
|---|---:|---|
| `assembly.rs` | 112 | what the serving config IS |
| `auth_epoch.rs` | 270 | the epoch value, and the store tagged with it (pre-existing debt, carried across the rename) |
| `client_verifier.rs` | 60 | what a valid client certificate is |
| `resumption_binding.rs` | 111 | whether a stored session is still a shortcut |
| `resumption_acceptance.rs` | 29 | (test-only; the handshake controls are inside a `#[cfg(test)]` region) |
| `mod.rs` | **223** | that all four facts belong to one listener |

### What invariant requires locality

The owner's whole claim is a FOUR-WAY RELATION: anchors, the epoch they digest to, the
cache tagged with it, and the signing budget, established together and unsplittable. The
things that make it unsplittable are the build methods — `docs/dev/sealed-owners.md` records
that for this owner **the projections ARE the operations**, because a fact projection would
hand the terms of the relation back as independently passable arguments.

So the field declarations and the only code permitted to read them must be readable
together. A reviewer's question is *"can a caller obtain these separately?"*, and the answer
is only checkable by seeing the private fields and every method that touches them on one
screen. Moving the build methods to a child module would keep them compiling — a child sees
its parent's privates — while splitting the question across two files. That is the reasoning
the decomposition would damage.

### Why the subordinate responsibilities cannot be separated further

They already have been. What remains is a constructor, one read projection, three build
methods, and two private seams; there is no second authority inside it. §8 question 2 gives
the answer **one**, with no "and".

### What compensates for the size

`proxy.tls_listener_state` is a class-V0 review unit carrying **both** `test://` and
`mutation://` evidence, so `attest` refuses it without a mutation PASS at its exact
fingerprint. Four registered probes each turn a declared control red:

| probe | weakening | control |
|---|---|---|
| T01 | a session store created per build | `a_rebuild_keeps_the_cache_and_the_epoch_of_the_state_it_was_built_through` |
| T02 | the epoch derived from anything but the owner's anchors | `the_epoch_digests_the_anchors_this_state_owns`, `a_different_anchor_set_is_a_different_state_with_its_own_empty_cache` |
| T03 | an enabled stateless ticketer, resuming outside the store | `no_config_this_owner_builds_can_resume_outside_the_store` |
| T04 | a signing budget created per delegated build | `a_delegated_rebuild_reuses_the_listeners_signing_budget` |

### What this record does not close

It is an exception for **this file at this size**, not for the subtree and not for
`tls.rs` — EX-004 stays `reviewed-action-required` until #574 lands and its census is
re-run. Review granularity equals exception granularity.
