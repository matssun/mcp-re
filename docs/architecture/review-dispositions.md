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
**Measured:** 1037 production lines on `main` @ `a735e8c`; **977 after the authority-A
relocation** (MCPRE-154).

### Update — authority A relocated (MCPRE-154)

The shutdown-drain authority has left this file. `AUDIT_FLUSH_TIMEOUT`, the bounded wait
and the reported outcome now live in `crate::audit_sink::drain`, together with
`flush_stderr_audit`, which moved to join them: the bound, the wait and the meaning of the
result are one authority and the composition root held two thirds of it.

The relocation also replaced the `bool` the wait returned with a two-case `AuditDrain`.
`false` there meant *the acknowledgement never came*, which is not the negation of
*drained* — it invited a reader to treat the unknown case as the failure case, and that
collapse is what an audit stream exists to prevent.

`app.rs` now calls one operation and reinterprets nothing. The teardown-ordering test
stays here on purpose: it asserts that `run` discharges the obligation on **every route
out of it**, which is a property of the composition root and not of the drain owner. The
owner's own tests assert what the two outcomes mean.

**The file-level §8 census has NOT been re-run**, so this record's remaining findings stand
as written and the status stays `reviewed-action-required`. Whether another separable
authority remains is exactly the question the re-census must answer, and predetermining it
here would be the thing this register exists to prevent.

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
| D | `key_files_read_from_disk` | nothing — a pure projection over `CustodyState` + `ChannelCredentialCustodyState` | stays; already pure and separately tested |
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

### EX-002 re-census after MCPRE-154 — **disposition changes to `reviewed-exception`**

The census this record declined to close is re-run, on the post-relocation tree, at **977**
production lines. Authority G has left for `crate::audit_sink::drain` with its constant, its
bounded wait and its two-valued outcome, and `app.rs` now calls one operation and
reinterprets nothing.

### §8 question 2 — how many independently describable authorities?

**One**, and it is the composition root itself.

| # | unit | decides | verdict |
|---|---|---|---|
| A | `run` / `run_validated` / `fleet_config` / `serve_fleet` | the order of effects, and the scope in which failure reclaims | **the composition root**; case-B, substantiated at `run_validated` |
| B | `build_actor_resolver` | which resolver answers which `SignerSlot` | composition — wires owner-provided seams; R-COMPOSE permits it |
| C | `check_key_file_perms` / `process_gids` | nothing — `KeyFileAccessPolicy::violation` decides | I/O the owner cannot perform |
| D | `key_files_read_from_disk` | nothing — a pure projection over two custody states | already pure and separately tested |
| E | `faulted_clock_refusal` | nothing — composes two owners' answers | composition |
| F | `channel_binding_effects` | nothing — a total function of the recognised `ChannelBindingState` | composition |

B through F were closed by the original census and are not re-argued. What changed is that
the one row that was **not** composition is gone, so the answer to question 2 is no longer
greater than one.

### Why this is now a B-case

The original record's reason for declining was specific and it has been discharged: *an
authority with its own constant, its own two-valued semantics, its own tests, and an
existing owner next door is not a unit deliberately kept intact — it is one nobody has
moved.* It has been moved.

What remains is a composition root and five thin projections over it, and R-COMPOSE
explicitly permits a root to combine owner-provided facts. Decomposing further would
relocate flat authority rather than remove it — the shape ADR-MCPRE-061 §3.4 warns against
— because there is no second authority left to give the pieces to.

**Size did not decide this.** 977 lines is not the argument, and it is worth saying why the
number is a poor proxy here: `run_validated` is 531 of them and its own comment records that
290 are code and the rest is the exception argument it carries at the item. A file-level line
count that is 55% one function's justification text is measuring documentation.

### What the exception does NOT cover

Review granularity equals exception granularity, in both directions. This record grants a
**file-level** exception to `app.rs`; it does not extend to any function inside it, and
`run_validated` keeps its own separately-substantiated item-level exception on
`clippy::too_many_lines`. Neither licenses growth: the ratchet applies to a
`reviewed-exception` entry exactly as it does to an unreviewed one.

One item is recorded as INBOUND rather than outbound: EX-007's disposition moves
`key_file_mode_is_insecure` **to** whichever owner performs the permission check, which is
authority C here. That is a cli.rs slice, and it will make this file's composition slightly
larger rather than smaller.

**Remediation [#592](https://github.com/matssun/mcp-re/issues/592) is complete.**


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

### EX-003 re-census after the hierarchy work

The disposition is implemented. `verify.rs` no longer exists: 1373 production lines became
**21 modules** under `verify/`, every one of them under the 200-line threshold, so the debt
entry is REMOVED rather than moved — a debt that is paid leaves the registry.

| | prod | what single fact it owns |
|---|---:|---|
| `verify/mod.rs` | 50 | the assembly, and the two-proposition argument |
| `floor/mod.rs` | 55 | *these bytes are what a trusted key signed, window current* |
| `floor/sf_dictionary.rs` | 138 | RFC 8941: one spelling, one value per label |
| `floor/signature_input.rs` | 66 | RFC 9421: the member value's shape |
| `floor/covered_components.rs` | 111 | the closed identifier set, each named once |
| `floor/signature_parameters.rs` | 179 | the closed, ORDERED parameter set |
| `floor/components.rs` | 80 | what the signature must cover |
| `floor/transport_headers.rs` | 64 | §4.1: a covered routing claim may not lie about the body |
| `floor/params.rs` | 107 | what this verifier ACCEPTS vs what the signer SAID (THM-0001) |
| `floor/trust_slot.rs` | 45 | the keyid was vouched for THIS slot |
| `floor/signature.rs` | 70 | the allowlisted algorithm is the one that runs |
| `floor/request.rs` | 147 | the request floor (THM-0014) |
| `floor/response.rs` | 140 | the response floors, bound and unbound (THM-0016/0017) |
| `full/mod.rs` | 30 | *…and it is an MCP-RE statement to act on* |
| `full/request.rs` | 122 | block validation, audience/target, artifact binding (THM-0015) |
| `full/response.rs` | 67 | signer correspondence and evidence agreement (THM-0018) |
| `full/delegated/mod.rs` | 49 | why delegated does not inherit the direct claims |
| `full/delegated/expectations.rs` | 27 | what the deployment expects of the CREDENTIAL |
| `full/delegated/credential_chain.rs` | 91 | the credential chains to a trusted root (§3 2–7) |
| `full/delegated/bound.rs` | 158 | …and answers THIS request (THM-0019) |
| `full/delegated/unbound.rs` | 140 | …and claims no binding, `;req` refused (THM-0020) |

The sum rose from 1373 to 1936. That is 21 module headers each stating the one fact its
module owns — precisely what the census found missing when four axes were multiplied into a
flat function list — and it is not headroom: no entry is left in the registry to grow into,
and a new file over 200 fails outright.

**The strongest evidence that the split followed the authority boundaries is the probe
registry, and it was not planned for.** Each of the 26 `verify.rs` mutation probes anchors
on the exact text of the check its conjunct names. Re-pointing them was mechanical — every
anchor resolved to **exactly one** of the new modules, and every one landed in the module
its conjunct is about: `M27-algorithm-allowlist` in `params.rs`, `M13-chain-to-root-issuer-slot-seam`
in `credential_chain.rs`, the six `M18…M24` unbound-delegated probes in `unbound.rs`. A
decomposition that had cut across the security argument would have produced anchors matching
zero files, or two.

`tools/verification/verify-mutations` then reports **PASS — 58 probes, each turning a
declared control red**, so no conjunct lost its protection in the move.

### What was deliberately NOT done

- **The four response paths keep their duplicated preamble.** `floor_bound_response`,
  `floor_unbound_response`, `delegated_bound_response` and `delegated_unbound_response` each
  repeat content-encoding, media-type, content-digest, parse, components and params. Folding
  them into one helper is the obvious LOC win and it would collapse **eight separately
  probed conjuncts into two** — M25/M12/M20 (content-digest ×3), M07/M11/M16/M19 (signature
  ×4), M10/M18 (`;req` refusal ×2) — trading the isolation the whole V0 argument rests on
  for a smaller diff. The registry already records one such coarse probe as *a coverage
  fact, not an isolation one*; manufacturing seven more would be the reverse of what this
  campaign is for.
- **`ResolvedActor` is still unsealed** (deviation 2), and `sigbase` is still a public
  module: the conformance KAT oracle reconstructs the exact RFC 9421 signature base through
  it, which is a consumer contract and not an accident of layering. Deviation 6 predicted
  it would become subordinate "when the floor gets its own module" — the floor now has one,
  and the answer is that `sigbase` is a subordinate of the floor in the DEPENDENCY sense
  while remaining public in the API sense. Those are different questions and only the first
  one moved.
- **No theorem was touched.** THM-0008 stays as it is, no claim was added, and no scope
  sentence changed. Paths in `verification.toml` and `mutation-probes.toml` moved because
  the sources did, which is maintenance of a measurement, not a claim.

### Disposition after the re-census

`verify.rs` is gone and no successor is over the threshold, so there is nothing left for
this record to hold `reviewed-action-required` over. §8 question 2 now answers **one** for
every module in the table — that was the test, and the twenty-one one-line answers above are
the result. The remaining EX-003 obligation is unchanged and is not structural: the owner
security-specification review of the THM-0014 … THM-0022 family, which this campaign was
instructed not to perform.

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
| F | Serving limits and options vocabulary (`ServerLimits`, `ServerOptions`, `PeerIdentityProvenance`) | the DoS ceilings and where a peer identity comes from | ~230 |
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

### What #574 changed, measured

`tls.rs` **1565 → 1068** production lines. Authority G — the blocking mTLS + hand-rolled
HTTP/1.1 harness — left the file into `blocking_mtls_harness/`, a four-module tree whose
members are all under the threshold: `mod.rs` 145 (the accept policy and the three entry
points), `connection.rs` 124 (one served connection, plus the adapters), `http1.rs` 187
(the framing), `deadline_stream.rs` 98 (the aggregate read deadline).

The relocation is justified by ownership. The harness owns no authentication policy: it
holds the live `ServerConnection`, so it is the only code that can produce a peer chain
from one, but every decision made from that chain is called in `tls.rs` and not
reimplemented. Three connection-shaped functions that used to live in the authority —
`connection_identity`, `resolve_identity` and `cert_lifetime_rejection` — were adapters
around the chain-form functions the async fleet already used, and they are gone rather
than moved: the harness now calls `resolve_identity_from_leaf` and
`cert_lifetime_rejection_for_chain` directly. `resolve_identity_from_leaf` consequently
lost its `allow(dead_code)` — the census claim that both paths reach the same verdict from
the same input is now structural rather than documented.

One function was reshaped instead of moved. `ocsp_rejection` took a `&ServerConnection`,
so moving it would have taken the online-OCSP fail-closed policy — which verdicts reject,
and what an unobtainable verdict means — out of the authority with the harness. It is now
`ocsp_rejection_for_chain`, matched to its sibling guards, and stays. Neither serving
path's behaviour changes: the async chain form still does not include the OCSP arm, which
remains the tracked `async_serve` + `online_ocsp` gap.

The per-connection sequence had been written twice, once per entry point (§8 question 10 at
harness scale): `serve_once_with_assertion` and `serve_connection` differed only in which
handler arity they called and where the socket came from. They are one
`connection::serve_one` now, so a guard cannot be present on one blocking path and absent
from the other. `serve`'s handler ignores the assertion argument, exactly as before.

`serve`, `serve_once` and `serve_once_with_assertion` remain exported from the crate root —
embedders already import them there — but their provenance is `blocking_mtls_harness`, and
no test-only consumer forces an export out of `tls`.

### EX-004 re-census after #574

Re-measured on the post-#574 tree, not carried forward. `tls.rs` is 1068 production lines
across **six** describable authorities plus a shared error vocabulary and one feature-gated
control:

| authority | prod | what single fact it owns |
|---|---:|---|
| serving options record | 225 | the per-connection resource bounds and identity strategy a listener serves under |
| per-request peer admission | 271 | whether this peer chain may be served this request |
| CRL file posture | 118 | whether a revocation list is loadable, parseable and fresh enough to rely on |
| delegated resolver validation | 93 | that a delegated signer's public key is the one in the served leaf |
| identity extraction | 67 | what verified identity a leaf certificate carries |
| header hygiene | 72 | which request headers may be trusted and which are illegal |
| `TlsError` | 31 | the refusal vocabulary (shared, not an authority) |
| `fault_accept_any` | ~98 | the deliberately-broken client-auth control (feature-gated) |

Two authorities left the file across #573 and #574 and the remaining six did not become one
authority by their departure — question 2's answer is still greater than one, so **the
disposition stays `reviewed-action-required`**. This record continues to decline a §14
exception.

It does **not** schedule further decomposition. The two units that moved were selected
because they had clear semantic seams and owners next door; nothing measured here
establishes that any of the remaining six is the next one, and the largest number in the
table is a documentation-heavy configuration record, not the widest authority. Whether to
open a third extraction is an owner decision on this evidence, not a consequence of the
line count.

### EX-004 re-census after ADR-MCPRE-063 Slice 1 (#602)

`tls.rs` is **1042** production lines. Identity extraction left, and the way it left is the
point: it was not moved to a neighbouring file, it was migrated into a designed authority
graph, leaving a facade that owns nothing.

| authority | prod | change |
|---|---:|---|
| identity extraction | 67 → ~20 (facade) | **migrated** to `communication_assurance` — parses, selects and validates nothing here |

That is the first entry in this table whose disposition came from a decision about the
architecture rather than from the file's own census, and it changes what the remaining rows
mean. This record's closing paragraph said the next extraction was an owner decision "on
this evidence"; the owner's answer was that the evidence is the wrong instrument. Which
authority moves next is now selected by [ADR-MCPRE-063](https://github.com/matssun/mcp-re/discussions/601)
and [`../architecture/communication-assurance.md`](communication-assurance.md) §9, from the
semantic graph — not from this table's line counts, and not from physical adjacency to what
just moved.

The disposition **stays `reviewed-action-required`**, and the registry entry was ratcheted
from 1068 to 1042. Five authorities plus the shared vocabulary remain; question 2's answer
is still greater than one, and this record still declines a §14 exception.

---

## EX-005 — `mcp-re-proxy/src/tls_listener_state/mod.rs` — **reviewed exception**

**Status:** `reviewed-exception`. **Measured:** 223 production lines, of which **85 are
code**; the remaining 138 are the module note and the item documentation. Created by
MCPRE-137 / #573; the parent census is EX-004.

### Why this is a B-case and not a shave

The unit is what is LEFT after five extractions, not a unit that was never examined. The
listener-state authority was decomposed into independently reviewable subordinates first.
All newly extracted responsibilities are below the threshold except `auth_epoch.rs`, whose
pre-existing 270-line debt remains independently registered and unreviewed:

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

## EX-004 — `mcp-re-http-profile/src/scitt.rs` — **census complete, disposition: decompose**

**Status:** `reviewed-action-required`. **Measured:** 1629 production lines on `main` @
`0a24acc` (`scripts/module_size_gate.py::production_lines`); 3081 total. **Component
blueprint:** [`components/scitt-transparency.md`](components/scitt-transparency.md), which
carries all twelve answers, the theorem and test/lane inventories, and the proposed split.
**Census issue:** [#575](https://github.com/matssun/mcp-re/issues/575) (MCPRE-139), the
first of the six blueprint censuses in the ADR-061 §5.3 size order.

### §8 question 1 — what single fact does it own?

None. The nearest single sentence — *a portable, offline-verifiable record of a call's
evidence* — needs an "and" at seven clauses, which §8 names as the evidence of a shallow
authority boundary.

### §8 question 2 — how many independently describable authorities?

**Seven**, plus a shared wire vocabulary and one composition function:

| authority | proposition | lines |
|---|---|---|
| evidence commitment | which digests a record commits to, and whether it identifies a verified call | 135 |
| SCITT statement type | this COSE_Sign1 is MCP-RE call evidence, attributed to its signing key | 209 |
| receipt wire form | these are a well-formed RFC 9942 receipt's fields | 201 |
| RFC 9162 Merkle proof | this path folds this leaf to this root at this position | 166 |
| COSE verification | valid under a key whose algorithm the header agrees with | 150 |
| retained correspondence | these bytes are the ones that statement was made about | 187 |
| service trust pin | the key an interop run verified against, and its provenance | 120 |

### §8 question 11 — what inconsistent values can callers construct?

The finding that outranks the size. **Four types state invariants their representations do
not hold**: `EvidenceCommitment` (all seven fields `pub`, so a `complete` label can be
paired with unrelated handles), `ResolvedTransparencyService` (whose own doc says the key
and the profiles "travel together" while all three fields are `pub`),
`CoseVerificationKey::EcdsaP256` (struct-literal construction bypasses the on-curve check —
mitigated by a re-check at verify time), and `ScittServiceTrustPin` (an illegal `EdDSA`-plus-`y`
pin is constructible and refused only when read).

`SignedStatement` and `Receipt` are the counter-examples in the same file: private
representation, `from_cose` the sole producer. The split is what makes the other four
reachable the same way.

### §8 question 8 — what public interface exists only because tests need it?

`PrototypeTransparencyService` — `pub`, re-exported at the crate root, documented "NOT a
production ledger", and used by three call sites, all tests.

### §8 question 12 — which lane establishes each property?

36 in-crate unit tests, 21 conformance tests, 8 proxy e2e tests, every lane executed for
this census and reporting non-zero. **Zero of the 33 theorem-registry entries concern this
unit** — the gap is the stated propositions, not the testing.

### Why the census does not grant an exception

A §14 exception must show that keeping the unit whole makes the security argument
*materially clearer*. Here the opposite is measurable: the retained-correspondence authority
re-explains the commitment's identity fields, the receipt accessors re-explain the Merkle
fold's limits, and the position rule is explained in three places because no unit owns it.
That is the cost of the size, written down in the file itself.

### Disposition

**Decompose**, along the seven authorities, and use the split to seal the four types in
question 11. `scitt.rs` stays `reviewed-action-required` until that work lands and this
census is re-run. The remediation issues are not opened by this census — ADR-061 orders the
campaign, and a census recommends and stops.

### Slice 1 (MCPRE-155) — the four question-11 types, answered

Ruling 1 of [#657](https://github.com/matssun/mcp-re/issues/657) puts the seals before the
file boundaries, because *file boundaries do not by themselves remove a single constructible
illegal value*. Three of the four are now unconstructible; the fourth turned out not to be
sealable, and saying so is the result rather than a shortfall.

| type | before | after |
|---|---|---|
| `CoseVerificationKey::EcdsaP256` | `{ x: [u8;32], y: [u8;32] }` — a struct literal could name two numbers that are not a point, and `from_ec2_p256` checked and then discarded the parsed key | carries a **`P256Point`** whose representation IS the decoded `VerifyingKey`. The decode is the proof; §11's operational test passes |
| `ScittServiceTrustPin` | every field `pub`; an `EdDSA` pin carrying an `ES256` `y` was constructible and refused only if somebody called `verification_key` | private representation behind a private `PinDocument` + `TryFrom`, so the `(algorithm, public_key)` PAIR is checked on the way in and `verification_key` is **infallible** |
| `EvidenceCommitment` | seven `pub` fields, so a `complete` label could be paired with an unrelated call's handles | private, **two named producers**: `from_reconstruction` (derived from one reconstruction) and `Deserialize` (a received CLAIM, trusted only after the issuer's COSE_Sign1 verifies) |
| `ResolvedTransparencyService` | all three `pub` while its own doc says they "travel together" | **not sealable** — see below |

`ResolvedTransparencyService` reaches `verify_receipt_offline` through a
`Fn(&str) -> Option<ResolvedTransparencyService>` seam, and there is a real second producer
with no pin behind it: the in-process `PrototypeTransparencyService` the conformance corpora
are built from. Against a seam, a private field only forces a constructor taking the same
arguments with the same absence of checking — ADR-061's *if this value is illegal, whose bug
is it?* answers "whoever implemented the resolver". The fields are private and the two
producers are NAMED (`pinned`, and `stated` whose name is its contract), which buys
legibility at every call site and not unconstructibility. That is the third measurement of
the rule in [`docs/dev/sealed-owners.md`](../dev/sealed-owners.md), and the first where the
seam's second producer is a shipped type rather than a test.

**Two things the seal changed elsewhere, both of them the boundary detector working:**

- `verify_retained_evidence`'s seven-field comparison became
  `EvidenceCommitment::corresponds_to`. Destructuring an owner to recreate a security
  relation is R-COMPOSE's failure mode, and it was live here: adding a field to the record
  left the comparison silently weaker until somebody remembered to extend it. It is now a
  compile error in one place.
- The conformance negative fixtures stopped mutating a parsed pin and now edit the pin
  **document** before parsing. That is the more faithful test: a pin an operator could ship
  by mistake, rather than a value that could only ever have existed in memory. The committed
  interop verdict tokens are unchanged, because both corpora pin `EdDSA` keys and the edits
  stay legal documents.

`scitt.rs` stays `reviewed-action-required`: the decomposition is the next slice, and this
record is not a re-census.

### Slice 2 (MCPRE-155) — the decomposition, and the EX-004 re-census

`scitt.rs` no longer exists: 1629 production lines became **18 modules** under `scitt/`,
every one under the 200-line threshold, so the debt entry is REMOVED rather than moved.

| module | prod | the one fact it owns |
|---|---:|---|
| `scitt/mod.rs` | 135 | the facade — it re-exports and owns nothing |
| `commitment/mod.rs` | 198 | A · which digests a record names, and whether they identify a call |
| `commitment/correspondence.rs` | 90 | when two commitments describe the same call |
| `wire.rs` | 134 | the COSE/CWT labels and byte layouts both sides must agree on |
| `statement/mod.rs` | 173 | B · this COSE_Sign1 is MCP-RE call evidence, attributed to its key |
| `statement/issuance.rs` | 87 | the bytes an issuer signs, and the header that types them |
| `receipt/mod.rs` | 132 | C · the receipt value and its projections |
| `receipt/parse.rs` | 149 | reading an RFC 9942 receipt off the wire |
| `merkle.rs` | 168 | D · this path folds this leaf to this root at this position |
| `cose_key/mod.rs` | 115 | E · what a COSE verification key is |
| `cose_key/verify.rs` | 106 | the allowlisted algorithm is the one that runs |
| `service.rs` | 87 | the key + profiles that go together for ONE service |
| `offline.rs` | 115 | the composition: verified offline, contacting nobody |
| `retained.rs` | 154 | F · these bytes are the ones that statement was made about |
| `trust_pin/mod.rs` | 117 | G · the key an interop run verified against |
| `trust_pin/document.rs` | 130 | the pin AS WRITTEN, and the one check that makes it a pin |
| `prototype/mod.rs` | 155 | the in-process stand-in — NOT a product |
| `prototype/tree.rs` | 66 | the RFC 6962 tree, BUILT — the build side of the cross-check |

**Ruling 2 is honoured: seven authorities did not become seven public modules.** Every
subordinate is `mod`, not `pub mod`; `scitt/mod.rs` is the facade and the crate's public
surface is unchanged, item for item.

**Four subtrees, and each has a reason that is not size.**

- `commitment/correspondence.rs` is a CHILD so it can see the parent's private
  representation. That is what keeps R-COMPOSE satisfied in both directions: the
  correspondence authority next door consumes a named verdict, and a field added to the
  record is a compile error in one place rather than a comparison that quietly stopped
  covering it.
- `statement/issuance.rs` is the other DIRECTION — reading must refuse everything it does
  not recognise, issuing must emit exactly one spelling of what it means.
- `receipt/parse.rs` is the receipt's sole producer and fills the private representation
  directly; anywhere else it would need a constructor taking every field, which is the seal
  undone to move a function.
- `prototype/tree.rs` gives the BUILD half of ruling 3's cross-check a name, so the
  independence is a fact about the architecture rather than about where two functions
  happen to sit.

**The test suite was partitioned, not moved wholesale.** The 63 test items became each
owner's own `mod tests`, over a shared `#[cfg(test)] mod fixtures` in the facade — inline
rather than a file, because `module_size_gate.py` reads FILES and cannot see a
`#[cfg(test)]` on a `mod` line, so a fixture file would have been measured as 260 lines of
production code. All 263 lib tests pass, the same count as before the split.

**Three `#[cfg(test)] pub(super)` affordances were added** rather than widening production
visibility: `EvidenceCommitment::verified_prefix_fields` and `without_submission_identity`,
`SignedStatement::with_edited_view`, and `Receipt::with_forged_inclusion_path`. Each exists
because a test that previously mutated a private field across what is now a module boundary
needs a named way to build the value it is about — and each compiles to nothing outside the
test build, so none is production surface.

### EX-004 disposition after the re-census

The census declined an exception on the ground that keeping the unit whole made the argument
*worse*, measurably: "the retained-correspondence authority re-explains the commitment's
identity fields, the receipt accessors re-explain the Merkle fold's limits, and the position
rule is explained in three places because no unit owns it". Each of those now has an owner,
and §8 question 1 has an 18-row answer with no "and" in it.

What remains for EX-004 is not structural: the theorem inventory is still **zero of 33**,
and #657 ruling 6 says to state propositions against these owners rather than against the
monolith — which is now possible for the first time. `PrototypeTransparencyService` still
needs classifying (ruling 4), and `ReceiptPositionProfile::Bound` is still not selectable
(ruling 5). Neither is this slice's.

## EX-005 — `mcp-re-proxy/src/transport.rs` — **census complete, disposition: decompose along the reachability boundary**

**Status:** `reviewed-action-required`. **Measured:** 1268 production lines on `main` @
`dc9f1c1` (`scripts/module_size_gate.py::production_lines`) — the registry baseline of 1305
predates ADR-MCPRE-064 Slice 4, which removed `MappedBinding`. **Component blueprint:**
[`components/transport-binding.md`](components/transport-binding.md). **Census issue:**
[#576](https://github.com/matssun/mcp-re/issues/576) (MCPRE-140).

### §8 question 2 — how many independently describable authorities?

**Five**, and unlike EX-004 the live ones are genuinely one story: identity policy, header
view, routing-header hygiene and the binding capability are four aspects of one request's
relation to its channel, in 355 lines. On question 2 alone a §14 exception would have been
arguable.

### §8 question 9 — what is unreachable under the current legality model?

**913 of 1268 production lines — 72% of the file.** `ChannelBindingState` has two
inhabitants (`ExactUriSan`, `ExactDnsSan`); `--transport-binding lb-assertion` and
`attested-ingress` are refused at Layer-A validation; and `TransportBinding` has exactly one
constructor. Neither the Mode-B nor the Mode-C assertion verifier can be reached from a
serving path.

**That code is retained deliberately** — `docs/AGENT_INSTRUCTIONS.md` §9 names both halves
of the mistake, and this census makes neither: it does not propose deleting the deferred
capability, and it does not propose wiring it up.

### Why this is nonetheless not a §14 exception

The decision rests on question 9 rather than question 2. A file where the one binding every
deployment enforces sits beside a capability no deployment can select, with nothing in its
shape or its module doc saying which is which, does not make the security argument clearer
by staying whole — and the two halves have **opposite change rules**. Splitting at that
boundary is two moves, not ten, and it puts the retention rule at the top of the file it
governs.

### §8 question 11 — what inconsistent values can callers construct?

Two types whose **names are the claim**:

- `TransportIdentity` — documented as *"a verified client identity extracted from a
  successfully-verified mTLS client certificate"*, with public fields and a public
  constructor taking any string and any claimed source. It is live.
- `AttestedIngressVerified` — the success product of Mode-C verification, all five fields
  public. Constructible with `cert_verification_result: Verified` by anything that can name
  the type. Currently unreachable, which limits the exposure and not the defect.

`TransportBinding` is the counter-example in the same file: private representation,
`pub(crate)` constructors, and a doc comment explaining why `pub(crate)` is the right lever
for a consumer set that lives in this crate.

### §8 question 12 — which lane establishes each property?

45 unit tests, 14 integration tests across three lanes, every lane executed for this census
and reporting non-zero. **Zero theorem-registry entries are owned by this unit.** THM-0023
and THM-0024 sit next door in `communication_assurance` and are easy to mistake for coverage
here; the open proposition that would be this unit's — *transport identity is derived only
from the verified client certificate* — cannot be stated honestly until `TransportIdentity`
is sealed, because it is false of a type anyone can build from a string.

### Disposition

**Decompose** along the reachability boundary — the live 355 lines stay, the 913 lines of
deferred ingress-assertion capability move to `transport/ingress.rs` with the retention rule
stated there — and **seal `TransportIdentity` and `AttestedIngressVerified`**. The sealing is
the part that changes what is provable. `transport.rs` stays `reviewed-action-required` until
that work lands and this census is re-run.

### EX-005 re-census after MCPRE-156

The disposition is implemented. `transport.rs` no longer exists; the debt moved with the
two halves and both entries carry this record.

| unit | prod | what governs it |
|---|---:|---|
| `transport/mod.rs` | 338 | the LIVE channel-binding authority — on the served path of every deployment that binds |
| `transport/ingress.rs` | 1012 | the DEFERRED ingress-attestation capability — unreachable in any validated deployment |

The sum rose from 1268 to 1350. That is not headroom and it is not an accounting slip: each
half now carries the module note stating which reachability rule governs it, which is
exactly what this census found missing — *nothing in its shape or its module doc says which
half governs served traffic*. Neither entry may grow from here.

**Question 9 is now answered by the file layout rather than by a census.** A reader who opens
`ingress.rs` is told in the first paragraph that nothing there can be reached from a serving
path, that this is an intentional deployment fact, and that its own test suite is the only
thing keeping it correct because no deployment exercises it.

**Question 11 is closed.** Both types whose names were the claim are sealed:

- `TransportIdentity` — private representation, exactly **two** producers, both
  verifications, both NAMED. `extract_identity` moved out of `tls.rs` into the identity
  module so the seal means something: a `pub(crate)` constructor beside a sibling producer
  is not a boundary in a crate whose composition root is in the same crate. The second
  producer, `attested_by_verified_ingress`, is `pub(super)` and belongs to the deferred
  verifier — stated rather than hidden, because a producer that exists and is not stated is
  how a seal becomes a story about the producers somebody remembered.
- `AttestedIngressVerified` — private representation, `verify` the only producer, reached
  only after eight checks. That is what lets its projections assert `Verified` and `Good`
  without re-reading anything.

**The open theorem stays open.** *Transport identity is derived only from the verified
client certificate* is now TRUE of the live path and true by construction rather than by
convention — but it is deliberately not written down. Ruling 5 of this record stands, and
the campaign that did this work was instructed not to draft the transport theorem.

**What was NOT done, and why.** `TransportBindingProvider` and `StaticIdentityProvider`
have **zero production consumers** — nothing in the crate calls `verified_identity`. They
are no longer a soundness problem, because the seal means the only identity they can carry
is one a verification produced. Removing them is a public-API narrowing outside this
slice's remit ("do not expand this into general transport cleanup"), so it is recorded here
rather than done.

**Status stays `reviewed-action-required`** on both halves. `ingress.rs` at 1012 lines is
one authority with two protocol versions inside it, and whether that is a §14 exception is
a question for whoever decides the Mode-C capability's future — not one this slice should
pre-empt.

## EX-009 — `mcp-re-client-core/src/response.rs` — **census re-run, disposition: decompose the classification half**

**Status:** `unreviewed` in the registry, and this record does not change that on its own —
it records the RE-RUN the MCPRE-172 parent asked for after items 2, 3 and 4 landed.
**Measured:** 608 production lines, down from 1108 at the sixth census (#580 / PR #670).
**Parent:** [#672](https://github.com/matssun/mcp-re/issues/672). **Blueprint:**
[`components/client-response-verification.md`](components/client-response-verification.md).

### What left, and what that establishes

| item | went to | why |
|---|---|---|
| the resolver/revocation pairing | `delegated_trust/mod.rs` (PR #673) | one typed trust input; the bad pairing is not expressible |
| the trust-anchor lifecycle | `delegated_trust/anchors.rs` | root rotation and revocation are the trust authority's, not the verifier's |
| the revocation seam | `delegated_trust/revocation.rs` | the other half of the same authority |
| the manifest's own lifetime | `delegated_trust/manifest_validity.rs` | outranks every root in the picture; found by the ratchet, not planned |
| the execution/retry contract | `execution_contract.rs` | *did the work run* is not *is this receipt genuine* |
| the 202 issuer-kid re-parse | deleted; `bodyless/acknowledged.rs` | the anchor is a verified product, not a second reading of the wire |

### §8 question 2 — how many independently describable authorities remain?

**Two**, and the second is why this record does not grant an exception:

| # | authority | prod | what single fact it owns |
|---|---|---:|---|
| A | delegated response verification | ~370 | that a response is a genuine, request-bound, delegated-signed answer from a trusted anchor |
| B | result classification | ~90 | what an MCP result MEANS — `ResultClass`, `classify_result`, `continuation_state`, `ClassifiedResponse` |

A is the file's subject and belongs here. **B is not verification at all**: `classify_result`
and `continuation_state` read a body's MCP lifecycle members and say nothing about whether
anything is signed, and `mcp-re-http-profile::result_class` already owns the discriminator
they read. The serving side reached the same conclusion in this campaign — its classifier
became `http_profile_serve/reply.rs` — and the client half is the same authority on the same
bytes.

### §8 question 6 — what does this file reconstruct that another owner decided?

Nothing, now. The two instances the census found are both gone: the 202 path's re-parse of
the credential header (item 2), and the pairing that let a revoked root resolve (Slice 1).

### §8 question 7 — what relationship exists only through call ordering?

`enforce_expected_server_signer` / `check_expected_server_signer` remain a pair of free
functions the verifier must remember to call after each of three verification arms. That is
item 7 of the parent — *whether the "direct-root mode only" path is still a supported
contract* — and it is deliberately **not answered here**: the question is its owner's, and
inventing a direct-root contract to close it would be the over-claim ADR-061 exists to
prevent.

### Disposition

**Decompose B**, then re-run. A file that verifies signatures and also decides what an MCP
result means is answering question 1 with an "and". This record does not schedule it: the
parent's ruled order governs, and the classification half is a cleanup rather than a defect.

## EX-006 — `mcp-re-proxy/src/ocsp.rs` — **census complete; actions 1 and 2 landed; the protocol remainder is a reviewed exception**

**Status:** `reviewed-exception`, granted 2026-08-28 by the repository owner over the
post-#697 remainder — see *Action 3* at the end of this record. **Measured:** 980 production
lines on `main` @ `d7abd3e`; 1271 at the original census on `main` @
`68e821b`. **Component blueprint:** [`components/online-ocsp.md`](components/online-ocsp.md).
**Census issue:** [#577](https://github.com/matssun/mcp-re/issues/577) (MCPRE-141).

### §8 question 2 — how many independently describable authorities?

**Four**, and the count is not what decides this one. The RFC 6960 request (A, 92 lines) and
the RFC 6960 §3.2 response trust chain (B, 393 lines) are **one coherent protocol
authority** — five conjuncts of one security argument that reference each other — and the
admission policy (C) and fetch orchestration (D) are thin and belong with them.

The fourth is the finding: **E, a 336-line outbound-fetch network policy** — scheme
allowlist, literal-private-IP classification including `inet_aton` dotted-decimal forms,
IPv4/IPv6 public-range predicates, and a resolver that re-vets every resolved address
against DNS rebinding. **Nothing about it is specific to RFC 6960.** Any future outbound
fetch this proxy performs needs it, and it is currently reachable only through a module
compiled out of the default build by a feature gate that has nothing to do with it.

### §8 question 9 — three independent gates, and the distinctions between them

| gate | kind |
|---|---|
| `#[cfg(feature = "online_ocsp")]` on `pub mod ocsp` | a **build** fact — the default build does not compile the module |
| THM-0013 — `--client-ocsp require` refused at the legality boundary | a **configuration** fact — no validated deployment is handed a checker |
| the only caller is `blocking_mtls_harness`, not the async fleet | an **architectural** fact — the production plane would not consult one |

Classified as the census issue asked: **legality-excluded** (C, D), **reusable protocol
mechanism despite unreachability** (A, B — `serving_capabilities.rs` says so in as many
words), **reusable general control despite unreachability** (E), and **test/responder
infrastructure** (none in the product; the responder is OpenSSL, provisioned by CI).

### §8 question 11 — the sharpest instance the campaign has found

`verify_and_map_response` performs all five §3.2 checks and returns a **three-valued `Copy`
enum**. `decide_allow(CertRevocationStatus::Good, false) == true` is reachable from anywhere,
with no responder, no signature and no freshness. **The entire trust chain collapses into a
value carrying no evidence of having been through it.**

EX-004's `EvidenceCommitment` and EX-005's `AttestedIngressVerified` are milder versions of
the same defect: those have a representation whose fields are public. Here there is no
representation to seal, because the success product was never given one. Today the only
consumer sits three lines from the producer; that is what makes it latent rather than live,
and it stops being latent the moment someone builds the async OCSP this code is retained for.

### §8 question 12 — one theorem, about the module not running

THM-0013 is the only registry entry, and its own scope sentence is the model the rest of the
campaign should copy: it *"establishes reachability and legality only … It says what no
deployment can turn on, not that what is turned off would be correct if turned on."*

**One evidence row is flagged.** `tests/integration_ext/ocsp_e2e_test.rs` prints a SKIP
notice and returns success when `MCP_RE_TEST_OCSP_RESPONDER_URL` is unset. The nightly
`live-infra-e2e` workflow does provision a real OpenSSL responder and was green on
2026-08-26; everywhere else the test exits 0 having proved nothing. The live-path property
therefore holds in one non-gating nightly lane and nowhere else.

### Disposition

**Not decomposition of the protocol.** Three actions, in order:

1. **Extract E** — the outbound-fetch/SSRF policy — into its own module, compiled
   unconditionally. It removes 26% of the file without touching the protocol and makes the
   control available to every future outbound fetch.
2. **Give the §3.2 chain a success product**, so a `Good` cannot be spoken by anything that
   did not earn it. This is also the prerequisite for the corresponding theorem.
3. **Then record a §14 exception** for the ~935-line protocol remainder: RFC 6960 §3.2 is a
   single security argument whose conjuncts reference each other, and splitting it would
   damage the reasoning. That exception is **the expected end state, not an assumed one**,
   and it must not be granted now — an exception over a file that still contains an
   unrelated 336-line control would be granting it for the wrong unit.

**Do not delete, and do not wire up.** Both prohibitions stand (`AGENT_INSTRUCTIONS` §9).
The recommended work makes the retained implementation better *as retained code* and moves
it no step closer to being selectable.

### EX-006 re-census after MCPRE-161 — actions 1 and 2 implemented

`ocsp.rs` **1271 → 980** production lines, close to the 26% this census predicted for action
1 alone. Action 3 — the §14 exception for the protocol remainder — is deliberately **not
granted**, exactly as the disposition requires: it is the expected end state, not an assumed
one, and it is a decision for whoever takes the remainder up.

#### Action 1 — authority E extracted, and compiled unconditionally

`mcp-re-proxy/src/outbound_fetch/` — four modules, none over the threshold:

| module | prod | gate | the one fact it owns |
|---|---:|---|---|
| `mod.rs` | 155 | **none** | a destination has passed the guard its PROVENANCE requires |
| `url.rs` | 57 | **none** | the scheme and host a URL names |
| `address.rs` | 180 | **none** | whether an address or host is outside our own network |
| `resolver.rs` | 101 | `online_ocsp` | every address connected to has passed the address guard |

**392 unconditional lines — the POLICY the census measured at 336 — and one gated module.**
The gate on `resolver.rs` (and on `VettedDestination::agent`, which installs it) is not the
coupling the census objected to. Binding the policy into a `ureq` agent can only exist where
an HTTP client is linked, and ADR-MCPS-018 keeps the default closure lean: the Bazel base
flavor deliberately links no HTTP client, which is how this was caught — `bazel build
//mcp-re-proxy:mcp_re_proxy` failed with `unresolved module or unlinked crate ureq` on the
first attempt to compile the whole authority unconditionally. The policy is unconditional;
the client binding cannot be, and the distinction is now stated rather than incidental.

**Provenance is carried in the TYPE, not in a bool or a caller's assertion.** The census
found the guard applied by a caller matching on a `Copy` enum three lines above the fetch —
correct, and correct only because those three lines are adjacent. There are now two
CONSTRUCTORS:

```text
VettedDestination::certificate_derived  → attacker-influenced
                                        → scheme allowlist + private-address block
                                        + resolved-address vetting at connect time

VettedDestination::operator_configured  → trusted configuration
                                        → scheme allowlist
```

A caller cannot assert that a certificate's URL is operator-configured, cannot obtain a
destination without passing the guard its constructor applies, and cannot turn the
connect-time vetting off for one it built as certificate-derived — `VettedDestination::agent`
hands out the configured HTTP client rather than a boolean, so the second half of the guard
travels with the value that earned the first.

**That removed a test-only kill switch rather than relocating it.** `OcspChecker` carried a
`vet_resolved_addresses: bool` and a `new_allowing_loopback` constructor so the redirect
control could fetch from `127.0.0.1`. With the provenance on the DESTINATION, that test says
what is true — the loopback responder is operator-configured, which is exactly the case a
certificate may not name and an operator may — and the switch is gone from the checker
entirely.

#### Action 2 — the §3.2 chain has a success product

The census called this the sharpest instance the campaign has produced: *"the entire trust
chain collapses into a value carrying no evidence of having been through it."*

`verify_and_map_response` now returns a `TrustedRevocationAnswer` with a private field and no
constructor taking a status. It is the sole producer, and it is reached only after all five
§3.2 checks. `OcspChecker::allows` takes `RevocationEvidence`, so a `Good` that nothing
earned cannot be handed to the admission decision — there is no way to make one.

**Responder `Unknown` and local inability are now different values.** `RevocationEvidence`
is `Answered(TrustedRevocationAnswer)` or `NotEstablished(NoResponderConfigured |
DestinationRefused)`. A responder that answers *"I do not know"* was reached, verified and
spoke; a check with no responder URL, or one whose destination the outbound guard refused,
reached nothing. Both deny under hard-fail — that is the POLICY and it stays
`OcspChecker::allows`'s — but only one of them is a statement about the certificate, and the
audit trail can no longer report the second as the first.

#### What the extraction surfaced that nothing had measured

Compiling the authority unconditionally is what the census asked for, and it had an immediate
consequence: the eight `clippy::indexing_slicing` sites in the `inet_aton` canonicalizer had
never been counted, because `ocsp.rs` is behind a feature gate the ratchet's default lane does
not enable. They were replaced by a slice pattern over `vals.as_slice()`, which states the
ARITY and the field widths as one fact instead of two related by an `n` that has to stay in
step — so the count did not move and the code is better for having been looked at.

The same run found a defect **in the gate**: `clippy_ratchet_gate.py::measure` raised only
when a failed clippy run produced NO messages, and compile ERRORS are messages. A `pub use`
of a feature-gated item made `mcp-re-proxy` fail to build, and the gate reported
`expect_used`, `indexing_slicing` and `too_many_lines` all *"down to 0"* from baselines of 35,
40 and 12 — instructing the operator to erase the debt register for a crate nobody had
linted. It now refuses on any non-zero status, and that refusal was verified by breaking the
build on purpose.

### Action 3 — the §14 exception, granted over the post-#697 remainder

**Ruling (repository owner, 2026-08-28): the 980-line remainder is a reviewed exception.**

The census made action 3 conditional on actions 1 and 2, and both have landed:

| condition the census set | state |
|---|---|
| the unrelated outbound-fetch/SSRF authority is out of the file | done — `src/outbound_fetch/`, compiled unconditionally |
| the RFC 6960 §3.2 conclusion has an earned success product | done — `TrustedRevocationAnswer` / `RevocationEvidence` |
| what is left is one coherent authority | yes — the re-census leaves the RFC 6960 protocol and nothing else |

**Why decomposition would damage the reasoning.** The remainder is the §3.2 verification
argument, and its parts are *conjuncts of one conclusion*, not stages of a pipeline:
responder signature, responder identity (delegated-signer authorisation via the
`id-kp-OCSPSigning` EKU or a direct CA match), CertID binding to the certificate actually
being admitted, freshness (`thisUpdate`/`nextUpdate` against the clock), and nonce
correlation. None of them is a security fact on its own. A responder signature that verifies
against a key nobody authorised proves nothing; a `Good` for a CertID that names another
certificate proves nothing; a verified, correctly-bound answer from last year proves
nothing. Splitting them into separately-callable units would hand out exactly the partial
results that §8 question 11 identified as this file's sharpest defect — and the repair for
that defect was to make the *whole* argument the only producer of the answer. Cutting the
argument into files would re-create producers of pieces of it.

**What invariant requires locality.** `TrustedRevocationAnswer` has one producer,
`verify_and_map_response`, and its meaning is *"all five §3.2 checks passed over this
certificate"*. That is a single-producer seal, and the seal is only as narrow as the module
that owns the private representation. Distributing the conjuncts across modules requires
either widening the constructor or inventing per-conjunct intermediate products — which
would put back the three-valued `Copy` enum the census condemned, one level down.

**Why the subordinate responsibilities cannot be separated.** They are not subordinate
*responsibilities*; they are predicates over one parsed response, sharing its DER
structures, its issuer material and its clock. The two parts that genuinely were separable
have already left: the outbound-fetch policy (action 1) and, before that, nothing else was
found. Question 2's re-run answer is **one**.

**Compensating evidence.** The size is not carried by review alone:

- the §3.2 conclusion is type-sealed — `OcspChecker::allows` takes `RevocationEvidence`, so
  no caller can speak a `Good` that did not pass the argument;
- responder `Unknown` and local inability are distinct values, so the audit trail cannot
  report one as the other;
- the unit tests in the file cover each conjunct's refusal path individually —
  `acceptance_wrong_certid_is_denied` and `signed_good_for_wrong_certid_is_denied`,
  `freshness_window_enforced` and `freshness_capped_when_no_next_update`,
  `acceptance_nonce_mismatch_is_denied`, `forged_signature_is_denied` and
  `wrong_key_signature_is_denied`, `delegated_responder_validity_window_enforced`,
  `rejects_non_successful_responder_status`. **One conjunct has only its positive case:**
  the `id-kp-OCSPSigning` EKU requirement is exercised by an EKU-bearing delegated
  responder, and no test mints a responder that lacks the EKU. That is a named gap in this
  record, not a claim;
- THM-0013 pins the reachability/legality fact — no validated deployment is handed a
  checker — and is explicit that it says nothing about correctness if one were.

**The exception does not claim stronger evidence than the file has.** The
`tests/integration_ext/ocsp_e2e_test.rs` limitation the census flagged **stands unchanged**:
the test prints a SKIP notice and returns success when `MCP_RE_TEST_OCSP_RESPONDER_URL` is
unset, so the live-responder property holds in the non-gating nightly `live-infra-e2e` lane
and nowhere else. This record grants an exception about *structure*; it makes no claim about
the live path, and a future decision to wire OCSP up must re-open that evidence question
before relying on it.

**What this exception does not license.** It is file-granular and it is not a licence to
grow: the ratchet applies to `reviewed-exception` entries exactly as to any other. Adding
another authority to `ocsp.rs` — a second protocol, a scheduler, a cache — is outside what
was reviewed here, and belongs in its own module.

`#661` (MCPRE-161) closes against this result. **No further OCSP implementation work is
scheduled**; `AGENT_INSTRUCTIONS` §9's do-not-delete / do-not-wire-up prohibitions stand.


## EX-007 — `mcp-re-proxy/src/cli.rs` — **census complete, disposition: move the materialization out**

**Status:** `reviewed-action-required`. **Measured:** 1170 production lines on `main` @
`7ec8f92` — the registry and the campaign index both said 1177, before the ADR-MCPRE-065 §11
authorization-flag family moved to its own child module. **Component blueprint:**
[`components/cli-and-materialization.md`](components/cli-and-materialization.md).
**Census issue:** [#578](https://github.com/matssun/mcp-re/issues/578) (MCPRE-142).

**ADR-MCPRE-058's ruling on `parse_args` was treated as evidence for neither side.** It is
function-granular, it remains valid, and it is not reopened here. What this census examined
is what shares `parse_args`'s file.

### §8 question 2 — how many independently describable authorities?

**Three**, and they are the three the census issue asked to be told apart:

| authority | lines |
|---|---:|
| **A — argv transport**: `parse_args`, `parse_timeout`, `parse_cert_lifetime`, `second_admission_limit` | 817 |
| **B — legality residue**: `key_file_mode_is_insecure` | 14 |
| **C — capability materialization**: `read_pkcs11_pin`, `build_attested_ingress_binding`, `build_key_source`, `build_ocsp_checker` | 297 |

**A and C never call each other.** The Layer-A boundary and `app::run` sit between them, so
separating them costs no locality — there is none to lose. A module named `cli` that reads a
PKCS#11 PIN off the filesystem and constructs KMS-backed key sources is not a CLI module,
and C's input is a *decided* `CustodyState` rather than an argument list.

### §8 question 6 — does the parser re-decide what `config_state::*` owns?

**No, and that is this unit's genuine strength.** The census went looking for the classic
drift and did not find it: `InFlightLimitRequest::Unspecified` is carried rather than
defaulted, the delegated-signing rotation defaults are `DelegatedSigning`'s constants,
`has_delegated_tls` carries a comment explicitly disclaiming itself as a check, and
`build_key_source` matches on `CustodyState::material()` instead of re-reading the request.
An earlier round of this campaign did that work and it holds.

### §8 question 7 — the proof is created, discarded, and recreated

`parse_args` ends with `ValidatedDeployment::try_from(config).map(into_inner)` — it
validates, then unwraps. `app::run` calls `try_from` **again**, recomputing every state
machine. `into_inner`'s own doc says the wrapper exists so it *"cannot be reconstructed
around an unchecked `DeploymentRequest`"*: the seal is earned in `parse_args` and opened one
line later.

**This is not a hole** — `app::run` re-validates, so the path fails closed however the
request was built. The cost is representational, and the double validation is its observable
consequence. The census deliberately does **not** rule on whether `parse_args` should return
a `ValidatedDeployment`: there is a real counter-argument (`app::run` must stay callable by
an embedder that never met a parser), and that is a design decision, not a census finding.

### §8 question 11 — requiredness is a parser-only rule over public fields

The `require` closure enforces eleven required flags; those fields are public `String`s on
`DeploymentRequest`, and the boundary does not re-check emptiness for the identity
coordinates. The file states the consequence in its own test comment — *"an embedder or a
test that builds the struct reaches the serving path with an empty coordinate and no parser
runs"* — and argues the exposure is bounded, since nothing dereferences those coordinates.

That argument is sound and it belongs in a disposition record rather than in a test comment.
`--client-ocsp`, `--revocation-list` and `--authz reference` were all moved to the boundary
for exactly this reason; requiredness was not.

### §8 question 12 — the three lanes, counted separately

158 unit tests, classified by what each one calls: **119 prove parsing**, **23 prove
legality** (through `unsafe_config_violations`, i.e. testing `config_state::validation` from
inside `cli.rs`), **6 prove materialization**, 10 are helpers. Six tests for 297 lines of
key-custody construction, against 119 for argv transport — C is the least-tested authority
in the file by an order of magnitude, and it is the one that builds key custody.

### Disposition

1. **Move C** — capability materialization — beside the other materializers
   (`signing_plane`, `trust_plane`, `serving_capabilities`), not beside a parser.
2. **Move B** — `key_file_mode_is_insecure` — to whichever owner performs the permission
   check.
3. **Record requiredness** as a parser-only rule: either it moves to the boundary like its
   three predecessors, or the fields stop being public `String`s.
4. **The discarded validation proof is recorded, not ruled.**

`parse_args` keeps its ADR-058 exception. `cli.rs` stays `reviewed-action-required` until the
moves land and this census is re-run.

## EX-008 — the KMS key-custody axis — **census complete, disposition: one common owner, no per-provider split**

**Status:** `reviewed-action-required` on all four units. **Measured** on `main` @ `7ec8f92`:
`gcp_kms_keysource.rs` 1149, `aws_kms_keysource.rs` 694, `key_source.rs` 362,
`kms_keysource.rs` 230 — **2435 production lines**. **Component blueprint:**
[`components/kms-key-custody.md`](components/kms-key-custody.md). **Census issue:**
[#579](https://github.com/matssun/mcp-re/issues/579) (MCPRE-143), run as **one conceptual
census over both backends**.

### §8 question 2 — three authorities, and the top two are already right

**Two providers is not two authorities.** The axis has a custody seam (`key_source.rs`), a
**provider-agnostic KMS protocol mapping** (`kms_keysource.rs`) whose own doc states the
principle — *"the protocol mapping is IDENTICAL across providers … a provider differs ONLY
in the `KmsEd25519Backend` network client"* — and the two cloud transports.

That structure is correct. The finding is that the transports did not stay inside it.

### §8 question 10 — the question that decides this census

Five duplications between the backends, of which four are pure copies
(`ED25519_SIGNATURE_LEN` — in **three** files, `NETWORK_TIMEOUT`, `MAX_ERROR_BODY_BYTES` +
`read_error_body`, and the local-key test-transport pattern) and one is a **security
classifier**.

The two `quota_verdict` functions share a structure, consume the same shared types
(`RemoteSignerFailure`, `QuotaVerdict`), call the same shared helpers, and carry
**near-identical doc comments describing the same historical defect** — the
`format!("{error:?}")`-and-`contains` classifier that a rewording upstream silently
disarmed. They differ in two data points: a JSON path and a token list.

**One semantic rule, two data tables, written twice.** A third provider would arrive with a
third copy, and a correction would have to be made in three places — which is how the
original defect survived as long as it did.

### §8 questions 4 and 5 — what the census looked for and did not find

No reconstruction of facts owned elsewhere: both backends consume `CustodyState` decisions,
delegate Ed25519 key interpretation to `Ed25519PublicKeyValue`, and consume the shared
failure vocabulary rather than re-deriving it from prose. The products are **better sealed
than anywhere else in this campaign** — private backends, public key fetched and validated
as Ed25519 at construction. The configs have public fields and that is correct: they are
requests, not products.

The residual is the seam itself: `sign_raw_ed25519 -> Vec<u8>` and
`public_key_spki_der -> Vec<u8>` state their contracts in prose.

### §8 question 6 — root and delegated signing are different propositions sharing a type

Both backends implement `KmsEd25519Backend` (response-evidence signing) **and**
`RawEd25519TlsSigner` (TLS handshake signing) — an RFC 9421 signature base and a TLS 1.3
CertificateVerify transcript, over one type.

In production they are two different keys, and the separation is real: `--aws-kms-tls-key-id`
/ `--gcp-kms-tls-key-version` are separate selectors, relation X2a refuses a dangling one,
and `cli.rs::build_key_source` constructs a **second backend instance** for the TLS role.

**The guarantee lives in `build_key_source` — the function EX-007 ruled should move.** The
two remediations touch the same code, and whichever owner receives it inherits the
role-separation guarantee. That must be preserved explicitly, not by accident.

### §8 question 3 — what a `KeySource` establishes, and what it cannot say

> *This process can produce Ed25519 signatures under a named key, and — for the KMS
> implementations — the private key is not in this process's address space.*

The second clause is the point of the whole axis and **the trait cannot express it**:
`FileKeySource`, `EnvKeySource` and `KmsKeySource` satisfy one trait, so a consumer holding
a `Box<dyn KeySource>` cannot distinguish a non-exporting custodian from a seed file. The
distinction is carried by `CustodyState` and the startup posture — a fact about
configuration standing in for a property of the value.

Recorded, **not acted on**: changing it is an ADR-MCPS-028 question about the seam.

### §8 question 12 — offline twins and live cloud, already separated

This axis has the artefact EX-006 wished for:
[`docs/security/cloud-kms-claims-map.md`](../security/cloud-kms-claims-map.md) states per
runner the trigger, whether it blocks, and what it contains. 39 + 14 + 6 offline unit tests
and a 12-test IRSA **offline twin** run in the blocking CI job; the genuine live-cloud lanes
(`gcp_kms_live_test`, `aws_kms_live_test`) run nightly, non-blocking, and only when that
backend's secrets are present.

**And they fail loudly when unconfigured** — `gcp_kms_live_test`'s doc says so in as many
words. That is the exact opposite of the OCSP e2e test EX-006 flagged for self-skipping to
green, and it is the pattern to copy.

**`key_source.rs` has zero tests** — 362 lines, the seam every custodian implements, against
the repository's own rule that every file carries a test module.

### Disposition

**No per-provider split, and no merge of the backends.** Instead:

1. a **common private owner for `quota_verdict`**, taking `(json path, token set,
   name-suffix rule)` as backend-supplied data;
2. lift the four pure duplications into the provider-agnostic owner;
3. **typed operands at the KMS seam** in place of `Vec<u8>` in both directions;
4. **record, do not act on**, the two representation questions — `KeySource`'s unexpressed
   custody clause, and the role separation held by `build_key_source`;
5. a test module for `key_source.rs`.

Re-measure after 1–3. `gcp_kms_keysource.rs` will stay over the threshold, and its remaining
bulk is one provider's genuine access-token mechanism — a candidate for its own §14
discussion, which this census does not pre-empt.
