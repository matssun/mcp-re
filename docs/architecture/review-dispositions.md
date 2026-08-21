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
seven theorems. **Remediation:** ~~#571~~ and ~~#572~~ implemented (THM-0014 … THM-0020);
the disposition may move to `reviewed-exception` only once that review lands and this
census is re-run. **Measured:** 1388 production lines after #571; 1598
after #570; 1640 before either. **Component blueprint:**
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
one `Verifier`. The two composition theorems the split makes expressible are #572.
`verify.rs` stays `reviewed-action-required` until that closes and this census is re-run:
the disposition records that work remains, not that nobody looked.

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
