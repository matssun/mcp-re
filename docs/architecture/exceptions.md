<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-061 §14 exception register

The durable records that `config/module-size-debt.toml`'s `exception_ref` fields point at.

A registry entry says one of two things about a unit over the 200-line threshold:

| status | meaning |
|---|---|
| `unreviewed` | over the threshold and **not yet investigated** |
| `reviewed-exception` | investigated under ADR-061 §8 and **deliberately kept intact**, with the record below saying why |

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

## EX-002 — `mcp-re-proxy/src/app.rs` — **census complete, exception NOT granted**

**Status:** stays `unreviewed`. **Measured:** 1037 production lines on `main` @ `a735e8c`.

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

ADR-061 §14 records a decision to keep something whole. It is not a place to park work.
So `app.rs` keeps `status = "unreviewed"` and this record states precisely what remains:
**relocate authority G to the audit-sink owner, then re-run this census.** Authorities B
through F are closed by it and need not be re-argued.

### The measurement worth keeping

`run_validated` is 531 of the file's 1037 production lines, and its own comment records
that 290 of those are code and the rest is the exception argument. A file-level number is
therefore a poor proxy for a file-level authority count here — which is ADR-061 §7 in one
unit: **size ordered this investigation; it did not decide it.**
