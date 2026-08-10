<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-059 Phase 0 — assurance baseline

**Captured at:** commit `126b093`, branch `refactor/adr-056-phase0-startup-characterization`
**Captured on:** 2026-08-10
**Captured before:** any Verus, Charon, Aeneas, or Lean dependency existed in this repository.

That last line is the reason this document exists and the reason it was written first.
Phase 0's deliverable is a measurement of what the repository's security assurance costs
*without* the platform ADR-MCPRE-059 introduces. Once the toolchains are installed the
"before" is gone and the comparison Phase 5 depends on cannot be reconstructed. Nothing
here changes production behaviour; Phase 0 is forbidden from requiring that.

---

## 1. The Security Review Funnel as it is invoked today

The funnel is a repository-local skill, `.claude/skills/security-audit-funnel`, not a CI
job. It is invoked by an operator against a source root and runs to the next gate, then
hands control back. State lives on disk so a re-invocation resumes rather than restarts.

| Stage | What runs | Cost shape | Gate |
|---|---|---|---|
| 1 — deterministic pre-scan | `scripts/prescan.py` (923 lines, stdlib only), polyglot and role-aware | ~0 tokens | NO-GO blocks stages 2-3 |
| 2 — pre-run review, no verification | Catalog agent + 3-lens review over the declared units | ~30 agents | act-now bucket fixed before stage 3 |
| 3 — full audit with adversarial verification | Same workflow plus a 3-skeptic Verify gate per high/critical finding, then invariants + synthesis | hundreds of agents; Verify is ~10x Review | verified findings + report |

The Verify gate exists solely to suppress false positives, which is why the funnel is
built to fix everything structurally confirmable *before* paying for it.

### What the funnel does not have

The funnel's scoping input is a hand-declared `UNITS` list plus the diff. It has no
representation of:

- whether a previously reviewed unit's conclusion is still valid;
- whether an unchanged consumer was invalidated by a changed guarantee;
- which test is the evidence for which security claim;
- which assumption a conclusion rests on;
- whether a toolchain, feature, or policy change invalidated a past result.

Re-running after a fix round therefore re-pays for conclusions that did not change. That
is precisely the gap ADR-MCPRE-059 §14 targets, and the numbers in §2 are what it will be
measured against.

---

## 2. Representative review cost — round 7, 2026-08-03

Recorded from `work/security-audit-2026-08-03/` (private, gitignored; figures reproduced
here because the baseline must survive that directory).

**Stage 1 — deterministic pre-scan**

```
verdict            GO
blocking defects   0
warnings           1
Rust files         121
Python files        52
crates             15
roles              library 128 | test 98 | script 22 | binary 10 | comproot 4
```

**Stage 2 — pre-run (unverified)**

```
review units       11        (hand-declared, not derived)
lenses              3        (general / conformance / security)
agents run         34
pin                5491cdd (clean tree)
```

**Cumulative finding ledger** (all rounds to date, `finding-ledger.jsonl`, 469 entries)

```
disposition        fixed 291 | open 167 | false-positive 7 | positive-control 4
severity           critical 1 | high 97 | medium 239 | low 125 | info 7
```

The false-positive rate against adjudicated findings is low (7 of 469), which says the
Verify gate is working — and equally that its cost is being paid to confirm things that
were already true. Token and wall-clock figures were not instrumented per run; that
instrumentation is itself a Phase 5 requirement, and its absence is recorded here rather
than estimated.

**Scope-selection cost.** All 11 units were reviewed each round regardless of what
changed. No mechanism existed to assert that any of them was still fresh.

---

## 3. Architectural units created by the ADR-MCPRE-057/058 refactor

These are the seams that did not exist when ADR-MCPRE-059 was drafted, and they are the
reason the ADR says this is the window to start.

| Unit | Location | Shape |
|---|---|---|
| runtime lifecycle | `mcp-re-proxy/src/runtime_state.rs` | 11 states, 10 events, one closed transition relation; invalid pair leaves state unchanged |
| materialization ownership | `mcp-re-proxy/src/materializing_runtime.rs` | owns partial construction; success applied only after all required resources are taken |
| post-drain teardown | `mcp-re-proxy/src/materialized_runtime.rs` | drain → security transition → reclaim, each gated on the prior lifecycle event |
| trust freshness | `mcp-re-proxy/src/trust_plane.rs` | `TrustStoreFreshness`, with a terminal `mark_stale_permanently` latch |
| signing custody | `mcp-re-proxy/src/signing_plane.rs` | active/retired with a terminal retirement latch |
| trust snapshot publication | `mcp-re-proxy/src/reloading_trust.rs` | resolver + signer map published as one unit behind one lock |
| serving capabilities | `mcp-re-proxy/src/serving_capabilities.rs` | seven optional capabilities behind `Established<T>`; ON-over-nothing unrepresentable |
| request dispatch boundary | `mcp-re-proxy/src/request_stages.rs` | `ReadyForDispatch` / `DispatchedExchange` around the one irreversible effect; `RetentionDisposition` sum type |

Pre-existing state-carrying types outside the refactor, all in pure crates:

```
mcp-re-core/src/replay.rs            ReplayDecision, ReplayDurabilityClass, ReplayCacheError
mcp-re-http-profile/src/chain.rs     ChainLabel, HopOutcome, IncompleteReason
mcp-re-http-profile/src/admission.rs AdmissionStatus
mcp-re-http-profile/src/result_class.rs ResultTypeClass
```

---

## 4. Inventory required by Phase 0 §4

### 4.1 Pure semantic modules (candidate V2 territory)

`mcp-re-core` (2 933 lines) and `mcp-re-http-profile` (14 138 lines) are constitutionally
free of networking, async, and filesystem access (ADR-MCPS-011/012, enforced by their
manifests). Smallest self-contained members:

```
mcp-re-http-profile/src/keyid.rs        75    RFC 7638 JWK thumbprint
mcp-re-http-profile/src/digest.rs       93    RFC 9530 content digest
mcp-re-core/src/encoding.rs             99    base64url no-pad
mcp-re-core/src/hash.rs                109    SHA-256 hash ids
mcp-re-http-profile/src/evidence.rs    117
mcp-re-core/src/time.rs                329    RFC 3339 freshness parsing
mcp-re-core/src/replay.rs              563    replay tier (holds a Mutex — see 4.2)
```

### 4.2 `unsafe` — 34 sites in 6 production files

| File | Sites | Nature |
|---|---|---|
| `mcp-re-proxy/src/pkcs11_native.rs` | 21 | PKCS#11 FFI over `cryptoki-sys` + `libloading`; the raw binding wrapper |
| `mcp-re-proxy/src/async_fleet.rs` | 7 | `libc` socket / `SO_REUSEPORT` / `listen` / `sysconf` |
| `mcp-re-proxy/src/pkcs11_keysource.rs` | 2 | `unsafe impl Send`/`Sync for Pkcs11Token` |
| `mcp-re-proxy/src/app.rs` | 2 | `libc::getegid` / group query |
| `mcp-re-proxy/src/main.rs` | 1 | signal-handler installation |
| `mcp-re-client/src/main.rs` | 1 | signal-handler installation |

All of it is in `mcp-re-proxy` and `mcp-re-client`. Neither pure crate contains any.
Test-only `unsafe` (the `mock-pkcs11` fixture and one conformance vector) is excluded.

Every one of these is outside the documented Aeneas subset and outside the first Verus
pilot. `unsafe impl Send`/`Sync for Pkcs11Token` is the most security-interesting of them
and is recorded as a candidate for a much later phase, not for a pilot.

### 4.3 FFI boundaries

One, reached two ways: `cryptoki-sys` (raw, `libloading`-only, deliberately chosen over
the high-level `cryptoki` crate) wrapped by `pkcs11_native.rs`, consumed by
`pkcs11_keysource.rs`. Plus `libc` for sockets, signals, and credentials.

### 4.4 Build scripts and proc macros

One build script in the whole repository: `sdk/typescript/build.rs`. No proc-macro crates.
This is unusually favourable — ADR-MCPRE-059 §5 treats build scripts and proc macros as
scope-broadening uncertainty, and there is almost none of it here.

### 4.5 Test and conformance evidence

```
#[test] functions in Rust crates     1 626
integration test files                  89
conformance crate                   mcp-re-conformance, with security_traceability_manifest.json
Python SDK suite                    199 tests
```

`mcp-re-conformance/security_traceability_manifest.json` already maps claims to evidence.
It is the closest thing the repository has to an evidence graph today and is the natural
first import for Phase 4.

### 4.6 Security assumptions currently implicit

Recorded as observations, not as registry entries — ADR-MCPRE-059 §12 forbids populating
the registry with anything that is not a real, owner-ratified assumption.

- SHA-256 collision resistance, relied on by keyids, content digests, and hash ids.
- Ed25519 as implemented by `ed25519-dalek`.
- The PKCS#11 module's own correctness behind the FFI wrapper.
- KMS providers behaving as their APIs document.
- The system clock being within the configured skew bound.
- `SO_REUSEPORT` kernel distribution behaviour on the serving path.

---

## 5. Baseline gate results, captured before any verification dependency

```
scripts/local_gate.sh --fast   PASS (stages 1-2)
bazel test //...               PASS — 81 tests, 81 pass (48 executed, 33 cached)
cargo test --workspace         PASS
Python SDK suite               199 passed
```

Stage 4 (the ADR-MCPRE-051 §7 SLO lane) was deliberately not run and is not part of this
baseline. ADR-MCPRE-059 §17 requires the Verus pilot to measure binary size, dependency
closure, and hot-path effect; the SLO comparison that measurement needs must be taken
against a stage-4 run on a quiet box, and that is a separate, owner-initiated act.

**Known load-sensitive test.** `app_startup_characterization_test::a_push_tier_without_an_
event_source_...` spawns a real proxy and times out under machine load. Verified to fail
identically on unmodified code at load ~35. It is a test-harness reliability defect, not
a code defect, and it must not be mistaken for a verification-platform regression later.

---

## 6. Pilot candidates

Phase 0's obligation is to *name* candidates. Final selection is confirmed at the entry to
Phases 2 and 3, when the pinned tools' actually supported subsets are known — ADR-MCPRE-059
§8 requires the pilot to stay inside the subset the tool supports at implementation time,
not the subset it was assumed to support at design time.

### 6.1 Verus pilot candidate — the runtime lifecycle

`mcp-re-proxy/src/runtime_state.rs`, `RuntimeLifecycle`.

Why this one: it is a closed transition relation over 11 states and 10 events with no I/O,
no async, and no allocation; it is already integrated in production rather than being a
diagram; and it has independent executable evidence in the form of an exhaustive
110-pair test. Verus has dedicated transition-system support, which is the match
ADR-MCPRE-059 §7 asks for.

Candidate invariant, drawn from the real semantics rather than invented:

> For every state `s` and event `e`, if `(s, e)` is not in the transition relation then
> applying `e` leaves the lifecycle in `s` and yields a refusal. `Stopped` is reachable
> only through `ResourceReclaimCompleted`, which is reachable only after
> `SecurityTransitionCompleted`, which is reachable only after the drain event. No event
> re-enters a terminal state.

That is a safety property that matters: it is the machine-checked form of "a runtime that
reports `Stopped` cannot still be holding signing or trust authority."

**Recorded obstacle.** Verus verifies at crate granularity — every item in a verified
crate must be verified or explicitly marked external. `runtime_state.rs` lives in
`mcp-re-proxy`, which is 49 768 lines and pulls in tokio, rustls, and FFI. Opting the
crate in would mean marking essentially all of it external, which inflates the trusted
computing base to the point where the proof's meaning is questionable.

Two resolutions exist, and choosing between them is Phase 2's decision, not Phase 0's:

1. accept the external-marking cost and scope it explicitly in the assumption registry; or
2. extract the lifecycle relation into a small pure crate, which is architecturally
   defensible on its own terms (it is already a pure value, and the repository already
   has the pure-crate pattern) but is a production change and therefore out of Phase 0.

Resolution 2 must not be adopted *merely* to make the tool happy — ADR-MCPRE-059 §18. It
qualifies only if it is a good change without the proof.

### 6.2 Aeneas/Lean pilot candidate — the keyid canonical form

`mcp-re-http-profile/src/keyid.rs`, `canonical_ed25519_jwk` and `jwk_thumbprint_ed25519`.

Why this one: 75 lines, pure, safe, sequential, no interior mutability, no async, no
Mutex — inside the subset Aeneas documents. And the interesting theorem needs no crypto
model at all:

> `canonical_ed25519_jwk` is injective on its input. Two distinct base64url-no-pad key
> encodings never produce the same JWK byte string.

That is a real security property. The function builds RFC 7638's canonical form by direct
string formatting rather than through a serializer, precisely so no reordering or
whitespace can change a derived keyid; injectivity is the statement that the format admits
no delimiter ambiguity. Format-string ambiguity in a canonicalization step is a classic
and quiet vulnerability class, and a keyid is a selector on the trust path.

SHA-256 collision resistance stays outside the proof, as a registered assumption with a
named external model. That separation — proving what is provable, declaring what is
assumed — is itself the demonstration Phase 3 is meant to produce.

Alternates if extraction of the above proves unsupported: `mcp-re-core/src/encoding.rs`
(base64url canonicality) and `mcp-re-core/src/time.rs::parse_rfc3339_utc` (freshness
window admissibility).

`mcp-re-core/src/replay.rs` was considered and rejected as a first pilot: `InMemoryReplayCache`
holds a `Mutex`, and interior mutability with shared-state concurrency is on Aeneas's own
list of current limitations.

---

## 7. Exit gate

| Requirement | Status |
|---|---|
| baseline committed | this document |
| pilots named | §6.1 and §6.2, with the Verus crate-granularity obstacle recorded |
| no production behaviour changed by Phase 0 | nothing outside `verification/` and `tools/verification/` was touched |
| existing gate results captured before verification dependencies | §5 |
