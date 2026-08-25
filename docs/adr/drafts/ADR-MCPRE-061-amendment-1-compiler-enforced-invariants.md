<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-061 Amendment 1: Compiler-Enforced Invariants — extending the adopted lint set

**Status:** 🟡 PROPOSED — drafted, NOT ratified, NOT yet posted to
[Discussion #567](https://github.com/matssun/mcp-re/discussions/567).
**Date drafted:** 2026-08-25
**Amends:** [ADR-MCPRE-061](https://github.com/matssun/mcp-re/discussions/567) §6.5
(the adopted lint set) and §6.4 (the ratchet).
**Evidence base:** a measured census of 78 candidate lints run over production
targets only (`cargo clippy --workspace --lib --bins`, `CLIPPY_CONF_DIR` pointed at
`config/clippy-strict/`), i.e. the identical lane
`scripts/clippy_ratchet_gate.py` measures. Reproduced in §2.
**Owner ruling captured:** 2026-08-25. The eight-point ruling is reproduced in §1
and every section below is written against it.

---

## §0 What this amendment is for

ADR-MCPRE-061 §6.5 adopted six lints. It did not claim the set was complete; it
claimed each of the six had an architectural reason. This amendment extends the set
using the same standard, and it exists because a measurement — not an opinion —
showed that several properties the architecture currently asserts in prose are
properties the compiler could be made to enforce.

The governing constraint, restated so nothing below can drift from it:

> **A-1. ADR-MCPRE-061 is a registry of protections with architectural reasons. It is
> not a maximal-Clippy policy.** Every adopted lint must name the invariant it
> enforces and the failure class it prevents. A lint that only produces tidier code
> is declined, and the declining is recorded (§9).

Two framings from the owner ruling are load-bearing and are adopted as text:

> **A-2. Zero-debt is not "free".** A new `deny` at zero sites costs nothing to land
> but establishes a future architectural constraint. It is better evidence for
> adoption than a low count is — nobody has to be paid off — but it is a decision,
> made deliberately and recorded, not a freebie.

> **A-3. Do not appease the linter.** Where a lint reports many sites, the deliverable
> is a *stated invariant*, not a zero count. §6 (numeric conversion) and §7 (visibility)
> are architectural slices that happen to have a lint as their verification, not lint
> campaigns that happen to touch architecture.

---

## §1 The owner ruling (2026-08-25), verbatim in substance

1. Open this amendment from clean `main`; do not mix it with ADR-MCPRE-066 work.
2. Land the zero-debt protections separately: Tier-0 lints at zero production sites,
   plus `#![forbid(unsafe_code)]` on the ten crates with no production `unsafe`.
   **`forbid` is not to be weakened with an allow mechanism later** — introducing
   `unsafe` into one of those crates must require an explicit architectural decision.
3. Do not ratchet all Tier-1 findings at once. Classify them and establish an
   adoption order by *the property being protected*, not by lint count.
   Priority: **A** `string_slice` → **B** `wildcard_enum_match_arm` →
   **C** `let_underscore_*` (semantic investigation first) →
   **D** `host_endian_bytes` + `iter_over_hash_type` → **E** unsafe-block discipline.
4. The cast family is its own architectural slice. Start at
   `mcp-re-core/src/time.rs`, determine the intended numeric domains and conversion
   rules, make them explicit, *then* ratchet. The result is a stated conversion
   invariant, not zero warnings.
5. `unreachable_pub` likewise: an architecture/ownership pass, not 47 mechanical edits.
   Publicness is part of the interface model.
6. Adopt `allow_attributes_without_reason` early; be careful with `allow_attributes`.
   Verify `#[expect]` works cleanly with the existing ratchet/toolchain setup first.
   Do not create a second lint-governance mechanism that fights §6.4's.
7. Tier 2 (ambient authority) becomes its own ruling inside this amendment. Identify
   the canonical owners and the permitted primitive boundary; the rule must express
   "time enters here", not "this method name is forbidden everywhere". Analyse
   `Instant::now` separately — wall-clock authority and monotonic elapsed-time
   measurement are related but not identical capabilities.
8. Keep an explicit non-adoption list with architectural reasons.

---

## §2 The measurement

Method: `cargo clippy --workspace --lib --bins --message-format=json` on the pinned
toolchain (1.97.1) with `CLIPPY_CONF_DIR=config/clippy-strict`, counting primary
spans, excluding any path under `tests/`. This is deliberately the same lane
`clippy_ratchet_gate.py::measure` uses, so a count here and a baseline there are the
same number measured the same way. 2,070 compiler messages were seen; the run
exited 0 (lints were passed as `-W`, so nothing aborted the measurement).

The full 78-lint table is in the PR description. The counts this amendment rules on:

| lint | production sites |
|---|---|
| `string_slice` | 21 |
| `cast_possible_truncation` / `_wrap` / `_sign_loss` / `_lossless` / `_precision_loss` | 20 / 14 / 9 / 2 / 5 |
| `as_conversions` | 78 |
| `integer_division` | 21 |
| `wildcard_enum_match_arm` | 16 |
| `match_wildcard_for_single_variants` | 3 |
| `allow_attributes` / `allow_attributes_without_reason` | 37 / 37 |
| `unreachable_pub` | 47 |
| `let_underscore_must_use` / `let_underscore_drop` | 30 / 30 |
| `undocumented_unsafe_blocks` / `multiple_unsafe_ops_per_block` | 1 / 4 |
| `host_endian_bytes` | 1 |
| `iter_over_hash_type` | 1 |
| `unsafe_code` (rustc) | 9, in exactly 2 crates |

**Confidence note, and a correction made while acting on it.** The census above
measures the *default* feature lane, so counts for feature-gated modules
(`redis_replay`, `async_serve`, KMS, `pkcs11`, `cpstore_etcd`) are lower bounds. Every
baseline this amendment authorises is therefore measured on the feature lane before it
is written to `config/clippy-debt.toml`.

That lane is **not** `--all-features`. This workspace refuses it by construction: the
`verify` feature raises `compile_error!` outside the pinned prover, so an
`--all-features` measurement exits non-zero having compiled almost nothing — and reads
as all-zeros if the caller does not check. (This happened during drafting; the run
reported 23 messages and rc=101 and every count as 0.) The correct lane is the one
`ci.yml`'s `cargo-features` job uses:

```
--features dev_env_key_source,pkcs11_keysource,redis_replay,online_ocsp,\
           aws_kms_keysource,gcp_kms_keysource,async_serve,cpstore_etcd
```

Re-measuring Tier 0 on that lane, production-only, changed the result: **`mem_forget`
is not zero.** `mcp-re-proxy/src/pkcs11_native.rs::Session::into_handle` calls
`std::mem::forget(self)` to transfer session-handle ownership past `Drop`, under an
existing `SAFETY:` comment that states exactly why. It is therefore removed from Tier 0
and folded into §4-E, where its disposition is an `#[expect(..., reason = ...)]` naming
that argument. It is the only such correction; every other Tier-0 lint is zero in
production on both lanes.

---

## §3 Tier 0 — zero-debt protections (ruling 2)

Adopted as `deny`, at zero production sites, landing on a separate branch from this
amendment. Implementation split them by the lane they are clean in, which is a
distinction the census did not anticipate and the landing forced:

- **Group A — zero in production *and* test code, on both lanes.** These can be denied
  in one step for every target, so they live in a single `[workspace.lints]` table in
  the root `Cargo.toml`, with each member opting in via `[lints] workspace = true`.
- **Group B — zero in production, non-zero in test code** (`panic_in_result_fn`,
  `exit`, `create_dir`, `assertions_on_result_states`, `partial_pub_fields`; 118
  `assertions_on_result_states` sites in `#[cfg(test)]` modules alone). A crate-level
  `#![deny]` would be red under every `--all-targets` lane. These go into
  `scripts/clippy_ratchet_gate.py`'s `ADOPTED` set, whose production-only measurement is
  precisely the mechanism §6.4 built for this case. They carry no debt entry, for the
  same reason `unwrap_used` does not. The gate's `compare()` was changed to deny at zero
  for *any* adopted lint outside `RATCHETED` — it previously skipped them, which would
  have made every zero-debt adoption inert.

**Why a `[workspace.lints]` table rather than thirteen `#![deny(...)]` blocks.** The
block was written into all thirteen crate roots first. `scripts/module_size_gate.py`
then failed six files that are registered in `config/module-size-debt.toml` and may not
grow whatever their status. That is the registry choosing the mechanism, and it chose
the better one: the rationale belongs in one place, not in thirteen copies. The cost is
that a workspace table reaches a member only through that member's opt-in, so
`scripts/workspace_lints_gate.py` was added — a membership check, plus a `--probe` that
compiles a deliberate `todo!()` inside a real member and requires the build to fail with
`clippy::todo`. A table that is merely present is the configuration-enforces-nothing
failure this repository has hit twice.

**One lint was dropped at this point:** `clippy::string_to_string` has been *removed*
from clippy 0.1.97. It measured 0 because it does not exist, and a removed lint reading
zero is a protection that protects nothing. It was caught only because putting the deny
in source made the compiler reject it. Recorded because the same trap applies to any
future addition to this list.

**Panic-freedom in a policy-enforcement point.** `todo`, `unimplemented`,
`panic_in_result_fn`. *Invariant:* a serving path returns a refusal, never a panic.
*Failure class prevented:* a reachable placeholder becomes a remote denial of
service against a proxy whose entire purpose is to stay available and fail closed.

**Process-lifetime authority.** `exit`. *Invariant:* only the composition root ends
the process. *Failure class:* a library-layer `process::exit` bypasses the audit
drain and teardown ordering, losing exactly the records that explain why it exited.
Zero production sites. The one `std::process::exit` in the tree is at
`mcp-re-proxy/src/app.rs:1415`, inside `mod tests` (opens at line 1039) — it is the
abrupt-termination fixture for the audit-drain test, and `--lib --bins` does not
compile it, which is why the census reads 0 and why this is a `deny`-at-zero.

**Pointer discipline.** `transmute_ptr_to_ptr`. *Invariant:* no pointer laundering
around the type system. (`mem_forget` was proposed here on the same argument — that
`mem::forget` on a `Zeroizing`/`SigningKey` defeats the ADR-MCPS-076 G-3 zeroization
guarantee — but it is not at zero. See the §2 correction; it moves to §4-E.)

**Ambient filesystem and I/O behaviour.** `verbose_file_reads`, `create_dir`,
`filetype_is_file`. *Invariant:* evidence stores create their directory trees
deliberately and do not confuse a symlink for a regular file. *Failure class:*
`create_dir` failing on a missing parent turns an evidence-retention failure into a
silent no-write; `filetype_is_file` is a TOCTOU-adjacent symlink confusion in the
retained-evidence store.

**Error-model hygiene.** `error_impl_error`, `try_err`.
*Invariant:* the refusal taxonomy stays a taxonomy — one named error type per
authority, no type named `Error` implementing `Error`, no `Err(x)?` laundering a
conversion the taxonomy did not authorise.

**Test-assertion honesty.** `assertions_on_result_states`. *Invariant:* a test that
asserts a `Result` state names which state. *Failure class:* `assert!(r.is_ok())`
discards the error, so a test that starts failing reports nothing about why —
directly the "do not report a green that measured nothing" rule.

**Structural.** `partial_pub_fields`, `rest_pat_in_fully_bound_structs`,
`same_name_method`, `rc_buffer`, `dbg_macro`, `pub_without_shorthand`.
*Invariant:* a type is either an opaque owner or a transparent record, never half of
each — which is precisely the R-SEAL boundary. `rest_pat_in_fully_bound_structs`
matters more than its name suggests: a `..` in a fully-bound pattern is how a newly
added security field silently escapes a match that was written to be exhaustive.

**rustc lints.** `non_ascii_idents` (trojan-source / homoglyph identifiers in a
security codebase), `unsafe_op_in_unsafe_fn` (edition 2021 makes this allow-by-default;
denying it means every `unsafe` operation sits in a visible `unsafe` block even inside
an `unsafe fn` — which matters precisely in the two crates §3.1 cannot forbid), and
`meta_variable_misuse` (a `macro_rules!` arm that misuses its metavariables is a
correctness defect).

`elided_lifetimes_in_paths`, `unused_lifetimes` and `unused_macro_rules` were on the
first list and are **dropped** on rule A-1: all three are at zero, but none names an
invariant this project holds. Adopting a lint because it is cheap is how a registry of
protections becomes a maximal-Clippy policy. They are recorded in §9.

### §3.1 `#![forbid(unsafe_code)]` on the ten safe crates

Measured: production `unsafe` exists in exactly two crates —
`mcp-re-proxy` (8 sites: `async_fleet.rs` ×5, `app.rs` ×2, `main.rs` ×1) and
`mcp-re-client` (1 site: `main.rs`). The other ten workspace crates contain none.

Landing that against the tree qualified the claim three times, and each qualification
is a result rather than an obstacle:

**(a) `mcp-re-conformance` has no crate root.** It declares no `[lib]` and no binary —
only `tests/` and `tools/`. There is no production compilation unit to protect, so the
attribute has nowhere to go and nothing to say. Nine crates, not ten.

**(b) `mcp-re-core` is not unsafe-free under the prover.** `--features verify` expands
Verus `assume_specification` items in `verus_std_specs.rs` into `unsafe fn`
declarations. A plain `#![forbid(unsafe_code)]` turned the Verus lane red — all six
units, `error: declaration of an unsafe function`. The census could never have seen
this: `verify` is excluded from every cargo lane by a `compile_error!` guard. The
attribute is therefore `#![cfg_attr(not(feature = "verify"), forbid(unsafe_code))]` on
the two prover crates, and the property it states is exact: **no `unsafe` in any build
of this crate that can ship.** The verify feature cannot ship — the crate refuses to
compile if cargo enables it. `tools/verification/verify-verus` returns PASS, 6 units,
with the attribute in place.

**(c) Three of the nine are blocked by the module-size ratchet, and this is worth the
owner's attention.** `mcp-re-http-profile/src/lib.rs` (237 lines),
`mcp-re-test-paths/src/lib.rs` (298) and `mcp-re-transport/src/lib.rs` (938) are all
registered in `config/module-size-debt.toml`, and a registered file may not grow by so
much as the four lines this attribute costs. There is no `[workspace.lints]` escape:
`forbid` applies to nine members not twelve, must not be overridable, and is
conditional on two of them — a lints table can express none of those three. Shortening
the comment to dodge the ratchet is exactly what the ratchet exists to prevent.

So `forbid` lands on six crates now — `mcp-re-core`, `mcp-re-host`,
`mcp-re-client-core`, `mcp-re-client-proxy`, `mcp-re-policy`, `mcp-re-demo` — and the
other three wait. **All three are `status = "unreviewed"`: nobody has performed the
twelve-question census on any of them.** The size registry is currently blocking a
security hardening on three crate roots whose architectural debt has never been
investigated, and one of them is `mcp-re-http-profile`, the RFC 9421 carrier. That is
an argument for prioritising those three censuses that did not exist before this work,
and it is the recommended next unit after §4-A.

*Invariant:* these crates are structurally incapable of acquiring `unsafe`. Verified,
not asserted: an `#[allow(unsafe_code)]` added to `mcp-re-core` alongside an `unsafe`
block is rejected as `error[E0453]: allow(unsafe_code) incompatible with previous
forbid`.
*Failure class prevented:* an `unsafe` block arriving in a pure crate through an
ordinary PR, unreviewed as an architectural change.

`forbid`, not `deny`, and this is the substantive part: `deny` can be overridden by
an inner `#[allow]`; `forbid` cannot be overridden at all, from anywhere inside the
crate. Introducing `unsafe` into one of these ten therefore requires deleting the
crate-level attribute — a diff that cannot be reviewed as anything other than what
it is. **Per ruling 2, no allow mechanism may be introduced to soften this.** If a
crate genuinely needs `unsafe` later, the amendment to remove its `forbid` is the
architectural decision, and it is recorded as one.

For `mcp-re-core` and `mcp-re-http-profile` this is the strongest single item in
this amendment: their purity is currently asserted in module documentation and in
ADR-MCPS-011/012, and enforced by a dependency gate that says nothing about
`unsafe`. This converts that prose into a compiler theorem.

**Interaction with §6 lint scoping.** `#![forbid(...)]` is a crate-level attribute,
which the §6.4 `allow_discipline` rule forbids for *adopted ratchet lints* because a
crate-wide suppression hides debt. `forbid` is the opposite operation — it removes
the ability to suppress — so the rule does not apply and `unsafe_code` is not a
ratchet lint. The gate is unchanged; this is recorded so a later reader does not
read the two as contradictory.

---

## §4 Tier 1 adoption order (ruling 3)

Ordered by the property protected. Each entry states the invariant, the failure
class, and the *unit of work*, which is not always "fix N warnings".

### A. `string_slice` — first, and as a security-boundary defect

21 production sites; the ones that matter are in the RFC 9421 carrier:
`mcp-re-http-profile/src/verify.rs` ×6 (lines 138, 144, 169, 175, 270, 362) and
`sigbase.rs` ×3 (263, 276, 282), plus `mcp-re-proxy/src/transparency.rs` ×5,
`kms_endpoint_policy.rs` ×3, `async_serve.rs` ×2, `mcp-re-transport/src/remote.rs` ×2.

*Invariant:* an attacker-supplied header cannot panic the parser.
*Failure class:* `&value[start..i]` on a `&str` panics if the index is not a UTF-8
character boundary. `verify.rs` splits `Signature-Input` / `Signature` structured-field
lists and `sigbase.rs` splits the `@authority` derived component — both operate on
bytes the client controls, on the request path, before any signature has been
verified. A multi-byte sequence positioned across a delimiter offset is a
remote panic reachable pre-authentication.

*Unit of work:* this is **not** a lint cleanup. Treat it as a defect: establish for
each of the nine carrier sites whether the index is derived from a byte scan (in
which case the correct fix is to operate on `&[u8]` and convert once at the end, not
to insert a boundary check) or from a `char_indices` walk (in which case it is
already safe and the `expect` names why). The proxy and transport sites are assessed
after, separately. Then `deny` the lint — not ratchet it. A residual baseline on a
panic-reachability property is the wrong shape: either the parser is total on
untrusted input or it is not.

*Precedent for the target shape:* `mcp-re-core/src/time.rs::parse_rfc3339_utc`
already carries a Verus `ensures` establishing exactly this totality property over
all inputs. That is the standard the carrier parser should be held to.

### B. `wildcard_enum_match_arm` — new variants as compile-time obligations

16 production sites, concentrated where it matters:
`mcp-re-proxy/src/config_state/tls_custody.rs` ×3,
`communication_assurance/certificate_chain_evidence.rs` ×2,
`http_profile_serve.rs` ×2, `mcp-re-http-profile/src/verify.rs` ×2,
`block/artifact_binding.rs`, `mcp-re-client-core/src/binding_spec/mod.rs`,
`response.rs`, `mcp-re-client-proxy/src/transport.rs`, `mcp-re-client`.
Plus `match_wildcard_for_single_variants` ×3.

*Invariant:* adding a variant to a security, refusal, or evidence enum produces a
compile error at every site that must now decide about it.
*Failure class:* a new refusal reason, a new custody mode, or a new evidence class
silently inherits the semantics of the existing `_ =>` arm. This is the same failure
the project already ruled against elsewhere — "a fail-closed default that was never
re-examined" — and it is the mechanism by which a *added* authority acquires an
*old* decision.

*Unit of work:* per site, decide whether the wildcard is (a) genuinely total over a
foreign enum the crate does not own (`rustls`, `redis`, `std::io::ErrorKind` — these
are `#[non_exhaustive]` upstream and a wildcard is *required*), or (b) over an
MCP-RE-owned enum, where it must be replaced by explicit arms. Only (b) is debt.
Expect the ratchet baseline to be the (a) count, and expect it to be non-zero and
legitimate — that is what distinguishes this from the `string_slice` shape.

### C. `let_underscore_must_use` / `let_underscore_drop` — investigate, do not rewrite

30 sites each. Per ruling 3C the disposition must be established before any edit.
A first semantic pass over the audit/transparency cluster found three distinct
classes, which is itself the argument for not mechanically rewriting them:

- **Documented and correct.** `transparency.rs:680`
  (`release_before_dispatch`) discards a submit result under an explicit written
  argument that a stale marker over-reports indeterminacy, which is the safe
  direction. `audit_sink.rs:177/178/190` swallow stderr write errors under a stated
  "a sink that cannot write must not fail a request". These want an `#[expect(...,
  reason = ...)]` pointing at the existing argument, and no code change.
- **Teardown / test-fixture cleanup.** `retained_evidence.rs:65/128/300`,
  `transparency.rs:893/900`, `transparency.rs:400` (`writer.join()`). Low risk;
  `join()` discarding a panic payload during teardown is worth one look.
- **A genuine finding.** `audit_sink.rs:149` discards the `Result` of
  `std::thread::Builder::spawn`. The comment three lines above justifies swallowing
  *write* errors; it does not cover *spawn* failure. If the audit writer thread never
  starts, nothing drains the bounded channel, every record is dropped into
  `STDERR_AUDIT_DROPPED`, and `report_drops` — which is the only thing that would
  announce the loss — runs solely inside the thread that failed to start. The
  failure mode is a proxy that serves traffic while emitting no audit stream and no
  indication that it is not emitting one.

*Invariant:* a discarded `Result` or guard is discarded on purpose, and the purpose
is written down.
*Failure class:* silent loss of audit evidence — directly relevant to the open
finding that authorization audit is unobserved (issue #637).

*Unit of work:* triage all 30, fix the findings, `#[expect]` the intentional ones
with their reason, then ratchet from whatever baseline remains.

### D. `host_endian_bytes` and `iter_over_hash_type` — determinism, 1 site each

`host_endian_bytes`: `mcp-re-proxy/src/async_fleet.rs`. *Invariant:* no value that
crosses a process, a replica, or a persistence boundary is encoded in native byte
order. *Failure class:* a fleet whose replicas disagree about a byte order on
heterogeneous hardware — a class of bug that does not appear on a homogeneous test
fleet and cannot be reproduced from a single-architecture CI lane.

`iter_over_hash_type`: `mcp-re-proxy/src/trust_cache.rs`. *Invariant:* no ordered
output derives from `HashMap`/`HashSet` iteration order. *Failure class:* a
non-reproducible digest or audit record in a system whose evidence model is built on
content addressing. Rust randomises `HashMap` seeding per process, so this is
non-deterministic *between runs of the same binary*, not merely between platforms.

Note `big_endian_bytes` (28 sites) and `little_endian_bytes` (1) are **not** adopted:
those are the deliberate wire encodings. Adopting only `host_endian_bytes` is the
whole point — it says "state your byte order", not "use this one".

*Unit of work:* fix both, `deny` both. Two sites; no ratchet entry.

### E. Unsafe-block discipline in the two unsafe crates

`undocumented_unsafe_blocks` ×1 (`app.rs`), `multiple_unsafe_ops_per_block` ×4
(`app.rs`, `async_fleet.rs`, `main.rs`, `mcp-re-client/src/main.rs`),
`unnecessary_safety_comment` ×1 (`shared_replay.rs`).

*Invariant:* every surviving `unsafe` operation exposes its safety argument, and each
`unsafe` region is the smallest practical one.
*Failure class:* a multi-operation `unsafe` block whose `SAFETY:` comment justifies
one operation and is read as justifying all of them. This is the readable-review
property ADR-MCPRE-061 exists for, applied to the nine sites where the compiler has
stopped checking.

*Interaction:* these five sites are exactly the code inside `boundary.libc` and
`boundary.pkcs11` (`verification/policy/trust-boundaries.toml`), which cap at V0
without a registered assumption. The `SAFETY:` comment and the boundary's `beyond`
field are two statements of the same trust; they should agree, and this is the pass
that makes them agree.

Plus `mem_forget` ×1, moved here from Tier 0 by the §2 feature-lane correction:
`pkcs11_native.rs::Session::into_handle` forgets `self` to transfer the session handle
past `Drop`, under a `SAFETY:` comment that already names the argument (the `Session`
holds only `Copy` fields and a `PhantomData`, so nothing but the now-caller-owned handle
survives). Its disposition is an `#[expect(clippy::mem_forget, reason = ...)]` pointing
at that comment — the invariant is stated, it is simply not stated to the compiler.

*Unit of work:* seven sites total, in two crates. Ratchet at the measured baseline,
drive to zero, then `deny`.

---

## §5 The `#[expect]` question (ruling 6) — VERIFIED, and the answer is sequenced

Ruling 6 asked for verification before adoption. It was performed, and it found a
conflict. **This is the finding that most changes the plan.**

**`clippy::allow_attributes_without_reason` — ADOPT.** 37 production sites. It fires
on both `#[allow(...)]` and `#[expect(...)]` lacking `reason = "..."`, and it
generalises §6.4's justification requirement — which today covers only the six
adopted lints, via a regex in `allow_discipline` — to *every* suppression in the
workspace. Same rule, wider scope, no new mechanism. Ratchet from 37.

**`clippy::allow_attributes` — DECLINE, for now, and the reason is a gate defect.**

`allow_attributes` pushes every `#[allow]` toward `#[expect]`. That is desirable in
itself: a stale `#[expect]` becomes a compile failure, so suppressions self-clean.
But `scripts/clippy_ratchet_gate.py::allow_discipline` matches

```python
ALLOW_INNER = re.compile(r"#!\[allow\(([^)]*)\)\]")
ALLOW_OUTER = re.compile(r"#\[allow\(([^)]*)\)\]")
```

Neither matches `#[expect(...)]`. Verified empirically against the pinned toolchain
by running `allow_discipline` over a probe file containing an unjustified
`#[expect(clippy::arithmetic_side_effects)]`: **0 problems reported.**

So adopting `allow_attributes` first would migrate all 37 suppressions to a form the
§6.4 justification rule cannot see, and would do it while reporting success. That is
the same failure class §6.4 was written to prevent — a suppression that makes the
gate stop asking — and it is the precise shape of the standing rule that a gate's
exemption is part of its measurement.

**Ruling:** the gate is fixed first, the lint is adopted second.

1. Extend `allow_discipline` to treat `expect` identically to `allow`: the wide-scope
   rule, the module rule, and the justification rule all apply to
   `#![expect(...)]` / `#[expect(...)]`.
2. Extend `--selftest` with a probe asserting an unjustified `#[expect]` of an
   adopted lint is rejected — so the gate proves it sees the form, in the same way
   `--activation-probe` proves the lints fire.
3. Only then adopt `clippy::allow_attributes` and migrate.

One mechanism, extended. Not a second one.

---

## §6 Numeric conversion authority (ruling 4)

`as_conversions` reports 78 sites and is **not** adopted. `as` is not the defect;
unstated conversion is. The adopted lints are the ones that name a specific loss:
`cast_possible_truncation` (20), `cast_possible_wrap` (14), `cast_sign_loss` (9),
`cast_lossless` (2), `cast_precision_loss` (5), `integer_division` (21).

This is the §6.6 `arithmetic_side_effects` argument applied to a gap that lint does
not cover: it excludes casts entirely, so `x as u32` states nothing about overflow
while `x + y` is required to.

### §6.1 `mcp-re-core/src/time.rs` — the invariant is already stated, elsewhere

Ruling 4 directs starting here. Doing so produced a result that inverts the expected
disposition, and it is the reason this section is a ruling rather than a work item.

`time.rs` carries 15 of the 21 `integer_division` sites, 3 `cast_possible_truncation`,
3 `cast_sign_loss` and 1 `cast_lossless` — the densest numeric-conversion cluster in
the workspace. It is also **the most strongly verified module in it.**
`parse_rfc3339_utc` carries a Verus `ensures` bounding its output to the
representable civil range; `days_from_civil` carries `requires`/`ensures` bounding
its result to `[-719528, 2932897]`; `parse_fixed_digits` carries ADR-MCPRE-059
assumption ASM-0001 stating the digit bound explicitly, *because* the verifier
cannot establish it.

The conversion rules are therefore not missing. They are stated, in the strongest
form this project has, in the theorem registry — and per the standing rule that a
Verus-proved postcondition outranks a seal, they outrank a lint too.

**Ruling 6.1.** For `time.rs`, the disposition is `#[expect(..., reason = ...)]`
naming the Verus specification or the ASM-0001 assumption that bounds each
conversion — not a rewrite to `try_from`. A `checked_` conversion inserted where a
`requires`/`ensures` pair already establishes the bound adds an unreachable error
path, and an unreachable error path in a verified module is a branch the legality
model says cannot be taken — question 9 of the twelve. The work is to confirm each
of the 22 sites is genuinely covered by a spec clause and to name which clause,
which is a *review of the proof's coverage*, not a code change.

Where a site turns out **not** to be covered, that is a gap in the theorem, and the
correct fix is to extend the specification, not to add a runtime check the proof
does not know about.

### §6.2 The proxy sites — this is where the debt is

`mcp-re-proxy` holds 16 `cast_possible_truncation`, 9 `cast_possible_wrap`, 6
`cast_sign_loss`, 5 `cast_precision_loss`, concentrated in
`async_fleet.rs` ×7, `stage_timers.rs` ×7, `delegated_tls.rs` ×4, `tls.rs` ×4,
`async_serve.rs` ×2, `http_inner.rs` ×2. None has a Verus specification.

These are shard counts, worker indices, timer durations and TLS record sizes — the
values where a truncating `as` produces a *plausible wrong number* rather than a
crash. `stage_timers.rs`'s 5 `cast_precision_loss` sites are integer nanoseconds
becoming `f64` for SLO reporting, which is where a measured latency silently stops
being the latency that was measured.

**Ruling 6.2.** The deliverable is a **stated numeric domain per owner**: for each
cluster, what the value means, what range it is known to inhabit, and which of the
three §6.6 dispositions applies (checked, deliberately-saturating, or
provably-bounded-with-a-named-invariant). The lints are then ratcheted from the
post-statement baseline. The important artefact is the statement; the count is how
we keep it true.

Note `mcp-re-proxy/src/clock.rs::now_unix` is itself such a site
(`d.as_secs() as i64`, a `u64`→`i64` narrowing) inside the module that owns clock
acquisition. It is a good first unit: small, security-relevant, and its
fail-direction argument is already written out in the module docs.

---

## §7 Time authority (ruling 7) — the wall clock is already modelled; the monotonic clock is not

Ruling 7 asked for the canonical owners and the permitted primitive boundary before
any denylist. Establishing them produced the second result that inverts the original
proposal.

### §7.1 Wall-clock: the boundary exists, is complete, and has zero drift

`verification/policy/trust-boundaries.toml` already declares `boundary.clock`:

> ACQUISITION of wall-clock time from the operating system. The authority this
> boundary names is the act of asking the OS what time it is and treating the answer
> as true — not the handling of a timestamp that some caller already supplied.

It lists 16 paths and caps them at `V0` without a registered assumption. It also
carries a recorded correction from 2026-08-11 for exactly the error this amendment
nearly repeated: the boundary once declared `mcp-re-core/src/time.rs`, "wrong in
both directions — it named a module that holds no clock authority, and it named none
of the sixteen that do."

Measured against the tree: **every** production `SystemTime::now` site is inside a
declared path, and **every** declared path contains at least one. Zero drift, both
directions.

So the original framing — "`SystemTime::now` at 30+ sites is ambient authority no
gate detects" — was wrong. It is declared authority, and the model is correct. The
proxy's `clock.rs` and the host's `SystemClock` are the two *wrappers*; the other
fourteen paths (`aws_sts.rs`, `gcp_kms_keysource.rs`, `redis_store.rs`, `ocsp.rs`,
`tls.rs`, `trust_cache.rs`, …) hold acquisition authority in their own right, for
protocol reasons — SigV4 request signing, OCSP `producedAt`, TLS validity — and the
boundary already says so.

**Ruling 7.1.** The rule to add is not a prohibition. It is a **consistency gate
between the code and the declaration**:

- `disallowed_methods = ["std::time::SystemTime::now"]` in the strict clippy config;
- each of the 16 declared owners carries an item-scoped
  `#[expect(clippy::disallowed_methods, reason = "boundary.clock — <what enters here>")]`;
- a gate assertion that the set of files carrying that `expect` is **exactly** the
  `boundary.clock` `paths` set.

This expresses "time enters here". Site 17 fails the build; a site removed from the
code without being removed from the declaration fails it too. The declaration is
true today by inspection and by nothing else — this makes it true by construction.

This is the shape ruling 7 asked for, and it is strictly better than a denylist:
the permission is granted by an architectural document, not by a name.

### §7.2 Monotonic time: an undeclared, distinct capability

`boundary.clock` covers wall-clock acquisition only. `std::time::Instant::now` is
measured at **64 production sites across 18 files**, of which **14 files hold
monotonic authority and no wall-clock authority at all** and appear in no boundary:
`mcp-re-client/src/serve.rs` ×14, `managed_worker.rs` ×8, `handshake_quota.rs` ×7,
`mcp-re-transport/src/lib.rs` ×4, `materialized_runtime.rs` ×4,
`deadline_stream.rs` ×3, `cli.rs` ×3, `control_runtime.rs` ×2, `stage_timers.rs` ×2,
`async_serve.rs` ×2, `delegated_tls.rs` ×2, and four singletons.

The capabilities are related but not identical, and the difference is what decides
the trust class:

| | wall clock (`SystemTime`) | monotonic clock (`Instant`) |
|---|---|---|
| what it asserts | a point on a timeline shared with peers | elapsed duration within one process |
| adversary model | an operator or NTP peer can move it; skew vs. a peer is unbounded | cannot be moved backwards; not attacker-controllable |
| comparable across processes | yes — and freshness, expiry and revocation depend on it | **no** — comparing across processes or reboots is meaningless |
| what a wrong reading does | admits a stale request, or refuses a fresh one | mis-sizes a timeout or a quota window |

Monotonic time is the *weaker* authority — which is the argument for declaring it
separately rather than folding it into `boundary.clock`. Folding would either
over-state the trust cost of 14 files or under-state it for the 16, and a boundary
that means two things is the same defect the 2026-08-11 correction repaired.

**Ruling 7.2.** Before any lint: declare `boundary.monotonic_clock` in
`trust-boundaries.toml`, with its own `beyond` ("whether the process was suspended
or the runtime descheduled between two readings") and its own
`max_class_without_assumption`. Then apply the §7.1 mechanism to
`Instant::now` against *that* boundary.

Sequencing matters here for a specific reason: `handshake_quota.rs` and
`deadline_stream.rs` use `Instant` to enforce security-relevant limits — handshake
rate limiting and connection deadlines. Declaring the boundary tells a reader what a
theorem over those modules does and does not cover, which is a result worth having
whether or not the lint is ever adopted.

---

## §8 Visibility (ruling 5)

`unreachable_pub`: 47 production sites. Per ruling 5 this is an ownership pass, not
47 edits.

*Invariant:* a `pub` item corresponds to an explicitly supported contract, per the
CLAUDE.md visibility ladder and ADR-MCPRE-061 §4.
*Failure class:* an item that is `pub` for no reason is indistinguishable from an
item that is `pub` for a reason, so the ladder stops carrying information — and the
§4 rule that "widening needs a reason at the point of widening" becomes unfalsifiable.

`unreachable_pub` is the mechanical form of exactly one clause of that ladder: it
finds items marked `pub` that are not reachable from outside the crate, i.e. cases
where the author reached for the top of the ladder and the compiler can prove a
lower rung suffices. It cannot judge whether a genuinely-reachable `pub` is
*justified* — that stays a review rule.

**Ruling 8.** Sequenced after §4-A/B/C/D, driven per owner rather than per warning,
using the `docs/dev/sealed-owners.md` procedure. Each of the 47 gets the narrowest
level that lets its legitimate consumer work, and the compile errors encountered
while narrowing are the boundary detector, not an obstacle. Ratchet from the measured
baseline once the first owner pass lands; `deny` is not expected in this amendment's
horizon.

Related and adopted with it as plain hygiene, because they measure the same thing
from the other side: `unused_qualifications` (30) — a `crate::foo::Bar` path where
`Bar` is in scope usually marks a module boundary that moved and a reader who no
longer knows where the owner is.

---

## §9 Explicitly NOT adopted, with reasons (ruling 8)

| lint | sites | why declined |
|---|---|---|
| `exhaustive_enums` | 127 | Pushes toward `#[non_exhaustive]`, which CLAUDE.md and `docs/dev/sealed-owners.md` rule **seals nothing here** — it binds only other crates, and every consumer of these owners lives in the same crate. Adopting it would encourage a marker that looks like a seal and is not. Actively harmful. |
| `exhaustive_structs` | 130 | Same, and it collides with §4-B: a `#[non_exhaustive]` enum *requires* the wildcard arm that §4-B is removing. |
| `as_conversions` | 78 | Bans the syntax rather than the unstated conversion. §6 adopts the five lints that each name a specific loss; this one would make every deliberate, provably-bounded cast a warning and dilute the signal. |
| `std_instead_of_core` | 225 | No `no_std` target exists or is planned. Pure churn. |
| `missing_errors_doc` | 213 | Documentation completeness, not an invariant. The refusal taxonomy is already specified in ADR-MCPS-040 and gated by the conformance corpus — a better authority than a doc-comment lint. |
| `str_to_string` / `string_to_string`* | 195 / 0 | Style. (*`string_to_string` is adopted at zero cost in §3 as a no-op-clone check, not as a style rule.) |
| `map_err_ignore` | 174 | Would flag `.map_err(\|_\| ...)`, which is frequently the *correct* fail-closed pattern: deliberately not propagating an inner error's detail into a refusal an untrusted peer will see. Adopting it would push against the error-taxonomy design. |
| `print_stderr` | 66 | The proxy is a daemon; stderr **is** the audit and log transport (`audit_sink.rs`). Denying it would ban the thing the design depends on. `print_stdout` is adopted at 1 site — stdout is not a log channel. |
| `impl_trait_in_params` | 60 | Style preference about API shape, no invariant. |
| `single_char_lifetime_names` | 60 | Style. |
| `missing_debug_implementations` | 52 | Would add `Debug` to types holding key material — actively wrong here. Declined on security grounds, not effort. |
| `big_endian_bytes` / `little_endian_bytes` | 28 / 1 | These are the deliberate wire encodings. Only `host_endian_bytes` is adopted (§4-D); the rule is "state your byte order", not "use this one". |
| `default_numeric_fallback` | 19 | Overlaps §6 without adding a distinct failure class; revisit after §6.2 states the numeric domains. |
| `mod_module_files` / `self_named_module_files` | 18 / 2 | Layout convention, and the two are mutually exclusive. No invariant. |
| `shadow_unrelated` | 15 | Reviewability argument is real but weak; would produce 15 renames with no property established. Deferred, not declined outright. |
| `missing_panics_doc` | 17 | Subsumed by §4-A: the goal is that the functions do not panic, not that they document that they do. |
| `semicolon_if_nothing_returned`, `else_if_without_else`, `match_same_arms`, `redundant_type_annotations` | ≤14 | Style. |
| `elided_lifetimes_in_paths`, `unused_lifetimes`, `unused_macro_rules` | 0 | At zero and therefore free to land, and dropped anyway: rule A-1 requires a named invariant, and these are readability and dead-code hygiene. Recorded so their absence reads as a decision rather than an oversight. |
| `string_to_string` | n/a | **Removed from clippy 0.1.97.** It measured 0 because it does not exist. Listed here so nobody re-adds it from an old census. |
| `cognitive_complexity` | 7 | Already declined in ADR-MCPRE-061 §6.5 — 6 of 7 are reported by `too_many_lines`. Recorded here so the declination is not re-litigated. |

---

## §10 Landing plan

Two branches, per ruling 1 and 2, neither touching ADR-MCPRE-066 work.

| # | content | gate impact |
|---|---|---|
| 1 | this amendment | docs only |
| 2 | §3 Group A (`[workspace.lints]` + `workspace_lints_gate.py`), Group B (gate `ADOPTED`), §3.1 `forbid` ×6 | no registry entry — all at zero |
| 2b | §3.1 (c): the twelve-question census on `mcp-re-http-profile`, `mcp-re-test-paths`, `mcp-re-transport` crate roots, then `forbid` on those three | module-size registry |
| 3 | §5 step 1–2: `allow_discipline` sees `expect`, plus its selftest probe | gate only |
| 4 | §5 step 3 + `allow_attributes_without_reason` | new registry entries |
| 5 | §4-A `string_slice` — as a defect, `deny` when closed | none if driven to zero |
| 6 | §4-B `wildcard_enum_match_arm` | new registry entries |
| 7 | §4-C `let_underscore_*` triage, incl. the `audit_sink.rs:149` finding | new registry entries |
| 8 | §4-D two determinism sites, `deny` | none |
| 9 | §4-E unsafe-block discipline, incl. the `mem_forget` site | new registry entries |
| 10 | §7.2 declare `boundary.monotonic_clock` | policy only |
| 11 | §7.1 + §7.2 `disallowed_methods` + boundary-consistency gate | new gate |
| 12 | §6.1 `time.rs` proof-coverage review | expects only |
| 13 | §6.2 proxy numeric domains, per owner | new registry entries |
| 14 | §8 `unreachable_pub` per-owner passes | new registry entries |

Items 5–14 are separate units of work, each closing on its own evidence. Nothing in
this amendment authorises landing them as one sweep.

## §11 What ratification of this amendment means

Accepting this document accepts §3 and §9 as decided, and §4–§8 as the *classification
and ordering*. It does not accept any particular baseline number: each registry entry
is written when its unit of work lands, measured under `--all-features` per §2.

It does not accept §5 step 3, §6.2, §7.1, §7.2, or §8 as executable yet — each names a
prerequisite (a gate fix, a stated numeric domain, a declared boundary, an owner pass)
that is itself the deliverable.
