# Round-7 security-audit checkpoint — handoff

This is a **preservation checkpoint**, not a completion record. It exists because the
round's work was sitting in an uncommitted working tree with its findings in a
gitignored directory — recoverable, but one `git checkout`, failed rebase, or
tree-is-disposable assumption away from being lost.

**It does not claim the five open findings are closed.** It claims exactly two things:
the 148 landed fixes are preserved, and the decisions taken about the remaining five
are recorded so the next context does not re-derive them.

## Identity

| | |
|---|---|
| branch | `checkpoint/security-audit-round-7` |
| base (pre-round `main`) | `5491cddb2d9ba2aa2cfbbf76d9a2b8b3645c64b0` |
| fixes commit | `fa5677a6e9549bca7c0f8dfda70d03e3cfc94023` |
| artifacts commit | see `git log --oneline base..HEAD` — the commit that added this file |
| diffstat (fixes commit) | 77 files changed, 10,499 insertions(+), 851 deletions(-) |
| `git status --short` at checkpoint | clean (0 entries) after both commits |
| working tree at the time of the fixes commit | 77 ` M`, 0 `??`, 0 staged, empty stash |

`work/` is ignored via `.gitignore:21`. The audit artifacts are therefore **force-added**
on this branch only. If these commits are ever replayed onto an ordinary development
branch, drop the artifacts commit and keep the fixes commit.

### Changed-file inventory (fixes commit, by area)

| area | files |
|---|---|
| `mcp-re-proxy` | 24 |
| `mcp-re-http-profile` | 13 |
| `sdk` (py/ts/fixtures/PARITY.md) | 9 |
| `mcp-re-client` | 6 |
| `deploy` (helm/docker/k8s/codebuild) | 6 |
| `scripts` | 4 |
| `mcp-re-core` | 3 |
| `tools` | 2 |
| `mcp-re-client-proxy` | 2 |
| `mcp-re-client-core` | 2 |
| `docs`, `.github`, `.gcloudignore` | 3 |

## Finding tally

153 clusters raised (stages 1 and 2; stage 3's adversarial verify gate skipped by owner
decision). Per `triage.json`:

- **148 `confirmed-fixed`** — landed in `226d786`
- **5 `needs-owner-ruling`** — NOT fixed, NOT closed, listed below

## Gate record

The commands and their **unfiltered** exit status. Two separate runs are recorded
because the last one predates a `scitt.rs` edit — see the caveat, which is the single
most important line in this document.

### Run A — `scripts/local_gate.sh`, 2026-08-04, pre-checkpoint tree

| stage | command | result |
|---|---|---|
| 1 static gates | `scripts/local_gate.sh` | **PASS** — image-tag, SLO-invocation, bazel-srcs and ES256-containment selftests all PASS (`final-gate.log:3-17`) |
| 2 cargo suites + SDK | same run | **FAIL**, `GATE_EXIT=1` (`final-gate.log:3344`) |
| 3 bazel parity | `scripts/local_gate.sh --from 3` | **FAIL** → **FAIL** → **PASS** (three attempts, below) |
| 4 local SLO lane | same run | **FAIL**, `GATE34_EXIT=1` (`final-gate-34c.log:232`) |

**Stage 2's failure was not a test failure.** Every cargo suite in the run passed; the
stage failed on its last step, `git diff --exit-code -- sdk/fixtures/parity_vectors.json`
(`local_gate.sh:165`), because the regenerated parity oracle carried the new
`non_ascii_params_and_binding` case while the fixture was still uncommitted — the gate
diffs the regenerated file against **HEAD**, not against the working tree. Re-verified
after the fixes commit on this branch: a throwaway venv, the same
`mcp_re_sdk-0.1.0-cp39-abi3-macosx_11_0_arm64.whl`, `tools/gen_sdk_parity_fixture.py`
→ `REGEN_EXIT=0`, `git diff --exit-code` → `DIFF_EXIT=0`. The failure was an artefact of
uncommitted state and clears on commit. This is now proven, not asserted.

**Stage 3 took three attempts, and both failures were real.**

1. `final-gate-34.log` — `bazel-gazelle-gate: FAIL`, missing target
   `mcp-re-client/BUILD.bazel: mcp-re-client_test`. The binary crate had no test target
   at all. Fixed by adding `mcp_re_client_cli_test` (`crate = ":mcp_re_client_cli"`)
   rather than by allowlisting.
2. `final-gate-34b.log` — gazelle gate PASS, but `//mcp-re-client:mcp_re_client_test`
   **FAILED TO BUILD**: `error[E0433]: cannot find module or crate mcp_re_http_profile`
   at `config.rs:669,799`. Missing Bazel dep edge. `Executed 0 out of 78 tests: 1 test
   passes, 1 fails to build, and 76 were skipped.`
3. `final-gate-34c.log` — `bazel-gazelle-gate: PASS`,
   **`Executed 73 out of 78 tests: 78 tests pass.`**

**Stage 4 FAILED and the failure is environmental — established by A/B, not asserted
from load.** Median **4450.7 rps** over 6 reps (4427.6–4491.1) against a floor of
4701.3, anchor 5530.9. Every latency percentile passed; only throughput fell. A detached
worktree at the pre-round pin `5491cdd`, measured on the same box within the hour, gave
**4583.4 rps** over 3 reps (4563.0–4636.9) — **the pre-round tree fails the same floor on
the same box**. No baseline may be declared from either. `ALLOW_NOISY_BOX` was not set.

The residual is the honest part: the two ranges do not overlap, a **~2.9% gap** that the
environmental argument does not explain, and of the order one would expect from
`reserve()`'s second pre-dispatch fsync chain plus the admission semaphore. **The round
may not be called throughput-neutral until an A/B/B/A runs on a genuinely quiet box.**
What it is *not* is the ~20% regression the raw gate line implies.

### CAVEAT — the gate-measured tree is not the committed tree

`mcp-re-http-profile/src/scitt.rs` was edited **after** `final-gate-34c.log` (12:56Z).
The edit is the C080 work: a corrected module doc comment, plus a `combine_sequence()`
test helper and the test
`the_tree_size_determines_the_leaf_index_within_every_ambiguity_class`, both inside
`#[cfg(test)]`. The verification function `rfc9162_root_from_inclusion_proof` is
unchanged.

What was verified on the post-edit tree: `cargo test -p mcp-re-http-profile` → **334
passed, 0 failed** (up from 333), and `cargo clippy -p mcp-re-http-profile --all-targets
-- -D warnings` → exit 0. That covers the only crate touched.

### Run B — checkpoint gate against the fixes commit

`work/security-audit-2026-08-03/checkpoint-gate.log` — `scripts/local_gate.sh --fast`
(stages 1–2), then `scripts/bazel_gazelle_gate.py` and `bazel test //...` for stage 3.
Stage 4 was deliberately not re-run: it is the environmental FAIL above, and re-measuring
on the same box would produce another number that means nothing. **Read this log before
trusting the checkpoint — if it is absent or non-zero, the gate has not been re-run
against the committed tree and the next context must run it.**

Re-running it earned its cost immediately: the first attempt **failed stage 1** on a
`cargo fmt --check` diff at `scitt.rs:1403` — inside the post-gate C080 test edit described
in the caveat above, i.e. exactly the code the last full gate never saw. Fixed with
`cargo fmt -p mcp-re-http-profile` and the fixes commit amended (`226d786` → `fa5677a`).
Stage 3 passed on that first attempt regardless: `bazel-gazelle-gate: PASS`,
`Executed 12 out of 78 tests: 78 tests pass`.

**Result against `fa5677a` — the tree this checkpoint actually contains:**

| stage | command | exit | measured |
|---|---|---|---|
| 1–2 | `scripts/local_gate.sh --fast` | `FAST_EXIT=0` | 156 cargo suites, **2107 passed, 0 failed**, 25 ignored; parity oracle regenerated and `git diff --exit-code` clean |
| 3 | `python3 scripts/bazel_gazelle_gate.py` | `GAZELLE_EXIT=0` | no unmanaged semantic drift |
| 3 | `bazel test //...` | `BAZEL_EXIT=0` | **`Executed 9 out of 78 tests: 78 tests pass.`** |

Started `2026-08-04T14:53:35Z`, finished `2026-08-04T15:53:11Z`. **No source file was
edited during the run.** The only files written while it ran were `HANDOFF.md`,
`triage.json` and the gate's own log — all under `work/`, which no build reads.

Stage 4 was not re-run; it remains the environmental FAIL characterised above, and the
quiet-box A/B/B/A is still owed.

## Post-checkpoint: the two slices were executed

Both slices named under "Next context" below have now been implemented on this branch.
The descriptions of the five findings that follow are the STATE AT CHECKPOINT and are
kept as the record of what was found; `triage.json` carries the current disposition and
a `resolution` field for each.

**Slice 1 — C095 fail-stop ceiling.** `FileManifestFloor::with_bounds(path, bootstrap,
ceiling)`, surfaced as `floor.ceiling_version` in `FloorConfig::Durable`. The comparison
is exactly `stored_floor <= ceiling → normal`, `stored_floor > ceiling → FloorAboveCeiling`,
never `min()`. Also enforced at `record()`, so a signed manifest above a stale ceiling is
refused before it writes a floor that would brick every later read, and at construction
when `bootstrap > ceiling`. The finding is NOT closed — it is superseded, per the ruling
below.

**Slice 2 — the C080/C082/C114 contract revision**, done as ONE revision under the
profile `mcp-re-evidence/v2`, with both frozen corpora regenerated.

- **C080**: `H(domain ‖ profile ‖ log_identity ‖ vds ‖ tree_size ‖ leaf_index ‖ root)`,
  every component length-delimited, in the receipt's PROTECTED header and marked
  CRITICAL. `Receipt::from_cose` refuses any critical label it does not understand, which
  is what stops a v1-only implementation from verifying a v2 receipt while ignoring the
  commitment. The pinned `ReceiptPositionProfile` (`Bound`/`Unbound`, default `Unbound`)
  governs whether ABSENCE is tolerated; a present-but-wrong commitment is refused under
  either. Checked after the receipt signature — before it, the value is just another
  attacker-supplied field — and against the DERIVED root.
- **C082**: `reconstruct_chain` takes a `ChainAudit` and enforces audience-tuple equality
  and `artifact_bindings[]` through `verify::enforce_full_profile_bindings`, the same
  function the live path calls. One implementation, so a `Complete` label cannot come to
  mean less than an admission.
- **C114**: `ChainReconstruction::submitted_commitment`, a length-delimited digest over
  the submitted hops, computed before anything is judged so it exists on every exit path.

The bytes are unchanged in one important place: the external cross-verification vectors
still carry v1 statement payloads and still verify. `submitted_commitment` reads with
`serde(default)` because a v1 statement genuinely has no submission identity — safe here
and deliberately NOT done for the receipt header, because this field sits inside the
payload the issuer's COSE_Sign1 covers, so it cannot be stripped.

## The five open findings

None of these is closed. All five are `needs-owner-ruling` in `triage.json`.

### R7-C080 — medium, `mcp-re-http-profile/src/scitt.rs:661`
*RFC 9162 fold admits restated `(leaf_index, tree_size)`.*

The round-6 doc claim that the fold binds the log position was **false**, and has been
corrected in the code. What the verifier computes is fixed by the *sequence of combine
directions* the loop takes, so any two positions producing the same sequence produce
byte-identical evidence — no hash collision required. RFC 9942's `RFC9162_SHA256` receipt
payload is the bare Merkle Tree Hash, which never covers `tree_size`.

**Exhaustive finite measurement** (a mirror of `rfc9162_root_from_inclusion_proof`,
enumerated over every pair with `tree_size <= 1024`): **98.4% of positions lie in a class
with at least one other member, spread over 251 distinct classes; only 4 pairs of 524,800
are unique.** Refusing ambiguous positions is therefore not an available defence.
*Recorded as an exhaustive finite measurement, not an algebraic characterisation — the
security conclusion does not depend on claiming it universally.*

Also measured: **no class contains two members sharing a `tree_size`**, so an
authenticated size would pin the index. **This is deliberately not the chosen fix** — it
is a property of the current verification algorithm, not of the evidence, and a security
contract that depends on a test continuing to pass is weaker than one that binds the fact
explicitly.

`Receipt::tree_size` / `Receipt::leaf_index` are now documented as unauthenticated
transport hints. The only workspace-wide readers are assertions in `scitt.rs`,
`mcp-re-conformance/tests/scitt_interop_test.rs:157-158` and
`scitt_vectors_test.rs:466-467`.

### R7-C082 — medium, `mcp-re-http-profile/src/chain.rs:287`
*Chain reconstruction uses the minimal request path.*

Block presence/validate/target-URI binding landed, verified against all seven frozen
chain vectors with no label movement. The remainder — audience-tuple equality and
`artifact_bindings[]` — needs `reconstruct_chain` to take `expected_audience` and
artifact material, which breaks `mcp-re-proxy/transparency.rs:696` and
`http_profile_vectors_test.rs:2309`, and flips all seven frozen chain vectors
(`expected_audience_hash` is the synthetic string `aud-scope-1`; the frozen hops carry an
`oauth-dpop` binding with no `Authorization` header).

### R7-C095 — medium, `mcp-re-client-proxy/src/manifest_floor.rs:111`
*The manifest rollback floor can be raised without bound by anyone who can write the
floor directory.*

True as a mechanism. `read_floor` takes `max()` over marker names with no ceiling and
`min_version()` is `max(directory, bootstrap)`, so one file named
`18446744073709551615` pins the floor at `u64::MAX` and
`mcp-re-client-core/src/trust_manifest.rs:298-303` then rejects every future manifest as
`Stale` — **including a break-glass revocation**. Reached on the serving path via
`mcp-re-client/src/anchors.rs:104-112` (`FloorConfig::Durable`). Same class as the TUF
fast-forward attack.

**CORRECTION to the rationale recorded in `triage.json` (`owner_correction` field).** The
recorded rationale rejected an operator ceiling on the grounds that it "clamps a
LEGITIMATE floor down and re-opens the rollback window." That describes a *defective*
ceiling, not a property of ceilings. The correct behaviour is:

```
stored_floor <= trusted_ceiling  ->  continue normal validation
stored_floor >  trusted_ceiling  ->  FAIL-STOP: inconsistent trusted state
```

and never `effective_floor = min(stored_floor, trusted_ceiling)`. The ceiling must itself
come from a trust domain the floor-directory writer cannot modify, or it adds no
security. This converts a silent rollback-window reopening into a loud, detected outage.
It does not close the finding — it cannot preserve availability after a malicious
fast-forward, only fail safely — but it is a real, local, available gain that neither the
original agent nor the first review proposed.

### R7-C114 — medium, `mcp-re-http-profile/src/scitt.rs:131`
*A Signed Statement about a chain broken at hop 0 has no identity — all such records are
byte-identical.*

The record needs an identity derived from the **submitted** hop bytes, which
`ChainReconstruction` never carries (it holds only the verified prefix). Blocked on two
frozen artifacts: `mcp-re-conformance/tests/vectors/scitt/*.json` are frozen COSE octets
embedding the serialized payload, and `scitt_vectors_test.rs:160-174` builds
`ChainReconstruction` as an exhaustive struct literal, so any new field breaks that crate.

### R7-C139 — low, `mcp-re-http-profile/src/verify.rs:800`
*Content-Digest hashes the full 16 MiB body before any signature or keyid work.*

Availability only, no bypass. Ordering confirmed at `verify.rs:807-808` with the signature
untouched until ~`verify.rs:830`; same shape at `verify.rs:1000, 1227, 1379, 1518` and
`bodyless.rs:670`. Not changed: reordering would put the trust store on the path of
digest-mismatched traffic, reversing the deliberate v0.11 grill C.1 choice and changing
which wire code fires for a message that is both digest-mismatched and signature-invalid
(frozen vectors); a pre-digest size bound has no home (`VerifierPolicy` carries no body
ceiling; the real one is the deployment's `max_body_bytes` in `mcp-re-proxy/src/tls.rs`).
The asymmetry is now documented at `verify.rs:805-816`.

## Settled decisions the next context should not re-derive

**C080, C082 and C114 require ONE coordinated corpus revision.** All three are blocked on
frozen conformance corpora, and all three are receipt/chain contract changes. Doing them
as three separate flinches at frozen vectors produces three incompatible intermediate
states. The owner has authorised corpus regeneration.

**The C080 fix is an explicit protected-header tuple commitment**, not reliance on
`tree_size` sufficiency. The commitment must be:

- versioned
- domain-separated
- unambiguously encoded — the project's canonical length-delimited discipline, **not raw
  concatenation**
- bound to the receipt profile *and* the verification algorithm
- explicit about **both** `tree_size` and `leaf_index`
- linked to the signed root rather than relying on an implicit relationship

Conceptual preimage (encoding to be the project's canonical form):

```
H(domain ‖ profile_version ‖ log_identity ‖ vds_algorithm ‖ tree_size ‖ leaf_index ‖ root_hash)
```

**Old receipts must not be retrospectively reinterpreted as satisfying the stronger
contract.** The revision needs a visible profile/schema transition:

- *old profile* — authenticates inclusion in the signed root, but not the exact exposed
  position tuple;
- *new profile* — explicitly authenticates the tuple and the C082/C114 bindings.

An implementation that understands only the old profile **must not** silently accept a
new receipt while ignoring the new commitment. Enforce via a critical protected parameter
or an equivalent profile-version rule.

This is a profile extension, not an RFC amendment: RFC 9942's protected-header map permits
additional protected parameters. Calling it "just a wire change" understates it — it
requires service-side signing changes — but it needs no new Merkle algorithm, and where a
service already publishes RFC 9162 signed tree heads, requiring an STH would need no
profile change at all.

**C095's ruling: security-critical floor state must not be authoritative state writable by
the actor it constrains.** The existing finding should be closed as *superseded by* a
concrete trusted-floor-store issue, once that issue has enforceable acceptance criteria.
Integrity alone is insufficient — a MAC does not prevent replay of an older validly-MACed
value (cf. Android Verified Boot rollback protection). Acceptance criteria must include:

- the constrained actor cannot write or reset the authoritative floor
- authenticated state
- anti-replay / monotonic freshness
- atomic, crash-consistent updates
- explicit recovery after corruption or malicious fast-forwarding
- audit evidence for every floor advance
- a test proving an old valid state cannot be replayed
- a test proving an excessive state causes a loud outage rather than a rollback

## Next context — two slices, in this order

1. **C095 fail-stop ceiling.** Small, local, independent of the corpus work. Exactly the
   comparison above; never `min()`. The ceiling's trust domain must exclude the floor-
   directory writer.
2. **Coordinated C080 / C082 / C114 receipt-profile and corpus revision.** One deliberate
   contract revision with a visible profile transition, then regenerate the frozen SCITT
   and chain corpora, then re-run `scripts/local_gate.sh`.

C139 remains an open owner ruling on digest-before-signature ordering; it is independent
of both slices.

Still outstanding regardless: **the quiet-box A/B/B/A** for the ~2.9% SLO residual, before
the round may be called throughput-neutral.

## Process rules this round established

Both are recorded in full in `README.md`; they are repeated here because they cost real
work.

**An agent must persist its findings file after every resolved finding, not at the end.**
All eight remediation agents were killed mid-edit by a quota exhaustion. None had written
results, so every agent's knowledge of what it had done was lost while ~6,900 lines of its
edits stayed in the tree — and a killed agent leaves a tree that does not compile
(`cargo check --workspace --all-targets` exited 101). Work held only in a context window
is lost whole; work on disk is lost only back to the last write.

**A mutation harness that can block is a harness that can publish a half-reverted tree to
every concurrent reader.** Two separate negative-control harnesses reverted a fix, launched
`cargo test`, and blocked — one on the build lock, one on a cold target directory — leaving
the source in its mutated state for minutes while other work read it. Both restored
correctly. Isolate the target directory, and treat the restore as the harness's obligation
on every exit path.
