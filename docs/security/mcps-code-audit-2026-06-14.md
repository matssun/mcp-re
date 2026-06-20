# MCP-S Stage-3 Verify-Audit Report (security-audit-funnel)

Date: 2026-06-14
Scope: 5 adversarial findings (#23, 3-lens panel) + fix re-verification (#20–26)

---

## 1. #23 Finding Verdict Summary

Panel rule: a finding is **confirmed** when ≥2/3 lenses vote `confirmed_real`.

| Finding | Claim (1-line) | confirmed_real | false_positive | already_mitigated | Verdict | Needs Redis | Locally fixable |
|---|---|:--:|:--:|:--:|---|:--:|:--:|
| F1-freshness-ordering | Non-positive remaining freshness TTL not pre-rejected before replay store consulted (trait lacks `now_unix`) | 0 | 0 | 3 | **Already mitigated** | No | Yes |
| F2-retain-until-bound | `retain_until = expires_at + skew` unbounded against non-positive/stale `expires_at` | 0 | 0 | 3 | **Already mitigated** | No | Yes |
| F3-redis-ttl-clamp | `compute_ttl_ms` clamps stale retain-until to 1ms and proceeds with the write | 0 | 0 | 3 | **Already mitigated** | No | Yes |
| F4-redis-wait-quorum | WAIT-quorum failure leaves nonce on primary → legitimate same-request retry rejected as replay | 2 | 0 | 1 | **CONFIRMED** | Yes (panel) | Split (see §4) |
| F5-inmem-unbounded | `InMemoryAtomicReplayStore::insert_if_absent` ignores `now_unix`, never prunes → unbounded keyspace | 0 | 1 | 2 | **Not real** (mitigated/FP) | No | Yes |

Net: **1 confirmed (F4)**, 4 not actionable as vulnerabilities (F1/F2/F3 already mitigated by pipeline step ordering; F5 mitigated/false-positive — in-memory store is documented test-only and the production Redis path derives a bounded PX TTL).

---

## 2. Three Buckets

### (a) Locally-proven fixes needed (macOS Rust unit tests, no Redis)

- **None of F1/F2/F3/F5 require a fix** — they are already mitigated or false-positive.
- **F4 (distributed-behavior lens only)** argues the gap is *confirmable and fixable locally*: the write-before-WAIT ordering, the absence of a compensating `DEL`, and the `SET-NX → Ok(None) → Replay` path are all statically visible, and the existing fake-connection harness (`run_with_reconnect` tests) can drive a scripted connection to prove orphan-then-replay and regression-test a compensating-`DEL` fix. This is the one lens that places F4 partly in this bucket. See §4 for the split.

### (b) Redis / distributed fixes needing cluster verification

- **F4-redis-wait-quorum (CONFIRMED, 2/3).** Both `correctness-from-source` and `threat-model` lenses set `needs_distributed_verification = true` / `locally_fixable = false`: demonstrating the full SET-lands → WAIT-fails-with-partial-ack → retry-sees-Replay sequence requires a real multi-replica Redis under induced replica lag; `WAIT` returning a partial ack count cannot be reproduced with macOS-local unit tests. The local test only covers the pure `wait_quorum_satisfied` boundary predicate.

### (c) False-positives / already-satisfied

- **F1-freshness-ordering** — already mitigated. `check_freshness` (pipeline step 9, `?`-aborts) runs before replay `check_and_insert` (step 12); stale requests (`now_unix > expires + skew`) are rejected with `ExpiredRequest` and never reach the store. Trait omitting `now_unix` is by design. Provable locally.
- **F2-retain-until-bound** — already mitigated. `retain_until = expires + skew` equals the freshness upper bound exactly; any replay that could still pass freshness still finds the entry live. A degenerate `retain_until` is unreachable because step-9 rejects the stale request first; `saturating_add` prevents overflow.
- **F3-redis-ttl-clamp** — already mitigated. `compute_ttl_ms` is pure TTL arithmetic, not the freshness gate. Stale requests are rejected at step 9; the only path to a 1ms clamp is the inclusive same-instant boundary (`now == retain_until`), where a positive 1ms TTL is the *security-correct* behavior (defeats a same-instant racing replay).
- **F5-inmem-unbounded** — mitigated / false-positive (2 mitigated, 1 FP). The in-memory store is documented single-process test/reference only; `cli.rs` wires `RedisAtomicReplayStore` (or fails closed when the `redis_replay` feature is absent). The historical H-8/H-9/MCPS-090 unbounded-growth bug lives in the *Redis* backend and is already fixed (`compute_ttl_ms` reads its own clock, clamps `.max(0)`, applies `SET … NX PX`). `now_unix=0` is a deliberate vestigial anchor a no-TTL store correctly ignores.

---

## 3. Fix Re-Verification (#20–26)

| Issue | fix_correct | complete | no_gaming | regressions | Status |
|---|:--:|:--:|:--:|---|---|
| #20 dup-key artifact / JCS preimage | yes | yes | yes | none | **CLEAN** |
| #21 XFCC asserted-identity | yes | **NO** | yes | none | **FLAGGED — incomplete** |
| #22 signing-scope hardening | yes | yes | yes | none | **CLEAN** |
| #24 response id provenance | yes | yes | yes | none | **CLEAN** |
| #25 inner-launch & key hygiene | yes | yes | yes | none (minor nits) | **CLEAN (with notes)** |
| #26 OCSP AIA SSRF (alt IPv4) | yes | yes | yes | none | **CLEAN** |

### Clean fixes (verified, anti-gaming confirmed)

- **#20** — `reference.rs` runs raw dup-rejecting `canonicalize` first, then derives the serde `Value`; dup-key artifacts error as `AuthorizationMalformed` before signature work. Counterfactual revert proved `duplicate_key_artifact_is_malformed_not_signature_verified` fails (`left=Allow` without the fix). Genuine black-box test.
- **#22** — All three sub-fixes verified via mutation testing: no-op'ing `scrub_proxy_owned_meta` fails 3 named tests; neutralizing the Ed25519 verify fails 2. Forged-request test uses a real capturing inner (planted-then-signed). Recursive scrub removes only the 4 protocol-owned keys; unrelated `_meta` survives at all depths.
- **#24** — Documentation + tests only (no production logic change), appropriate because the gap was already closed by existing mechanisms and #24 pins the invariant. Mutation spot-check: dropping top-level `id` from the preimage fails `tampered_top_level_id_fails_verification_and_is_not_signed`.
- **#26** — `parse_inet_aton_ipv4` runs only on the `Err(_)` fall-through; can only *add* blocks for numeric forms, real hostnames still permitted. Matches `inet_aton(3)`. Re-implementing pre-fix vs fixed `host_is_public` over the 11 blocked inputs shows pre-fix leaks all 11 as public. IPv6 alternate forms are intentionally not covered by #26 (it is IPv4-specific).

### Flagged / not fully clean

- **#21 XFCC asserted-identity — INCOMPLETE (fix_correct=yes, complete=NO).** Implemented core is correct and non-gamed (identity routed through `validate_asserted_identity_value`; RFC2253 `\<hexpair>` decode fails closed; element-aware split; cross-element disagreement fails closed; counterfactual revert of `unescape_rfc2253_value` proven). **Two acceptance items unmet:**
  1. **Leaf-only selection deviation.** The acceptance text said identity taken from the LEAF element with non-leaf failing closed; the implementation instead uses consistency-across-elements (any disagreement fails closed). This was a **deliberate, user-approved decision** (XFCC element ordering is not a guaranteed invariant) documented in PR #28 — but the issue's acceptance wording still says "leaf-only" and should be reconciled so it is not a silent divergence.
  2. **Unbalanced-quote NOT failing closed (no test).** The acceptance explicitly required unbalanced-quote XFCC values to fail closed. `split_outside_quotes` leaves `in_quotes=true` after a stray `"`, so e.g. `URI="spiffe://a,URI=spiffe://evil` collapses two elements into one (and can defeat the cross-element conflict check). **No unterminated-quote test exists.** → genuine residual gap.
  - **Recommendation:** add an unbalanced/unterminated-quote fail-closed branch + test, and reconcile the leaf-vs-consistency acceptance wording before closing #21.

### Clean with non-blocking notes

- **#25 inner-launch & key hygiene — CLEAN.** Anti-gaming mutation spot-check on `failed_retry_does_not_cache_the_session` passes (revert → FAILS at `logins==3`). Non-blocking notes: (i) per-PID `0700` temp dirs are never `Drop`-cleaned and accumulate in `$TMPDIR` (PID-reuse is safe — the validate branch re-adopts only an own-uid `0700` real dir, fails closed on symlink/foreign-uid/loose-perm squat); (ii) the Linux-only `close_range` path was not compile-exercised on the Darwin host (`target_os=linux`-gated; relied on Linux CI).

---

## 4. #23 Remediation Plan (keyed to buckets)

| Finding | Action | Safe on macOS now? | MUST hit Redis? |
|---|---|:--:|:--:|
| F1 | No fix. Ordering already pinned by `expired_precedes_bad_signature` + step-11-before-12 tests. | Yes | No |
| F2 | No fix. Invariant pinned by `prune_after_retain_until_readmits_triple`. | Yes | No |
| F3 | No fix. Behavior pinned by the clamp + pipeline ordering tests. | Yes | No |
| F5 | No fix. Bound is the documented caller `prune()` responsibility for the test-only store; production Redis path already bounded. | Yes | No |
| **F4** | **Either** a compensating cleanup (`DEL`/`UNLINK`) of the just-written primary key on WAIT shortfall, **or** (per acceptance #2) document + test the current fail-closed retry semantics. | Partly | Yes (final) |

### F4 split (only confirmed finding)

- The current behavior is the **intended ADR-MCPS-020 durability-over-availability tradeoff**: the failing request surfaces the distinct *retryable* `ReplayCacheUnavailable` (not a silent allow), and MCP-S clients re-sign with a fresh nonce per attempt, so a re-signed retry is `Fresh`.
- A compensating `DEL` would improve same-nonce retry availability but **must not open a replay window** — do not drop the nonce if the write may actually have replicated. This is an ADR-MCPS-020 design decision, not a mechanical fix.
- Acceptance #2 explicitly permits the alternative: **document + test the retry semantics**. The fake-connection harness (`run_with_reconnect`) can lock either choice locally; final sign-off of the distributed behavior needs a real multi-replica Redis.

### Bottom line

- **Implement now (macOS-local):** the **#21 unbalanced-quote fail-closed branch + test** (genuine residual gap in a merged PR). F4 needs a design decision first.
- **Design decision needed:** F4 — compensating-`DEL` vs document-and-test, reconciled with ADR-MCPS-020.
- **Block on Redis cluster verification:** F4 final sign-off only.
- **No action:** F1, F2, F3, F5.
