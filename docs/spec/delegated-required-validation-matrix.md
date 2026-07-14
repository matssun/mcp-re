# Delegated-Required Validation Matrix (ADR-MCPRE-052)

**Audience:** an engineer deciding whether the delegated-signing profile is proven
locally end-to-end — the gate that must be green **before** a GKE run is treated as
an honest production validation (MCPRE-122).

**Delegated-signing is the ONLY response-signing mode.** Direct-root response signing
has been removed from the runtime surface (no CLI flag, no config path, no serving
construction, no deploy manifest). Every "direct-root … rejected" cell below is a
*negative* proof built from a deliberately-named pre-052 fixture — it does **not**
imply a direct-root serving mode exists. See the governing note in
`ResponseSigningMode`'s removal (there is no such enum) and the CLI: `--response-signing-mode`
no longer exists.

This is an **acceptance gate**, not an ADR. ADR-MCPRE-052 records the *decision*
(the delegated-signing design: a root/KMS issuer that mints short-lived delegated
Ed25519 keys off the request path; each RFC 9421 response signed by the in-memory
delegated key; a compact-JWS credential carried inline; fail-closed availability;
revocation/trust-epoch as a hard verifier gate). This document is the *proof
obligation* for that decision: each required behavior mapped to the exact test that
proves it. It changes whenever a test is added or renamed, so it does not belong in
the immutable ADR stream.

## How this matrix cannot rot

Per the project convention (see [`conformance-guide.md`](../conformance-guide.md)):
the spec states the rule, the ADR records why, this matrix says what must be proven,
and the tests prove it — with three machine guards so the mapping cannot silently
drift out of truth. This document quotes **no** counts; the guards re-derive
everything from reality.

1. **Security traceability manifest** —
   [`mcp-re-conformance/security_traceability_manifest.json`](../../mcp-re-conformance/security_traceability_manifest.json),
   guarded by `//mcp-re-conformance:security_traceability_guard_test`. Every
   delegated-required serving / wiring / E2E row below is an entry there mapping the
   property to its Bazel target **and** its named `test_fn`. The guard reads each
   cited source from disk at test time and **FAILS** if a target or `test_fn` is
   renamed or removed. This is the enforcement referenced by the `MANIFEST` tag.
2. **Frozen credential-verification corpus** — the `d01`–`d22`
   delegation-profile vectors
   (`mcp-re-conformance/tests/delegation_vectors_test.rs`), guarded by
   `frozen_delegation_corpus_verifies` (each vector verifies to its exact
   `mcp-re.*` verdict), `regenerated_delegation_fixtures_match_committed_bytes`
   (byte drift), and `corpus_covers_the_full_taxonomy` (every frozen delegation
   token appears ≥ once). Referenced as `CORPUS`.
3. **Frozen wire tokens** — `delegation_wire_strings` /
   `full_taxonomy_wire_strings` in `mcp-re-core/src/error.rs` assert every
   delegation token's `Display` and `wire_code()` are stable. Referenced as
   `TOKENS`.

Rows tagged `CI` are unit-proven in-crate (`delegated_server_signer.rs`) and run in
every CI build, but are not manifest-pinned against rename; their **matrix cell** is
additionally guarded at the integration altitude by a `MANIFEST` row (noted inline).

---

## A. Server-side serving contract

| # | Required behavior | Proof (`test_fn`) | Altitude | Enforced |
|---|---|---|---|---|
| A1 | Delegated-signed **success** verifies via credential→root chain; root touched only at issuance (never per request) | `delegated_success_response_verifies_and_root_touched_once` | serve (PEP) | MANIFEST |
| A2 | Request-**bound** rejection receipt is delegated-signed and verifies bound (`replay_detected`) | `delegated_bound_rejection_verifies` | serve | MANIFEST |
| A3 | **Preflight/unbound** rejection is delegated-signed and classified unbound, never falsely request-bound | `delegated_preflight_rejection_verifies_unbound` | serve | MANIFEST |
| A4 | **No active key** → fails closed: 503 + frozen `delegated_signing_unavailable` + **unsigned** (no direct-root sign, no unsigned 200) | `missing_delegated_key_fails_closed` | serve | MANIFEST |
| A5 | **Direct-root** (pre-052) response rejected `delegation_credential_missing` — no downgrade (built from a named pre-052 fixture; there is no direct-root serving mode) | `direct_root_response_rejected_in_delegated_required_mode` | verify | MANIFEST |

## B. Server-side rotation & fail-closed lifecycle

| # | Required behavior | Proof (`test_fn`) | Altitude | Enforced |
|---|---|---|---|---|
| B1 | Rotation **K1→K2**: successor verifies; predecessor verifies through the overlap; root touched only at rotation | `delegated_required_wiring_serves_verifies_and_rotates` (+ corpus `d19`/`d20` overlap-accept) | wiring / corpus | MANIFEST + CORPUS |
| B2 | Past-expiry predecessor **rejected** (verifier is key-lifecycle-agnostic; any expired credential is refused) | corpus `d02_credential_expired` | corpus | CORPUS |
| B3 | **Fail-closed at exp**: the hot-path snapshot is never honored past `exp` | `snapshot_fails_closed_past_expiry` (cell also guarded by A4/B1) | rotor unit | CI |
| B4 | **Transient issuance failure** keeps serving the still-valid key, then fails closed at its own `exp` — no stale-key extension, no direct-root fallback | `issuance_failure_serves_the_valid_key_then_fails_closed_at_expiry` (cell also guarded by B1 fail-closed segment) | rotor unit | CI |
| B5 | Fail-closed issuance with **no prior key** retires the snapshot (serves nothing) | `fail_closed_issuance_retires_the_snapshot`, `no_key_before_first_rotate_fails_closed` | rotor unit | CI |
| B6 | Issuance retry uses bounded jittered exponential backoff, capped by remaining key validity (no hot-spin, never sleeps past `exp`) | `backoff_never_sleeps_past_a_still_valid_key`, `backoff_is_exponential_then_ceilinged`, `backoff_once_expired_uses_the_ceiling_not_the_negative_ttl` | rotor unit | CI |
| B7 | Rotation health metrics count success/failure and reset the streak; time-to-expiry tracked | `metrics_count_success_and_reset_the_failure_streak`, `seconds_to_expiry_tracks_the_published_key` | rotor unit | CI |
| B8 | Root/KMS issuer touched **only** at issuance/rotation, never per response | A1 (`root_invocations()==1`/5), B1 (`==2` across rotation), KMS lane `kms_calls==1` | serve / live | MANIFEST |

## C. Client-side credential verification

All client verification cells are the frozen `d01`–`d22` corpus (each a black-box KAT
through the single production entry point `verify_delegated_response_full`), backed by
the per-gate unit tests in `mcp-re-http-profile/src/delegation.rs`.

| # | Required behavior | Proof (vector → verdict) | Enforced |
|---|---|---|---|
| C1 | Delegated success accepted | `d01_valid` → ok | CORPUS |
| C2 | Substituted credential rejected (keyid ≠ delegated_kid; signed by non-cnf key) | `d12`, `d13` → `delegation_key_mismatch` | CORPUS |
| C3 | Stripped credential rejected | `d14_credential_stripped` → `delegation_credential_missing` | CORPUS |
| C4 | Direct-root rejected in delegated-required mode | `d10_required_rejects_direct_root` → `delegation_credential_missing` | CORPUS |
| C5 | Wrong audience / audience-scope / lifted-to-wrong-server-signer rejected | `d06`, `d07`, `d15` → `delegation_audience_mismatch` | CORPUS |
| C6 | Wrong profile rejected | `d05_profile_mismatch` → `delegation_profile_mismatch` | CORPUS |
| C7 | Wrong key_use rejected | `d04_key_use_invalid` → `delegation_key_use_invalid` | CORPUS |
| C8 | Expired credential rejected | `d02_credential_expired` → `delegation_credential_expired` | CORPUS |
| C9 | Not-yet-valid credential rejected (collapses to the expired token, by design) | `d03_not_yet_valid` → `delegation_credential_expired` | CORPUS |
| C10 | Stale trust-epoch rejected; bounded-rollout previous epoch accepted | `d08` → `delegation_trust_epoch_stale`; `d09` → ok | CORPUS |
| C11 | Untrusted / forged issuer rejected | `d16` → `delegation_issuer_untrusted`; `d17`,`d18` → `delegation_credential_invalid` | CORPUS |
| C12 | Body / response-signature tamper rejected | `d21` → `digest_mismatch`; `d22` → `delegation_key_mismatch` | CORPUS |
| C13 | Unsigned response rejected (client fails closed) | `unsigned_response_is_rejected` (`mcp-re-client-core`) | CI |
| C14 | Unbound signature not accepted as success (a 200 must carry `;req`) | `unbound_signature_is_not_accepted_as_success` | CI |

## D. Client-side revocation enforcement (ADR-MCPRE-052 §7)

| # | Required behavior | Proof (`test_fn` / vector) | Enforced |
|---|---|---|---|
| D1 | Revoked **delegated_kid** rejected | `revoked_delegated_kid_rejects_success`; corpus `d11_revoked_delegated_key` | CI + CORPUS |
| D2 | Revoked **issuer_kid** rejected | `revoked_issuer_kid_rejects_success` | CI |
| D3 | Revoked **jti** rejected (client entry point forwards jti to the seam) | `revoked_by_jti_rejects_success` (client-core), `revoked_by_jti_is_revoked` (`delegation.rs`) | CI |
| D4 | A revoked key cannot deliver a trustworthy **rejection** either | `revoked_delegated_key_rejection_receipt_is_rejected` | CI |
| D5 | Non-revoked credential with a **non-empty** denylist still verifies (seam is not blanket-deny) | `non_revoked_credential_verifies_with_nonempty_list` | CI |
| D6 | Rotation to a fresh key succeeds while the old kid is revoked | `rotation_to_new_delegated_key_succeeds_when_old_revoked` | CI |
| D7 | Revocation source is a **required**, non-defaultable route field (cannot be silently never-revoked) | `ClientVerification::DelegatedRequired(DelegationPolicy, Box<dyn RevocationSource>)` — compile-time (route.rs) | type system |

## E. End-to-end (plain client ↔ client-proxy ↔ server-proxy ↔ backend)

| # | Required behavior | Proof (`test_fn`) | Altitude | Enforced |
|---|---|---|---|---|
| E1 | Happy path round-trips to a client-verified delegated success and back to plain MCP | `plain_client_round_trips_through_delegated_required_server` | two-proxy | MANIFEST |
| E2 | Replay → request-bound delegated rejection, client classifies `replay_detected`, fails closed | `replayed_request_yields_a_verified_delegated_rejection` | two-proxy | MANIFEST |
| E3 | Direct-root downgrade refused (`delegation_credential_missing`) | serving `direct_root_response_rejected_in_delegated_required_mode` (A5); client-core `direct_root_success_is_rejected_no_credential`; corpus `d10` (C4) — not re-driven two-proxy (a direct-root SERVER no longer exists) | serve / client / corpus | MANIFEST + CORPUS |
| E4 | Revoked server key refused (`delegation_revoked`) — live revocation seam | `revoked_server_delegated_key_is_refused_by_client` | two-proxy | MANIFEST |
| E5 | Non-revoked denylist still round-trips (not blanket-deny) | `non_revoked_client_still_round_trips` | two-proxy | MANIFEST |
| E6 | Rotation K1→K2 end to end | `delegated_required_wiring_serves_verifies_and_rotates` (B1) | wiring | MANIFEST |
| E7 | No-key / expired server state fails closed before signing | `missing_delegated_key_fails_closed` (A4) | serve | MANIFEST |
| E8 | Wrong audience / profile refused | corpus `d05`, `d06`, `d07`, `d15` (C5/C6) | corpus | CORPUS |

## F. Taxonomy / wire tokens

| # | Required behavior | Proof | Enforced |
|---|---|---|---|
| F1 | Every delegation token + `delegated_signing_unavailable` is stable in `Display` and `wire_code()` | `delegation_wire_strings` | TOKENS |
| F2 | `replay_detected` remains classified | `full_taxonomy_wire_strings`, `errors_compare_by_value` | TOKENS |
| F3 | The frozen delegation token **set** cannot silently narrow | `corpus_covers_the_full_taxonomy` | CORPUS |

### The boundary that must hold

- **Server-side inability to sign** → `mcp-re.delegated_signing_unavailable`
  (no active valid delegated key; issuance failed; rotation expired). Emitted by the
  signer, not a verification verdict. Proven by A4.
- **Client-side rejection of a bad/expired/revoked credential** → the specific
  `delegation_*` verifier code (C/D rows). These are **not** collapsed into one
  generic delegation failure.
- **`not_yet_valid` deliberately collapses** into `delegation_credential_expired`
  (one freshness token for both bounds). C8/C9, corpus `d02`/`d03`.

---

## Altitude honesty

The matrix records the **altitude** each cell is proven at, and does not overclaim.
The two-proxy E2E lane (E1–E5) exercises the real `ClientProxy` ↔ `HttpProfileProxy`
round trip directly. Rotation (E6), no-key fail-closed (E7), and wrong-audience/
profile (E8) are proven at the production-wiring, serving, and frozen-corpus
altitudes respectively rather than re-driven through the two-proxy harness — the
verifier and signer are shared code, so the lower-altitude proof is the same logic
without the transport scaffolding. Where a cell's deepest proof is an in-crate unit
test (`CI`), the corresponding **integration cell is `MANIFEST`-guarded** and noted
inline, so no matrix cell depends on an unpinned test alone.

## G. Live Cloud KMS root (local, before GKE)

The rows above use an in-memory root so they stay hermetic. These lanes run the
SAME delegated-required paths with a **real Cloud KMS** key as the credential-
issuing root — the honest local proof that the production serving path and the
authority flip work on a non-exporting cloud root, before any GKE run. They are
cargo-only, feature-gated (`gcp_kms_keysource`), with a hermetic offline-seed twin
that runs in CI and an `#[ignore]` live twin. Runner:
[`docs/security/gcp-kms-delegated-required.sh`](../security/gcp-kms-delegated-required.sh)
(no secrets; set `PROJECT_ID`, authenticate `gcloud`, run).

| # | Required behavior | Proof (`test_fn`) | Enforced |
|---|---|---|---|
| G1 | Production serving wiring on a real KMS root: `build_delegated_signing(config, kms_root)` + `new_delegated` serves & verifies | `gcp_kms_delegated_required_serving_{offline_local_seed,live}` | CI + LIVE |
| G2 | Zero per-request KMS ops at the SERVING altitude — N served responses invoke Cloud KMS only at issuance/rotation (counted via a wrapping `ResponseSigner`) | `gcp_kms_delegated_required_serving_*` | CI + LIVE |
| G3 | Rotation to a KMS-issued successor serves & verifies (one extra KMS op) | `gcp_kms_delegated_required_serving_*` | CI + LIVE |
| G4 | Client revocation seam on a KMS-rooted credential — deny (revoked kid → `delegation_revoked`) and allow (non-matching denylist round-trips) | `gcp_kms_delegated_required_serving_*` | CI + LIVE |
| G5 | Authority flip: a pre-052 direct-root response (KMS signs directly, no delegation evidence block) is REJECTED under delegated-required — no downgrade | `gcp_kms_authority_flip_{offline_local_seed,live}` | CI + LIVE |
| G6 | Authority flip: the delegated (post-052) authority is accepted; the KMS issues the credential | `gcp_kms_authority_flip_*` | CI + LIVE |
| G7 | Trust-epoch flip on a KMS-rooted credential — old epoch rejected after the accepted set advances (`delegation_trust_epoch_stale`); bounded-rollout `{new, old}` accepted | `gcp_kms_authority_flip_*` | CI + LIVE |
| G8 | Key-authority rotation + revocation flip — KMS issues a successor; revoking the predecessor kid fails its responses closed while the successor's verify | `gcp_kms_authority_flip_*` | CI + LIVE |

`CI` = the hermetic offline-seed twin runs on every push (feature-gated job).
`LIVE` = the `#[ignore]` twin, verified against the real Cloud KMS via the runner.
These lanes have no Bazel target, so they are not in the traceability manifest;
they are cited here and guarded by the offline twin in CI.

## H. Trust-anchor (master/root key) lifecycle

The rows above exercise the **delegated** key — the short-TTL key on the hot path.
These rows exercise the **root/master** key itself: rotating the trust anchor the whole
fleet chains to, revoking a root, and surviving a root that can no longer issue. This
is NOT delegated-key rotation. The verifier-side mechanism is
[`TrustedIssuerSet`](../../mcp-re-client-core/src/response.rs) (current /
retired-with-`valid_until` / revoked / unknown-reject); the server-side property is the
rotor's fail-closed-on-issuance-failure contract. All hermetic (two in-memory roots
through the same seam a KMS root plugs into), so they run on every push.

| # | Required behavior | Proof (`test_fn`) | Altitude | Enforced |
|---|---|---|---|---|
| H1 | Root rotation — during an overlap window BOTH the outgoing (retired, in-window) and incoming (current) root are accepted | `during_overlap_both_roots_are_accepted` | verifier | MANIFEST |
| H2 | Root rotation — after the overlap `valid_until` closes, the retired root is rejected (`delegation_issuer_untrusted`) even before the credential's own exp, and only the new root is accepted | `after_overlap_old_root_rejected_new_root_accepted` | verifier | MANIFEST |
| H3 | Retirement window is inclusive at `valid_until` then closes | `retirement_window_boundary_is_inclusive_then_closes` | verifier | CI |
| H4 | Unknown issuer (not in current/retired) is rejected | `unknown_issuer_is_rejected` | verifier | MANIFEST |
| H5 | An empty trust-anchor set trusts no root (a delegated-required verifier never silently trusts one) | `empty_trust_anchor_set_trusts_no_root` | verifier | CI |
| H6 | Root revocation — revoking an `issuer_kid` invalidates EVERY descendant delegated credential immediately (`delegation_revoked`), before its exp, without chasing each delegated key | `revoked_issuer_invalidates_all_descendants_before_exp` | verifier | MANIFEST |
| H7 | Root revocation isolation — revoking one root leaves other trusted roots fully accepted | `revoking_one_root_does_not_disturb_the_other` | verifier | MANIFEST |
| H8 | Root issuance failure — an unavailable KMS root serves only until the current delegated key expires, then fails closed; never extends the key, never falls back to direct-root | `root_issuance_failure_serves_until_delegated_key_expiry_then_fails_closed` | rotor | MANIFEST |

`MANIFEST` = pinned in `security_traceability_manifest.json` (guard fails on rename/removal); `CI` = runs under the same green test file (`//mcp-re-proxy:root_key_lifecycle_test`).

**Live cross-KMS root rotation is a GKE-phase lane, not a local one.** Proving H1/H2/H6
against *real* Cloud KMS requires TWO roots, i.e. a **separate disposable** KMS
key/version — never the shared test root in `work/test-gcp-cloud.sh`, and never by
disabling it. That live lane (`#[ignore]`, gated on a disposable second-key env var)
is deferred to the GKE phase alongside the fleet/rolling-update dimensions; the
hermetic §H rows are the pre-GKE gate.

## I. Root-authority rotation via signed manifest (automated, no HITL)

§H proves the verifier's trust-anchor decisions. These rows prove the DISTRIBUTION +
AUTOMATION layer: a signed, versioned trust-anchor manifest carries a root rotation, and
roots are AUTO-PROVISIONED (no human creates a key). Design + provisioning fence:
[`docs/spec/root-authority-rotation.md`](./root-authority-rotation.md).

| # | Required behavior | Proof (`test_fn`) | Altitude | Enforced |
|---|---|---|---|---|
| I1 | Signed manifest loads current/retiring/revoked into the trust anchors; a rotation A→A+B overlap→B and A-revoked verifies/rejects per manifest; rollback to the pre-revocation version refused | `root_rotation_via_signed_manifest_with_auto_provisioned_roots` | verifier | MANIFEST |
| I2 | Manifest signed by a non-pinned key / bad signature is rejected | `untrusted_signer_is_rejected` · `tampered_manifest_fails_the_signature` | verifier | CI |
| I3 | Expired manifest fails closed | `expired_manifest_fails_closed` | verifier | CI |
| I4 | Rollback to a lower manifest version is rejected | `rolled_back_manifest_version_is_rejected` | verifier | CI |
| I5 | Wrong-profile manifest rejected | `wrong_profile_is_rejected` | verifier | CI |
| I6 | A root is AUTO-PROVISIONED (Root B minted on the fly) — no human-in-the-loop key creation | `root_rotation_via_signed_manifest_with_auto_provisioned_roots` (in-memory) · `gcp_kms_root_rotation_live` (live KMS) | provider | MANIFEST + LIVE |
| I7 | LIVE: the identical rotation runs against TWO real, DISPOSABLE Cloud KMS roots, self-provisioned and cleaned up; the shared root is never touched | `gcp_kms_root_rotation_live` | live | LIVE |

`MANIFEST` = pinned in the traceability manifest; `CI` = the manifest unit tests
(`mcp-re-client-core/src/trust_manifest.rs`) run on every push; `LIVE` = the
`#[ignore]` lane run via [`docs/security/gcp-kms-root-rotation.sh`](../security/gcp-kms-root-rotation.sh)
against real Cloud KMS with two disposable key versions (doc-cited, gazelle-allowlisted;
no Bazel target). I7 was executed green against real Cloud KMS.

## This is the gate before GKE

Every row above — including the live Cloud KMS lanes (§G), the trust-anchor
lifecycle (§H), and signed-manifest root rotation (§I) — is green locally today
(`bazel test //...` green; the three guards pass; the KMS lanes pass offline in CI
and against the real Cloud KMS via the runner). That is the precondition for
treating a GKE run as an honest production validation — not a first proof. Because
§G already proves the delegated-required serving path and the authority flip on a
**real Cloud KMS root**, a GKE validation adds only the dimensions this matrix
**cannot** exercise on one host:

- a real **multi-replica fleet** with per-core rotors sharing one KMS-rooted trust
  anchor (here it is a single in-process rotor);
- **rolling-update overlap** timing under live traffic (K1 draining while K2 serves);
- **network transport** (mTLS) rather than in-process objects;
- the **SLO baseline** remaining acceptable with per-response delegated signing;
- **live cross-KMS root rotation** (§H, H1/H2/H6) across a *separate disposable* KMS
  key — the trust-anchor overlap and revocation proven hermetically here, re-run
  against two real cloud roots (never the shared test root).

GKE proves those live-infra properties. It does **not** re-prove the protocol
correctness or the KMS-root/authority-flip behavior above — that is this matrix's
job, and it is done locally.
