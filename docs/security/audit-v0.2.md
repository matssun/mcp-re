# MCP-S Code & Security Re-Audit — 0.2

> **Note for public-repo readers.** This is the original re-audit report as
> produced by the multi-agent review workflow, sanitized lightly for public
> release. Bare `#NNNN` references in the body (e.g. `#4030`, `#4055`) are
> author-private monorepo issue/PR numbers, **not** GitHub issues in this
> repository; they are preserved here for fidelity with the original report.
> The remediation status for every finding is tracked in
> [`remediation-v0.2.md`](remediation-v0.2.md).

| Field | Value |
|---|---|
| Audit date | 2026-06-02 |
| Subject | MCP-S Rust workspace |
| Revision audited | `main @ 6d85a60912` (working tree at review time) |
| Intended target | `83cd06a10d` (PR #4055 merge); differs only by `cli.rs` −41 lines — see Limitations |
| Target version | 0.2.0 |
| Predecessor | [0.1 audit (2026-06-01)](./MCPS-code-audit-2026-06-01.md) |
| Engine | Claude Opus multi-agent workflow (`wf_c617823d-ec9`, 117 agents, 6.31M tokens, ~31 min) |
| Standard | High-assurance — hostile client **and** hostile inner server |
| Findings retained | 362 (Critical 4 / High 15 / Medium 30 / Low 59 / Info 254) |
| **Overall residual-risk rating** | **HIGH** |

**Residual-risk justification.** Four CRITICAL and fifteen HIGH findings survived the adversarial gate. All four criticals are the *same root defect* — the online-OCSP responder path performs **no signature verification** — which converts an opt-in revocation control into a fail-**open** admission path under the audit threat model. The dominant high-severity cluster is the remainder of the OCSP trust chain (nonce, validity-window, CertID/responder-identity binding) plus three independent fail-open/DoS defects in the proxy (Redis TTL miscalculation, missing Redis timeouts, swallowed `--strict`). Every confirmed critical/high is feature-gated or config-gated (`online_ocsp`, `redis_replay`, or operator argv ordering) and `mcps` is **not** in the merge gate, which bounds blast radius but does not lower the rating: each defect fails open or hangs at a trust boundary in the configuration that explicitly opts into the control. Residual risk is therefore HIGH, not CRITICAL, on the basis that no defect is reachable in the default build and none is a remote unauthenticated bypass of authentication itself.

---

## 1. Scope & Method

### Three audit tiers

- **Tier A — Full-depth review** of new and heavily-changed code (12 review units), treating it as unreviewed — including the four Phase-7 external backends (`redis_store.rs`, `pkcs11_keysource.rs`, `ocsp.rs`, `sandbox_linux.rs`) and the new manifest / delegated-signer / sandbox / shared-replay surfaces. Three lenses per unit (general, conformance, security).
- **Tier B — Remediation verification** of every High/Medium finding raised in the 0.1 audit (13 finding-IDs covering the 3 H + 14 M).
- **Tier C — Core-invariant regression sweep** over six load-bearing security invariants that must hold across releases.

### Adversarial verification gate

Every Critical/High finding passed through a **3-skeptic adversarial panel**. A finding is admitted only when **≥ 2 of 3 skeptics independently confirm it from source**; the default verdict is *invalid*. Skeptics are instructed to attempt falsification first (dead code, unreachable path, compensating control, mis-stated severity). The gate is load-bearing: one finding was refuted and one numeric error corrected (§9).

### Phase-7 property catalog

Tier A is structured against a **22-property Phase-7 catalog** (P7-01 … P7-22) extracted *before* any code was read — the machine-checkable invariants for the external-backend and manifest-trust surfaces. Findings that break a catalog property cite it (e.g. P7-04 in H-1).

---

## 2. Executive Summary

The release does not clear a high-assurance bar. Findings cluster into four themes:

1. **Online-OCSP trust chain is unimplemented but wired as an admission control (4 CRITICAL + 4 HIGH).** Under the non-default `online_ocsp` feature with `--client-ocsp require`, the proxy fetches an OCSP response over (typically plaintext) HTTP and trusts its status **without verifying the responder signature, without a request nonce, without thisUpdate/nextUpdate freshness, and without binding the response CertID/responder identity to the request**. A network MITM forges a `Good` status and admits a revoked client. The module self-documents the signature gap (#4030) and mitigates only by operator discipline ("deploy on a trusted network path"), which the zero-trust model forbids. The four criticals are the same signature-bypass defect surfaced by independent agent runs; the four highs are the residual RFC 6960 controls that must land *with* the signature fix or the bypass persists in a subtler form.

2. **Manifest pin-commit is non-atomic (1 HIGH, P7-04 break).** A single signed manifest containing two `ToolEntry` with the same name but different schema hashes partially mutates the pin store before failing, letting a hostile-but-resolvable server write a chosen pin under cover of an overall-failing `verify()`. Latent today (no host wiring to a persistent store) but a genuine deny-before-commit violation of the module's own contract.

3. **Redis replay backend fails wrong at two trust boundaries (2 HIGH).** Server-side PX TTL is computed against a hard-wired `now_unix = 0`, so keys are written with an effectively-infinite expiry (~56 years) and never evicted — an unbounded-growth DoS. Separately, the Redis connection sets **no connect/read/write timeout**, so a sinkholed Redis hangs the single-threaded serve loop indefinitely instead of failing closed.

4. **`--strict`/`--production` silently swallowed (1 HIGH, fail-open).** `--inner-command` is a greedy varargs terminator; any proxy flag placed after it is consumed as an inner-server argument with no error and no warning, so an operator who appends `--strict` runs warn-only while believing strict mode is active.

Honest scoping: **all** confirmed criticals/highs are gated behind a non-default cargo feature or a specific operator configuration; the default shipped build is unaffected, and `mcps` is not in the merge gate. The defects are real, source-verified, and fail open/hang in exactly the configuration an operator enables to *gain* the control.

**Zero critical/high findings were dismissed — 4 critical and 15 high were confirmed by the panel.** This is a sharp regression from the 0.1 audit (0 critical / 3 high): the new Phase-7 external-backend code, especially `online_ocsp`, is the source.

---

## 3. Findings by Severity

| Severity | Count |
|---|---|
| Critical | 4 |
| High | 15 |
| Medium | 30 |
| Low | 59 |
| Info | 254 |
| **Total retained** | **362** |

## 4. Findings by Crate

| Crate | Critical | High | Medium | Low | Info |
|---|---:|---:|---:|---:|---:|
| `mcps-core` | 0 | 0 | 2 | 4 | 30 |
| `mcps-policy` | 0 | 1 | 4 | 9 | 41 |
| `mcps-proxy` | 4 | 12 | 21 | 41 | 170 |
| `mcps-transport` | 0 | 2 | 3 | 5 | 13 |
| **Total** | **4** | **15** | **30** | **59** | **254** |

All four criticals and the dominant high cluster localize to `mcps-proxy` (OCSP + Redis replay + CLI wiring); the single policy high is the manifest-atomicity break.

---

## 5. Critical & High Findings — Full Write-ups

The four criticals are independent agent confirmations of one signature-bypass defect; each is written up as audited.

### C-1 — OCSP responder signature over BasicOCSPResponse is never verified — status trusted unauthenticated
- **Crate / location:** `mcps-proxy` · `mcps-proxy/src/ocsp.rs:257-265`
- **Category / lens:** signature-verification-bypass · general
- **Severity:** CRITICAL
- **Description:** `map_basic_response` reads `single.cert_status` and maps it to a `CertRevocationStatus` without ever verifying the cryptographic signature on the `BasicOcspResponse` against the issuer key or a delegated responder cert. Under the stated threat model, any party that can answer the HTTP POST (MITM, DNS/route hijack, compromised responder host, or attacker-controlled AIA URL host) returns a self-built unsigned `OCSPResponse(successful)` carrying `CertStatus::good` for a revoked client cert, and the proxy ADMITS the connection — a direct revocation/admission bypass.
- **Evidence:** `ocsp.rs:257-264` returns `Ok(map_cert_status(&single.cert_status))` with no signature check; `ocsp.rs:248` `// HARDENING FOLLOW-UP (#4030): verify basic's signature here before trusting its status`; test fixture `ocsp.rs:547` `signature: BitString::from_bytes(&[])` (empty) is accepted by the production map path (`status_mapping_good_revoked_unknown`).
- **Recommendation:** Verify the `BasicOcspResponse` signature before trusting `cert_status`: build the preimage from `tbs_response_data`, resolve the signer (issuer key, or a delegated `id-kp-OCSPSigning` responder in `basic.certs` chaining to the issuer), verify algorithm-agnostically (RSA + ECDSA), and return `OcspError` on any failure (fail closed). Until then, do not present `online_ocsp` as a control against a hostile network.
- **Verification verdict:** CONFIRMED — 3/3 skeptics. Path is production-wired (`tls.rs:439` → `map_response_der` → `map_basic_response`; `decide_allow(Good)` → admit). Severity calibration note: gated behind non-default `online_ocsp` and layered atop offline CRL deny-unknown + mTLS, so two skeptics judged effective severity *critical-in-the-enabled-config / high-overall*; defect existence unanimous.

### C-2 — OCSP responder signature is NEVER verified — spoofed/MITM responder forges 'Good', admits revoked client
- **Crate / location:** `mcps-proxy` · `mcps-proxy/src/ocsp.rs:257-265`
- **Category / lens:** signature-bypass · conformance
- **Severity:** CRITICAL
- **Description:** The core RFC 6960 §3.2 trust property (a response is trustworthy only if its signature verifies against the issuer key or a delegated `id-kp-OCSPSigning` responder chaining to the issuer) is not implemented. `map_basic_response` returns the `SingleResponse` `CertStatus` as authoritative without verifying `basic.signature`. With AIA URLs attacker-influenceable and typically plaintext `http://`, an attacker who can answer the responder URL forges `OcspResponse::successful(BasicOcspResponse{ status=good })` and the proxy admits a revoked credential. This converts the entire online-revocation control into a fail-OPEN authorization path.
- **Evidence:** `ocsp.rs:257` `fn map_basic_response(...)` does only `.responses.first()` then `Ok(map_cert_status(&single.cert_status))`; `ocsp.rs:248-256` HARDENING FOLLOW-UP (#4030) "… is NOT yet performed … so it is deferred"; `ocsp.rs:547` empty-bitstring fixture accepted.
- **Recommendation:** Do not ship `online_ocsp` as a security decision without responder-signature verification, OR make the unverified path refuse to return `Good` (treat every response as `Unknown` so hard-fail denies). Implement RSA+ECDSA verification of `signature` over `tbs_response_data` against the issuer SPKI, plus delegated-responder handling, before trusting status. The documented "trusted network path" mitigation is not enforced and is insufficient under zero-trust.
- **Verification verdict:** CONFIRMED — 3/3 skeptics. Admission wiring confirmed (`tls.rs:439-446`; `decide_allow` `Good→true`). Two skeptics noted the additive-layer / non-default-feature context; one rated critical for the enabled config, defect unanimous.

### C-3 — OCSP responder signature is NEVER verified — network MITM forges Good and bypasses revocation
- **Crate / location:** `mcps-proxy` · `mcps-proxy/src/ocsp.rs:257-265`
- **Category / lens:** crypto / signature bypass · security
- **Severity:** CRITICAL
- **Description:** `map_basic_response` trusts the `BasicOCSPResponse` status without verifying the responder's signature over `tbs_response_data`. Any party able to answer the HTTP POST returns a self-authored, unsigned (or arbitrarily-signed) response asserting `CertStatus::Good` for a revoked attacker-held leaf; the proxy maps it to `Good` and admits the connection, defeating the entire online-revocation control. The module's own doc and inline note concede this is unimplemented; unit fixtures build responses with an EMPTY signature and the production path accepts them.
- **Evidence:** `ocsp.rs:257-264` (no signature check); `ocsp.rs:248-256` HARDENING FOLLOW-UP "verify basic's signature here before trusting its status … is NOT yet performed". Transport is plaintext `ureq::post(url)` (`ocsp.rs:210`) to the leaf AIA URL (`ocsp.rs:291-305`).
- **Recommendation:** Do not rely on `online_ocsp` as an admission control until `BasicOCSPResponse.signature` is verified against the issuer key or a delegated `id-kp-OCSPSigning` responder chained to the issuer. Enforce the trusted-path property architecturally, not by operator discipline.
- **Verification verdict:** CONFIRMED — 3/3 skeptics. Inputs attacker-influenceable (client-presented leaf, AIA fallback, no responder-TLS pinning). One skeptic calibrated effective severity to high given the feature gate + CRL layer; defect unanimous.

### C-4 — OCSP responder signature NEVER verified (conformance lens, signature gate absent)
- **Crate / location:** `mcps-proxy` · `mcps-proxy/src/ocsp.rs:257-265`
- **Category / lens:** signature-bypass · conformance
- **Severity:** CRITICAL
- **Description:** Same defect, audited under the conformance lens: the production map path accepts a `BasicOCSPResponse` with no signature gate. The empty-signature test fixture passing through `map_response_der` to a `Good`/`Revoked`/`Unknown` mapping is machine-proof that no verification occurs; admission on `Good` follows from `decide_allow`.
- **Evidence:** `ocsp.rs:257-265`; `ocsp.rs:248-256`; `ocsp.rs:547` `BitString::from_bytes(&[])`; admission via `tls.rs:441 if checker.allows(status) { None }` with `decide_allow(Good)→true`.
- **Recommendation:** As C-1/C-2/C-3 — fail closed (`Unknown`) on any unverified response; implement algorithm-agnostic responder-signature verification + delegated-responder chain/EKU validation before honoring `cert_status`.
- **Verification verdict:** CONFIRMED — 3/3 skeptics. Reviewers consistently noted the non-default `online_ocsp` gate and offline-CRL underlayment; the bypass nullifies the incremental promise of the online feature exactly where the operator believes revocation is enforced.

### H-1 — Multi-tool pin commit is NOT atomic for duplicate tool names (P7-04 break)
- **Crate / location:** `mcps-policy` · `manifest_verifier.rs:119-132`
- **Category / lens:** correctness/atomicity · security
- **Severity:** HIGH
- **Description:** P7-04 requires that NO tool's pin commits unless EVERY tool clears the rug-pull gate. The verifier uses a read-only pre-check over `pins.pinned()` then a separate commit loop, with no duplicate-tool-name detection anywhere in the manifest path. A signed manifest containing two `ToolEntry` with the same name but different `(version, schema_hash)` — e.g. `[echo@1.0.0/hashA, echo@1.0.0/hashB]` — passes the pre-check (store unmutated). The commit loop records `hashA`, then the second entry hits the same-version-different-hash arm and returns `ManifestRugPull` — *after* echo's pin was mutated to `hashA`. `verify()` returns an error yet the store is partially mutated, contradicting the module contract ("leaves the pin store unchanged") and P7-04's deny-before-commit guarantee. A hostile-but-resolvable server forces a chosen pin under cover of a failing verification, poisoning TOFU on a persistent store.
- **Evidence:** Pre-check `manifest_verifier.rs:119-127` reads unchanged store; commit loop `manifest_verifier.rs:130-132` mutates mid-iteration via `check_and_record`; `InMemoryManifestPinStore::check_and_record` inserts on first sighting then errs on the conflicting duplicate (`manifest_pin.rs:71-97`); no dedup/`HashSet`/unique guard in `manifest.rs` or `manifest_verifier.rs`.
- **Recommendation:** Reject a manifest with duplicate tool names (`ManifestMalformed`) before the commit step, OR make the commit transactional (stage all `check_and_record` results in a scratch copy and swap only on full success). The pre-check must account for in-manifest duplicates the same way the commit does.
- **Verification verdict:** CONFIRMED — 3/3 skeptics. Caveat: latent today — no production code outside `mcps-policy` calls `verify()`, and only the in-memory reference store exists. High on a contract/fail-closed basis: the documented atomicity guarantee is violated and a hostile server writes a chosen pin during a failing verify; it becomes live the moment a persistent store is wired.

### H-2 — No OCSP nonce sent or validated — responder replies are replayable
- **Crate / location:** `mcps-proxy` · `mcps-proxy/src/ocsp.rs:310-322`
- **Category / lens:** replay · general
- **Severity:** HIGH
- **Description:** `build_ocsp_request_der` builds the request with only a single `Request(cert_id)` and no Nonce extension (RFC 6960 §4.4.1); the map path never looks for or compares a response nonce. With no nonce binding request to response, freshness cannot be asserted per-request — an attacker on the path replays a previously-captured (even validly-signed) `Good` response for the same CertID after revocation.
- **Evidence:** `ocsp.rs:316-318` `OcspRequestBuilder::default().with_request(Request::new(cert_id)).build()` — no `.with_nonce(...)`; map path `ocsp.rs:231-265` never references a nonce; grep for `nonce` in `ocsp.rs` returns nothing.
- **Recommendation:** Generate a random nonce, attach it as the request Nonce extension, and require the response Nonce to match (fail closed on mismatch/absence when the responder supports nonces). Meaningful only once signature verification exists.
- **Verification verdict:** CONFIRMED — 3/3 skeptics. Severity note: dominated by the signature gap today; the nonce is the correct residual anti-replay control once signatures are verified.

### H-3 — SingleResponse CertID is not matched against the requested CertID — first response blindly trusted
- **Crate / location:** `mcps-proxy` · `mcps-proxy/src/ocsp.rs:258-264`
- **Category / lens:** response-binding · general
- **Severity:** HIGH
- **Description:** `map_basic_response` takes `responses.first()` and maps its status without confirming `SingleResponse.cert_id` equals the requested CertID (`issuer_name_hash`, `issuer_key_hash`, `serial_number`, `hashAlgorithm`). A responder/MITM returns a `SingleResponse` for a *different*, still-valid certificate's CertID and has it accepted as the leaf's status. Even with a future signature check, an attacker who can obtain any validly-signed `Good` from the responder could substitute it for the revoked leaf. RFC 6960 §3.2 requires this binding.
- **Evidence:** `ocsp.rs:258-263` takes `.responses.first()` with no comparison of `single.cert_id` to the request CertId; the request CertID (`build_sha256_cert_id`, `ocsp.rs:335-360`) is discarded after request build.
- **Recommendation:** Recompute the requested CertID and select the matching `SingleResponse`; fail closed if no match is present. Land together with signature verification, not after.
- **Verification verdict:** CONFIRMED — 3/3 skeptics. A genuine RFC 6960 §3.2 binding violation; orthogonal to the signature gap (a future signature check does NOT cover it).

### H-4 — No OCSP nonce — captured 'Good' responses are replayable (conformance lens)
- **Crate / location:** `mcps-proxy` · `mcps-proxy/src/ocsp.rs:310-322`
- **Category / lens:** replay · conformance
- **Severity:** HIGH
- **Description:** Same nonce-omission defect under the conformance lens: the request carries no Nonce extension; with the absent signature check there is no request→response binding, so a previously captured (even legitimately-signed) `Good` for a now-revoked certificate is replayable and accepted.
- **Evidence:** `ocsp.rs:316-318` no `.with_nonce(...)`; grep confirms no `nonce` token anywhere in the file.
- **Recommendation:** Add a cryptographically-random nonce and require the response to echo a matching Nonce extension; reject (fail closed) on mismatch/absence when the responder supports nonces.
- **Verification verdict:** CONFIRMED — 2/3 skeptics (gate held: one skeptic refuted, see §9). Admitted on the ≥2/3 rule; severity acknowledged as coupled to #4030.

### H-5 — thisUpdate/nextUpdate freshness is never validated — stale/expired responses accepted
- **Crate / location:** `mcps-proxy` · `mcps-proxy/src/ocsp.rs:257-265`
- **Category / lens:** validity-window · conformance
- **Severity:** HIGH
- **Description:** RFC 6960 §3.2/4.2.2.1 requires rejecting a `SingleResponse` whose `thisUpdate` is in the future or whose `nextUpdate` is in the past. The production map path never reads `single.this_update`/`single.next_update`; it returns the status regardless of age. Even with signature verification, an old signed `Good` is honored indefinitely.
- **Evidence:** `ocsp.rs:259-264` reads only `single.cert_status`; no `this_update`/`next_update` reference in production code (the `build_response_der` fixture sets a `now` `thisUpdate` that production never consumes).
- **Recommendation:** After signature verification, enforce `now >= thisUpdate` (small skew) and, when present, `now <= nextUpdate`; map a stale/future response to `Unknown` so hard-fail denies.
- **Verification verdict:** CONFIRMED — 3/3 skeptics. The 2024-dated fixture passing in 2026 is machine-proof.

### H-6 — OCSP carries no nonce AND thisUpdate/nextUpdate never checked — captured 'Good' replayable indefinitely (security lens)
- **Crate / location:** `mcps-proxy` · `mcps-proxy/src/ocsp.rs:316-318, 257-265`
- **Category / lens:** replay / clock · security
- **Severity:** HIGH
- **Description:** Combined-lens write-up of H-4+H-5: bare `OcspRequestBuilder::default().with_request(...)` with no Nonce, and `map_basic_response` ignores `this_update`/`next_update` entirely. With no nonce binding and no validity-window enforcement, a once-captured legitimately-signed `Good` for a now-revoked leaf replays forever — survives the future signature fix.
- **Evidence:** `ocsp.rs:316-318` (no `.with_nonce`); `ocsp.rs:259-264` (only `cert_status`); fixture `ocsp.rs:531` hardcodes 2024-01-01 that production never validates; `decide_allow` (`ocsp.rs:376-382`) branches on status only.
- **Recommendation:** Add a random Nonce and require it echoed; enforce `now ∈ [thisUpdate, nextUpdate]` (reject/fail-closed when `nextUpdate` absent or past).
- **Verification verdict:** CONFIRMED — 3/3 skeptics. Non-redundant of the signature gap: the freshness window must close the moment signatures start being trusted.

### H-7 — Responder identity not bound to requested issuer — responder_id and CertID echo unchecked
- **Crate / location:** `mcps-proxy` · `mcps-proxy/src/ocsp.rs:259-264`
- **Category / lens:** authz scoping / responder identity · security
- **Severity:** HIGH
- **Description:** `map_basic_response` takes `responses.first()` without confirming `SingleResponse.cert_id` matches the sent CertID and without checking `tbs_response_data.responder_id` at all. A responder/MITM returns `Good` for a different certificate/serial than queried, treated as the answer for the verified leaf.
- **Evidence:** `ocsp.rs:259-264` never compares `single.cert_id` to the request CertID and never inspects `responder_id` (read only in the test fixture).
- **Recommendation:** Assert `single.cert_id` equals the sent CertID (or locate the matching `SingleResponse` by CertID), and validate `responder_id` against the issuer / delegated responder once signature verification lands.
- **Verification verdict:** CONFIRMED — 3/3 skeptics. Notable: unlike the signature gap, the missing CertID/`responder_id` binding is NOT mentioned in either deferral note — undocumented.

### H-8 — Redis server-side TTL computed against hard-coded now_unix=0 → keys never expire (DoS)
- **Crate / location:** `mcps-proxy` · `shared_replay.rs:168-169` + `redis_store.rs:79-82`
- **Category / lens:** TTL/expiry correctness · general
- **Severity:** HIGH
- **Description:** `SharedReplayCache::check_and_insert` hard-codes the `now` anchor to `0`. The in-memory store ignores `now_unix` (default build fine), but `RedisAtomicReplayStore` derives `ttl_secs = expires_at_unix.saturating_sub(now_unix)` — with `now_unix=0` this equals `retain_until`, an absolute Unix timestamp (~1.78e9), then `×1000` yields a PX of ~1.78e12 ms ≈ **56 years**. Under `redis_replay`, a hostile client flooding distinct valid nonces grows the Redis keyspace without bound (no Redis prune step exists). NOT fail-open for replay (entries persist longer, so protection stays conservative), hence HIGH not CRITICAL.
- **Evidence:** `shared_replay.rs:169` `Ok(self.store.insert_if_absent(&key, retain_until, 0)?)`; `redis_store.rs:79` `let ttl_secs = expires_at_unix.saturating_sub(now_unix).max(0);`; `redis_store.rs:82` `let ttl_ms: u64 = (ttl_secs as u64).saturating_mul(1000).max(1);`.
- **Recommendation:** Pass the actual current Unix time (injected Clock / `SystemTime::now`) as `now_unix` so the Redis PX equals the intended `retain_until - now` window. Add a live-Redis black-box test asserting PTTL is in the expected seconds range.
- **Verification verdict:** CONFIRMED — 3/3 skeptics. Magnitude corrected by the gate: PX is in **milliseconds**, true expiry ~**56 years** (the original "~56,000 years" was 1000× off). A ~56-year TTL is operationally "never expires" and the unbounded-growth DoS stands.

### H-9 — Server-side TTL against hard-wired now_unix=0 → server-side eviction never happens (security lens)
- **Crate / location:** `mcps-proxy` · `mcps-proxy/src/redis_store.rs:79-82` (caller `shared_replay.rs:168-169`)
- **Category / lens:** TTL/expiry correctness · security
- **Severity:** HIGH
- **Description:** Security-lens write-up of the same defect: `SET ... NX PX <ttl_ms>` is intended to mirror the in-memory retain-until window, but with `now_unix=0` the PX is the absolute retain-until instant, so Redis never evicts and the keyspace is an unbounded-growth surface. The in-memory store ignores `now_unix`, masking the defect in the only Bazel-tested path.
- **Evidence:** `shared_replay.rs:169` literal `0`; `redis_store.rs:79-82` PX derivation; in-memory `prune` at `shared_replay.rs:206-208` is the only eviction path and has no Redis equivalent.
- **Recommendation:** Thread a real wall-clock `now` from `check_and_insert`; give the store its own clock rather than feeding `0`. Add a live-Redis test asserting PX is on the order of `(expires_at + skew - now)`.
- **Verification verdict:** CONFIRMED — 2/3 skeptics (gate held). One skeptic refuted the "~56,000-year / never happens" framing as overstated (true ~56 years, arguably medium); admitted on ≥2/3 with corrected magnitude, dissent recorded in §9.

### H-10 — Redis connection has no connect/read/write timeout — hung Redis hangs the single-threaded serve loop (never fails closed)
- **Crate / location:** `mcps-proxy` · `mcps-proxy/src/redis_store.rs:53-57` (connect) and `93-102` (per-op query)
- **Category / lens:** connection-error handling / DoS · security
- **Severity:** HIGH
- **Description:** `connect()` uses `client.get_connection()` with no connection timeout, and `insert_if_absent` issues a blocking `redis::cmd("SET")...query(&mut *conn)` with no socket read/write timeout. The serve loop is single-threaded and blocking, and the replay check sits BEFORE dispatch. A Redis that accepts TCP but never answers (sinkholed, half-open, compromised middlebox) blocks `query()` forever, stalling the entire proxy. It does NOT fail closed — it HANGS — violating the "never hang" trust-boundary requirement.
- **Evidence:** `redis_store.rs:53` `client.get_connection()` (no `*_with_timeout`); `redis_store.rs:99-102` `.query(...)` with no prior `set_read_timeout`/`set_write_timeout`; grep for `timeout` returns nothing. Every other trust-boundary I/O on the loop IS bounded (client/inner sockets via `--read-timeout-secs`/`--write-timeout-secs`; OCSP fetch mandatory timeout), making the Redis path the lone unbounded blocking I/O.
- **Recommendation:** Set bounded read AND write timeouts (`Connection::set_read_timeout`/`set_write_timeout`, or `get_connection_with_timeout`) so a stalled backend surfaces as `ReplayStoreError::Unavailable` within a bounded window and the boundary fails closed. Wire the bound from the existing `--read-timeout-secs`/`--write-timeout-secs` config.
- **Verification verdict:** CONFIRMED — 3/3 skeptics. Replay-before-dispatch ordering verified (`proxy.rs:214-218` before `proxy.rs:254`). Scoped to `redis_replay` + `--replay-cache shared`; the SET op uses no TLS, so an on-path attacker fully controls the socket.

### H-11 — `--strict`/`--production` placed after `--inner-command` is silently swallowed (fail-open)
- **Crate / location:** `mcps-proxy` · `mcps-proxy/src/cli.rs:284-287`
- **Category / lens:** fail-open / argument parsing · general
- **Severity:** HIGH
- **Description:** `parse_args` treats `--inner-command` as a greedy trailing-varargs terminator: `inner_command = args[i+1..].to_vec(); break;`. Every token after `--inner-command` — including valueless security flags `--strict`, `--production`, `--allow-env-keysource` — is consumed verbatim as an inner-server argument and never interpreted. `mcps-proxy --inner-command my-server --strict` yields `config.strict == false` (warn-only) with NO error and NO warning, silently skipping the strict-posture rejection of env keys / disabled cert lifetime / inherit-env / cn_legacy / best-effort rlimits. The swallowed flag is also injected into the hostile inner server's argv.
- **Evidence:** `cli.rs:284` `if flag == "--inner-command" { inner_command = args[i + 1..].to_vec(); break; }`; strict gate `cli.rs:696-704` guarded by `if config.strict`. Tests miss it because every strict test splices flags at position 0.
- **Recommendation:** Require `--inner-command` to be terminated explicitly (e.g. `--`) with security flags parseable on either side, OR scan the post-`--inner-command` tail for known proxy flags and hard-error. Add a black-box test that `--strict` AFTER `--inner-command` is rejected or honored, never silently dropped.
- **Verification verdict:** CONFIRMED — 3/3 skeptics. One skeptic added an empirical black-box proof: a temporary unit test calling `parse_args` with `--strict` appended asserted `!config.strict` and `inner_command.contains("--strict")` — PASSED (strict swallowed, leaked into inner argv), test reverted. Silent downgrade at a trust-posture boundary; argv-ordering-dependent (not network-reachable) but fails open with no diagnostic.

> **High-finding accounting.** The 15 confirmed HIGH findings comprise 1 in `mcps-policy` (H-1) and 14 across the proxy/transport surface (H-2 … H-11 documented above, plus 4 further proxy/transport highs grouped under the same OCSP/replay clusters). The crate table (§4) is authoritative for per-crate counts: `mcps-transport` 2, `mcps-proxy` 12, `mcps-policy` 1.

---

## 6. Medium / Low / Info Findings

Per-crate distribution (authoritative counts; individual write-ups are retained in the workflow finding store, transcript `wf_c617823d-ec9`):

| Crate | Medium | Low | Info |
|---|---:|---:|---:|
| `mcps-core` | 2 | 4 | 30 |
| `mcps-policy` | 4 | 9 | 41 |
| `mcps-proxy` | 21 | 41 | 170 |
| `mcps-transport` | 3 | 5 | 13 |
| **Total** | **30** | **59** | **254** |

Medium (30) is concentrated in `mcps-proxy` (21) — residual hardening and conformance edge-cases around the new backends. Low (59) is style/defensive-depth/minor robustness. Info (254) is observations, documentation notes, and confirmed positive controls; no action required.

---

## 7. Tier B — 0.1 Remediation Verification

Every High/Medium finding from the 0.1 audit (13 finding-IDs covering the 3 H + 14 M) was re-verified against current source and its associated regression tests. **9 closed, 4 partial, 0 regressed, 0 open.**

| 0.1 finding | Status | Summary |
|---|---|---|
| **H-1/H-2** — unbounded recursion in public canonicalize/parse | **PARTIAL** | `parse`/`canonicalize` fixed: `MAX_PARSE_DEPTH=128` enforced on both the raw-bytes parser (`canonical.rs:329-339`) and the serde-Value path (`canonical.rs:147,157`), fail-closed via `CanonicalizationFailed`, regression-tested incl. a 100k-deep pathological input and a proptest boundary case. **Residual:** the serializer `write_value` (`canonical.rs:181-214`), reachable from the public `canonicalize_value` over the public `JcsValue` enum, has **no** depth bound. In-crate unreachable (every `JcsValue` reaching it comes from the bounded parse) and no production caller constructs deep values, but an external crate could overflow the stack. Fix: bound `write_value` mirroring `MAX_PARSE_DEPTH` (or make `JcsValue` non-publicly-constructible) + a deep-value regression test. |
| **H-3** — persistent inner blocking pipe I/O can hang the serve loop | **PARTIAL** | **Read side fully fixed + tested** (MCPS-074): absolute `libc::poll` deadline, no disable path (`--inner-read-timeout-secs` rejects 0), buffer-drain handling of unterminated lines, `MAX_INNER_LINE_BYTES` incremental cap, `MAX_SKIPPED_LINES`, black-box self-disarming tests. **Residual:** the **write side** (`persistent_inner.rs:313-321` `stdin.write_all`) is still unbounded blocking with no `POLLOUT`/deadline; a hostile inner that completes the handshake then refuses to drain stdin on a request larger than the OS pipe buffer wedges the single-threaded loop — the same H-3 class on the write half. No write-stall test. |
| **M-1** — absent on_behalf_of taxonomy token (P005) | **CLOSED** | Fails closed, denies before dispatch, dedicated regression test exercises the real serde error message. |
| **M-2** — absent authorization_hash taxonomy token (P007) | **PARTIAL** | Fixed for the single-field-absent and present-but-malformed cases via structural-absence mapping (`constraints.rs:159-161`) + tests. **Residual:** serde reports only the *first* missing field, so co-omission of an earlier required field re-routes to `CanonicalizationFailed` (still fails closed). To fully close: classify on an explicit presence check rather than serde message ordering. |
| **M-3/M-6** — client transport no timeouts | **PARTIAL** | `ClientLimits` adds connect/read/write timeouts + response cap (defaults 30s/30s/30s/16MiB), applied in `round_trip` before send; tested. **Residual recommended:** a single `Instant`-based aggregate read deadline in `read_response_bounded` (mirror cli.rs MCPS-074) and route write `WouldBlock`/`TimedOut` through a `Timeout` classification. |
| **M-4/M-5** — client unbounded response read (OOM) | **CLOSED** | Bounded read present and correct. |
| **M-7** — one-shot inner blocking stdin write_all | **CLOSED** | Fixed in MCPS-084 (`09816e86a0`). |
| **M-8** — DurableReplayCache no fsync | **CLOSED** | Fixed in MCPS-083 (`b6648c32a0`): fsync data file + directory. |
| **M-9** — persistent inner stdout read no timeout (P179) | **CLOSED** | Fully fixed with machine-checked regression coverage (read-side; see H-3 note for the residual write-side). |
| **M-10** — RevocationSource bool-only API | **CLOSED** | Fixed at the API level (indeterminate verdict expressible) and enforced fail-closed at every production call site with distinct wire tokens + regression tests. |
| **M-11/M-13** — drift guard omits packages | **CLOSED** | Guard now scans all 9 mcps packages (was 5), with a fail-closed regression test; `bazel query` ground-truth confirms zero drift. |
| **M-12** — cross-transport parity omits 2 vectors | **CLOSED** | `tampered_id` and `missing_envelope` now run cross-transport. |
| **M-14** — demo evidence fields overclaim | **CLOSED** | Fixed in MCPS-086 (`6ad1317cb5`): both overclaimed fields honestly sourced/named. |

> **Theme note.** The DoS-at-trust-boundary theme that dominated 0.1 is mostly closed but **recurs** in the new backend code (H-8/H-9 unbounded Redis growth, H-10 serve-loop hang) and in the two residual partials (H-1/H-2 serializer, H-3 write side). The class is not yet eliminated workspace-wide.

---

## 8. Tier C — Core-Invariant Regression Sweep

Six load-bearing invariants were swept against the new Phase-7 code. **Five returned a clean source-verified HOLD. The sixth (fail-closed backends) is recorded as VIOLATED for the OCSP backend — see the divergence note.**

| Invariant | Result | Evidence |
|---|---|---|
| Request signature binding — every admitted request Ed25519-verified over the canonical full JSON-RPC object; no alternate preimage | **HOLDS** (high) | Single admit gate `Proxy::handle_with_transport` (`proxy.rs:202`) → `mcps_core::verify_request` is the sole admission decision (`proxy.rs:214-223`); manifest/delegated-signer introduce no alternate preimage. |
| Deny-before-dispatch — authz denial precedes any inner write | **HOLDS** (high) | `verify_request` first; on `Ok`, Phase-5 policy gate (`proxy.rs:231-246`); on `Deny` the inner server is never reached. |
| Replay ordering + shared/Redis store fail-closed | **HOLDS** (high) | `pipeline.rs:192-199` (verify, step 11) precedes `pipeline.rs:201-212` (replay, step 12); step 12 unreachable unless verify returns `Ok`. (The `now_unix=0` TTL bug is flagged here as a non-breaking observation → H-8/H-9.) |
| Response-to-request hash binding (incl. delegated/HSM signer) | **HOLDS** (high) | `request_hash` is written *inside* the signed preimage (`proxy.rs:349-354`) before signing; the delegated/HSM signer signs exactly that preimage. |
| **Fail-closed at every new fallible backend** | **VIOLATED (OCSP)** | The Tier C agent returned `holds=true` but explicitly caveated the OCSP responder-signature deferral (#4030). Tier A proves that caveat is a live **fail-open** admission path (C-1…C-4). Redis fails by **hang** not closed (H-10); `--strict` silently downgrades (H-11). Recorded as VIOLATED. (Sandbox platform-gate, PKCS#11-error, and CRL/OCSP `Unknown→deny` paths *do* fail closed.) |
| JCS canonicalizer integrity under the recursion bound | **HOLDS** (high) | `git diff` over the canonicalizer across the Phase-7 span is empty — backends touched zero canonicalizer code; bound does not weaken correctness; proptest intact. |

> **Verification-method divergence (load-bearing meta-finding).** The fail-closed-backends *invariant agent* judged the OCSP `#4030` signature gap an accepted "documented deferral, not a regression" and returned HOLDS. The three independent Tier A lenses (general/security/conformance) plus the 3-skeptic gate rated the **same code** four times CRITICAL fail-open. The deeper full-depth review correctly overrode the invariant sweep's pass. **Lesson:** an invariant-level sweep can rubber-stamp a tracked deferral that is in fact a live fail-open; do not treat a printed HOLDS as closure. This is why the audit runs Tier A independently of Tier C rather than trusting the invariant rollup.

---

## 9. Refuted / Corrected by the Skeptic Panel (gate is load-bearing)

`refutedCount = 1`, plus one numeric correction. The gate filtered overstated framing rather than rubber-stamping:

- **Refuted — "No OCSP nonce" as a standalone HIGH (general framing).** One skeptic (high confidence) confirmed the facts (no Nonce sent/checked, no `thisUpdate`/`nextUpdate`) but rejected the *standalone, independently-exploitable HIGH* framing: the nonce is an OPTIONAL RFC 6960 extension, the real freshness control is `nextUpdate`, and the replay vector is subsumed by the missing-signature follow-up (#4030). The finding still **passed at ≥2/3** (H-4); the dissent is recorded so the honest residual is "OCSP trust gated only by an unverified status — signature (#4030) AND `nextUpdate` both missing."
- **Corrected — Redis TTL magnitude (H-8/H-9).** The finding originally claimed "~56,000 years / never happens"; one skeptic refuted the magnitude (PX is in milliseconds → true expiry ~**56 years**, a 1000× error) and argued for medium. Admitted at ≥2/3 with the corrected ~56-year figure adopted throughout §5; a 56-year TTL is still operationally "never expires."

---

## 10. Residual Risk, Limitations, and Recommended Follow-ups

### Residual risk
Overall **HIGH**. Four criticals collapse to one unimplemented OCSP signature gate; the high cluster is the rest of the OCSP trust chain plus three fail-open/hang/DoS defects and the manifest-atomicity break. All are gated behind non-default features (`online_ocsp`, `redis_replay`) or a specific operator argv ordering, and `mcps` is not in the merge gate — so the **default shipped build is not affected**, which is why the rating is HIGH and not CRITICAL. But each defect fails open, hangs, or silently downgrades in exactly the configuration an operator enables to *gain* the control, which is unacceptable at the high-assurance bar. **Do not advertise `online_ocsp` as a security control, and do not cut the `mcps-v0.2.0` tag, until at least follow-ups 1–4 land.**

### Audit limitations
- **Engine HEAD vs. cited pin.** Agents ran against working-tree HEAD `6d85a60912`; the script cited `83cd06a10d` (PR #4055 merge). The two differ only by `cli.rs` (−41 lines at HEAD); agents `git diff`-confirmed the audited regions of `mcps-core`/`mcps-transport`/`ocsp`/`redis_store`/`shared_replay` are byte-identical across the span, and read `cli.rs` at the target where relevant. Findings apply at the reviewed source. The version-file bump to `0.2.0` and the `mcps-v0.2.0` tag remain release-time steps after remediation.
- **No live execution.** Timeout/TTL/signature findings are source-trace + one in-process `parse_args` proof (H-11). H-8/H-9/H-10 recommend live-Redis PTTL/timeout black-box tests; the OCSP criticals recommend a live MITM/forged-responder test.
- **Medium/Low/Info** are reported by count; individual write-ups remain in the workflow finding store.

### Recommended follow-ups (priority order)
1. **OCSP trust chain — blocks shipping `online_ocsp` as a control (C-1…C-4, H-2…H-7).** In one change: responder-signature verification (RSA+ECDSA, issuer key or delegated `id-kp-OCSPSigning` chain/EKU), CertID-echo binding (H-3/H-7), `responder_id` validation (H-7), `thisUpdate`/`nextUpdate` enforcement (H-5/H-6), and request Nonce (H-2/H-4/H-6). Until done, the unverified path must refuse to return `Good` (treat as `Unknown` → hard-fail denies). Closes #4030.
2. **Manifest pin atomicity (H-1).** Reject duplicate-name manifests (`ManifestMalformed`) or make the commit transactional, before any persistent store is wired.
3. **Redis replay correctness (H-8/H-9/H-10).** Thread a real wall-clock `now` for the PX TTL; set bounded connect/read/write timeouts wired from existing config; add live-Redis black-box tests for PTTL range and stalled-backend `Unavailable`.
4. **CLI fail-open (H-11).** Make proxy flags after `--inner-command` a hard parse error (or require `--` termination); add the black-box ordering test.
5. **Close the two Tier-B partials fully (H-1/H-2 serializer surface; H-3 write-side stdin; M-2 presence-check; M-3/M-6 aggregate deadline).**
6. **L-1 — supply-chain scan.** Run `cargo-deny` / SBOM advisory + license + duplicate-version scan across the `mcps-*` crate graph (carried from the 0.1 critic-gap list, still unverified) and gate it in CI.

---

*Generated from machine-validated structured findings (workflow `wf_c617823d-ec9`: 117 agents, 6.31M tokens). Tier B/C tables in §7–§8 reconciled from the structured remediation/invariant datasets; §5 write-ups and §9 from the adversarial-gate output. Severity counts are computed, not narrated.*
