<!-- SPDX-License-Identifier: Apache-2.0 -->

# Design Note: HTTP Evidence Carrier Cutover (isolate-then-remove migration)

## Status

**Proposed — control-plane migration scope. Authored 2026-07-11.**

This note performs the migration that
[`active-profile-and-legacy-quarantine.md`](active-profile-and-legacy-quarantine.md)
**authorized but explicitly deferred** — its change #9 / acceptance criterion #9
("Runtime / feature-flag boundary … the isolate-then-remove migration"). It is
the concrete, sequenced scope for making the **RFC 9421 + RFC 9530 HTTP evidence
carrier** the actual production serving carrier and quarantining the legacy
Native JCS / object profile out of the production entrypoints.

It is a **scope document**, not the implementation. No production behaviour is
changed by adopting it. It defines the phases, the exact code surfaces, and the
gating that keeps ADR-MCPRE-050 / 051 / 052 honest until the cutover is real.

## The finding this note responds to

Owner stance (2026-07-11), verified against the tree:

> The intended production posture is HTTP transport + RFC 9421 HTTP Message
> Signatures + RFC 9530 Content-Digest + JOSE/JWS delegated signing credential,
> HTTP in / HTTP out. If the live async fleet currently verifies/signs
> object-profile `_meta`/JCS evidence, then the serving path has not caught up to
> ADR-050/051.

**It has not.** Verified 2026-07-11 by tracing every call site:

| Concern | Production serving path (today) | HTTP evidence carrier (target) |
|---|---|---|
| Request verification | `mcp_re_core::verify_request_dispatch_preflight` (object / draft-02 `_meta`) — `mcp-re-proxy/src/proxy.rs:332` | `mcp_re_http_profile::verify_request_full` (RFC 9421 + 9530) |
| Replay admission | inline in `handle_with_transport_async` against the async tier (object replay key) | `dispatch_request_with_tier_gate` (HTTP-profile replay key) |
| Response signing | `dispatch_and_sign_async` → object `result._meta.response` Ed25519 — `mcp-re-proxy/src/proxy.rs:537,745` | `sign_response_full` / `sign_delegated_response_full` |
| Delegated custody | **not reachable** (no HTTP response signing on the hot path) | `DelegatedSigningCustody` (`mcp-re-http-profile/src/custody.rs`) |

The production entrypoint is a single path: `main.rs` `run()` → `serve_fleet`
(`mcp-re-proxy/src/main.rs:820,842`) → `make_handler` (`:878`) →
`Proxy::handle_with_transport_async` (`mcp-re-proxy/src/proxy.rs:317`). Its own
doc-comment calls it "the ONLY request path," and it runs the **object** carrier.

The RFC 9421 carrier functions (`verify_request_full`, `sign_response_full`,
`sign_delegated_response_full`, `dispatch_request_with_tier_gate`) appear
**nowhere in `mcp-re-proxy/src`** — only in `mcp-re-http-profile/tests/*`,
`mcp-re-proxy/tests/*`, `mcp-re-conformance/tests/*`, and one wired-end-to-end
**example** binary, `mcp-re-proxy/examples/http_profile_proxy.rs` (self-described:
"the ADR-MCPRE-050 go-forward carrier wired end-to-end over the wire … NOT the
object/legacy path"). The GKE client (`docs/security/mcp_re_gke_client.py`) and
both SDKs sign object `_meta` evidence over HTTP *transport*.

This exactly matches the quarantine note's deferred change #9: *"the
native/object path is still the default-on carrier on the live serving/verify
path."* The cutover was authorized there; this note scopes it.

## De-risking: the target path already exists end-to-end

The cutover is **promotion, not green-field**. `examples/http_profile_proxy.rs`
already runs the real pipeline over the proxy's own verify / replay / forward /
sign code against a Streamable-HTTP (FastMCP) backend:

```
reconstruct HttpRequest → verify_request_full (RFC 9421 + 9530 + evidence block)
  → dispatch_request_with_tier_gate (fail-closed replay admission)
  → strip proxy-owned _meta, forward clean JSON-RPC via HttpInnerPool
  → sign_response_full (bound to THIS request)   [build_signed_rejection on any fail-closed step]
```

`DelegatedSigningCustody` already composes `sign_delegated_response_full` with
clock-injected rotation and a KMS-issuer seam (`custody.rs:239`). The work is to
lift this proven path into the per-core async **serving binary**, wire delegated
custody onto it, and move the clients/proofs onto the HTTP carrier — then
quarantine the object path out of production.

## Scope — acceptance criteria (owner's seven requirements)

The cutover is complete when **all** hold:

1. Production async fleet request verification uses HTTP-profile
   `verify_request_full` (not `verify_request_dispatch_preflight`).
2. Production response signing uses HTTP-profile `sign_response_full` /
   `sign_delegated_response_full` (delegated custody on the hot path).
3. The GKE client and cross-replica / SLO proofs exercise RFC 9421 / 9530
   evidence, not object `_meta` evidence.
4. Both SDKs put the HTTP evidence carrier on the wire.
5. The object-profile serving path is removed or quarantined from production
   entrypoints (default-off, `--strict`-rejected).
6. Conformance and SLO proofs are rerun against the HTTP evidence carrier.
7. ADR-MCPRE-050 / 051 / 052 status stays **blocked** (not Implemented) until 1–6
   are true and green in CI.

## Phased plan

Each phase is independently landable and CI-gated. No phase weakens a security
claim; the object path stays default-on until Phase 5 flips the default, so every
intermediate state is shippable.

### Phase 0 — Status honesty (do first, no code)

The blocker for *claiming* the carrier is now, not at the end.

- **Revert ADR-MCPRE-050 (#398) and ADR-MCPRE-052 (#400) from `status:implemented`
  to `status:accepted`** (blocked-pending-cutover). Both assert a carrier
  (RFC 9421 sole carrier / JOSE-JWS delegated credential *in the HTTP evidence*)
  that the production path does not serve. This is requirement #7. **Owner action
  — a published-status reversal; not performed by this note.**
- Keep ADR-MCPRE-051 (#399) `accepted`. Do not flip.
- Update `docs/PROJECT_STATUS.md` / `docs/MCP-RE-IN-ONE-PAGE.md`: the served
  evidence is currently the object carrier over HTTP transport; the RFC 9421
  carrier is proven as a library + example, cutover in progress.

### Phase 1 — Serving-path carrier seam (`mcp-re-proxy`)

Introduce a production HTTP-profile request path alongside the object one, behind
a flag; do not delete anything yet.

- Add `Proxy::handle_http_profile_async` (mirror of `handle_with_transport_async`)
  that runs `verify_request_full` → `dispatch_request_with_tier_gate` →
  forward via `HttpInnerPool` → `sign_response_full`, reusing the async replay
  tier and async inner pool already wired in `serve_fleet`. The example is the
  reference implementation to promote.
- Add CLI flag `--evidence-carrier {object|http}` in `mcp-re-proxy/src/cli.rs`,
  **default `object`** for this phase, following the `--transport-identity-source
  cn_legacy` precedent the quarantine note cites (deprecated value, later
  strict-rejected). `serve_fleet`'s `make_handler` selects the handler on it.
- `make_handler` (`main.rs:878`) branches on the flag. Everything else in
  `serve_fleet` (SO_REUSEPORT fleet, drain, replay tier) is carrier-agnostic and
  unchanged.
- Tests: promote `mcp-re-proxy/tests/http_profile_dispatch_test.rs` coverage to a
  served-path e2e through `serve_fleet` with `--evidence-carrier http`.

### Phase 2 — Delegated custody on the hot path (ADR-051 §5 / ADR-052)

Only reachable once Phase 1 exists (delegated signing IS HTTP-profile).

- Instantiate `DelegatedSigningCustody` in the HTTP-profile serving path with an
  injected KMS issuer (issuance/rotation via `spawn_blocking`, off the per-core
  await path), short-TTL in-memory delegated key, root in KMS.
- Response signing calls `sign_delegated_response_full`; each served response
  carries the JOSE/JWS delegation credential in its RFC 9421 evidence
  (`custody.rs` already does this).
- CLI: `--delegated-signing` (opt-in) with issuer-kid / trust-epoch / ttl / overlap
  wiring from `CustodyConfig`. Add a served-path e2e proving root-KMS invocation
  count stays bounded under load (rotation, not per-request root signing).

### Phase 3 — Clients and SDKs onto the HTTP carrier (requirements #3, #4)

- `mcp-re-client-core` / `mcp-re-client-proxy`: sign requests with the HTTP-profile
  `sign_request_full` path and verify responses with `verify_response_full`.
- Python + TS SDKs: expose the HTTP-carrier sign/verify over the *same*
  `mcp-re-client-core` seam (byte-identical preimage invariant preserved).
- `docs/security/mcp_re_gke_client.py`: replace `sign_request_with_signer` +
  `_meta[response_meta_key()]` with RFC 9421 request signing + response
  verification. Signed-rejection receipts become reachable (they are an
  RFC 9421 feature the object client explicitly cannot use today).

### Phase 4 — Rerun the proofs on the HTTP carrier (requirement #6)

- Conformance: ensure `conformance_manifest.json` marks the HTTP-profile
  request/response + delegation vectors as the production suite; the object suite
  is retained as frozen legacy regression only (per quarantine D2).
- SLO / fleet: rerun the ADR-051 §7 load harness and the live GKE
  cross-replica-replay + zero-drop-rolling-update proofs against
  `--evidence-carrier http` (`docs/bench/adr-051-*`,
  `docs/security/gke-*`). Re-baseline `adr-051-slo-targets.json` on the HTTP
  carrier (RFC 9421 verify is more work per request than object preimage; expect a
  new, honestly-measured number).

### Phase 5 — Quarantine the object path from production (requirement #5)

- Flip `--evidence-carrier` default to `http`; make `object` `--strict`-rejected
  and emit a deprecation warning when selected.
- Remove `handle_with_transport_async` (object) from the production entrypoint, or
  gate it behind a non-default `legacy_object_serving` cargo feature. Keep the
  object verifier only for frozen-vector / forensic use (quarantine D2).
- Delete or feature-gate `dispatch_and_sign` / `dispatch_and_sign_async` from the
  production path.

### Phase 6 — Flip the ADR statuses (requirement #7)

Once Phases 1–5 are green in CI and the live GKE proofs are re-run on the HTTP
carrier:

- ADR-MCPRE-050 → Implemented (RFC 9421 sole carrier is now *served*, not just a
  library).
- ADR-MCPRE-051 → Implemented (§5 delegated custody on the served hot path; §7 SLO
  re-baselined on the HTTP carrier).
- ADR-MCPRE-052 → Implemented (delegated credential served in HTTP evidence).

## Non-goals

- stdio (out of scope — quarantine D4).
- Ingress/gateway evidence survival (quarantine D5 / Non-goals).
- Removing the object verifier from frozen-vector / forensic contexts (retained as
  regression history — quarantine D2).
- Broadening any multi-node / replay claim beyond the declared shared-tier
  posture.

## Vocabulary

Per quarantine D1: this is the **active HTTP profile** replacing the **legacy JCS
object profile** on the serving path. Not a "two-profile architecture" — a
migration from a deprecated carrier to the one active carrier.

## Related

- [`active-profile-and-legacy-quarantine.md`](active-profile-and-legacy-quarantine.md)
  — authorizes this migration (change #9 / acceptance criterion #9).
- ADR-MCPRE-050 (#398) — RFC 9421 + RFC 9530, the one carrier.
- ADR-MCPRE-051 (#399) — per-core async serving; §5 delegated custody; §7 SLO.
- ADR-MCPRE-052 (#400) — JOSE/JWS delegated credential in the HTTP evidence.
- Reference path: `mcp-re-proxy/examples/http_profile_proxy.rs`.
