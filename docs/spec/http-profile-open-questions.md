<!-- SPDX-License-Identifier: Apache-2.0 -->

# HTTP Standards Profile — Open Questions (ADR-MCPRE-050, seed Work Item 5)

Status tracker for the standards questions the v0.11 seed raised, updated with
what the signed-off grill already answered. Owner: Mats. All previously open
items were ratified by owner rulings on 2026-07-07 (recorded below);
implementation triggers remain where the work is not yet built.

## Resolved by the v0.11 grill / ADR-MCPRE-050

1. **Which request components must the MCP profile require?** — Resolved
   (grill B.1): `@method`, `@target-uri`, `content-digest`, `content-type`;
   plus raw `authorization`/`dpop` when present, exactly-once. Implemented in
   `mcp-re-http-profile/src/ids.rs`.
2. **Is a request body digest enough, or is a canonical MCP body digest needed
   for non-HTTP transports?** — Resolved (grill H.1): the native JCS-int53
   preimage IS the canonical non-HTTP commitment; no third digest scheme.
3. **How should response signatures bind to request components?** — Resolved
   (grill C.1): RFC 9421 `;req` components (`@method`, `@target-uri`,
   `content-digest`, `content-type`) plus the split-form `request_evidence`
   handle over the request signature base.
4. **How should authorization artifacts be referenced without leaking
   secrets?** — Resolved (grill D.1): digest-of-artifact-bytes discipline;
   DPoP tokens via RFC 9449 `ath`, mTLS-bound tokens via RFC 8705 `x5t#S256`,
   never raw token bytes in evidence.
5. **How should DPoP and HTTP Message Signatures compose?** — Resolved
   (grill B.2): two mandatory non-substitutable proofs; the MCP-RE signature
   covers the `dpop` header; keys are distinct roles.
6. **Is EPOP/rctx the future answer for non-HTTP transports?** — Resolved
   stance (grill H.1): non-normative tracking; re-evaluate on
   `draft-ietf-oauth-*` adoption or SEP-1932/successor referencing it.
7. **What is the minimal MCP-specific conformance corpus?** — Resolved shape
   (grill I.1); seed corpus at `mcp-re-conformance/tests/vectors/http-profile/`.

## Ratified by owner rulings, 2026-07-07 — implementation triggers remain

**Implementation status (2026-07-07).** All eight rulings are now implemented
AFK as issues MCPRE-92…99 (GitHub #295–#302). The rulings text below is retained
verbatim as the decision record; each is landed as:

| # | Ruling | Issue | Landed in |
| --- | --- | --- | --- |
| 1 | Wire-code taxonomy | MCPRE-92 (#295) | `mcp-re-core/src/error.rs` (+5 codes), `mcp-re-http-profile/src/error.rs` remap |
| 2 | Body evidence block | MCPRE-93 (#296) | `mcp-re-http-profile/src/block.rs` (`actor_id`, `audience_hash` pinned) |
| 3 | Replay key | MCPRE-94 (#297) | `mcp-re-http-profile/src/replay.rs` (five-tuple onto core tiers) |
| 5 | DPoP/mTLS/RAR bindings | MCPRE-95 (#298) | `mcp-re-http-profile/src/artifact.rs` + corpus h09–h14 |
| 6 | Signed rejection | MCPRE-96 (#299) | `mcp-re-http-profile/src/rejection.rs` + corpus h18–h22 |
| 7 | MRTR continuation | MCPRE-97 (#300) | `block.rs` `HttpContinuation` (3 handles) + corpus h15–h17 |
| 8 | Structured Fields strictness | MCPRE-98 (#301) | `verify.rs` param-order gate + `structured_fields_strictness_test.rs` |
| 4 | Third-party cross-verify | MCPRE-99 (#302) | `tools/rfc9421_cross_verify.py`, `rfc9421_cross_verification_test.rs`, CI gate |

Note: the `request_binding_mismatch` code (ruling 1) is minted but not yet
emitted — response splices are currently caught cryptographically as
`response_sig_invalid` (see corpus h21); it activates when the response body
evidence block's `request_evidence` handle gets an explicit comparison.

1. **Per-failure wire-code mapping.** RULED: current proof-path direction
   ratified (`mcp-re-http-profile/src/error.rs` mappings stand as internal
   verdicts). Public signed-rejection codes must be grouped by security
   meaning, and the taxonomy gains five ratified additions for that surface:
   `mcp-re.malformed_envelope`, `mcp-re.digest_mismatch`,
   `mcp-re.artifact_binding_failed`, `mcp-re.request_binding_mismatch`,
   `mcp-re.continuation_binding_failed`. These extend the frozen taxonomy in
   `mcp-re-core/src/error.rs` (no parallel namespace); none exist there today.
   Trigger for the code work: signed-rejection slice.
2. **Body evidence block schema.** RULED: implement
   `se.syncom/mcp-re.http.request` with required `profile`, `audience`,
   `artifact_bindings`, and `continuation` fields. No raw secrets. It is
   semantic evidence protected by `Content-Digest` and the RFC 9421 signature
   — not a custom crypto envelope. Trigger: next slice after the proof path.
3. **Replay-cache integration.** RULED: reuse the existing cache tiers.
   Replay key = `(profile_id, signature_label, actor_id, audience_hash,
   nonce)` — extends the grill-era `(signer, audience, nonce)` key with the
   profile id and signature label (ADR-MCPRE-050 Threat Model amended to
   match). Freshness from RFC 9421 `nonce`/`created`/`expires`; DPoP `jti`
   stays a separate mechanism, never a substitute. Trigger: full profile;
   reuses `mcp-re-core/src/replay.rs`.
4. **Third-party RFC 9421 cross-verification in CI.** RULED: required before
   full-profile parity is declared green. Pin ONE external RFC 9421
   implementation and verify vectors both ways (the external implementation
   validates MCP-RE-produced vectors; the MCP-RE verifier validates
   externally produced signatures). The proof path's RFC 9421 Appendix B.2.6
   known-answer test remains the interim oracle.
5. **DPoP/RAR artifact-binding vectors.** RULED: add full-profile
   artifact-binding vectors. The MCP-RE signature covers raw
   `authorization`/`dpop` headers exactly once; artifact binding uses
   RFC 9449 `ath`, RFC 8705 `x5t#S256`, RAR artifact digest, etc. Raw token
   bytes never appear in evidence. Trigger: full-profile artifact-binding
   slice.
6. **Signed rejection implementation.** RULED: HTTP-first — JSON-RPC error
   body + `Content-Digest` + RFC 9421 response `Signature`. The stable
   machine signal is the wire code in `error.data`
   (`mcp_re_error.wire_code`), never `error.message`. Trigger: full profile;
   first signed-rejection implementation anywhere in MCP-RE.
7. **MRTR continuation over standards handles.** RULED: MRTR stays
   MCP-specific. Continuation binds to standards-derived evidence handles:
   previous request signature-base digest, input-required response
   signature-base digest, AND a `requestState` digest — a third handle that
   extends the native two-hash `mcp-mrt` shape for the HTTP profile
   (`requestState` is opaque-but-digest-bound, no longer only opaque).
   Trigger: full profile.
8. **Structured Fields strictness.** RULED: strict RFC 8941/RFC 9421 parsing.
   Closed component and parameter set for v1. Parameter or component
   reordering that changes the signature base fails verification — this is
   normative, not an implementation accident. Trigger: full-profile spec
   text records it.

## SEP-facing stance (ruled 2026-07-07) — carry into the community post

- RULED stance: RFC 9421 + RFC 9530 + the OAuth sender-constrained-token
  standards likely cover the HTTP cryptographic carrier in full. The
  MCP-specific remainder is: JSON-RPC result/error-level response-to-request
  binding, signed rejection semantics, MRTR continuation binding, and the
  conformance corpus. (Still falsifiable against the corpus — present it as
  a claim to review, not a settled fact.)
- **`@authority` floor.** RULED: do not raise the global covered-component
  floor; `@target-uri` stays required. For reverse-proxy / TLS-terminating
  deployments, exact reconstruction of the external `@target-uri` is
  mandatory; if it cannot be reconstructed, strict verification fails.
