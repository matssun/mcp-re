<!-- SPDX-License-Identifier: Apache-2.0 -->

# HTTP Standards Profile — Open Questions (ADR-MCPRE-050, seed Work Item 5)

Status tracker for the standards questions the v0.11 seed raised, updated with
what the signed-off grill already answered. Owner: Mats. Each open item names
its resolution trigger.

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

## Open — with named triggers

1. **Per-failure wire-code mapping ratification.** The proof path maps
   HTTP-profile failures onto frozen `mcp-re.*` tokens
   (`mcp-re-http-profile/src/error.rs` — e.g. missing covered component →
   `mcp-re.missing_envelope`, foreign tag → `mcp-re.unsupported_version`,
   unresolved keyid → `mcp-re.actor_binding_failed`). Trigger: MUST be
   ratified by Mats before signed rejections ship (the codes become
   wire-visible there); until then they are internal verdicts.
2. **Audience-tuple body evidence block schema.** The request-side
   `se.syncom/mcp-re.http.request` block (audience tuple, `artifact_bindings`,
   `continuation`) is specified by the grill but not yet implemented.
   Trigger: next slice after the proof path (full-profile work).
3. **Replay-cache integration.** The proof path enforces the freshness window;
   the `(resolved signer identity, resolved audience, nonce)` replay key must
   be wired to the existing cache tiers at the dispatcher. Trigger: full
   profile; reuses `mcp-re-core/src/replay.rs` unchanged.
4. **Third-party RFC 9421 cross-verification in CI.** The proof path's
   independent oracle is the RFC 9421 Appendix B.2.6 known-answer test
   (byte-exact signature base + deterministic Ed25519 signature). The ADR's
   no-merge gate for the FULL profile additionally requires a pinned external
   implementation (e.g. Python `http-message-signatures`) validating the
   vector corpus in CI. Trigger: before the parity gate is declared green.
5. **DPoP/RAR artifact-binding vectors.** Registry tokens and typed
   profile-crate schemas for the OAuth pair (grill E-8) plus their vectors.
   Trigger: full-profile artifact-binding slice.
6. **Signed rejection implementation.** HTTP-first per ADR-MCPRE-050 §6
   (status map ratified; `error.message` stays human-readable). Trigger: full
   profile; first signed-rejection implementation anywhere in MCP-RE.
7. **MRTR continuation over standards handles.** Derivation ratified
   (signature-base hashes, body-only); implementation binds to the existing
   `Continuation::McpMrt` shape. Trigger: full profile.
8. **Structured Fields strictness.** The proof-path parser admits a closed
   component set and the profile's exact parameter forms; the full profile
   must decide how much of RFC 8941 generality to accept (e.g. parameter
   reordering by intermediaries is currently a verification failure — likely
   correct, but must be stated normatively). Trigger: full-profile spec text.

## SEP-facing questions to carry into the community post

- Is an MCP HTTP profile of RFC 9421 + RFC 9530 + OAuth sender-constrained
  standards sufficient for the runtime-evidence chain, given the two claimed
  MCP-specific gaps: (1) JSON-RPC result/error-level response-to-request
  binding, (2) MRTR continuation binding? (Both falsifiable against the
  conformance corpus.)
- Should the covered-component floor be raised (e.g. `@authority` in addition
  to `@target-uri`) for deployments behind TLS-terminating proxies?
