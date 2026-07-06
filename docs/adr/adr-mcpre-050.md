<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-050: Standards-Aligned HTTP Profile — RFC 9421 + RFC 9530 as the Cryptographic Carrier for HTTP Transports

## Status

Proposed

_First ADR under the `ADR-MCPRE` tag: `ADR-MCPS-NNN` ids are frozen historical
evidence (rename, #289/PR #291); the number sequence continues from 049._

## Context

Discord feedback on the SEP-facing MCP-S/MCP-RE proposal (Paul Carleton, Yaron
Zehavi, Max) correctly challenged whether MCP-RE was reinventing what existing
standards already provide: RFC 9421 defines HTTP request/response signatures
over selected message components; RFC 9530 defines `Content-Digest`; RFC 9449
(DPoP) and RFC 8705 (mTLS) define sender-constrained OAuth token use; RFC 9396
(RAR) expresses fine-grained authorization details; RFC 9700 recommends
sender-constrained, replay-resistant OAuth profiles; and SEP-1932 already
discusses a DPoP profile for MCP.

The current draft-02 implementation is a hardened, conformance-gated prototype
that proves the full security shape — signed request, freshness, replay
protection, audience binding, authorization-artifact binding, signed response
bound to the request, and MRTR continuation binding (ADR-MCPS-047, implemented
and vector-covered). But its wire carrier is a custom `_meta` envelope over a
custom JCS/int53 canonicalization (`mcp-re-jcs-int53-json-v1`), which is not
wire-compatible with HTTP Message Signatures and creates avoidable SEP-facing
friction. Two facts sharpen the choice:

- The repo has **no** RFC 9421/9530 surface today; the transport is minimal
  mTLS HTTP/1.1 with Content-Length framing (`mcp-re-transport`,
  `mcp-re-proxy`). An HTTP-signatures profile is greenfield, not a retrofit.
- Signed rejection receipts (ADR-MCPS-046) are designed but **not
  implemented**; rejections today are unsigned JSON-RPC errors that clients
  must not trust.

The decision space was resolved by the v0.11 Codex-assisted grill
(`docs/grilling-seed/mcp-re-v0.11-grill-decisions.md`, signed off 2026-07-06;
transcript alongside). This ADR records the grill's Work Item 1 and carries the
Work Item 2 mapping appendix. It follows the ADR-MCPS-041 lineage (strict
profile dispatch, no-default expected-profile policy) and re-scopes
ADR-MCPS-046 as described below.

## Decision

For HTTP transports, MCP-RE adopts **RFC 9421 HTTP Message Signatures plus
RFC 9530 `Content-Digest` as the cryptographic carrier** — the **MCP-RE HTTP
standards profile** (profile id/tag `mcp-re-http-v1`), the SEP-facing center of
gravity — while the draft-02 native `_meta` envelope remains a fully supported
carrier (the **MCP-RE native profile**, sole normative non-HTTP carrier) and no
draft-02 wire element may be deprecated before the machine-checked parity gate
defined here passes.

## Threat Model

Unchanged security properties, new carrier. The HTTP profile must preserve
every property the native profile proves, fail-closed:

- **Integrity/authenticity:** Ed25519 (`alg="ed25519"` per the RFC 9421
  registry) over covered components `@method`, `@target-uri`,
  `content-digest`, `content-type` (plus raw `authorization` and `dpop` when
  present, exactly-once); `Content-Digest` = sha-256 over unencoded content
  bytes; any `Content-Encoding` on a signed MCP request is a fail-closed error.
- **Freshness/replay:** RFC 9421 `created`/`expires`/`nonce` required on every
  signature; DPoP `jti` never substitutes; replay key remains
  `(resolved_signer_identity, resolved_audience, signature_nonce)`; all
  existing cache tiers and `replay_cache_unavailable` fail-closed semantics
  carry over verbatim.
- **Response binding:** response signature covers `@status`,
  `content-digest`, `content-type` plus request components via RFC 9421
  `;req` (`@method`, `@target-uri`, `content-digest`, `content-type`); the
  compact handle `request_evidence` (split `{digest_alg, digest_value}` form)
  is SHA-256 over the request's signature base, body-carried.
- **Rejection evidence:** the HTTP profile is the **first implementation** of
  signed rejections and rejection signing is REQUIRED conformance behavior;
  `wire_code` lives only in `error.data.mcp_re_error` (frozen taxonomy reused,
  no parallel namespace); unsigned rejections under `require_mcp_re` fail
  closed with client-local `mcp-re.rejection_unsigned`.
- **Continuation (MRTR):** the `mcp-mrt` two-hash shape is kept; handles are
  SHA-256 over the profile-MANDATED verified signature bases; body-only
  carriage; no fallback to native JCS hashes inside the HTTP profile.
- **Downgrade:** cross-profile evidence presented under the wrong policy fails
  closed in BOTH directions; the expected-version policy generalizes to an
  `accepted_profiles` set with no default, failing closed at startup
  (ADR-MCPS-041 rule preserved).

## Rationale

The right response to the standards feedback is not to defend a custom
cryptographic layer but to compose existing standards and keep only what is
genuinely MCP-specific: which JSON-RPC body semantics are covered, how a signed
response binds to a signed request at the result/error level, signed rejection
semantics with stable wire codes, MRTR continuation binding, external
decision-artifact binding without interpretation, and the conformance corpus.
Everything else — signature syntax, digests, key/algorithm expression,
sender-constrained token binding — already has an RFC. The native profile
remains load-bearing: it is the only transport-agnostic carrier (stdio,
embedded), the migration bridge, and the proof harness; it is publicly labeled
"conformance-gated migration bridge and native transport profile", never
"experimental".

## Alternatives Considered

- **Keep the custom envelope as the SEP-facing proposal** — rejected: it asks
  the MCP community to adopt new cryptographic wire surface where RFC 9421/9530
  already standardize the same functions; the Discord feedback made the
  friction explicit.
- **DPoP alone (SEP-1932 direction)** — rejected as insufficient: DPoP binds
  OAuth token use to a proof key; it does not sign the MCP request/response
  content or bind responses to requests. In the HTTP profile DPoP composes as
  a covered header, never as a substitute.
- **EPOP / `rctx` as the carrier** — deferred: individual Internet-Draft, not
  WG-adopted; tracked non-normatively with named re-evaluation triggers
  (adoption as `draft-ietf-oauth-*`, or SEP-1932/successor referencing it
  normatively).
- **A third "canonical MCP body digest" for non-HTTP transports** — rejected:
  the native JCS-int53 preimage already is the canonical non-HTTP commitment;
  a parallel scheme adds downgrade/confusion surface with no consumer.
- **Do nothing** — rejected: leaves the SEP conversation anchored on custom
  crypto and stalls standards review of the genuinely MCP-specific gaps.

## Consequences

### Positive

- SEP-facing proposal becomes "an MCP profile of existing RFCs plus a small
  MCP-specific rule set" — reviewable by HTTP-Sig/DPoP/RAR experts on their
  own terms.
- Signed rejections finally get built (HTTP-first), closing the ADR-MCPS-046
  gap on the profile that will actually face enterprises first.
- The artifact-binding generalization (`artifact_bindings[]`) gives PDP
  decisions, DTR approvals, classifier results, and human approvals a typed,
  bind-not-interpret home alongside OAuth artifacts.

### Negative

- Two parallel carriers must be maintained until the parity gate passes and a
  later ADR retires native wire elements; every security property needs
  vectors in both corpora.
- Handwritten RFC 9421/9530 code (no vetted Rust crate adopted) is new
  high-cost surface; mitigated by the S15 golden-vector + independent
  cross-verification gate below.
- The HTTP profile is HTTP-only by construction; non-HTTP transports remain on
  the native profile indefinitely.

### Neutral

- `mcp-re-core` is untouched (stays transport-agnostic, method-transparent);
  all HTTP-profile code lands in a new `mcp-re-http-profile` crate.
- draft-01/draft-02 vector corpora remain byte-frozen.

## Compliance and Enforcement

- **Parity gate (blocking any native deprecation):** HTTP-profile corpus green
  on positive + negative vectors: valid request/response/rejection/continuation,
  body tamper, response splice, wrong `Content-Digest`, missing covered
  component, `Content-Encoding`-present rejection, stale/expired signature,
  replayed nonce, wrong keyid/signer/tag/label, artifact-binding forms,
  MRTR splice, cross-profile downgrade both directions, unknown profile id.
- **Corpus home:** `mcp-re-conformance/tests/vectors/http-profile/` with its
  own manifest, registered from `conformance_manifest.json`; frozen static
  oracle (signature-base bytes, `Content-Digest` values, Ed25519 signature
  bytes from pinned keys — Ed25519 is deterministic, so byte-comparison is
  honest; never generalized to ECDSA) plus a regenerated drift guard.
- **Independent verification (no-merge gate):** CI must validate the vector
  set through a pinned third-party RFC 9421 implementation and run
  RFC 9421/9530 worked examples as known-answer tests; no external validation,
  no merge.
- **Fail-closed policy:** `accepted_profiles` is a required explicit set; if
  unset the verifier/service fails closed at configuration/startup.

## Resolved Design Questions (v0.11 grill, signed off 2026-07-06)

Normative details ratified as slate E-1…E-12 in
`docs/grilling-seed/mcp-re-v0.11-grill-decisions.md`:

1. One profile-id tag both directions: `tag="mcp-re-http-v1"`; signature
   labels `mcp-re` (request) / `mcp-re-response` (response and rejection).
2. **No new MCP-RE HTTP header fields.** Header surface = standard fields
   only; all MCP evidence travels in body `_meta` blocks
   (`se.syncom/mcp-re.http.request`: audience tuple, `artifact_bindings`,
   `continuation`; `se.syncom/mcp-re.http.response`: `server_signer`,
   `request_evidence`), protected by the signed `content-digest`.
3. `request_evidence` uses the v0.6 split digest convention
   (`digest_alg`/`digest_value`), not prefix form.
4. `server_signer` (TrustResolver-resolved identity) stays distinct from
   RFC 9421 `keyid` (key selector); `keyid` never introduces trust.
5. `artifact_bindings[]` (required, non-empty) generalizes
   `authorization_binding` for the next wire version with the
   `artifact_type`/`binding_type` axis split and seven registry tokens;
   draft-02 keeps its frozen names. Typed profile-crate schemas plus
   `ath`/`x5t#S256` verification ship for DPoP and RAR in v0.11; the other
   five types bind via reference/opaque forms until a consumer appears.
6. ADR-MCPS-046 is re-scoped **native-profile-only**; the native rejection
   envelope is built only when a non-HTTP conforming consumer requires trusted
   rejection reasons (named trigger recorded there). Normative status map:
   400 malformed/canonicalization/profile, 401 authn/proof, 403
   audience/trust/authz/policy, 409 replay, 503 fail-closed infra; status is a
   signed routing hint, `wire_code` is authoritative; `error.message` stays
   human-readable.
7. MRTR keeps `previous_request_hash`/`input_required_response_hash` names;
   derivation is profile-scoped (native: JCS preimage; HTTP: mandated
   signature base), self-described by the signed profile id.
8. EPOP/`rctx` tracked non-normatively; native profile is the sole normative
   non-HTTP carrier.

## Appendix — draft-02 → HTTP standards profile mapping (Work Item 2)

| draft-02 native element | HTTP standards profile equivalent |
|---|---|
| `_meta["se.syncom/mcp-re.request"]` envelope | `Signature-Input`/`Signature` headers (label `mcp-re`) + body evidence block `se.syncom/mcp-re.http.request` |
| `version: "draft-02"` + `canonicalization_id: "mcp-re-jcs-int53-json-v1"` | profile id `mcp-re-http-v1` carried as the signed RFC 9421 `tag` parameter (no JSON canonicalization in the HTTP profile) |
| JCS/int53 signing preimage | RFC 9421 signature base over covered components; body bound via RFC 9530 `Content-Digest` (sha-256, unencoded bytes) |
| `signature.alg: "Ed25519"` | `alg="ed25519"` (RFC 9421 HTTP Signature Algorithms registry) |
| `signature.key_id` | RFC 9421 `keyid` parameter (selection hint; trust via TrustResolver) |
| `signer` / `audience` | resolved signer identity via TrustResolver; audience tuple in the body evidence block (richer than `@target-uri`) |
| `nonce`, `issued_at`, `expires_at` | RFC 9421 signature parameters `nonce`, `created`, `expires` |
| `authorization_binding` (`opaque-bytes` \| `authz-system-reference`) | `artifact_bindings[]` with registry `artifact_type`s; DPoP tokens via RFC 9449 `ath`, mTLS-bound tokens via RFC 8705 `x5t#S256`, RAR via exact-bytes or reference+digest |
| `request_hash` (`sha256:<b64url>` over JCS preimage) | `request_evidence` `{digest_alg:"sha256", digest_value}` over the request's RFC 9421 signature base |
| Response envelope (`server_signer`, `request_hash`) | response signature (label `mcp-re-response`) covering `@status`, `content-digest`, `content-type` + `;req` components; body block `se.syncom/mcp-re.http.response` |
| Unsigned JSON-RPC error (`-32003`, `data.mcp_re_error`) | signed HTTP rejection: same JSON-RPC error body + `Content-Digest` + response signature; wire codes reused verbatim |
| `continuation` (`mcp-mrt` two hashes over JCS preimages) | same object, hashes over the mandated RFC 9421 signature bases; body-only |
| Replay key `(signer, audience, nonce)` | unchanged (resolved identity, resolved audience, signature nonce) |
| `tests/vectors/draft-02/` corpus | `mcp-re-conformance/tests/vectors/http-profile/` corpus (existing corpora byte-frozen) |

## Related

- Grill record: `docs/grilling-seed/mcp-re-v0.11-grill-decisions.md`,
  `…-grill-transcript.md`, seed `mcp-re-v0.11-seed.md` (PR #293)
- Prior ADRs: ADR-MCPS-041 (strict dispatch / no-default policy),
  ADR-MCPS-046 (signed rejection receipts — re-scoped native-only by this ADR),
  ADR-MCPS-047 (MRTR continuation binding), ADR-MCPS-017/020 (replay tiers)
- Standards: RFC 9421, RFC 9530, RFC 9449, RFC 8705, RFC 9396, RFC 9700,
  draft-richer-oauth-httpsig, draft-ambekar-oauth-epop, MCP SEP-1932
- Code (planned): new crate `mcp-re-http-profile`; `mcp-re-core` untouched
