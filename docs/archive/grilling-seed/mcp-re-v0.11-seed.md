# MCP Runtime Evidence Standards-Alignment Spike

**Rewritten baseline after Discord feedback from Paul Carleton, Yaron Zehavi, and Max.**

## Executive verdict

MCP Runtime Evidence should be reframed before further SEP-facing work.

The public framing should **not** be:

> MCP needs a new custom cryptographic envelope.

The better framing is:

> MCP Runtime Evidence is an MCP runtime-evidence profile that composes existing standards where possible: RFC 9421 HTTP Message Signatures, RFC 9530 Digest Fields / `Content-Digest`, OAuth sender-constrained-token mechanisms such as DPoP and mTLS, RAR authorization details, and possibly future EPOP / `rctx` alignment.

The current implementation remains valuable. It proves the security shape: signed request, freshness, replay protection, audience binding, authorization-artifact binding, signed response bound to the request, signed rejection semantics, MRTR continuation binding, and conformance vectors.

But the current custom draft-02 wire shape should be treated as the **experimental/native MCP-RE profile and migration bridge**, not as the first SEP-facing cryptographic center of gravity.

For HTTP transports, the standards-facing target should be:

```text
MCP-RE-over-HTTP =
  RFC 9421 HTTP Message Signatures
  + RFC 9530 Content-Digest / Digest Fields
  + OAuth sender-constrained-token binding where applicable
  + small MCP-specific rules for JSON-RPC runtime evidence,
    response-to-request binding, signed rejection semantics,
    and MRTR continuation binding.
```

## Why this pivot matters

The Discord feedback correctly challenged whether MCP-RE is actually solving something already covered by existing standards:

- RFC 9421 already defines HTTP request/response signatures.
- RFC 9530 already defines message content digests.
- RFC 9449 DPoP already defines proof-of-possession for OAuth access-token use.
- RFC 8705 already defines mTLS certificate-bound access tokens.
- RFC 9396 RAR already expresses fine-grained authorization details.
- RFC 9700 already recommends sender-constrained tokens and replay-resistant OAuth profiles.
- `draft-richer-oauth-httpsig` explores OAuth proof-of-possession using HTTP Message Signatures.
- `draft-ambekar-oauth-epop` explores protocol-neutral proof-of-possession context, including MCP-like JSON-RPC examples.
- MCP SEP-1932 already discusses a DPoP profile for MCP.

The right response is not to defend a custom cryptographic layer. The right response is to ask:

> What, if anything, remains MCP-specific after existing standards are composed correctly?

The likely answer is narrow:

1. The exact MCP JSON-RPC runtime object/body semantics that must be covered.
2. Response-to-request binding at the MCP result/error level.
3. Signed rejection semantics and stable MCP wire codes.
4. MRTR / `InputRequiredResult` continuation binding.
5. Mapping external decision artifacts — RAR, PDP decision, DTR approval, classifier result, human approval receipt — into a request evidence chain.
6. MCP-specific conformance vectors.

## Important corrections to the earlier spike

### 1. Do not deprecate Ed25519 itself

The current code uses Ed25519. That should not be framed as a standards problem by itself.

RFC 9421 includes Ed25519 / EdDSA support. The thing to demote for the HTTP standards profile is the **custom MCP `_meta` envelope plus JCS/int53 JSON canonicalization profile**, not Ed25519 as a signing algorithm.

Better wording:

```text
Custom draft-02 `_meta` envelope and JCS/int53 canonicalization:
  experimental/native MCP-RE profile and migration bridge.

Ed25519:
  still acceptable as an algorithm where supported by the selected standards profile.
```

### 2. Be precise about `Content-Digest`

For the HTTP profile, `Content-Digest` should bind the HTTP message content bytes defined by the HTTP representation/content rules.

The profile must specify details such as:

- whether compression/content-encoding is allowed;
- whether clients sign/digest compressed or uncompressed content;
- whether the MCP body must be sent without transformation;
- how intermediaries are handled;
- whether the signature covers `content-digest`, `content-type`, and any relevant encoding headers.

Do not casually say “exact transmitted bytes” without specifying the HTTP content model.

### 3. Do not delete `request_hash` conceptually

The current `request_hash` is a SHA-256 hash of the custom MCP-RE signing preimage. That exact meaning should not be the standards-facing primary binding.

But a compact request evidence handle may still be useful for:

- MRTR continuation;
- audit correlation;
- signed rejection receipt linkage;
- conformance test references;
- retained evidence chains.

So the action is not “remove request_hash.” It is:

```text
Replace the custom preimage-hash meaning for the HTTP profile.
Retain or rename a request evidence handle if needed.
Derive it from standard evidence components such as request Content-Digest,
HTTP signature base digest, or a named MCP evidence-chain digest.
```

### 4. Do not narrow `authorization_binding` to OAuth only

RAR, DPoP, and mTLS are first-class standards-aligned cases. But Paul’s classifier example shows a broader need:

```text
external decision artifact binding:
  - RAR authorization details
  - DPoP / sender-constrained access token
  - mTLS certificate-bound token
  - PDP decision
  - DTR approval
  - classifier / DLP result
  - human approval receipt
```

MCP-RE should not interpret those artifacts. It should bind them to the exact request and make them verifiable according to policy.

The seam remains:

> bind, do not interpret.

### 5. Treat EPOP as promising but non-normative for now

EPOP’s `rctx` is conceptually attractive because it can express protocol-neutral request context and has MCP-style examples. But it is currently an Internet-Draft, not a stable RFC.

So the near-term stance should be:

```text
Use mature standards where possible:
  HTTP Message Signatures, Content-Digest, DPoP, mTLS, RAR.

Track EPOP / rctx for future protocol-neutral and non-HTTP alignment.
Do not make EPOP normative in the next SEP/IG post.
```

## Standards mapping table

| Current MCP-RE feature | Existing standards coverage | Remaining gap | Proposed action |
| --- | --- | --- | --- |
| Request signature envelope in MCP `_meta` | RFC 9421 signs selected HTTP request components. RFC 9530 provides content digests. `draft-richer-oauth-httpsig` shows OAuth proof-of-possession with HTTP Message Signatures. | Current draft-02 signs a canonicalized JSON-RPC object using an in-body envelope. That is not wire-compatible with HTTP Signatures. | **Add standards HTTP profile.** For HTTP transport, emit `Content-Digest`, `Signature-Input`, and `Signature`. Keep the current `_meta` envelope as the experimental/native MCP-RE profile and migration bridge. |
| `canonicalization_id = mcps-jcs-int53-json-v1` | RFC 9421 defines the HTTP signature base. RFC 9530 digests HTTP message content. Neither requires JSON canonicalization. | Current profile has a custom JSON subset and canonicalization rules. This is valuable for prototype conformance but creates SEP-facing friction. | **Deprecate as public HTTP crypto selector.** For HTTP, bind content via `Content-Digest` and covered HTTP components. Keep canonicalization only for the current native profile and legacy vectors. |
| Ed25519 signing | RFC 9421 supports EdDSA / Ed25519. | The issue is not Ed25519; the issue is the custom envelope and preimage. | **Keep where appropriate.** Do not present Ed25519 as legacy. Align algorithm naming and key identifiers with RFC 9421 for HTTP profile. |
| `request_hash` over custom signing preimage | RFC 9421 response signatures can cover request components using request context. RFC 9530 can bind request body content. | Current `request_hash` is over MCP-RE’s custom preimage, not the HTTP signature base or content digest. | **Narrow and rename.** Replace as primary response-binding primitive for HTTP. Retain a request evidence handle if needed for MRTR/audit, derived from standard evidence components. |
| `authorization_binding` | RFC 9449 DPoP binds token use to a proof key and token hash. RFC 8705 defines mTLS certificate-bound access tokens. RFC 9396 defines RAR authorization details. | Current binding is more generic than OAuth. It also covers opaque artifacts and authorization-system references. | **Wrap then standardize.** Define artifact binding profiles for RAR, DPoP, mTLS, token introspection, PDP decisions, DTR approvals, classifier attestations, and opaque artifacts. |
| Nonce / replay | RFC 9421 has signature parameters such as `nonce`, `created`, `expires`, and `tag`. DPoP uses `jti`, `iat`, and optionally server nonces. EPOP introduces context and proof claims. | Current nonce lives in the MCP-RE body envelope. Replay cache semantics are MCP-RE-specific. | **Keep behavior, move source.** Use standard signature/proof parameters where possible. Keep MCP policy rules for cache behavior, fail-closed posture, and fleet replay requirements. |
| Response signature | RFC 9421 supports response signatures and request-derived components using request context. `Content-Digest` can protect response content. | Current profile signs a JSON-RPC response envelope in `_meta`, including `request_hash`. | **Add standards HTTP response profile.** Sign response status/content digest and selected request components. Keep current response verifier as native profile until the standards profile is proven. |
| Signed rejection receipt | RFC 9421 + `Content-Digest` can sign HTTP error responses. | MCP-specific semantics remain: JSON-RPC error, stable wire code, outcome, diagnostic disclosure rules, and unsigned reasons being untrusted. | **Keep semantics, replace crypto framing for HTTP.** A signed rejection receipt becomes a signed HTTP response carrying a JSON-RPC error body with protected MCP wire code. |
| MRTR / `InputRequiredResult` continuation binding | No mature RFC directly defines MCP continuation binding. EPOP `rctx` is relevant but immature. | Need to bind continuation request to the exact prior input-required response and prior request. | **Keep MCP-specific.** Re-express identifiers in terms of standard evidence handles once the HTTP profile is defined. |
| Conformance corpus | RFCs include examples, but not MCP-specific adversarial vectors. | Current corpus is a major asset but targets the custom native profile. | **Keep and extend.** Preserve native profile vectors. Add standards-profile vectors for HTTP signature bases, content digests, response/request binding, signed rejection, MRTR, and artifact binding. |

## Code impact table

| Component | Decision | Design impact before refactor |
| --- | ---: | --- |
| Request signature envelope | **Add standards profile / wrap current** | Do not remove current `_meta` envelope yet. Implement an RFC 9421 + `Content-Digest` HTTP profile alongside it. |
| `canonicalization_id` | **Keep native; deprecate for HTTP profile** | For HTTP, move away from JSON canonicalization as the cryptographic center. Keep for native profile and regression vectors. |
| Ed25519 | **Keep available** | Align algorithm expression with RFC 9421 where used. Do not add P-256 just because another MCPS proposal used it. |
| `request_hash` | **Narrow / rebase** | Stop treating custom preimage hash as primary standards-facing primitive. Define a standards-derived request evidence handle if needed. |
| `authorization_binding` | **Generalize into artifact binding profiles** | Map OAuth/RAR/DPoP/mTLS cases explicitly. Keep opaque/external decision artifacts as generic bindings where no OAuth artifact exists. |
| Nonce / replay | **Keep semantics / move placement** | Use HTTP Signature / OAuth proof parameters where possible. Keep replay cache, fail-closed behavior, fleet cache requirements. |
| Response signature | **Add standards profile / keep native verifier** | Define RFC 9421 response signature profile. Keep draft-02 response envelope as native/migration path. |
| Signed rejection receipt | **Keep MCP semantics / standards crypto** | Use signed HTTP response + JSON-RPC error body in HTTP profile. Retain MCP `wire_code` semantics. |
| MRTR continuation binding | **Keep MCP-specific** | Preserve security property. Rebase continuation identifiers onto standards evidence handles later. |
| Conformance corpus | **Keep and extend** | Add new standards-profile vectors. Do not discard native profile vectors. |

## Recommended next architecture stance

### Public stance

Use this language:

> MCP Runtime Evidence is not a new custom cryptographic layer for MCP. It is a standards-aligned runtime-evidence profile for high-value MCP tool calls. For HTTP transport, it should compose HTTP Message Signatures, Content-Digest, and OAuth sender-constrained-token standards, with small MCP-specific rules for JSON-RPC runtime semantics, response-to-request binding, signed rejection receipts, and MRTR continuation binding.

### Internal stance

Current draft-02 remains useful, but its status changes:

```text
draft-02 native MCP-RE profile:
  hardened prototype
  conformance scaffold
  migration bridge
  reference for security properties

standards HTTP profile:
  SEP-facing target
  should reuse RFC 9421, RFC 9530, RFC 9449, RFC 8705, RFC 9396, RFC 9700
```

### Standards-profile wire sketch

Request over HTTP:

```text
Authorization: Bearer ...
DPoP: ...                         # if DPoP profile is used
Content-Digest: sha-256=:...:
Signature-Input: mcp-re=(...);created=...;nonce=...;keyid=...;tag="mcp-re"
Signature: mcp-re=:...:
Content-Type: application/json
```

Covered request components should likely include:

```text
@method
@target-uri or @path
content-digest
content-type
authorization or a safe authorization-derived component
dpop or DPoP token hash where appropriate
mcp-specific tag / evidence profile id
```

Response over HTTP:

```text
Content-Digest: sha-256=:...:
Signature-Input: mcp-re-resp=(...);created=...;keyid=...;tag="mcp-re-response"
Signature: mcp-re-resp=:...:
Content-Type: application/json
```

Covered response components should likely include:

```text
@status
content-digest
content-type
request content-digest via RFC 9421 request-component context
request @method / @path or @target-uri via request-component context
```

Signed rejection:

```text
HTTP status: 4xx/5xx as appropriate
JSON-RPC error body includes stable MCP wire_code
HTTP response has Content-Digest and RFC 9421 response Signature
```

MRTR continuation:

```text
Initial request:
  signed request + request evidence handle

InputRequiredResult:
  signed response bound to initial request evidence

Continuation request:
  signed request that includes inputResponses and echoed requestState
  plus continuation binding to prior input-required response evidence

Terminal response:
  signed response bound to continuation request evidence
```

## What remains MCP-specific

The standards profile should not try to standardize authorization logic, risk logic, classifiers, or tool semantics.

The MCP-specific layer should define only:

1. Which MCP JSON-RPC body fields are security-relevant for runtime evidence.
2. How a signed response binds to a signed request.
3. How JSON-RPC error / rejection semantics are represented.
4. How MRTR continuations bind to the exact prior `InputRequiredResult`.
5. How external artifacts are referenced and bound without interpretation.
6. What a conforming verifier must reject.
7. What conformance vectors must prove.

## What should happen before another SEP / IG post

Before posting again:

1. **Acknowledge the standards feedback explicitly.**
2. **Do not propose custom MCP crypto.**
3. **Say the work is being reframed as a standards-aligned MCP Runtime Evidence profile.**
4. **Ask one focused question:**

   > Is an MCP profile of HTTP Message Signatures + Content-Digest + OAuth sender-constrained-token standards sufficient for the runtime-evidence chain, or is there an MCP-specific gap around response binding and MRTR continuations?

5. **Do not lead with the existing custom envelope.**
6. **Mention the implementation only as evidence that the security properties have been prototyped and tested.**
7. **Invite mapping help from DPoP/RAR/HTTP-Sig people.**

Suggested Discord follow-up:

```text
Thanks all — this is changing how I should frame the work.

I do not want to propose new MCP cryptography if the right answer is to profile existing standards. My current conclusion is that MCP Runtime Evidence should first be evaluated as an MCP profile of HTTP Message Signatures + Content-Digest + OAuth sender-constrained-token mechanisms such as DPoP/mTLS/RAR, with EPOP/rctx tracked for future protocol-neutral proof context.

The part I still want to test is whether existing standards fully cover the MCP runtime evidence chain:

approved action / classifier result / authorization artifact
→ exact MCP JSON-RPC request body
→ dispatch decision
→ exact MCP response
→ MRTR continuation round trips if present

If HTTP-Sig + Content-Digest + RAR/DPoP already covers that, I should align with it and trim the custom envelope. If not, the useful MCP-specific work may be limited to response-to-request binding, signed rejection semantics, continuation binding, and conformance vectors.
```

## Proposed immediate work items

### Work item 1 — Standards-profile ADR

Create an ADR:

```text
ADR-MCPRE-0XX: Standards-Aligned HTTP Profile
```

Decision:

```text
For HTTP transports, MCP-RE will use RFC 9421 HTTP Message Signatures and RFC 9530 Content-Digest as the cryptographic carrier. The draft-02 native envelope remains supported as an experimental/migration profile until the standards profile reaches feature parity.
```

### Work item 2 — Mapping appendix

Create a mapping appendix:

```text
draft-02 field -> standards-profile equivalent
```

Examples:

```text
canonicalization_id -> profile id / no JSON canonicalization for HTTP
request_hash -> request evidence handle derived from Content-Digest/signature base
authorization_binding -> artifact binding profile
nonce -> HTTP Signature nonce / DPoP jti / profile replay id
server_signer -> HTTP Signature keyid / trust resolver entry
```

### Work item 3 — Minimal standards-profile proof

Implement a minimal HTTP standards-profile proof path beside the native profile:

```text
request:
  content-digest + RFC 9421 signature

response:
  content-digest + RFC 9421 signature covering request components

negative tests:
  body tamper
  response splice
  wrong content-digest
  missing covered component
  stale nonce
  wrong keyid
```

### Work item 4 — Conformance vectors

Add vectors for:

```text
HTTP signature base construction
Content-Digest calculation
request-to-response binding
signed rejection body
MRTR continuation binding
RAR/DPoP artifact binding
```

### Work item 5 — Standards issue list

Track open questions:

```text
1. Which request components must the MCP profile require?
2. Is request body digest enough, or do we need a canonical MCP body digest for non-HTTP transports?
3. How should response signatures bind to request components?
4. How should authorization artifacts be referenced without leaking secrets?
5. How should DPoP and HTTP Message Signatures compose when both are present?
6. Is EPOP/rctx the future answer for non-HTTP MCP transports?
7. What is the minimal MCP-specific conformance corpus?
```

## References

- RFC 9421 — HTTP Message Signatures: <https://www.rfc-editor.org/rfc/rfc9421.html>
- RFC 9530 — Digest Fields: <https://www.rfc-editor.org/rfc/rfc9530.html>
- RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP): <https://www.rfc-editor.org/rfc/rfc9449.html>
- RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens: <https://www.rfc-editor.org/rfc/rfc8705.html>
- RFC 9396 — OAuth 2.0 Rich Authorization Requests: <https://www.rfc-editor.org/rfc/rfc9396.html>
- RFC 9700 — Best Current Practice for OAuth 2.0 Security: <https://www.rfc-editor.org/rfc/rfc9700.html>
- draft-richer-oauth-httpsig-02 — OAuth Proof of Possession Tokens with HTTP Message Signatures: <https://www.ietf.org/archive/id/draft-richer-oauth-httpsig-02.html>
- draft-ambekar-oauth-epop — JSON Web Token Profile for OAuth 2.0 Enveloped Proof of Possession: <https://datatracker.ietf.org/doc/draft-ambekar-oauth-epop/>
- MCP SEP-1932 DPoP Profile discussion: <https://github.com/modelcontextprotocol/modelcontextprotocol/pull/1932>

## Final verdict

Continue MCP-RE, but change the center of gravity.

Do not lead with:

```text
custom Ed25519/JCS envelope in MCP _meta
```

Lead with:

```text
standards-aligned runtime evidence for MCP:
HTTP Message Signatures + Content-Digest + OAuth sender-constrained-token bindings,
with MCP-specific response, rejection, continuation, and conformance rules.
```

The current implementation should be preserved as the native profile and proof harness until the standards profile reaches parity. Only then should custom wire elements be deprecated or removed.
