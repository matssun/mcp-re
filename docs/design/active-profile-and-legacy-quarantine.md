<!-- SPDX-License-Identifier: Apache-2.0 -->

# Design Note: MCP-RE Active Profile Boundary and Legacy Quarantine

## Status

**Proposed — control-plane document. Adopted 2026-07-09.**

This note is normative for *design intent*. It freezes the post-ADR-MCPRE-050
worldview so that humans and agents stop rediscovering the deprecated Native
JCS / object profile and treating it as a live design option. It lands
**before** further ADR-MCPRE-052 or standards-facing work.

**The Native JCS / object profile is DEPRECATED. It is not an alternative
security mechanism and it is not a supported evidence carrier.** Any code that
still exists under it remains for reasons unrelated to security evidence; it
confers no standing as a signing profile. There is one security carrier — the
RFC 9421 + RFC 9530 HTTP profile — and this note enforces that.

## Purpose

There is **one active MCP-RE target profile**:

> **RFC 9421 HTTP Message Signatures + RFC 9530 Content-Digest**, composed with
> standards-shaped OAuth / custody credentials where applicable.

Native JCS / object-profile signing is **DEPRECATED**. It MUST NOT be the
foundation for any evidence, delegated signing, runtime profile, SEP/IG
proposal, or production design — and it is not a fallback or alternative to the
HTTP profile.

This document exists because prior repository language still lets a reader infer
that the JCS object profile is a live design option or a second security
mechanism. **It is neither.**

## Authority chain

```
ADR-MCPRE-050  (Accepted)  Standards-aligned HTTP profile is the target carrier.
ADR-MCPRE-051  (Proposed)  Production serving architecture: per-core async HTTP
                           data plane + stateless Streamable-HTTP inner plane +
                           authoritative replay tier + delegated signing custody.
ADR-MCPRE-052  (Proposed)  Delegated signing = a JOSE/JWS credential carried in
                           the RFC 9421 HTTP evidence (NOT a JCS object).
This note   (Proposed)     Deprecates the Native JCS / object profile as a
                           security mechanism; makes the boundary explicit and
                           enforceable.
```

## The decision

**The Native JCS / object profile is deprecated.** It is superseded as the
security carrier by the RFC 9421 + RFC 9530 HTTP profile (ADR-MCPRE-050). It is
not an alternative mechanism, not a fallback, and not a second carrier. Whatever
JCS-related code remains in the tree is retained for reasons unrelated to
security evidence and MUST NOT be presented, extended, or relied on as a signing
profile. New evidence — including delegated signing (ADR-MCPRE-052) — uses the
HTTP profile only.

## Non-goals — ingress survival is not our job

MCP-RE is **not** responsible for preserving evidence through arbitrary ingress,
load balancers, or header-mangling infrastructure. The stance:

> Ingress / gateway / load-balancer compatibility is a **deployment contract**,
> not a reason to keep a custom body-signed JCS profile alive.

If ingress mutates covered HTTP evidence, the deployment chooses one of the
established modes, none of which is "revive JCS":

1. Verify before mutation.
2. Preserve the covered request context.
3. Treat the gateway as an explicit trusted evidence boundary.
4. Re-issue protected internal context after verification.

## Decisions

### D1 — One active target profile

MCP-RE has one active production evidence profile:

| Concern | Standard |
|---|---|
| HTTP request/response evidence | RFC 9421 HTTP Message Signatures |
| Body integrity | RFC 9530 Content-Digest |
| Authorization / sender constraint | DPoP, mTLS, RAR, or other standards-profile bindings where applicable |
| Delegated signing custody | standards-shaped delegated credential (JOSE/JWS, ADR-MCPRE-052) carried in the HTTP evidence |

There is **no live "two-profile" architecture.**

**Forbidden wording for new design work:**

- `object profile + HTTP profile`
- `native JCS profile + HTTP profile`
- `JCS carrier + HTTP carrier`

**Correct wording:**

- `active HTTP profile`
- `legacy JCS object profile`

### D2 — Native JCS is deprecated as a security mechanism

Native JCS / object-profile signing is **deprecated**. It is **not** a security
mechanism, **not** an alternative carrier, and **not** a fallback. Any remaining
JCS code is retained for reasons unrelated to security evidence; that retention
grants it no standing as a signing profile.

It MUST NOT be used, presented, or extended for:

- new ADRs,
- delegated signing credentials,
- ADR-MCPRE-052,
- runtime evidence,
- SEP / IG proposals,
- the production serving profile,
- ingress / gateway compatibility,
- any new signing/verification path.

Old conformance vectors and forensic verification of already-issued evidence are
the only contexts in which the JCS verifier is exercised at all, and only as
frozen regression history — never as a live carrier for anything new.

### D3 — Structured MCP context belongs in the body, not a second signature system

The reason once given for object/JCS evidence — *"some MCP context does not fit
cleanly in headers"* — is obsolete.

- MCP-specific data lives in the **JSON body**.
- **Content-Digest** binds the body bytes.
- **RFC 9421** signs Content-Digest and the relevant HTTP components.

So the answer to "this does not fit in headers" is **not** "use JCS." It is:
put the structured context in the body and bind it with Content-Digest + HTTP
Message Signatures. (ADR-MCPRE-052 §2 is the worked example: the delegation
credential rides inline in the body `_meta` block, protected by the covered
`content-digest`.)

### D4 — stdio is OUT OF SCOPE for MCP-RE

**Owner decision (2026-07-10): MCP-RE will not own stdio transport support.** The
production contract is **HTTP in, HTTP out** — the RFC 9421 + Content-Digest HTTP
profile is the only carrier and the only transport MCP-RE implements. MCP-RE-owned
stdio serving, stdio inner transport, stdio proxying, and stdio test topology have
been REMOVED (there is no `mcp-re-stdio-bridge`, no stdio serving path, no stdio
CLI flags, no stdio conformance/demo topology). This is not "legacy compatibility"
framing — stdio is simply **out of scope**.

```
MCP-RE (the only shape):
  RFC 9421 + Content-Digest HTTP profile in
  Streamable-HTTP inner backend out
```

If a client or server is stdio-only, an **EXTERNAL plain-MCP adapter** does the
stdio↔HTTP bridging, entirely outside MCP-RE — for example
[FastMCP remote](https://github.com/jlowin/fastmcp) (bridges a remote
Streamable-HTTP/SSE MCP server into a stdio host) or FastMCP's proxy provider
(HTTP↔stdio). MCP-RE talks HTTP to that adapter:

```
stdio-only MCP client
  → EXTERNAL plain-MCP stdio→HTTP adapter (e.g. FastMCP)   ← NOT part of MCP-RE
  → RFC 9421 + Content-Digest  (MCP-RE HTTP profile)
  → MCP-RE proxy
  → Streamable HTTP
  → HTTP MCP backend  (a stdio-only backend is likewise fronted by an external adapter)
```

Any remaining stdio reference in the tree is **pending deletion**, never a
supported compatibility mode.

### D5 — Ingress mutation is not a reason to keep JCS

The old argument — *"body-carried evidence may survive header-mangling
infrastructure"* — is **rejected**. MCP-RE's production responsibility is to
define the evidence profile and the verification boundary, not to work around
arbitrary gateway mutation with custom body crypto. Gateway compatibility
belongs in a separate deployment contract (see Non-goals).

### D6 — ADR-MCPRE-052 must not use Native JCS

ADR-MCPRE-052 defines delegated signing-key attestation using a standards-shaped
credential carried by the HTTP evidence profile.

**Forbidden foundations:** JCS-signed delegation object; native object-profile
attestation; a custom `mcp-re.delegation/v1` JCS carrier; a two-carrier
object/JCS + HTTP split.

**Adopted direction (already in ADR-MCPRE-052):** a compact JOSE/JWS (JWT)
delegation credential, root-signed, `cnf`-bound to the delegated Ed25519 key,
carried inline in the RFC 9421 response evidence, verified against the root trust
anchor.

*Status: ADR-MCPRE-052 already conforms to D6 — it is the JOSE/JWS rewrite. D6
records the constraint so no future revision regresses.*

## Required repository changes

Tracked as the action list for this note. ✅ = done in this change; ⏸ =
deliberately deferred (see note).

1. **Add this design note** under `docs/design/`. ✅
2. **Add `docs/CURRENT_ARCHITECTURE.md`** — the short, top-level pointer to this
   note (one screen: active profile, legacy quarantine, stdio, ingress). ✅
3. **Patch ADR-MCPRE-051 wording** — §2 no longer describes JCS as *active* core
   verification (the active path is the HTTP profile); §4 replay language names
   the **HTTP-profile** replay key for production, legacy object-profile keys
   confined to legacy code. ✅
4. **Patch the ADR index / README** — explicit *Active vs Legacy* section; the
   deprecated JCS ADRs are not read as current production architecture. ✅
5. **Add `docs/AGENT_INSTRUCTIONS.md`** — the worldview an agent must load before
   editing ADRs, specs, or design docs. ✅
6. **Mark deprecated JCS / object-profile docs** — a deprecation note on
   ADR-MCPS-004, ADR-MCPS-005, and the core spec (`docs/spec/mcp-re-core-spec.md`);
   the ADRs stay immutable "Accepted" historical records (per the ADR
   supersession convention) with the note added, not a destructive relocation. ✅
7. **Name deprecated code surfaces at module boundaries** — deprecation comments
   on `mcp-re-core/src/canonical.rs` and the `canonicalization_id` constant in
   `mcp-re-core/src/ids.rs`. Renames were rejected: the JCS identifiers still
   thread through `mcp-re-client-core`, `mcp-re-proxy`, `mcp-re-conformance`, both
   SDKs, and frozen vectors/manifests, so a rename would ripple destructively and
   trip the drift guards. Comments make the map clear without that blast radius. ✅
8. **CI vocabulary firewall** — `scripts/jcs_vocabulary_gate.py`, wired as a fast
   step in the `cargo` CI job (`.github/workflows/ci.yml`). ✅
9. **Runtime / feature-flag boundary** — ⏸ **deferred.** Making legacy JCS a
   default-off, opt-in, `--strict`-rejected runtime flag is a *behaviour-changing
   migration*: the native/object path is still the default-on carrier on the live
   serving/verify path (proxy draft-02 serving, `mcp-re-client-core` signing, the
   object conformance suite). Flipping its default belongs to the isolate-then-
   remove migration, gated on its own tests, not to this design-control note. This
   note *authorizes* that migration; it does not perform it. Follow the existing
   `--transport-identity-source cn_legacy` precedent (deprecated value,
   strict-rejected) when it is done. **Scoped 2026-07-11 in
   [`http-evidence-carrier-cutover.md`](http-evidence-carrier-cutover.md)** — the
   sequenced plan that performs this migration and gates ADR-050/051/052 status on
   it.

### CI vocabulary firewall — scope and policy

`scripts/jcs_vocabulary_gate.py` enforces **D1's forbidden framings** — the exact
"two-profile" wordings (`object profile + HTTP profile`,
`native JCS profile + HTTP profile`, `jcs carrier + HTTP carrier`, and mirror
forms). It is a *vocabulary* gate on the forward-design surface, not a semantic
JCS detector; semantic intent is carried by the deprecation banners and
`docs/AGENT_INSTRUCTIONS.md`.

- **Scanned surface:** `docs/adr/adr-mcpre-*.md`, `docs/design/*.md`.
- **Allowlisted** (must name the framings to forbid them): this note.
- **Carve-outs:** a same-line repudiation marker (deprecated / legacy / forbidden
  / not / never / rejected / off-target / superseded) or a fenced code block.
- **Policy:** any live (non-repudiated) framing fails CI with:

```
Native JCS/object-profile is DEPRECATED — not a security mechanism, not an
alternative carrier. Use RFC 9421 + RFC 9530 HTTP profile language for active design.
```

The broader lexical ban originally sketched (every bare `object profile` /
`canonicalization_id` token) was rejected: those tokens appear legitimately —
to *declare the deprecation* — throughout ADR-MCPRE-050/052, so a bare-token ban
would either red-CI the very docs that establish the boundary or force a
fragile per-line negation heuristic. The framing gate is precise and stable.

## LEGACY banner (for quarantined docs)

Every quarantined file starts with:

```
> LEGACY / DEPRECATED
>
> This document describes the pre-ADR-MCPRE-050 Native JCS object profile.
> It is retained only for migration, old vectors, forensic verification, or
> development compatibility.
>
> It is NOT the MCP-RE target profile and MUST NOT be used for new evidence,
> delegated credentials, runtime profiles, SEP/IG proposals, or production
> architecture.
>
> The active profile is ADR-MCPRE-050: RFC 9421 HTTP Message Signatures +
> RFC 9530 Content-Digest. See docs/design/active-profile-and-legacy-quarantine.md.
```

## Acceptance criteria

This note is complete when:

1. `docs/design/active-profile-and-legacy-quarantine.md` exists. ✅
2. `docs/CURRENT_ARCHITECTURE.md` exists and points here. ✅
3. Native JCS / object-profile docs are clearly marked deprecated. ✅
4. ADR-MCPRE-051 no longer describes JCS as active core verification. ✅
5. ADR-MCPRE-051 replay language names only the HTTP-profile replay key for
   production; legacy object-profile keys are confined to legacy compatibility. ✅
6. ADR-MCPRE-052 contains no Native JCS / object-profile foundation. ✅
7. CI rejects the forbidden two-profile framing in forward-design docs. ✅
8. stdio is documented as adapter / proxy-to-proxy compatibility only. ✅ (D4)
9. Runtime warnings / flags make legacy modes explicit. ⏸ deferred to the
   isolate-then-remove migration (see change #9 above) — now scoped in
   [`http-evidence-carrier-cutover.md`](http-evidence-carrier-cutover.md).

## Related

- ADR-MCPRE-050 — Standards-Aligned HTTP Profile (RFC 9421 + RFC 9530; the one
  carrier). Controlling authority for D1–D6.
- ADR-MCPRE-051 — High-Throughput Serving Architecture (per-core async data
  plane; stdio relocated out of the TCB — D4).
- ADR-MCPRE-052 — Delegated Signing-Key Attestation (JOSE/JWS credential; D6).
- `docs/CURRENT_ARCHITECTURE.md`, `docs/AGENT_INSTRUCTIONS.md`.
