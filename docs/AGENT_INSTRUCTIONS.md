<!-- SPDX-License-Identifier: Apache-2.0 -->

# Agent Instructions: MCP-RE Current Worldview

**Read this before editing any ADR, spec, or design doc, or proposing any new
evidence / signing / profile design.** It exists because agents keep
rediscovering the legacy Native JCS / object profile and treating it as a live
option. It is not.

1. Read [`docs/CURRENT_ARCHITECTURE.md`](CURRENT_ARCHITECTURE.md) and
   [`docs/design/active-profile-and-legacy-quarantine.md`](design/active-profile-and-legacy-quarantine.md)
   first.
2. Treat **ADR-MCPRE-050** as the active evidence-profile authority: the one
   carrier is **RFC 9421 HTTP Message Signatures + RFC 9530 Content-Digest**.
3. Do **not** propose Native JCS, object-profile signing, `canonicalization_id`,
   `mcp-re-jcs-int53-json-v1`, or a "two-profile (object + HTTP)" split for new
   design. Native JCS is **deprecated** — not a security mechanism, not an
   alternative carrier, not a fallback. Do not present it as a live option.
4. Do **not** use ingress / header-mangling survival as a reason to revive JCS.
   Ingress compatibility is a deployment contract, not an evidence-profile
   concern.
5. Do **not** put stdio in the production profile. stdio compatibility is handled
   by the out-of-TCB adapter / proxy-to-proxy bridge (`mcp-re-stdio-bridge`),
   reached over HTTP like any other backend (ADR-MCPRE-051 §3).
6. **ADR-MCPRE-052** defines delegated signing as a standards-shaped JOSE/JWS
   credential carried in the RFC 9421 HTTP evidence — **not** a JCS-signed
   object. Do not regress it toward an object profile.
7. "Some MCP context does not fit in headers" is **not** a reason for JCS. Put
   structured context in the JSON **body**; bind it with Content-Digest + RFC
   9421 (ADR-MCPRE-052 §2 is the worked example).

If a task seems to require Native JCS for *new* work, stop — it does not. Re-read
the design note; if you still believe it does, raise it with the maintainer
rather than reintroducing the legacy profile.
