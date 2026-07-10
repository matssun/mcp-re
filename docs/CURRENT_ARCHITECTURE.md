<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-RE Current Architecture

**One screen. If you are about to design, propose, or implement anything, read
this first, then read
[`docs/design/active-profile-and-legacy-quarantine.md`](design/active-profile-and-legacy-quarantine.md).**

MCP-RE has **one active target profile**:

- **RFC 9421** HTTP Message Signatures
- **RFC 9530** Content-Digest
- standards-shaped OAuth / custody credentials where applicable
  (DPoP, mTLS, RAR; delegated signing via the JOSE/JWS credential of
  ADR-MCPRE-052)
- stateless **Streamable-HTTP** inner backends for production (ADR-MCPRE-051)

**Native JCS / object-profile signing is DEPRECATED.** It is not a security
mechanism, not an alternative carrier, and not a fallback. It MUST NOT be used
for new evidence, delegated signing, runtime profiles, SEP/IG proposals, or
production design. Any JCS code that remains is retained for reasons unrelated to
security evidence and is exercised only against frozen regression vectors and
forensic verification of already-issued evidence.

**stdio is OUT OF SCOPE for MCP-RE** (owner decision 2026-07-10). MCP-RE is
HTTP-profile only — HTTP in, HTTP out. A stdio-only client or server is bridged to
HTTP by an **external** plain-MCP adapter (e.g. FastMCP), entirely outside MCP-RE;
MCP-RE owns no stdio serving, inner transport, or bridge. See
[`docs/design/active-profile-and-legacy-quarantine.md` §D4](design/active-profile-and-legacy-quarantine.md).

**Ingress / gateway / header-mangling survival is not an MCP-RE evidence-profile
responsibility.** Deployments must verify before mutation, preserve the covered
context, or use an explicit trusted evidence boundary — never revive a custom
body-signed JCS profile.

## Authority

| ADR | Role |
|---|---|
| ADR-MCPRE-050 (Accepted) | Standards HTTP profile is the one carrier |
| ADR-MCPRE-051 (Accepted) | Per-core async data plane; stateless inner plane; authoritative replay; delegated custody; HTTP-profile only (stdio out of scope) |
| ADR-MCPRE-052 (Proposed) | Delegated signing = JOSE/JWS credential in the RFC 9421 evidence (not a JCS object) |
| [Active Profile Boundary and Legacy Quarantine](design/active-profile-and-legacy-quarantine.md) | Freezes this worldview; quarantines legacy JCS |

Legacy `ADR-MCPS-*` records (e.g. ADR-MCPS-004 Ed25519-over-JCS, ADR-MCPS-005
JCS canonicalization) are **historical**. They describe the pre-ADR-MCPRE-050
native profile and are not current production architecture.
