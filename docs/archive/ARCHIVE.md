<!-- SPDX-License-Identifier: Apache-2.0 -->

# Archive — frozen historical record (do not treat as current)

**Everything under `docs/archive/` is historical.** It describes the MCP-RE
**Native JCS / object profile** (RFC 8785 / JCS canonicalization, Ed25519 over the
whole JSON-RPC object, `_meta` envelope). That profile is **DEPRECATED and deleted
from the code** — superseded by the RFC 9421 + RFC 9530 HTTP profile as the sole
carrier under **ADR-MCPRE-050**.

## Rules for agents and contributors

- **Do not** cite, extend, or reintroduce anything here as current design.
- **Do not** treat the audits below as covering today's code — they were run against
  the JCS-era implementation that no longer exists. A fresh audit against the 0.11 /
  RFC 9421 code is the record of current posture, not these.
- Current architecture lives in [`../CURRENT_ARCHITECTURE.md`](../CURRENT_ARCHITECTURE.md),
  the design boundary in
  [`../design/active-profile-and-legacy-quarantine.md`](../design/active-profile-and-legacy-quarantine.md),
  and the forbidden-vocabulary rules in [`../AGENT_INSTRUCTIONS.md`](../AGENT_INSTRUCTIONS.md).

## Why it is kept

Provenance. This material is a timestamped record that the JCS/object work was
designed, implemented, audited, and reviewed (MCPS lineage; patent-pending). The
complete JCS engine — canonicalizer, object verification pipeline, `jcs_*`
conformance vectors, proptest, and audits — is also recoverable from git at the tag
**`pre-adr-mcpre-050-jcs`** (the last commit with the full profile intact, before the
purge deleted it).

## Contents

| Path | What it is |
| --- | --- |
| `security/audit-v0.1.md`, `audit-v0.2.md`, `audit-v0.5.md` | Multi-agent code/security audits of the pre-0.11 native-profile releases. |
| `security/remediation-v0.2.md` | Finding-by-finding remediation status for the v0.2 native-profile tree. |
| `security/finding-ledger.jsonl` | Cross-round finding ledger for the native-profile audits (frozen). |
| `security/README.md`, `security/scans/*` | The audit-round index and the raw machine scan artifacts that produced the audits above. |
| `grilling-seed/*` | Grill transcripts, decisions, and seeds (v0.5 → v0.11) that fed the native-profile ADRs. |
| `spec/project-planning-brief.md` | The original MCP-RE planning brief — native/JCS profile. |
| `spec/upstream-proposal-brief.md` | The native-profile upstream proposal brief (never posted). |
