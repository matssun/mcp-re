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
5. **stdio is OUT OF SCOPE for MCP-RE** (owner decision 2026-07-10). MCP-RE is
   HTTP-profile only — do not add stdio serving, a stdio inner transport, stdio
   proxying, stdio CLI flags, or stdio tests. A stdio-only client/server is bridged
   to HTTP by an EXTERNAL plain-MCP adapter (e.g. FastMCP); MCP-RE talks HTTP to it.
   Do not reintroduce a stdio bridge or frame stdio as "legacy compatibility."
6. **ADR-MCPRE-052** defines delegated signing as a standards-shaped JOSE/JWS
   credential carried in the RFC 9421 HTTP evidence — **not** a JCS-signed
   object. Do not regress it toward an object profile.
7. "Some MCP context does not fit in headers" is **not** a reason for JCS. Put
   structured context in the JSON **body**; bind it with Content-Digest + RFC
   9421 (ADR-MCPRE-052 §2 is the worked example).
8. **Ignore [`docs/archive/`](archive/ARCHIVE.md).** Everything there is frozen
   pre-ADR-MCPRE-050 history — the Native JCS / object profile, its security audits,
   and old grill seeds. Do **not** cite it as current, treat its audits as covering
   today's code, or copy design from it. The full JCS-era snapshot is also
   recoverable from the git tag `pre-adr-mcpre-050-jcs`.

9. **Some capabilities are REFUSED, NOT REMOVED — do not "fix" either half.**
   Configuration validation refuses several things that are nonetheless still
   compiled: `--transport-binding attested-ingress` (Mode C) and `lb-assertion`
   (Mode B), `--authz reference`, `--revocation-list`, and `--client-ocsp require`.
   Two opposite mistakes to avoid. Do **not** delete
   the code behind a refusal as "dead" — Mode C is retained deliberately, and its
   verifier is exercised by tests so it stays correct while unreachable. Do **not**
   wire one up to make it work; each is gated on a decision, not on effort (Mode C
   needs a specification saying what an attestor may assert before attestation becomes
   authority by implication). If a refusal seems wrong, raise it — do not relocate,
   weaken, or route around it. A refusal belongs at the lowest boundary the state it
   constrains can enter through, which for configuration is `ValidatedDeployment`, never
   the composition root.

   `--replay-cache` **was** on this list and is now DELETED, by an explicit owner ruling
   (2026-08-15): every legal replay state is shared, so the selector chose between one
   live option and two refusals, and refusing was the only thing it still did. The
   durability tier is the sole selector now. That is what raising a refusal looks like
   when the answer turns out to be "the input should not exist" — it is not a precedent
   for deleting the others, each of which still gates a decision rather than a vocabulary.

10. **Run the local gate before anything else, and never fake a green.** One command:
   `scripts/local_gate.sh` (see [`docs/dev/local-gate-order.md`](dev/local-gate-order.md)).
   It is free and it is the precondition for every PR and every cloud run — no
   `gcloud builds submit`, no GKE cluster, no baseline declaration ahead of it. Two
   specific traps, both of which produce a lane that LOOKS green while measuring
   nothing: `tls_load_harness_bench` is **not** `#[ignore]`, so `-- --ignored` runs
   ZERO tests and exits 0 (use `-- --exact`); and a relative `MCP_RE_LOADGEN_OUT` is
   written under the package root where the gate will not find it. Use
   `scripts/local_slo_lane.sh`, which refuses both. If a command reports success,
   confirm it actually ran what you think it ran before reporting it as done.

If a task seems to require Native JCS for *new* work, stop — it does not. Re-read
the design note; if you still believe it does, raise it with the maintainer
rather than reintroducing the legacy profile.
