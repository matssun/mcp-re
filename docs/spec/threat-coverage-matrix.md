<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-S Threat-Coverage Matrix

Purpose: map each external (NSA-identified) MCP-security concern to an MCP-S coverage
level and the §A capability that backs it — **derived from [`v0.5-claim-matrix.md`](./v0.5-claim-matrix.md) §A**.

This matrix carries **no independent conformance/test mapping**. It is one node on the
single evidence spine ([ADR-MCPS-036](../adr/adr-mcps-036.md)): every row references a
§A capability claim (Direct / Partial) or a stated non-goal plus the guard that defends
it (Out of scope). It does not restate claim wording — read the strength off the named
§A row so that a change to §A propagates here without a second edit ([ADR-MCPS-033](../adr/adr-mcps-033.md) §5).

## How to read this file

- **Coverage** is one of **Direct** (Core enforces the relevant property uniformly),
  **Partial** (Core binds but does not interpret — the decision is a profile/policy
  concern), or **Out of scope** (an explicit non-goal, defended by a named guard).
- **§A reference** names the capability row in `v0.5-claim-matrix.md` §A whose strength
  governs the concern, **or** the non-goal + guard for an out-of-scope concern. Where the
  §A capability is *deployment-dependent; see §B*, the deployment strength is read off the
  named §B axis — this matrix never asserts a standalone strength.

## Threat-coverage matrix

| External concern | Coverage | §A reference (or non-goal + guard) |
| --- | --- | --- |
| Message tampering in transit | **Direct** | §A *Message authenticity* and §A *Integrity* (unconditional) |
| Spoofed / unauthenticated server identity | **Direct** | §A *Signer identity* (unconditional); key-custody blast radius read off §B Axis 3 |
| Audience confusion / token-/request-redirection to the wrong recipient | **Direct** | §A *Audience binding* (coverage **Direct** — Core enforces `audience`) |
| Stale-message / freshness-window abuse | **Direct** | §A *Freshness* (unconditional, single-request check) |
| Replay of captured messages | **Direct** (single-node) / deployment-dependent across nodes | §A *Replay resistance* (*deployment-dependent; see §B Axis 1*) |
| Response forgery / response-to-request mismatch | **Direct** | §A *Response binding* (unconditional) |
| Forged or caller-injected verified security context | **Direct** | §A *Verified security context* (unconditional — the proxy is sole writer of `.verified`) |
| Stale-trust / delayed credential revocation | deployment-dependent | §A *Revocation / trust propagation* (*deployment-dependent; see §B Axis 2*) |
| Ingress / transport-identity spoofing at the edge | deployment-dependent | §A *Ingress binding* (*deployment-dependent; see §B Axis 4*) |
| Signing-key compromise blast radius | deployment-dependent | §A *Key custody / blast radius* (*deployment-dependent; see §B Axis 3*) |
| Confused-deputy / delegated-authority abuse (`on_behalf_of`, `authorization_hash`) | **Partial** | §A *Delegation / authorization binding* (coverage **Partial** — Core **binds**, the AuthorizationProfile interprets; [ADR-MCPS-013](../adr/adr-mcps-013.md)) |
| Tool poisoning / malicious or drifted tool descriptors (rug pull) | **Out of scope** | Non-goal: MCP-S Core is method-transparent and does not interpret method semantics ([ADR-MCPS-030](../adr/adr-mcps-030.md)). Guard: method-transparency pair (verdict independent of JSON-RPC method) + the static drift guard banning concrete MCP method-name literals in `mcps-core/src` |
| Unsafe / malicious tool *output* handling | **Out of scope** | Non-goal: §A *Tool safety* = **none, by design** ([ADR-MCPS-030](../adr/adr-mcps-030.md)). Guard: same method-transparency pair — Core makes no claim about an invoked tool's output |
| Tool sandboxing / execution-environment isolation | **Out of scope** | Non-goal: tool-invocation policy and method-semantics enforcement live **outside** Core (MTCI / policy / host layer, each with its own ADR — [ADR-MCPS-030](../adr/adr-mcps-030.md)). Guard: the method-transparency drift guard keeps method-aware logic out of `mcps-core/src` |

## Scope note

The three **Out of scope** rows are the adjacent tool-catalog / tool-execution domain that
is most often confused with MCP-S scope. Per [ADR-MCPS-030](../adr/adr-mcps-030.md): MCP-S
can protect messages that *carry* extension data (including tool-catalog data), but does not
define the semantics of those extensions. Those concerns belong to a separate MCP extension
or profile (MTCI / `mcps-policy` / the host layer) and compose with MCP-S without being part
of Core.
