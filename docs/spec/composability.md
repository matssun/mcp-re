<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-RE Composability

Purpose: clarify how MCP-RE composes with adjacent MCP extensions without defining their semantics.

**MCP-RE can protect messages that carry extension data, but does not define the semantics of those extensions.**

MCP-RE is a transport-agnostic message-security profile. It signs and verifies MCP
messages and the verified security context they carry; it is deliberately
*method-transparent* and treats every MCP message body as an opaque signed payload
([ADR-MCPS-030](../adr/adr-mcps-030.md)). Adjacent layers own their own semantics.
MCP-RE protects the messages that carry those semantics without interpreting them,
so an extension can ride on a message MCP-RE authenticates without MCP-RE becoming
aware of, or responsible for, what that extension means.

## Adjacent-layer table

The table reads across the seven layers a deployment may compose. For each layer it
names what the layer *owns*, what *MCP-RE provides* for messages at that layer, and
what *MCP-RE does NOT provide* (and therefore leaves to the layer's own specialist).

| Layer | Layer owns | MCP-RE provides | MCP-RE does NOT provide |
|---|---|---|---|
| Transport | The wire connection and, where used, the mTLS peer certificate and channel. | Optional transport termination and transport binding — binding the verified transport peer to the object signer. | The transport itself as a security claim; a valid transport peer is not by itself a valid signer. |
| Admission / identity | Whether a server was admitted as a tool provider, and at what sensitivity. | The admitted-identity anchor as the trust root for verifying response signatures. | The admission decision, the admission registry, or the sensitivity classification. |
| Caller governance | Who may invoke a call, for what purpose, under what approval context. | Binding of the signer's authorization artifact (`authorization_hash`) and the signer's signed assertion of acting-for (`on_behalf_of`). | Interpretation of the grant, RBAC, role hierarchies, or any allow/deny ruling — the configured AuthorizationProfile decides ([ADR-MCPS-013](../adr/adr-mcps-013.md)). |
| Runtime security evidence | The per-call cryptographic facts about a single message. | Authenticity, integrity, freshness, replay resistance, audience binding, authorization binding, response binding, and verified security context. | Method semantics; MCP-RE never parses an MCP method body to reach an enforcement decision. |
| Tool-catalog integrity | Whether a tool descriptor changed, whether a catalog was operator-approved, rug-pull / drift detection. | Authenticity and integrity for the *messages* that carry tool descriptors or catalog data. | Descriptor hashing, catalog pinning, signed tool manifests, or any tool-catalog governance semantics. |
| Interception / enforcement | The seam at which evidence and authorization are evaluated before a call reaches the inner server. | A verify-before-dispatch sidecar (`mcp-re-proxy`) that fails closed when verification or an enabled authorization profile denies. | The policy a deployment chooses to enforce, or any enforcement of semantics MCP-RE does not itself verify. |
| Audit / receipts | The portable, verifiable record of what happened and why. | Per-call evidence primitives and a frozen audit rejection/success vocabulary derived from the error taxonomy. | A portable receipt format, or packaging the evidence into a downstream-verifiable receipt. |

## Worked example — tool-catalog integrity (confusion-prevention)

Tool-catalog integrity is the adjacent domain most often confused with MCP-RE scope,
so it is worked here as a single confusion-prevention example. The voice is
deliberately conditional: it describes how a separate extension *would* compose,
not a roadmap, subproject, or MCP-RE deliverable.

If a deployment also wanted signed tool descriptors — so that a changed or
rug-pulled tool surface could be detected — that would be a *separate* MCP
extension, the MCP Tool Catalog Integrity Profile (MTCI). MTCI would own the tool
descriptor semantics: which tools a server may advertise, whether a descriptor
changed, and whether a catalog was operator-approved. MCP-RE would still sign and
verify the messages that carried those descriptors, binding them to the admitted
identity and proving they were authentic and unmodified in transit — but MCP-RE
would not recompute descriptor hashes, pin a catalog, or rule on whether a
descriptor change is acceptable. The two would compose: MCP-RE protects the
carrier, MTCI interprets the cargo. This is exactly the load-bearing line above —
MCP-RE can protect messages that carry extension data, but does not define the
semantics of those extensions.
