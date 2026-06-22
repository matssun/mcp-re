# MCP-S Ubiquitous Language

Canonical glossary for the MCP-S monorepo. One sentence per term. Distinct concepts get distinct names; overloaded words are flagged below.

## Language

- **MCP-S** — A transport-agnostic message-security profile for MCP providing authenticity, integrity, freshness, replay resistance, audience binding, authorization binding, response binding, and verified security context.
- **MCP-S Core** — The pure-crypto verification layer (`mcps-core`) that signs/verifies MCP messages and is deliberately *method-transparent* (does not parse MCP method semantics).
- **Release version** — Milestone label for a delivery (`0.3.1`, `0.4`, `0.5`); independent of the wire version.
  - `0.3.1` = current released baseline.
  - `0.4` = in-flight security hardening release.
  - `0.5` = proposal-readiness / NSA-alignment release (docs, conformance, claim hardening; no wire change).
- **Wire / envelope version** — The on-the-wire envelope schema version, currently `draft-01`; frozen unless a dedicated ADR justifies a field change.
- **Method-transparent** — MCP-S Core treats every MCP message as an opaque signed payload; no Core code path requires `tools/list` / `tools/call` or any method semantics for an enforcement decision.
- **MTCI** — MCP Tool Catalog Integrity Profile; a *separate* future MCP extension for signed tool descriptors, explicitly outside MCP-S Core (ADR-MCPS-030).

_Avoid_: "MCP-S version" without qualifying release vs. wire; using "0.5" to imply a wire/protocol change.

- **Canonical security boundary** — `docs/spec/security-boundary.md` is the single signed honesty gate. Under the 0.5 convention (ADR-MCPS-032) `docs/SECURITY_BOUNDARY.md` is reduced to a redirect stub, never a competing claim doc — that reduction is part of the 0.5 work (issue #149) and is not yet applied on `main`.
- **Docs root** — top-level `docs/` is the only documentation root; `components/mcps/docs/` and `documents/mcps/` are forbidden (workspace is isolated, ADR-MCPS-012).
- **Claim matrix lineage** — the 0.5 claim matrix `docs/spec/v0.5-claim-matrix.md` (created during the 0.5 work, ADR-MCPS-033 / issue #152) supersedes `docs/spec/v0.3-claim-matrix.md`, preserving the four-axis tiered structure (replay durability, trust propagation, key custody, ingress binding); never a flat list.

- **Method-transparency proof** — CI-enforced (not just documented) via two artifacts mapped to ADR-MCPS-030: a behavioral equivalence test (verdict independent of JSON-RPC `method`) and a static drift guard banning concrete MCP method-name literals (`tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list`, `prompts/get`, `sampling/createMessage`, `completion/complete`) in non-test `mcps-core/src`.
- **Method-aware logic** — Any future method-semantics enforcement lives outside `mcps-core` (MTCI / `mcps-policy` profile / `mcps-proxy` adapter / host layer), introduced with its own ADR; never inside Core.

_Avoid_: a second/third security-boundary doc; a flat claim list parallel to the tiered matrix; banning the bare `"method"` field (Core must still sign/canonicalize the full object).

- **Capability-claim matrix (§A)** — Reviewer-facing per-capability allowed/forbidden wording; every capability is either *unconditional* or *"deployment-dependent; see §B"* (no third category). Lives in `v0.5-claim-matrix.md` §A above the tiered §B.
- **Deployment-tier matrix (§B)** — The four-axis tiered composition (replay durability / trust propagation / key custody / ingress binding); composed claim is the AND of declared tiers, bounded by the weakest.

- **Audit rejection vocabulary** — Derived from the frozen `McpsError::wire_code()` taxonomy (`error.rs` is the sole authority); rejection events are `event_type: mcps.request.rejected|mcps.response.rejected` + `reason: <frozen wire_code>`. CI drift guard asserts every emitted reason ∈ `wire_code()`. Optional non-normative `reason_label` for display only.
- **Audit success vocabulary** — Only events the error enum cannot express: `mcps.request.accepted`, `mcps.response.signed`.
- **Single-node local replay profile** — One proxy instance with a durable local file-backed replay cache; replay-safe only within that instance; sanctioned public entry profile (ADR-MCPS-017). Distinct from the multi-node tier below.
- **Single shared store fail-closed tier** — A multi-node Axis-1 replay tier (`SINGLE_STORE_FAIL_CLOSED`) using one shared store, valid only if store loss makes the fleet fail closed until possibly-fresh requests expire. Not the single-node profile.
- **Strict multi-node production minimum** — `REDIS_WAIT_QUORUM` or stronger (`meets_strict_production_minimum`, ADR-MCPS-020); never invent a new threshold.

_Avoid_: calling both the local-file profile and the shared-store tier "single-node"/"single-store" casually.

- **Authorization binding (bind-not-interpret)** — Core binds `authorization_hash`; the configured AuthorizationProfile (ADR-MCPS-013) interprets it and decides allow/deny. Core never validates artifact contents, provides RBAC, or emits a "mismatch." 0.5 adds no new authorization mechanism — wording only.
- **on_behalf_of** — Core binds the signer's *signed assertion* of acting-for; it does not prove the delegation is legitimate (a profile/policy decision).
- **Coverage split** — audience binding = **Direct** (Core enforces `audience`); delegation (`on_behalf_of` + `authorization_hash`) = **Partial** (Core binds, does not interpret). Never the fuzzy "Partial/Direct" cell.
- **MTCI in the proposal** — Composability clarification only: conditional voice, no repo citation/link in the first proposal, not roadmap/subproject. One worked example as confusion-prevention (tool catalog is the adjacent domain most-confused with MCP-S scope). Load-bearing line: "MCP-S can protect messages that carry extension data, but does not define the semantics of those extensions."
- **Proposal-ready (0.5)** — Dual gate. Mechanical: every §A claim maps to a named green test in `security_traceability_manifest.json`; method-transparency pair green (→ADR-030); audit drift guard green; forbidden-claim guard green over proposal-facing docs; conformance + traceability manifests drift-guard green. HITL: owner signs boundary + claim-matrix updates (no self-approval). **Rule: no traceability-mapped green test, no proposal claim.** Deck/FAQ/NSA-appendix are non-gating.
- **Evidence spine** — One chain: §A claim → traceability manifest → named test → CI green → referenced by the NSA/threat-coverage matrix. The NSA matrix is derived from §A (references claims/non-goals), never an independent conformance mapping.
- **draft-01 freeze (0.5)** — 0.5 adds zero wire-envelope fields; request/response envelopes unchanged. No in-release field-add path. A claim unsupportable by draft-01 is cut from 0.5 and ejected to a separate `draft-02` ADR (new field + threat model + tests as post-0.5 work). Scope-freeze line: "MCP-S 0.5 is proposal-readiness over draft-01. No wire-envelope changes. Field gaps become draft-02 work."

_Avoid_: "small field addition" / "just one metadata field" / "NSA alignment field" inside 0.5.

## Flagged ambiguities

- **`documents/mcps/security-boundary.md`** (canonical doc §7) — stale path reference; rename to `docs/spec/security-boundary.md`. Fix in 0.5.
- **`v0.3-claim-matrix.md` contains v0.4+ content** — filename lies about contents (epic #68/#69/#70/#71 v0.4 results live there). Fix in 0.5 by folding into `v0.5-claim-matrix.md` §B and stubbing the v0.3 file.
