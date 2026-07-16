<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-RE v0.13 Grill Input — Authorization-Evidence Interoperability and Production Completion

> **Status: GRILL INPUT — nothing here is decided.** This document seeds a
> pp-grill-me session. Its output feeds a new PRD (GitHub Discussion) and, from
> there, downstream ADRs and issues. Candidate ADR titles below are **inputs to
> the grill, not decisions** — deliberately not written as ADRs yet. Strategy
> questions that are not for public view are routed to a separate private note
> under `work/` (git-ignored) and only referenced here by topic.

## Why now

Three things converged in July 2026:

1. **PRD #148 is finished in substance but still open in form.** It is the only
   open PRD Discussion. Its epic (#158, "MCP-S 0.5 Proposal Readiness and NSA
   Security Alignment") closed 2026-06-23, and all six of its ADRs
   (ADR-MCPS-031…036, Discussions #379–#384) are labeled `status:implemented`.
   Its concrete content is bound to a world that no longer exists: the project
   was MCP-S at v0.5 over a frozen `draft-01` object envelope; today it is
   MCP-RE at v0.12.1, HTTP-profile only (RFC 9421 + RFC 9530, ADR-MCPRE-050),
   with delegated JOSE/JWS signing (ADR-MCPRE-052) and a live-proven GKE fleet
   (ADR-MCPRE-051). Editing #148 into the present would destroy its value as a
   historical decision record.

2. **MCP Enterprise-Managed Authorization (EMA) went stable 2026-06-18**
   (`io.modelcontextprotocol/enterprise-managed-authorization`, from SEP-990),
   with Okta as first IdP and Anthropic / VS Code / several MCP servers
   shipping support. This is the first stable enterprise authorization layer
   MCP-RE can *compose with* — the composition MCP-RE was architected for
   (bind-not-interpret) but has never formalized against a real, stable target.

3. **The production story has a small, honest residual.** v0.12.1 shipped the
   live KMS-via-Workload-Identity GKE proof, but Proof 4 (zero-drop rolling
   update) dropped 2 of 590 in-flight requests on GKE, and the production
   root-authority (trust-anchor) controller is still design-only.

The durable inheritance from #148 — precise scope, method transparency,
claims-map-to-tests ("no test, no claim"), external threat coverage, dual
mechanical+HITL readiness gate — is correct and stays. What v0.13 must do is
re-aim that discipline at the architecture that now exists, and add the one
genuinely new capability: EMA composition.

## Verified current state (evidence inventory)

Facts checked 2026-07-15, with sources:

- **Release:** v0.12.1 (2026-07-14), `CHANGELOG.md`. Serving path is
  RFC 9421 `HttpProfileProxy`, delegated-required response signing is the ONLY
  response-signing mode (direct-root deleted from the runtime surface,
  2026-07-13). stdio is fully removed; external adapters (FastMCP) front
  stdio-only servers.
- **ADR authority (Discussions):** ADR-050 `status:implemented` (#398);
  ADR-051 `status:implemented` (#399 — body: "Accepted — ratified 2026-07-09
  … Fully realized in v0.11"); ADR-052 `status:implemented` (#400).
  *Correction to the pre-grill investigation, which assumed ADR-051 was still
  "Accepted, not yet Implemented".*
- **Rolling-update residual:** `CHANGELOG.md` v0.12.1 Known issues — GKE
  rollout dropped 2/590 in-flight requests (kube-proxy endpoint-propagation
  timing; in-process and kind lanes pass; likely fix: longer
  `drainPreStopSeconds`). This coexists with the v0.11 claim of a "zero-drop
  rolling update over a real L4 LoadBalancer" in `docs/PROJECT_STATUS.md` — a
  live claim-vs-evidence tension the "no test, no claim" discipline must
  resolve.
- **Root authority:** more is BUILT than the investigation assumed
  (`docs/spec/root-authority-rotation.md`): `TrustedIssuerSet`
  (current/retiring-`valid_until`/revoked/unknown, fail-closed) and the signed,
  versioned `TrustAnchorManifest` (org/admin-key signed, expiry fail-closed,
  rollback-protected) are implemented and tested; the fenced
  `TestRootAuthorityProvider` + `gcp-kms-root-rotation.sh` live lane has run
  GREEN against real Cloud KMS with disposable roots. What is DESIGN-only: the
  **production governed controller** (`mcp-re-admin rotate-root`), break-glass
  revocation governance, manifest distribution beyond static file/config, and
  the GKE fleet-scale rerun.
- **EMA predecessor doc:** `docs/spec/ema-composition.md` exists but is stale —
  it predates the HTTP profile (stdio diagrams, "v0.5.1", "EMA exists as a
  proposal"). Its durable content: Mode 1 (bind, for EMA-native backends) vs
  Mode 2 (enforce, sole-PEP private backends) and the "EMA twice" rule
  (exactly one enforcement point per call).
- **Evidence-spine staleness (Workstream 1 confirmation):**
  `docs/PROJECT_STATUS.md` still says "Current release: v0.10.1";
  `docs/spec/v0.5-claim-matrix.md` is scoped to the frozen `draft-01` envelope;
  `docs/spec/security-boundary.md`'s signed-off sections describe the
  deprecated native/object profile; `docs/spec/threat-coverage-matrix.md`
  derives from the v0.5 §A; `CONTEXT.md` glossary is flagged stale.
- **Community vehicle already exists:** open Security Discussions #172
  (layered architecture composition contracts), #175 (Runtime Evidence Profile
  proposal — already reframed as "compose existing standards"), #232 (MRT
  continuation evidence).
- **Uncommitted work in flight:** stateless cross-replica MRT continuation
  (ADR-MCPS-047 extension, four proofs green on kind) and the ADR/PRD
  Discussions-migration repo changes are pending review/commit.

## EMA in one paragraph (the composition target)

EMA flow (stable spec): the MCP client authenticates the user via enterprise
SSO and holds an identity assertion (ID token / SAML); it exchanges that at the
IdP for an **ID-JAG** (Identity Assertion JWT Authorization Grant — RFC 8693
token exchange; the IdP evaluates org policy here); it presents the ID-JAG to
the **MCP Authorization Server**, which validates it (signature via IdP JWKS,
audience/issuer/expiry) and issues an **audience-restricted access token** for
the MCP resource server; the client then calls the MCP server with that access
token. The ID-JAG is a client↔IdP↔AS artifact; the artifact present on the
runtime request is the **access token**. Therefore MCP-RE binds the access
token (plus its sender constraint), not the ID-JAG.

The boundary that must survive the grill intact: **EMA decides and provisions
authorization; MCP-RE binds the resulting authorization evidence to the exact
signed runtime request.** MCP-RE does not become an IdP, an authorization
server, or a policy engine, and makes no EMA-implementation claim.

## Adjacent draft to track — SEP-3004 (Tamper-Evident Audit Record Contract)

[SEP-3004](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3004)
(Draft, Standards Track, no sponsor yet; developed in #security-ig) defines an
**off-wire, at-rest** audit primitive: a sorted-JSON canonical byte form over a
minimal protected core (`event_id`, `occurred_at`, `principal_id`,
`event_type`, `tool_name`, `outcome` ∈ allowed/denied/deferred/error), a
type-keyed registered-`extensions` object, an append-only SHA-256 hash chain,
a deterministic verification procedure, and a structured attestation manifest.
Registered extensions so far: `caller-governance` (full), `runtime-security`
(Interlock, drift/quarantine — carries an opaque `evidence_hash`
`<alg>:<hex>` commitment to out-of-band evidence), `admission-control` (named,
cross-ref ATSA #2809).

**The layering is naturally complementary, and v0.13 must keep it that way:**

- SEP-3004 answers "was the *record* of a governance decision altered after
  the fact?" (at-rest tamper evidence). MCP-RE answers "was *this exact wire
  call* genuinely the authorized, fresh, non-replayed one, and is its
  response/rejection bound to it?" (wire-time cryptographic evidence).
  Different layer, different threat, same composition pattern MCP-RE already
  uses everywhere: bind, don't absorb.
- The natural seam is SEP-3004's `evidence_hash` opaque-commitment pattern:
  an audit record can commit to MCP-RE runtime evidence (the RFC 9421
  signature/content-digest, a signed rejection, a delegation-credential kid)
  as out-of-band evidence — MCP-RE evidence becomes what a record *points
  at*, never what MCP-RE re-implements as a log.
- Non-overlap rules for v0.13: MCP-RE MUST NOT define its own tamper-evident
  audit-log/hash-chain construction (if the ADR-MCPS-035 audit vocabulary
  ever grows an at-rest story, it anchors to SEP-3004 by reference); and
  SEP-3004's sorted-JSON canonicalization is an off-wire record form — it
  does not reopen any on-wire object-canonicalization question for MCP-RE
  (RFC 9421/9530 remains the sole carrier). Community messaging must keep
  those two canonical forms visibly distinct.
- "Portable audit receipts" is today an explicit MCP-RE non-claim
  (`PROJECT_STATUS.md`). SEP-3004 is the plausible future path to that claim
  — via a registered `runtime-evidence`-style extension type carrying MCP-RE
  evidence commitments — not via anything MCP-RE builds alone.

Grill questions (fold into Branch 5):
- Do we engage now with a proposed `runtime-evidence` extension registration
  for SEP-3004, or only cross-reference it from Discussion #172 (layered
  composition contracts) until it has a sponsor? (It is a draft; building
  against it is premature — referencing it is cheap.)
- Should the refreshed threat-coverage matrix (Branch 1) gain an explicit
  "audit-trail tamper evidence: out of scope, composes with SEP-3004" row?
- Does the audit-redaction rule in the EMA profile (Branch 4: artifact
  appears in audit output as hash only) deliberately align with SEP-3004's
  `<alg>:<hex>` commitment syntax so the two compose without translation?

## Disposition of #148 (proposed, to confirm in grill)

Close #148 as **completed historical planning** — do not rewrite it. Post a
status note (draft below), apply/adjust status labels, and point forward to the
new PRD. Posting is outward-facing and stays HITL (Mats posts or approves).

> **Status update — July 2026.** This PRD has completed its original purpose:
> its implementation epic #158 is closed, and ADR-MCPS-031 through
> ADR-MCPS-036 are implemented. The project has since moved beyond the v0.5
> assumptions — MCP-S was renamed MCP-RE, the native object carrier was
> deleted, and RFC 9421 + RFC 9530 is the sole production evidence profile
> (ADR-MCPRE-050), with delegated JOSE/JWS signing (ADR-MCPRE-052),
> client-side enforcement, fleet replay coherence, and live GKE validation
> (ADR-MCPRE-051). This discussion is retained as the historical
> proposal-readiness PRD. Forward planning continues in
> *PRD: MCP-RE v0.13 — Authorization-Evidence Interoperability and Production
> Completion*, which carries forward the durable principles established here —
> precise scope, method transparency, external threat coverage, and
> "no test, no claim" — applied to the current HTTP-profile architecture.

## Candidate workstreams (grill branches)

### Branch 1 — Regenerate the evidence spine for the current architecture

The v0.5 machinery (claim matrix, threat-coverage matrix, boundary doc,
traceability manifest, forbidden-wording gate, dual mechanical+HITL gate) is
the useful inheritance; its *content* is obsolete.

Proposed scope: a current claim matrix and security-boundary document over the
RFC 9421/9530 profile; threat-coverage matrix refreshed against current
external guidance; every public claim traced to a named green test; explicit
known limitations; obsolete v0.5/draft-01 language removed from
current-facing docs (starting with `PROJECT_STATUS.md`). Coverage must extend
to: HTTP-profile evidence, signed rejections, delegated signing, root and
delegated key lifecycle, client-proxy enforcement, fleet replay coherence,
trust propagation, GKE custody, SDK behavior, SLO claims.

Open questions to grill:
- New claim-matrix version anchored to v0.13, or a living un-versioned matrix
  CI-tied to `VERSION`?
- Does the boundary doc get re-signed from scratch (new §-structure for the
  HTTP profile) or amended with a supersession chain?
- Which stale docs are rewritten vs archived to `docs/archive/` (the v0.3/v0.5
  matrices, the old `security-boundary.md` signed sections, `ema-composition.md`)?
- Does the forbidden-wording gate need new vocabulary (e.g. forbid "zero-drop"
  while Proof 4 is not green; forbid multi-cloud custody claims while AWS KMS
  is not live-proven)?

### Branch 2 — Root-authority production lifecycle (candidate: ADR-MCPRE-053)

The verifier side is done (§H/§I, live cross-KMS rotation green). The gap is
the **governed production controller** and fleet-scale operation:

- `mcp-re-admin rotate-root` — create/select new KMS root, publish
  version-bumped signed manifest (new root current, old retiring with
  `valid_until = now + overlap`), switch the rotor's issuer, drop old root
  after overlap;
- break-glass immediate revocation (manifest with issuer `revoked`), possibly
  two-person;
- rotation audit trail (who, when, old→new, overlap);
- manifest distribution channel evolution (static file/config → signed remote
  feed) without verifier change;
- custody of the org/admin manifest-signing key itself;
- GKE lane: live cross-KMS rotation re-run at fleet scale.

Open questions to grill:
- New ADR-053 vs. extending ADR-052 §H/§I? (The mechanism ADR is implemented;
  a distinct lifecycle/governance ADR keeps authority decisions separately
  ratifiable — but that's a recommendation, not a decision.)
- Who/what is the control point for scheduled rotation — explicit admin
  command, CI release approval, or both?
- Is two-person approval in scope for break-glass, and how is it enforced in a
  solo-operator project (honest answer may be "documented posture, not
  mechanism")?
- Where does the manifest live operationally on GKE (ConfigMap, mounted
  secret, signed feed)? What is the propagation bound, and does it inherit the
  ADR-021 bounded-staleness vocabulary?

### Branch 3 — Production completion residuals

- **Rolling update:** fix the 2/590 GKE drop (candidate: longer
  `drainPreStopSeconds` + readiness-gate sequencing), re-run Proof 4 to green.
  Until green, reconcile the v0.11 "zero-drop" wording with the v0.12.1 known
  issue — claim integrity requires one of: fix-and-reprove, or narrow the
  claim.
- **AWS KMS:** adapter shipped but not live-proven; multi-cloud custody is
  correctly not claimed. Decide: live-prove in v0.13, or explicitly park it
  (and keep the non-claim).
- **In-flight work:** land the uncommitted MRT cross-replica continuation and
  the Discussions-migration changes before the new PRD's baseline is cut.
- Define the v0.13 completion gate (candidate): root rotation/revocation green
  at fleet scale + automated disposable KMS roots green + rolling-update proof
  green + delegated-required GKE lane green + SLO gate green.

Open questions to grill:
- Is the rolling-update residual a release blocker for v0.13 or a tracked
  known-issue with narrowed claim wording?
- Does ADR-051 need a status annotation (implemented-with-known-issue) or is
  the CHANGELOG known-issue sufficient authority?

### Branch 4 — EMA composition profile (candidate: ADR-MCPRE-054)

Formalize EMA composition over the existing bind-not-interpret architecture
(supersede `docs/spec/ema-composition.md`; carry forward Mode 1/Mode 2 and the
"EMA twice" rule into the HTTP-profile world).

Evidence chain to bind: enterprise IdP issues ID-JAG → MCP authorization
server issues audience-restricted access token → client binds the access token
to the MCP request → MCP-RE signature binds request body, target
audience/resource, authorization artifact, and the sender constraint (DPoP
proof or mTLS certificate binding).

Decisions the profile must make (grill each):
- How the client proxy receives the EMA-issued access token (config, callback,
  ambient header from the plain-MCP client?).
- Sender-constraint profiles: DPoP `ath` binding, RFC 8705 mTLS `x5t#S256`
  (already proven in v0.11), or both — and which is the default.
- Audience semantics: how the MCP resource identifier compares with MCP-RE's
  audience binding; what "wrong resource" rejects as (frozen wire code).
- Representation of token issuer/audience/resource metadata in verified
  context (bind-not-interpret: hashes and identifiers, not parsed policy).
- Failure taxonomy: missing, mismatched, expired, wrong-resource,
  wrong-issuer, substituted-after-signing artifacts — each a named fail-closed
  rejection.
- Redaction: the artifact never appears in audit output (hash only).
- Client-proxy behavior when EMA is unavailable (fail closed where policy
  requires EMA; what does "policy requires EMA" mean per-deployment?).
- Mode 1 vs Mode 2 selection surface in the HTTP-profile config, and whether
  Mode 2 (sidecar-enforces) is even in v0.13 scope or deferred.

Conformance lane (hermetic): test IdP → ID-JAG → test authorization server →
access token → client proxy → signed request → server proxy. Negative lanes at
minimum: wrong resource, wrong AS audience, token substituted after signing,
wrong enterprise IdP, expired token, DPoP key mismatch, mTLS cert mismatch,
introspection deny/revoked, MCP-RE audience ≠ token resource, missing artifact
where required. Optional follow-on: interop lane against a real EMA-capable
IdP or the `modelcontextprotocol/ext-auth` reference implementation.

Open questions to grill:
- Do we build the hermetic test IdP + AS ourselves or reuse ext-auth reference
  code (license/dep hygiene)?
- Is the ID-JAG itself ever bound (e.g. audit-linkage use cases) or strictly
  never present at the runtime layer?
- Naming: is this a new deployment mode, an authorization-profile instance
  (ADR-MCPS-013 seam), or an artifact-binding profile entry?

### Branch 5 — Ecosystem readiness (from implementation- to adoption-risk)

- **Independent conformance:** publish the RFC 9421/9530 + delegation vectors
  (d01–d22 plus request/response/rejection vectors) as a standalone versioned
  package; make MCP-RE implementable without the Rust code; grow the existing
  python-cryptography JOSE cross-verify into an independent non-Rust
  verifier/test oracle; define conformance levels.
- **External review:** re-run the security-funnel review against the current
  architecture; structured fuzzing for RFC 9421 parsing, delegation
  credentials, and rejection paths; external review if sponsorship appears;
  publish the threat model separately from implementation detail.
- **MCP community proposal:** continue through the existing open Discussions
  (#172/#175/#232) — lead with focused questions (should MCP define a
  runtime-evidence extension/profile; which evidence properties belong at the
  MCP layer; how are EMA/DPoP/mTLS artifacts bound to exact tool calls; should
  signed rejection evidence be interoperable; extension vs deployment
  guidance) rather than "please adopt MCP-RE".
- **SEP-3004 positioning** (see the dedicated section above): reference it
  from #172 as the at-rest audit seam MCP-RE composes with; decide whether a
  `runtime-evidence` extension registration is proposed now or after it gains
  a sponsor.

Open questions to grill:
- What is the smallest credible independent-verifier increment (extend the
  existing python cross-verify vs a fresh minimal verifier)?
- Fuzzing harness placement: in-repo CI lane vs OSS-Fuzz application?
- Which of the three open Discussions is the spearhead, and does EMA binding
  (Branch 4) become its next Update post?

## Candidate sequencing (to grill, not decided)

1. Grill → new PRD posted → #148 closed out with the status note (HITL post).
2. Branch 3 quick wins early (rolling-update fix; land uncommitted work) —
   they de-risk every later live proof.
3. Branch 2 (root-authority controller + GKE lane).
4. Branch 1 evidence-spine regeneration (after 2/3 so the matrix documents the
   completed state, not a moving target) — though the forbidden-wording fixes
   for today's over-claims ("zero-drop", PROJECT_STATUS version) should not
   wait.
5. Branch 4 EMA profile.
6. Branch 5 ecosystem readiness (vectors package can start anytime; community
   Update posts follow the EMA profile).

Grill question: is Branch 1's claim-matrix work a gate for the PRD itself
(claims first, then build) or a closing artifact per workstream?

## Routed to the private strategy note (`work/`, not for publication)

Topics only — content lives in `work/mcp-re-v0.13-strategy-notes.md`:
positioning and adoption strategy; external-review sponsorship; EMA vendor
landscape and engagement order; versioning/1.0 trajectory; what is
deliberately not said publicly while residuals are open.

## Sources

- Repo: `CHANGELOG.md` (v0.12.x), `docs/PROJECT_STATUS.md`,
  `docs/spec/root-authority-rotation.md`, `docs/spec/ema-composition.md`,
  `docs/spec/v0.5-claim-matrix.md`, `docs/spec/threat-coverage-matrix.md`,
  `docs/spec/security-boundary.md`.
- Discussions: #148 (PRD), #158 (epic, closed), #379–#384 (ADR-031…036),
  #398/#399/#400 (ADR-050/051/052), #172/#175/#232 (community proposals).
- SEP-3004: [PR modelcontextprotocol#3004](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3004)
  (Draft, unsponsored, checked 2026-07-15; spec text read at head commit
  `377f8d2`; cross-refs ATSA #2809, runtime-security #2624, SEP-2484;
  reference implementation: `github.com/notboatanchor/gif`).
- EMA: [MCP EMA extension page](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization),
  [ext-auth spec + reference implementations](https://github.com/modelcontextprotocol/ext-auth),
  [MCP blog announcement](https://blog.modelcontextprotocol.io/posts/enterprise-managed-auth/)
  (stable 2026-06-18; SEP-990; Okta first IdP; Anthropic/VS Code + nine
  servers at launch).
