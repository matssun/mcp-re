<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-S Proposal Scope

Purpose: state what MCP-S 0.5 proposal-readiness includes and excludes over draft-01.

**MCP-S can protect messages that carry extension data, but does not define the semantics of those extensions.**

## Scope statement

MCP-S 0.5 is a proposal-readiness release. Its work is documentation, conformance,
and claim hardening over the existing `draft-01` wire envelope — making every
claim reviewable and traceable to a green test — not new protocol mechanism. It
adds no capability that `draft-01` cannot already carry, and it reuses the existing
ADRs for any decision it touches rather than re-deciding them.

## draft-01 freeze

**MCP-S 0.5 is proposal-readiness over draft-01. No wire-envelope changes. Field
gaps become draft-02 work.**

0.5 adds zero wire-envelope fields; request and response envelopes are unchanged.
There is no in-release field-add path. A claim that `draft-01` cannot support is
cut from 0.5 and ejected to a separate `draft-02` ADR — its new field, threat
model, and tests are post-0.5 work — rather than smuggled in as a "small field
addition," a "just one metadata field," or an "NSA alignment field." The wire
envelope version stays `draft-01` and is frozen unless a dedicated ADR justifies a
field change.

## Authorization — bind, not interpret

Authorization in 0.5 is wording only; it adds no new authorization mechanism.
MCP-S Core *binds* authorization and leaves *interpretation* to a configured
profile ([ADR-MCPS-013](../adr/adr-mcps-013.md)):

- **Core binds `authorization_hash`.** Core carries the opaque
  `authorization_hash` inside the signed request envelope and binds it
  cryptographically, so tampering with the referenced artifact breaks the Core
  signature binding.
- **The AuthorizationProfile interprets it.** The configured AuthorizationProfile
  parses the artifact, validates it, and decides allow or deny.
- **Core never validates artifact contents, provides RBAC, or emits a mismatch.**
  Core does not parse the authorization artifact, ships no role-based access
  model, and produces no mismatch verdict; any allow/deny ruling is the profile's.

Likewise, `on_behalf_of` binds the signer's *signed assertion* of acting-for;
Core binds that assertion but does not prove the delegation is legitimate, which
remains a profile/policy decision.
