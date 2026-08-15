<!-- SPDX-License-Identifier: Apache-2.0 -->

# PENDING OWNER APPROVAL — correction to `security-boundary.md`

**Status: PROPOSED. NOT APPROVED. NOT APPLIED.**

`security-boundary.md` is `type:HITL` — authored by an agent, approved only by the human
owner, and the author does not self-approve it. This file therefore holds a proposed
correction rather than applying one. It is release-gating: the claim it corrects is false
in the present tense, and a document called *security boundary* is the wrong place to
leave that standing.

**Owner action required — do all five in ONE change, or none of them.** A partial
application leaves the correction mechanism behind as the next fossil, which is the failure
this file exists to correct:

1. review the replacement below;
2. approve the exact text (amend first if it is wrong — approving an amended text is fine,
   approving text you have not read is not);
3. apply it to `security-boundary.md`;
4. delete this file;
5. remove the `### Outstanding` entry from `CHANGELOG.md` in the same commit.

Steps 4 and 5 are not tidying. Scaffolding that outlives its purpose reads as an open
issue forever, and a release-gating entry nobody can discharge trains readers to ignore
the heading.

## The defect

`docs/spec/security-boundary.md`, in the list of what MCP-RE protects:

> - **Delegated authorization** (Phase 5, reference signed-authorization profile).
>   The proxy enforces the authorization profile **deny-before-dispatch** — an
>   unauthorized request never reaches the inner server
>   ([ADR-MCPS-013](https://github.com/matssun/mcp-re/discussions/362)).

This asserts, in the present tense, that an enforcement control is active. It is not.
`mcp-re-proxy/src/cli.rs` refuses the only value that would select it:

> `--authz reference` selects the reference/conformance signed-authorization profile
> … must be rebuilt on the HTTP-profile request evidence first. Run `--authz off`.

So `authz` is `Off` in every configuration the proxy accepts, and no request is subject to
an authorization decision. Nothing reaches an evaluator, because there is no evaluator on
the RFC 9421 serving path.

The document's deprecated-object-profile banner explains why the entry is stale. It does
not make the sentence safe: a reader checking whether MCP-RE decides *may-act* is told it
does, and the banner above does not read as retracting an enforcement claim.

## Proposed replacement

> - **Delegated authorization — NOT LIVE.** The reference signed-authorization profile
>   (Phase 5, [ADR-MCPS-013](https://github.com/matssun/mcp-re/discussions/362)) was bound
>   to the retired object carrier and has not been rebuilt on HTTP-profile request
>   evidence. `--authz reference` is **refused at configuration validation**, so every
>   deployment runs with authorization off and MCP-RE answers **who signed this** and
>   **which channel it arrived on**, never **may-act**. Authorization must be enforced
>   upstream of the proxy. The preserved vectors at
>   `mcp-re-policy/tests/vectors/phase5_vectors.json` specify non-live semantics for a
>   future profile and are not evidence about any release; nothing executes them.

## Why this shape

Three properties the replacement is meant to hold, for review against:

1. **It states the boundary, not just the absence.** A reader learns which question MCP-RE
   does not answer and where they must answer it instead.
2. **It names the mechanism of the refusal.** "Refused at configuration validation" is
   checkable against `unaccepted_authz_profile_refusal`; "not implemented" would not be.
3. **It keeps the ADR citation.** The decision record is still the decision record; only
   the present-tense enforcement claim is withdrawn.

## Related, already corrected

The same false-claim class was corrected in the non-HITL documents in the same change:
`docs/transport-hardening-guide.md` (the `PolicyEvaluator` row), `docs/conformance-guide.md`
(Phase-5 was advertised as a conformance category with no harness), and
`docs/adr/README.md` (ADR-MCPS-013 marked implemented). `docs/sidecar-deployment-guide.md`
already stated the refusal correctly and needed no change.
