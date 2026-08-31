<!-- SPDX-License-Identifier: Apache-2.0 -->
# Consolidated owner specification-review packet — ADR-MCPRE-059 §28

**Status: EMPTY — every theorem carries an independent specification-review record.**

That is the packet working, not the packet being skipped: its subject is the
COMPLEMENT of `verification/reviews/specification/`, so it shrinks by itself as records
are written and reaches nothing exactly when nothing is unreviewed. A future theorem
appears here the moment it is registered.

The assumption register below is retained: assumptions are reviewed on their own axis
and an empty theorem set says nothing about them.

Grouped by permanent system root, each root followed by its `depends_on` closure in
dependency order. A theorem appearing under more than one root is stated once, at its
first appearance, and cross-referenced afterwards. Theorems that already carry an
independent record — THM-0001 to THM-0042 — are NAMED in each closure and not restated:
this campaign did not reopen any of them, so re-reviewing them here would ask for a
decision that has been taken.

**Where the *lowest honest proposition* argument lives.** In each theorem's **Scope**,
which is where the registry keeps it: every scope says what the claim does NOT establish,
which neighbouring theorem owns that instead, and — for the claims resting on source-text
controls — why the property is EVIDENCE rather than unconstructibility. Copying that
argument into a second field would create two places for it to disagree, which is the
failure `_DUPLICATED_AUTHORITY` exists to prevent. Read the Scope as the justification.

**Deviations from the ratified architecture** are collected in one section at the end
rather than scattered per theorem, because there are six and each is a decision the owner
may want to read against the others.


---

## Theorems outside every declared root closure

None.

## Deviations from the ratified architecture

Six, each stated as a decision rather than a note.

**1. THM-0073 is UNCONDITIONAL.** The ruling's target wording was *where policy requires
the roles to be distinct*. Measurement found no supported deployment for which sharing a
key between the response-signing and channel-signing roles is desirable, and a one-valued
policy input invented to make the condition expressible would be an input that selects
nothing. Every deployment is held to it, so the ratified conditional is satisfied
everywhere rather than left as a dormant branch. If a deployment that legitimately shares
one key exists, this is the deviation to reverse.

**2. THM-0081's outside set is FOUR replies, not one.** The proposal said *one declared
pre-exchange transport refusal*. The measurement found four: the channel/routing refusal
is a served response, while the malformed message, the oversized body and the shed are
built at the hyper type and would have been invisible to a control that counted only the
first. All four are pre-handler. A FIFTH exit was found and is named rather than absorbed:
`served_to_hyper`'s framing fallback answers after the exchange has decided, and the claim
made about it is narrow and measured — an empty 500, which advertises no retry.

**3. THM-0053 got its own unit rather than joining the currency unit.** ASM-0012 declares
the assertion verifier OPAQUE to the currency theorem and its review requirement names a
separate unit as the discharge. `http_profile.admission_assertion` overlaps
`http_profile.admission_currency`'s paths deliberately: they are two authorities in one
file, and the registry already said so.

**4. THM-0073's owner MOVED** from `proxy.cross_machine_legality`, as the ruling
anticipated it might: a request-level classifier reads locators, and the decisive fact
exists only once both backends have answered. The new owner is a materialization relation.

**5. Two production changes were made**, both implied by the ratified architecture rather
than new design. `build_key_source` now returns `MaterializedSigningRoles` — the source is
opened privately and leaves the module only through the role comparison — and
`refusal_provenance_gate.py` gained clause 12. ADR-MCPRE-067 §10 is clarified in
`docs/architecture/components/cli-and-materialization.md` §11; the ADR's own text in the
discussion thread has NOT been edited, because that is an outward-facing publish.

**6. Two missing edges were found and closed, and one gap was found and left open.**
THM-0083 (what a request IS, decided once) was absent from the whole tree though R1
quantifies over it; THM-0070 was reachable from no root though R5c's totality needs it.
Both are now edges. Nothing was invented to make the graph look complete.

## Assumption register

| id | scope | mechanism |
|---|---|---|
| ASM-0001 | unit://core.time_rfc3339 | verus:external_body |
| ASM-0002 | unit://core.time_rfc3339 | verus:assume_specification |
| ASM-0003 | unit://core.time_rfc3339 | verus:assume_specification |
| ASM-0004 | unit://core.time_rfc3339 | verus:external_type_specification |
| ASM-0005 | unit://http_profile.freshness_window | verus:assume_specification |
| ASM-0006 | unit://http_profile.freshness_window | verus:assume_specification |
| ASM-0007 | unit://http_profile.freshness_window | verus:external_body |
| ASM-0008 | unit://http_profile.freshness_window | verus:external_body |
| ASM-0009 | unit://http_profile.freshness_window | verus:external_body |
| ASM-0010 | unit://http_profile.freshness_window | verus:assume_specification |
| ASM-0011 | unit://http_profile.admission_currency | verus:external_body |
| ASM-0012 | unit://http_profile.admission_currency | verus:external_body |
| ASM-0013 | unit://http_profile.admission_currency | verus:external_type_specification |
| ASM-0014 | unit://http_profile.admission_currency | verus:assume_specification |
| ASM-0015 |  | none |
| ASM-0018 | unit://http_profile.artifact_typing | verus:external_body |
| ASM-0019 | unit://http_profile.artifact_typing | verus:external_body |
| ASM-0020 | unit://http_profile.artifact_typing | verus:assume_specification |
| ASM-0021 | unit://http_profile.continuation_unbypassability | verus:external_body |
| ASM-0022 |  | none |
| ASM-0023 | unit://http_profile.continuation_binding | verus:external_body |
| ASM-0024 | unit://http_profile.admission_currency, unit://http_profile.artifact_typing, unit://http_profile.continuation_binding, unit://http_profile.continuation_unbypassability, unit://http_profile.freshness_window | verus:uninterp |
| ASM-0025 | unit://http_profile.admission_currency, unit://http_profile.artifact_typing, unit://http_profile.continuation_binding, unit://http_profile.continuation_unbypassability, unit://http_profile.freshness_window | verus:uninterp |
| ASM-0026 | unit://http_profile.admission_currency, unit://http_profile.artifact_typing, unit://http_profile.continuation_binding, unit://http_profile.continuation_unbypassability, unit://http_profile.freshness_window | verus:uninterp |
| ASM-0027 | unit://http_profile.verifier_results | none:trusted-primitive |
| ASM-0028 | unit://http_profile.verifier_results | none:trusted-primitive |
| ASM-0029 | unit://http_profile.verifier_results | none:trusted-seam |
| ASM-0030 | unit://proxy.certificate_identity | foreign-dependency |
| ASM-0031 | unit://proxy.ed25519_public_key | foreign-dependency |
| ASM-0032 | unit://proxy.credential_key_correspondence | foreign-dependency |
| ASM-0033 | unit://proxy.channel_associated_credential | foreign-dependency |
| ASM-0034 | unit://proxy.channel_associated_identity | foreign-dependency |
| ASM-0035 | unit://proxy.mechanism_verified_credential | foreign-dependency |
| ASM-0036 | unit://proxy.authenticated_relationship_peer | foreign-dependency |
| ASM-0037 | unit://http_profile.keyid, boundary://boundary.crypto_primitives | none:trusted-primitive |

