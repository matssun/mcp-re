# HTTP Profile Conformance Notes (v0.13)

**Audience:** an implementer or reviewer checking MCP-RE against the published
profile set — [#414](https://github.com/matssun/mcp-re/discussions/414) (layered
architecture), [#415](https://github.com/matssun/mcp-re/discussions/415) (HTTP
profile), [#416](https://github.com/matssun/mcp-re/discussions/416) (continuation
profile), all rev 2.

This document states the rules the v0.13 work settled where the published profile
left a choice to the deployment, and names the test that proves each one. It does
not restate the profiles themselves. Per project convention: the spec states the
rule, the ADR records why, the guide explains how to use it, the tests prove it.

Every decision here was taken under the 2026-07-17 standards audit tracked by
[epic #435](https://github.com/matssun/mcp-re/issues/435).

---

## §1.5 — `keyid` is an RFC 7638 JWK thumbprint

**Rule.** A keyid the profile ISSUES is the base64url-no-pad SHA-256 RFC 7638 JWK
thumbprint of the key it names. For an Ed25519 OKP key the thumbprint input is the
canonical JWK `{"crv":"Ed25519","kty":"OKP","x":"<b64url>"}` — required members
only, lexicographic, no whitespace (RFC 8037 §2).

This aligns with the Web Bot Auth / WIMSE conventions #415 rev 2 §1.5 names, and
makes a keyid self-describing: any party holding the key can recompute the kid and
check the two agree, with no issuer-private numbering to interpret.

**A keyid remains a selector, never trust input.** Deriving the kid from the key
does not make the key trusted. The trust seam still resolves the kid to a
verification key for a specific signing slot, and a kid that "matches" the key a
message carries earns nothing — that check would be circular. This is the
CONTEXT.md anchor rule and it is unchanged.

**Scope.** The convention binds keys the profile issues — today, the delegated
response-signing keys minted by `DelegatedSigningCustody`. Externally-managed keys
(a root anchor in a KMS, a client key enrolled out of band) keep whatever kid their
key management assigns: §1.5 says "unless key management requires otherwise", and
a KMS resource name is exactly that case. A verifier never requires a kid to be a
thumbprint; it requires the trust seam to resolve it.

**Migration.** Delegated kids changed shape (`<issuer>/delegated/<n>` → thumbprint).
Nothing on the wire parses a kid — it is an opaque selector everywhere — so the
change is contained to issuance. Tests that spelled the old literal now assert the
property they meant: that a *delegated* key signed rather than the root, that a
successor differs from its predecessor, or that the kid matches its own key's
thumbprint.

**Proven by.** `keyid.rs::rfc8037_a3_known_answer` (a third-party KAT — RFC 8037
§A.3 pins this exact thumbprint), `custody.rs`, `delegated_wiring.rs::builds_and_first_rotate_publishes_a_snapshot`.

---

## §13.1 — the algorithm allowlist is the agility mechanism

**Rule.** Algorithm acceptance is a verifier-local allowlist, defaulting to
`["ed25519"]` — exactly the previously hardcoded behavior. A signature naming an
algorithm outside the allowlist is rejected `mcp-re.unsupported_version` at the
parameter gate, BEFORE key resolution and before any cryptographic work.

The IANA HTTP Signature Algorithms registry has grown (ML-DSA and others).
**Registration is not deployment consent.** A registry entry never widens what this
verifier accepts; only the local allowlist does. Protected content states which
algorithm the signer used — it never states which are acceptable.

**No new algorithms are enabled by this work.** The allowlist is plumbing: it moves
the decision from a constant to a policy value, so adding an algorithm later is a
deliberate local act rather than a code change.

**Proven by.** `policy.rs::allowlist_is_the_agility_mechanism`,
`policy.rs::default_is_ed25519_only_with_bounded_skew`, and the frozen negative
vector `h23_request_alg_not_allowlisted` (a registered-but-not-allowlisted `alg`
rejected on policy, not on crypto).

---

## §5.1 — clock skew is explicit and bounded

**Rule.** The request and response freshness gates apply a bounded, symmetric
clock-skew tolerance from the verifier-local policy:

```
reject unless  created - skew <= now  <  expires + skew
reject if      expires <= created                        (skew-free)
```

| Tier | `max_clock_skew` |
|---|---|
| Default | 30s — matches the delegation-credential path, so one deployment does not run two notions of "close enough" on the same message |
| Strict production | 0s — exact-time semantics through the same seam |
| Hard cap | 300s — a configuration above this fails closed at construction |

**Skew is a tolerance, not a policy escape.** It is symmetric (a slightly
future-dated `created` and a slightly past `expires` are the same honest clock
disagreement), it is capped, and an out-of-bounds configuration is rejected when
the policy is built rather than silently widening the window. A degenerate window
(`expires <= created`) gets no tolerance at all: that is a property of the message,
and no amount of clock disagreement makes it well-formed.

**This changed accepted behavior.** The previous gate was exact. Messages within
30s of their window edge are now accepted by default where they were rejected
before. That is the point of §5.1 — the previous behavior was not "stricter", it
was an *unstated* policy of zero, which fails honest clients whose clocks differ by
a second.

**Proven by.** `rfc9421_security_properties_test::request_within_the_skew_bound_is_accepted_but_beyond_it_is_not`
(both edges pinned to the second), `::future_dated_request_within_the_skew_bound_is_accepted`
(the symmetric edge), `::strict_tier_policy_restores_exact_freshness`,
`proof_path_test::degenerate_window_fails_closed_regardless_of_skew`, and
`policy.rs::out_of_bounds_configuration_fails_closed`.

---

## Where the policy lives

`VerifierPolicy` (`mcp-re-http-profile/src/policy.rs`) carries both the allowlist
and the skew bound. Its fields are private and validated at construction, so a
policy cannot be widened past its bound after the fact.

The seam is additive: `verify_request`, `verify_response`, and friends are the
`VerifierPolicy::default()` case of `verify_request_with_policy`,
`verify_response_with_policy`, etc. A deployment that wants the strict tier or an
extra algorithm passes a policy; everything else keeps calling what it called.
`DelegationExpectations` carries a `policy` field for the delegated response path —
distinct from its `max_clock_skew`, which governs the CREDENTIAL's own window.

---

## #416 §7.1/§7.3 — evidence handles are domain-separated by role

**Rule.** Every evidence handle is a SHA-256 over a role-labeled preimage:

```
handle = base64url-no-pad( SHA-256( <role label> || 0x00 || <mandated input> ) )
```

| Role | Label | Input |
|---|---|---|
| Request evidence | `mcp-re-http-v1/request-evidence` | the request's RFC 9421 signature base |
| Response evidence | `mcp-re-http-v1/response-evidence` | the response's RFC 9421 signature base |
| Request state | `mcp-re-http-v1/request-state` | the opaque MRTR `requestState` bytes |

**Why this changed.** Previously all five handle sites shared one derivation, so a
handle's role was carried only by which field it sat in — and the response handle
was in fact derived by the request-role constructor. §7.3 requires role
distinction robust against substitution. A positional convention is not that: it
holds exactly as long as every consumer reads the right field, which is the
assumption an attacker is trying to break. With a label per role, a request-role
and a response-role handle over identical bytes are *different values*, so a
handle lifted into the wrong field cannot verify. The separation is cryptographic
rather than clerical.

The `0x00` separator makes the encoding injective: labels are ASCII and can never
contain a NUL, so no two (label, input) pairs collide. The labels are
profile-scoped, so they also separate this profile's handles from a future one's.

**Breaking.** Handle bytes changed; both frozen corpora were regenerated. This was
sequenced BEFORE the corpus content-pinning (#427) precisely so the corpus is
pinned once, against the final bytes.

**Proven by.** `evidence.rs::roles_are_domain_separated_over_identical_bytes`,
`::label_and_input_cannot_be_confused`, `::handle_is_not_a_bare_digest_of_the_base`,
vector `h28_chain_role_swapped_handles_incomplete`.

---

## #416 §9 — retained-chain reconstruction

**Rule.** A complete call record requires re-linking and verifying every hop
R0→S0→R1→…→Sn. The verdict is never a bare boolean: a chain is `Complete`, or
`Incomplete` and names the hop that broke it plus the verified prefix that stands.

Per hop, reconstruction checks: the request verifies; the response verifies and is
`;req`-bound to it; for hops after the first, the continuation re-links to the
previous hop's two role-labeled handles; and the chain's shape — every hop before
the last is non-terminal, the last is terminal, only the first may lack a
continuation.

**The failure it prevents.** Given R0→S0 and R2→S2 with R1→S1 missing, every
retained message still verifies and S2 is a genuine, correctly-signed terminal
result. A checker that only verified signatures would call that a complete record.
It is not: a turn is unaccounted for. §9.3 — a terminal response completes only its
own request unless the whole chain verifies.

**Handles are recomputed, not retained.** The §9.2 evidence list is carried by the
messages themselves plus the trust seam. Retaining derived handles alongside the
bytes would let a retention bug or a dishonest archivist state a handle that
disagrees with the bytes next to it; recomputing means the bytes are the only thing
anyone has to keep honest.

**Terminal classification is caller-supplied.** `resultType == "input_required"` is
MCP-level semantics (ADR-MCPS-047). The standards profile binds bytes; it does not
read MCP result models. `HopOutcome` is the seam.

**Proven by.** `chain_reconstruction_test` (12 tests; the load-bearing one is
`missing_middle_hop_is_incomplete_not_a_complete_terminal`, which asserts each
retained hop verifies on its own BEFORE asserting the chain does not) and vectors
`h24`–`h29`.

---

## #416 §13.2 — negative-category coverage map

Every §13.2 category maps to a vector, an existing test, or an explicit N/A.

| §13.2 category | Covered by | Kind |
|---|---|---|
| Missing previous-request handle | `h25_chain_missing_middle_hop_incomplete`, `later_hop_without_a_continuation_is_incomplete` | vector + test |
| Wrong previous-request handle | `h16_continuation_splice`, `h27_chain_foreign_continuation_incomplete` | vector |
| Missing response handle | `later_hop_without_a_continuation_is_incomplete` | test |
| Wrong response handle | `h27_chain_foreign_continuation_incomplete`, `h28_chain_role_swapped_handles_incomplete` | vector |
| Response from another chain | `h27_chain_foreign_continuation_incomplete` | vector |
| Artifact substitution/alteration | `h10`, `h12`, `h14` (DPoP / mTLS / RAR mismatch) | vector |
| Unknown binding identifier | `binding_identifier_test` — unknown `artifact_type`, unknown `binding_type`, and both shape/`binding_type` disagreements are `malformed_envelope`, never a silently-ignored binding | test |
| Classification outside protected content | **N/A by construction.** The terminal/non-terminal discriminator is read from the JSON-RPC `result`, which is inside the body that `content-digest` covers. There is no unprotected classification surface to attack: the profile mints no header carrying it (v0.11 grill E-3), and `HopOutcome` is supplied by the caller from already-verified content, never parsed from the wire by the profile. |
| Invalid response signature claiming non-terminal | `tampered_hop_is_named_by_index` (hop named, `ResponseUnverifiable`) | test |
| Truncated chain | `h26_chain_truncated_incomplete` | vector |
| Replayed continuation | five-tuple replay tier — `replayed_request_is_rejected_by_the_replay_tier`, `replayed_request_yields_a_verified_delegated_rejection` | test |
| Duplicate single-use across replicas | cross-replica atomic single-use — `mrt_continuation_serving_test` (open-on-A / answer-on-B) | live proof |
| Stale continuation | freshness gate + bounded skew — `request_within_the_skew_bound_is_accepted_but_beyond_it_is_not` | test |
| Wrong audience/server | `h18_rejection_bound_valid` (`invalid_audience`), `full_profile_test` audience binding | vector + test |
| Terminal spliced onto another continuation request | `h29_chain_terminal_spliced_incomplete` | vector |

---

## #416 §13.4 — conformance claims

What MCP-RE claims today, and what it does not:

| Claim | Status | Basis |
|---|---|---|
| **Base** — per-turn request/response binding | **Claimed** | RFC 9421 dual binding + `request_evidence`; `h01`–`h08` |
| **One-hop** — a single continuation binds its three handles | **Claimed** | `h15`–`h17`, `block.rs` |
| **Multi-hop** — consecutive non-terminal turns re-link to a terminal end | **Claimed** | `h24`, `chain_reconstruction_test` |
| **Fleet-safe** — cross-replica atomic single-use | **Claimed** | shared-Redis correlation store; live open-on-A/answer-on-B proof (ADR-MCPS-047) |
| **Complete retained-chain reconstruction** | **Claimed** | `chain.rs`; `h24`–`h29`; incomplete records name the failing hop |

Claims deliberately NOT made: per-event SSE evidence (deferred to a future
companion profile, §3.4); tasks and elicitation models (#416 §1.4); portable
audit receipts (Layer 5 — roadmap, see #434).
