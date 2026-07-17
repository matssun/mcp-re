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
