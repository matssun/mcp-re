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

## §3.4 — covered exchanges are JSON mode

**Rule.** A covered request or response MUST carry `Content-Type: application/json`.
Anything else — most consequentially a `text/event-stream` response — is a profile
violation and fails verification with `mcp-re.serialization_failed`. Media types are
compared case-insensitively; parameters are allowed (`application/json; charset=utf-8`
is JSON mode); a `+json` structured suffix is NOT (`application/problem+json` fails).

**Why it fails rather than degrades.** Per-event SSE evidence is explicitly deferred
to a future companion profile, so there is no way to make a per-event statement
today. A stream admitted on a covered exchange would carry a signature over the
response as a whole while every event inside it went individually unattested — the
evidence would look complete and cover nothing that mattered. Failing closed is the
only honest option until that companion profile exists.

`content-type` was already a covered component, so the signature always bound
whatever was sent. Coverage is not constraint: this gate constrains the VALUE, which
nothing previously did.

**Wire code.** Reuses the frozen `mcp-re.serialization_failed` that
`ContentEncodingPresent` maps to — both are content-model/value-domain violations of
the protected message. No new token (E-11: no parallel namespace).

**The backend `Accept` decision.** The proxy's inner-backend client KEEPS
`Accept: application/json, text/event-stream`. MCP Streamable HTTP requires a client
POST to accept both, and a conformant backend (FastMCP) answers a json-only Accept
with 406 — narrowing it would turn a profile rule into an interop failure. The rule
is enforced where it belongs, on the response: the backend client refuses a
non-JSON response explicitly (rather than incidentally, when SSE framing fails to
parse as JSON), and the verifier gates all five covered paths — request, response,
response-unbound, and both delegated response paths. A credential chain to the root
does not make a stream evidenceable.

**Proven by.** `json_mode_test` (7 tests, incl. `the_rejected_sse_response_was_genuinely_signed`,
which pins that the rejected stream carried a VALID signature — JSON mode is enforced
as its own rule, not as a side effect of a crypto check happening to fail), and the
frozen vector `h30_response_sse_on_covered_exchange` (a genuinely-signed SSE response).

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

**The registry is typed, and that is a correction.** A list of strings cannot
express the property that makes an allowlist safe — "…and this crate has a verifier
for that". While it was strings, a policy naming `ml-dsa-65` accepted a message
DECLARING `ml-dsa-65` at the parameter gate, and verification ran Ed25519 anyway:
a genuine Ed25519 signature over a base declaring ML-DSA verified. The agility
interface itself created an algorithm-confusion path. A `ProfileAlgorithm` variant
now exists only where an implemented verifier exists, `VerifierPolicy::new` refuses
any token that does not resolve to one, and the gate returns the *typed* algorithm
so the verifier must dispatch on it — a new variant will not compile until its
verifier is wired.

**Proven by.** `algorithm_confusion_test` (an Ed25519 signature declaring ML-DSA is
rejected; the same signature declaring the truth verifies; the unsafe policy cannot
be constructed), `policy.rs::an_algorithm_without_a_verifier_cannot_be_allowlisted`,
and the frozen negative vector `h23_request_alg_not_allowlisted`.

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
| Classification outside protected content | `a_truncated_chain_cannot_be_relabelled_complete`. **This row previously claimed N/A by construction and was wrong.** The discriminator does live inside `content-digest`-covered content — but `reconstruct_chain` took the classification from a caller array *parallel to* the hops, and that array was authoritative. A caller could label a signed `InputRequiredResult` as terminal and a truncated chain reconstructed as COMPLETE. The classification is now derived from each response's body after that response verifies; there is no parameter left to lie with. |
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

---

## §4.1 — MCP transport headers are covered when present

**Rule.** `Mcp-Method`, `Mcp-Name`, and `Mcp-Protocol-Version` are coverable
components, and each is **conditionally mandatory on exactly the
`authorization`/`dpop` pattern: present means covered**. Additionally, a covered
`Mcp-Method` MUST agree with the JSON-RPC `method` in the covered body; a
disagreement is `mcp-re.malformed_envelope`.

**The gap this closes.** `Mcp-Method` states in the clear which method a request
carries. Uncovered, that claim can diverge from the signed body — an intermediary
reads `tools/list` off the header and routes, logs, or authorizes on it while the
signed body says `tools/call`. The proxy never routes on these headers
(ADR-MCPS-025: untrusted hints, the body is authoritative) and that does not
change. What changes is that the header can no longer *lie* about a signed body,
which is worth more than a header nobody is permitted to believe.

**Presence, not configured version, is the condition.** §4.1 frames the rule as
version-conditional. Presence is the operative test because it is the question the
verifier can answer from the message in front of it: if the sender put the header
on the wire, the signature covers it or the request is rejected. A deployment
whose version does not define these simply never sends them, and nothing fires —
so the rule is version-conditional in effect without the signer or verifier being
configured with a version they would then have to be trusted to state honestly.

**Divergence is checked AFTER the signature.** Before it, both sides of the
comparison are unauthenticated and two attacker-chosen strings agreeing proves
nothing. After it, both are protected — so a disagreement is the *signer* stating
two different methods, and the verifier refuses rather than picking a winner.

**`mcp-session-id` is scoped OUT — not deferred, excluded.** Protocol sessions are
a 2025-11-25 concept that MCP 2026-07-28 removes, and MCP-RE never adopted them:
its serving path is stateless per-request by design (ADR-MCPRE-051). There is no
session for a session id to identify, and covering a header whose referent does not
exist would manufacture the appearance of a binding over nothing. It is therefore
absent from the coverable set, and a sender that hand-crafts it into the covered
set is rejected as an unknown covered component. That is the intended answer, not
an omission.

**Proven by.** `mcp_transport_headers_test` (9 tests, incl.
`mcp_session_id_is_not_a_coverable_component` and
`the_component_allowlist_is_still_closed` — widening the allowlist for these three
must not have opened it generally), and vectors `h31_mcp_headers_covered_valid`,
`h32_mcp_method_present_but_uncovered`, `h33_mcp_method_body_divergence`.

### The full §4.1 transport contract — `McpTransportPolicy`

Header integrity above is *one* half of §4.1: a header that is *sent* is covered
and must not lie. The other half is which headers MUST be sent, which protocol
versions are acceptable, and agreement with the protected body. That is
[`McpTransportPolicy`], attached to a `VerifierPolicy` and enforced by
`verify_request_with_policy` AFTER the signature verifies.

**`McpTransportPolicy::mcp_2026_07_28(supported_versions)`** is the strict
per-request contract:

| Requirement | Enforced |
|---|---|
| `Mcp-Method` present on every POST | ✅ absent ⇒ `missing_envelope` |
| `MCP-Protocol-Version` present on every POST | ✅ absent ⇒ `missing_envelope` |
| Version ∈ the deployment's supported set | ✅ otherwise ⇒ `unsupported_version` — a client's claim is not consent |
| `MCP-Protocol-Version` = body `io.modelcontextprotocol/protocolVersion` | ✅ disagreement ⇒ `malformed_envelope` |
| `Mcp-Method` = body `method` | ✅ (always on, policy or not) ⇒ `malformed_envelope` |
| `Mcp-Name` present for `tools/call` / `resources/read` | ✅ absent ⇒ `missing_envelope` |
| `Mcp-Name` = `params.name` (`tools/call`) / `params.uri` (`resources/read`) | ✅ disagreement ⇒ `malformed_envelope` |

**Every check runs after the signature, against protected values.** Before it, both
a header and the body are attacker-chosen, so their agreement — or a version
string's value — proves nothing. After it, a present header is covered (the
closed-allowlist gate enforced present ⇒ covered), so a required header that is
present is signed, and a disagreement is the *signer* contradicting itself.

**`allow_legacy_header_omission` gates ABSENCE only.** A deployment still serving
pre-2026-07-28 clients sets it: a request carrying *none* of these headers is
served as legacy rather than rejected. Any header it *does* carry is still validated
in full — the flag waives "you must send it", never "it may lie".

**Opt-in and additive.** The default `VerifierPolicy` attaches no transport policy,
so a deployment that has not opted in behaves exactly as before (present-header
integrity only, absence allowed). Supported versions are a constructor input rather
than hardcoded, so the policy does not bake in a spec that is not yet final.

**Proven by.** `mcp_transport_headers_test` — the full contract through the real
verify path (`a_required_header_absent_is_rejected_through_verify`,
`an_unsupported_protocol_version_is_rejected_through_verify`,
`protocol_version_header_body_divergence_is_rejected_through_verify`,
`mcp_name_body_divergence_is_rejected_through_verify`,
`legacy_omission_serves_bare_client_but_rejects_a_lie_through_verify`), the
`mcp_transport.rs` unit tests, and frozen vectors `h38`–`h41`.

---

## MCP protocol version: applicability and the 2026-07-28 target

**MCP-RE performs no protocol-version negotiation.** This is the finding that
matters for #426, whose headline task was "bump the backend handshake /
protocol-version handling to 2026-07-28". There is no handshake to bump:

- the serving path is stateless per-request by design (ADR-MCPRE-051);
- the proxy forwards single request/response exchanges and holds no session state;
- the only `2025-06-18` in the Rust tree is a **comment** citing which spec
  revision mandates the dual `Accept` header — not a negotiated version.

The audit read that comment as a pinned protocol version. It is not. So "pinned to
2025-06-18" overstates the coupling: MCP-RE is version-agnostic where versions are
negotiated, and the features 2026-07-28 removes — protocol sessions, the GET
stream, SSE resumability — are ones MCP-RE never adopted. Its stateless direction
is already the 2026-07-28 direction.

**Applicability, stated honestly.** MCP-RE's HTTP profile applies to any MCP
version that carries JSON-RPC over Streamable HTTP POST in JSON mode. It covers
the MCP transport headers when a sender sends them (§4.1 above), which spans
2025-11-25 and 2026-07-28 without a version switch. It makes no conformance claim
for tasks or elicitation models (#416 §1.4), and none for protocol sessions.

**What is genuinely blocked.** The 2026-07-28 spec is final on 2026-07-28; the
RC-shape guards below are prep, not a conformance claim:

| Prep item | Status |
|---|---|
| `-32003` non-collision with MCP-reserved `-32020..=-32099` | **Verified + tested** — also inside JSON-RPC's implementation-defined `-32000..=-32099`, where an application code belongs |
| SEP-2322 `resultType: "input_required"` snake_case discriminator | **Matches the RC + drift-guarded** — a rename in the final text fails a test rather than silently classifying continuations as terminal, which would end a call record at hop 1 and look like success |
| Handshake bump | **N/A** — no negotiation exists to target |
| Final-text confirmation | **Blocked until 2026-07-28** |

**Proven by.** `mcp_2026_07_28_alignment_test`.

---

## §3.4/§8.1 — bodyless component sets and the signed 202

**Rule.** Two NAMED bodyless sets, enforced exactly — not relaxations of the
bodied ones:

| Set | Covered components |
|---|---|
| Bodyless request (§8.1) | `@method`, `@target-uri`, `content-digest` (over empty content). No `content-type`. |
| Bodyless response (§3.4) — the signed `202 Accepted` | `@status`, `content-digest` (over empty content), plus the full `;req` binding to the originating request. No `content-type`. |

**Named, not relaxed.** The verifier is told which set it is checking and enforces
that set exactly; it never *notices* a body is absent and drops a requirement.
Otherwise "no content-type because there is no content" and "content-type stripped
in flight" would be the same observation. Under named sets, a bodied message
missing its content-type still fails AND a bodyless message carrying one also
fails — both directions are enforced.

**Why `content-digest` over empty content.** A digest of nothing is not ceremony:
it makes "this message has no body" a *signed statement* rather than an absence.
Without it, a body stripped in flight and an intentionally empty one would be
indistinguishable.

**Why the `;req` binding is mandatory on the 202.** A bodyless response has no body,
so it cannot restate its `request_evidence` the way a bodied response does. The
`;req` components are therefore the ONLY binding — an acknowledgement that could be
lifted onto another notification would acknowledge nothing.

**What a signed 202 claims — exactly.** THE ENFORCEMENT BOUNDARY AUTHENTICATED AND
ACCEPTED THIS MESSAGE. Not that a requested cancellation completed, not that the
inner application observed the notification, not that any action was taken (#418).

**Proven by.** `bodyless_202_test` (11 tests, incl.
`signed_202_binds_only_to_its_own_notification` and
`the_bodied_request_set_still_requires_content_type` — the new sets must not have
weakened the old one).

### OPEN — the signed 202 cannot carry a delegation credential (needs an owner ruling)

The profile-crate component sets above are complete and tested. The **proxy serving
path is NOT wired to emit a signed 202**, because doing so would require breaking
one of three currently-ratified rules:

1. **§3.4 (published)** — the 202 is bodyless: no body, no `content-type`.
2. **Delegated-required (governing, 2026-07-13)** — delegated signing is the ONLY
   response-signing mode; direct-root response signing was deleted from the runtime
   surface and survives only as negative-test fixtures.
3. **ADR-MCPRE-052 §2** — the inline delegation credential (`server_delegation`)
   rides in the response evidence block, i.e. **in the response body**, protected
   because `content-digest` covers it.

A bodyless 202 has no body, so it cannot carry the credential that
delegated-required obliges it to carry. The three rules are jointly unsatisfiable
for this message shape. The options, none of them free:

| Option | Cost |
|---|---|
| (a) Give the 202 a minimal body carrying only the response evidence block | Contradicts §3.4's bodyless set — the published profile would need amending |
| (b) Carry the credential in a header | Violates E-3 (no new MCP-RE header fields); also unprotected unless covered |
| (c) Resolve the credential out of band / from cache | New trust seam and freshness surface; the client must obtain it somehow |
| (d) Exempt the 202 from delegated-required, resolving its key through the trust seam | Violates the governing delegated-required rule; reintroduces a direct-root signing path |

This is a signing-authority decision, so it is deliberately NOT taken here.
`sign_accepted_202` / `verify_accepted_202` implement the §3.4 shape faithfully and
are usable by a deployment whose response keys resolve through the trust seam
directly; wiring them into the delegated-required serving path awaits the ruling on
#418. Recorded there rather than resolved by implementation.

---

## §12.2 — the vector corpus is content-pinned

**Rule.** Every corpus manifest carries a per-file SHA-256 and a `corpus_digest`
over the sorted `<path>:<sha256>` list. Loaders verify each fixture's bytes
**before running it** and fail closed on mismatch. CI publishes both digests.

§12.2: "a tag or branch name alone is insufficient to prove that two reviewers used
the same corpus." A filename list — which is what the manifests were — has the same
weakness one level down: it proves which files were *meant* to be there, not what
was in them. Two reviewers on the same tag, one with a locally-edited vector, would
both report "corpus green" and mean different things.

**Sorted, so the digest tracks content and not emission order.** Otherwise
reshuffling the fixture builder would churn the published digest while every vector
stayed byte-identical, and reviewers would learn to ignore it.

**Verified before running, not after.** A fixture whose bytes do not match the
manifest is not a vector — it is an unknown file with a familiar name, and running
it would report a verdict about something nobody pinned. The corpus digest is
checked first, so a corpus cannot be edited into agreeing with itself.

**The external KATs are pinned too**, and they mattered most. `external_kat.json`
and `external_delegation_kat.json` are third-party artifacts — signatures produced
by python-cryptography, independently of ed25519-dalek — and they anchor the
independent cross-verification claim. Both were sitting in the corpus directories
**unpinned and unnamed by any manifest** until the no-unlisted-vectors check found
them. Silent drift there would have changed what "independently cross-verified"
means while every test still passed. They are hashed in place; the writer never
rewrites them.

**Published digests** (regenerate with the golden writers; CI emits these to the
job summary):

| Corpus | manifest SHA-256 | corpus digest |
|---|---|---|
| `http-profile` | `9e0080ec0dfe7def529f0e47bd12c43f4316fa2ca9f305a8f023e75adc535dc9` | `d8af1242831ce3be953ce2ec98a1a62e53e42e05f982b6fe734c1adeae1413ef` |
| `delegation-profile` | `82ff7b2b98b74f7d60af3d99f8fae52227c67852cfb954613cc6ae20f090a40c` | `899462fa9da4596bfc04c755d07cd6e0cc85abee7c3d5696396ecd13840311be` |

These pin the corpus AFTER the byte-changing work (#430 domain separation, #432
keyid migration), per the epic's sequencing note — so the corpus is pinned once,
against final bytes, rather than twice.

**Proven by.** `corpus_pinning_test` (5 tests): every fixture matches its published
hash AND no vector on disk is absent from the manifest; the digest commits to the
entries; a one-byte edit breaks the hash (the pin bites — a manifest carrying
hashes nobody checks is worse than no hashes, because it reads as a guarantee);
adding or removing a vector moves the digest; the digest is order-independent.

---

## §10 — the verified-context carrier and the reserved-field guard

**Rule.** The PEP may hand its verified conclusion to the inner server in a
RESERVED `_meta` block, `se.syncom/mcp-re.verified-context`, but ONLY under an
explicit trust configuration. Caller-supplied content at that key is stripped at
the boundary — always, whether or not the carrier is enabled.

**The carrier is not evidence, and that is the whole design.** Every other block in
this vocabulary is signed and digest-bound: anyone with a key can check it. This
one is the opposite — the PEP's *conclusion*, on the PEP's authority alone, with no
signature over it. That is deliberate. A signature would imply the inner server
could evaluate trust independently, which is exactly the job the PEP exists to have
already done.

**So the channel IS the trust.** The PEP → inner-server channel MUST be one only
the PEP can write to: loopback, a same-pod sidecar, a UNIX socket. If anything else
can reach the inner server, it can assert any verified context it likes and the
inner server has no way to tell. There is no cryptographic fallback here. That is
why `VerifiedContextPolicy` defaults to `Disabled` and enabling it is an explicit
operator act (`with_verified_context_carrier`) asserting something the code cannot
check.

**What it carries.** Trust-resolution OUTPUTS: the resolved `actor_id` to authorize
on, the verified audience, the request-evidence handle as the audit correlation key.
The presented `key_id` is included and explicitly labelled audit-only — a keyid is a
selector the caller chose, and handing it to the inner server unlabelled would
invite authorizing on the one value the attacker controls.

**The guard, and why it is unconditional.** A caller that could seed the reserved
key would be asserting its OWN verified context to a server that believes the block
implicitly — an authentication bypass, not a spoofing nuisance. The strip therefore
runs on every request regardless of policy: a deployment with the carrier disabled
must not be one config flip (or one reserved-key rename) away from forwarding
attacker-authored context. Strip first, write second, so what the inner server reads
is always the PEP's conclusion and never the caller's assertion.

**Proven by.** `verified_context_carrier_test` — in particular
`a_caller_seeded_verified_context_never_reaches_the_inner_server`, where the client
LEGITIMATELY SIGNS a body containing a forged admin context. The request verifies;
the forged block still never reaches the inner server, under both policies. A
signature proves who wrote the bytes; it never proves the bytes are true.
Also `context.rs` unit tests (the strip is idempotent and preserves unrelated
`_meta` keys).

**ADR-MCPS-008** recorded the propagation intent; this is its realization. The
carrier is additive and defaults off, so nothing about the existing serving path
changes for a deployment that does not opt in.
