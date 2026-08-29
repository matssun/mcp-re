<!-- SPDX-License-Identifier: Apache-2.0 -->

# Component Blueprint: Client Response Verification

**Census:** MCPRE-144 / [#580](https://github.com/matssun/mcp-re/issues/580) · ADR-MCPRE-061 §5.3, §8, §13
**Unit:** `mcp-re-client-core/src/response.rs`
**Measured:** 1105 production lines at `def5de1`, via `scripts/module_size_gate.py::production_lines`
**Outcome: DECOMPOSE.** Eight independently describable authorities, three of which have no
relationship to response verification at all. Not a §14 exception.

---

## 1. Purpose

The return leg of `crate::request`. Given a received `HttpResponse` and the context the client
kept from signing, it establishes that the response is genuine RFC 9421 + RFC 9530 evidence
bound to *this* request, on both the direct-root and the ADR-MCPRE-052 delegated-required
paths, and hands the caller a typed outcome.

The file is pure: no networking, no async, no filesystem. Trust resolution stays behind the
actor-resolver seam, which the proxy and the SDK bindings inject.

---

## 2. The twelve questions

### Q1 — What single security/control fact does this unit own?

**It does not own one.** A truthful one-sentence answer needs at least six "and"s:

> A received response is genuine evidence bound to this request, **and** the signer is the one
> policy pinned, **and** the credential chains to a root this client trusts at `now` under the
> rotation/overlap/revocation lifecycle, **and** the credential is not revoked, **and** the
> configured clock skew is bounded to the profile's range, **and** the server's execution/retry
> disposition is read back without inventing a state, **and** a preflight-unbound receipt is at
> least about these request bytes, **and** a bodyless 202 acknowledgement is authentic.

ADR-MCPRE-061 §8 states that an answer to question 1 needing an "and" is evidence of a shallow
authority boundary. This one needs seven.

### Q2 — How many independently describable authorities exist inside it? — **eight**

| # | authority | items | prod lines (approx) | depends on the others? |
|---|---|---|---|---|
| **A** | Bound response verification + unexpected-signer pin (direct-root) | `ResponseExpectation`, `verify_signed_response`, `enforce_expected_server_signer`, `check_expected_server_signer` | ~85 | — |
| **B** | Result classification / continuation | `ResultClass`, `ClassifiedResponse`, `verify_and_classify_response`, `classify_result`, `continuation_state` | ~80 | A (one call) |
| **C** | Delegated-credential revocation seam | `RevocationSource`, `StaticRevocationList` | ~60 | no |
| **D** | **Trust-anchor lifecycle** — root rotation, overlap window, root revocation, manifest expiry | `TrustedIssuerSet` (four states, two resolver forms, `is_expired`, retirement-wins) | ~215 | no |
| **E** | Delegation policy + clock-skew bounding — **EXTRACTED** to `delegation_policy.rs` | `DelegationPolicy`, `bounded_clock_skew`, `verifier_policy`, `with_expectations` | ~90 | no |
| **F** | **Execution/retry contract** (ADR-MCPRE-058 §10) | `ExecutionStatus`, `RetrySafety`, `ExecutionContract`, `rejection_receipt` | ~165 | **no — reads a verified body, performs no verification** |
| **G** | Delegated response verification orchestration | `DelegatedOutcome`, `VerifiedDelegatedResponse`, `verify_delegated_response`, `_anchored`, `check_unbound_receipt_is_about_this_request`, `RECEIVED_DIGEST_ALG` | ~230 | C, D, E, F |
| **H** | 202 acknowledgement verification | `verify_delegated_accepted_202{,_pinned,_anchored,_anchored_pinned}`, `delegation_issuer_kid` | ~145 | C, D, E |

**D, F and C are the clearest extractions.** D is a *trust-anchor lifecycle* — the master-key
analogue of revocation, with its own four-state model and its own contradiction-resolution rule —
sitting in a file whose subject is response verification. F is a *disposition vocabulary* over a
body that has already been verified; it performs no cryptography and has no dependency on any
other authority here. C is a two-method seam trait plus its in-memory implementation.

### Q3 — What does it decide?

- Whether a verified-but-unexpected signer fails closed (A, and the delegated form in G/H).
- Whether a root issuer is trusted **at `now`** — current, retired-in-window, retired-expired,
  revoked, unknown, or blanket-expired by manifest deadline (D).
- Which of `current`/`retired` wins when a manifest lists a kid in both — **retirement wins**, so
  a published retirement cannot be undone by a stale `current` entry (D).
- Whether a rejection receipt verifies bound, else unbound, and never unbound-as-success (G).
- Whether a preflight-unbound receipt is about *these request bytes* (G).
- What clock skew is actually applied: the configured value **clamped** to the profile's bound (E).

### Q4 — What does it merely execute?

The cryptography. Every signature check is `mcp_re_http_profile::Verifier::*`. This unit
supplies expectations and consumes verdicts.

### Q5 — What does it merely transport?

~~`DelegationPolicy`'s fields into `DelegationExpectations`~~ — it no longer transports them:
the fields are private in `delegation_policy.rs` and `with_expectations` is the single
projection, so this module receives the built expectations rather than the representation.
Still transported: the verified `VerifiedMcpResponse` out to the caller, and the verbatim
disposition tokens in `ExecutionContract`.

### Q6 — What facts does it reconstruct that another owner already decided?

**One real instance, and two deliberate non-instances that should stay non-instances.**

- **`delegation_issuer_kid` (H) re-derives a fact the verified product already carries.**
  On the bodied path the issuer kid comes from the verified product
  (`verified.delegation_issuer_kid`). On the 202 path the same fact is re-derived by re-scanning
  the raw headers, base64url-decoding the compact-JWS header segment and re-parsing it. The
  function's own doc concedes the hazard — *"on its own this parses an untrusted header"* — and
  is safe only because the caller calls it after verification. **One fact, two derivations, one
  of them from untrusted bytes, related only by call ordering.** See Q7.
- **`classify_result` is NOT a reconstruction** and must not become one: it delegates to
  `mcp_re_http_profile::result_class::classify_result_type`, so the SEP-2322 drift guard that
  pins the discriminator covers the proxy, chain reconstruction and both SDK bindings too.
- **`continuation_state` is NOT a reconstruction**: it forwards to
  `result_class::input_required_state`. This is load-bearing history — both SDK bindings
  previously open-coded the JSON walk and collapsed the malformed case to `None`, which their
  transports read as terminal, handing an elicitation to the application as a completed tool
  result. **Any decomposition must preserve the single discriminator.**

**A divergence worth recording separately:** for an out-of-range clock skew the profile's
`VerifierPolicy::new` **refuses**, while `DelegationPolicy::bounded_clock_skew` **clamps**. Two
dispositions for one illegal input. The clamp is deliberate and documented (a misconfiguration
should not make every response unverifiable, and both windows must read one number), but the two
owners state different things about the same value.

### Q7 — What security relationship exists only through call ordering or local variables?

**Three, and the first is the most serious.**

1. **The resolver/revocation pairing in `verify_delegated_response` (G).** The public function
   takes the root resolver and the `RevocationSource` as two independent arguments. Passing a
   `TrustedIssuerSet`-derived resolver together with an *empty* revocation list verifies
   credentials under a root the operator has marked **REVOKED**, with nothing indicating the
   revocation is inert. The codebase is fully aware of this: `verify_delegated_response_anchored`
   exists to take the set once, `anchored_resolver` is private *"only safe because the caller is
   this module"*, and the public `response_resolver` defensively refuses revoked issuers to make
   the raw seam safe alone. **The invariant is protected by a documented convention plus a
   defensive fallback — not by a type.** Revocation of a trust anchor is the one decisive action
   that invalidates every descendant credential at once; it must not depend on remembering to
   pass a value twice.
2. **`delegation_issuer_kid` must only be called after verification succeeds** (H). Enforced by
   documentation.
3. **`check_unbound_receipt_is_about_this_request` must run before an unbound receipt is
   reported as a refusal** (G). It does, in one call site, by construction of that function's
   body — not by a type that makes the unchecked unbound verdict unusable.

### Q8 — What public interface exists only because tests need it?

**Corrected at the ADR-MCPRE-067 Phase-9 re-run — the original answer counted textual
references and reported them as consumers.** Three of the numbers below were reference counts
over the whole repository, and a reference is not a consumer: `verify_signed_response`'s "3"
was its own definition, its `pub use` in `lib.rs`, and a *comment* in `mcp-re-host` explaining
that it is deliberately NOT re-exported.

Re-measured by call site rather than by grep count:

| item | production consumers outside this file |
|---|---|
| `TrustedIssuerSet`, `classify_result`, `DelegationPolicy`, `verify_delegated_accepted_202`, `StaticRevocationList`, `ResponseExpectation`, `ExecutionContract`, `continuation_state` | real — `mcp-re-client-proxy`, `mcp-re-client`, `mcp-re-host`, `sdk/python`, `sdk/typescript`, `mcp-re-conformance`, the proxy's async integration lanes |
| `verify_signed_response` | **none** — no caller anywhere in the repository, including tests |
| `verify_and_classify_response` | **none** — no caller anywhere in the repository |
| `verify_delegated_response_anchored` | **the item no longer exists**; PR #673 replaced it with the one-trust-authority seam |

So the honest answer to Q8 is not "none found". Two public functions have **no consumer at
all** — not a test, not a fixture, not a conformance vector. Whether they remain a supported
contract is deviation 5 below, and it is an owner decision rather than a census finding.

### Q9 — What branches are unreachable under the current legality model?

**Corrected at the Phase-9 re-run, for the same reason as Q8.** The four `TrustedIssuerSet`
states, the bound/unbound receipt fallback and the 202 path do all have production consumers.

The direct-root path does **not**. `enforce_expected_server_signer` (A) is documented *"Direct-root
mode only"*, and its only caller is `verify_signed_response`, which has no caller. It is therefore
unreachable from anywhere in this repository — the original "reachable" rested on the same
reference count Q8 corrects. The governing rule that **delegated-required is the only
response-signing mode** is what left it that way; see deviation 5.

### Q10 — What facts are represented more than once?

- The **root issuer kid**, per Q6 — from the verified product and from a raw header re-parse.
- ~~The **clock skew**, as configured (`DelegationPolicy::max_clock_skew`, `pub`) and as applied
  (`bounded_clock_skew()`)~~ — **CLOSED.** It is represented once. `new` clamps and the field is
  private, so there is no configured-but-unapplied value left to read.
- **`TrustedIssuerSet` is both a resolver and a `RevocationSource`** — one object, two seams, and
  Q7.1 is the consequence.

### Q11 — What inconsistent values can callers construct?

**All three carrier types have fully public fields, and one says so explicitly.**

- ~~`DelegationPolicy::max_clock_skew`~~ — **CLOSED.** `new` clamps, every field is private, and
  the type lives in its own module so the clamp binds the verifier next door rather than only
  callers outside the crate. `clippy::partial_pub_fields` is what forced the last step: sealing
  one field beside three `pub` siblings tells a reader which field somebody sealed, not which one
  carries an invariant.
- ~~`ResponseExpectation` — `request`, `request_evidence` and `expected_server_signer_keyid` are
  all `pub`, so an expectation can pair one exchange's request with another's evidence handle~~ —
  **CLOSED for the in-process half at the Phase-9 re-run.** The three fields are private, the type
  lives in its own `response_expectation.rs`, and `for_signed(&SignedRequest)` takes the owner that
  produced the pair rather than two halves — the five in-tree call sites were all destructuring
  `SignedRequest`'s sealed representation and re-pairing it (R-COMPOSE). `new(request, evidence)`
  remains for the FFI seam, where both SDK bindings rebuild the halves from scalars and no owner
  survives to be taken instead; THM-0018's caveat still covers that path, and per
  `docs/dev/sealed-owners.md` sealing past an external seam would be theatre.
- `TrustedIssuerSet` — a kid may be in `current` and `retired` simultaneously. The contradiction is
  resolved at *read* time (retirement wins) rather than made unconstructible. The read-time rule is
  correct and fails safe; the state remains representable.

### Q12 — Which test/build/proof lane actually establishes each claimed property?

**22 tests, one lane, zero theorems.**

- **Lane:** `#[cfg(test)] mod delegated_tests` in-file, no feature gate. Runs under
  `cargo test -p mcp-re-client-core --lib` and under Bazel
  `//mcp-re-client-core:mcp_re_client_core_test`. **Not a vacuous lane** — the tests compile and
  run in both. `mcp-re-client-core/tests/` does not exist; there is no integration lane for this
  crate.
- **Theorem inventory: `verification/policy/theorems.toml` holds 33 theorems and NOT ONE
  references `mcp-re-client-core`.** Every response theorem (THM-0016/0018/0019/0020 and the
  shared bound/unbound propositions) is stated over `mcp_re_http_profile::Verifier::*`.
  Classification per ADR-MCPRE-059:

  | property | status |
  |---|---|
  | the underlying signature/binding facts | **in registry** — over the profile verifier, inherited by this unit's calls |
  | the unexpected-signer pin (both paths) | **gap** |
  | the trust-anchor lifecycle: overlap window, retirement-wins, manifest expiry, revoked-root resolution | **gap** |
  | bound-then-unbound fallback, never-unbound-as-success | **gap** |
  | the received-digest binding of a preflight receipt | **gap** |
  | skew clamping equality across both windows | **gap** |
  | execution/retry contract: `Unstated` ≠ `NotExecuted` | **gap** |

  **This is the unit's largest evidence weakness.** Its most consequential additions — every
  decision in Q3 — are exactly the ones with no registry entry. Recorded, per #663's rule, without
  a numeric quota: the right number is the number that proves the propositions the extracted
  owners state.

---

## 3. Position in the system

```text
mcp-re-http-profile          the RFC 9421 + RFC 9530 carrier; ALL cryptography
        ^
        |  Verifier::verify_{bound,unbound,delegated_*}_response
        |
mcp-re-client-core/response.rs      THIS UNIT — expectations in, typed verdicts out. Pure.
        ^
        |
  +-----+------+--------------+-------------+
  |            |              |             |
client-proxy  mcp-re-client  sdk/python  sdk/typescript      injects the live resolver
```

---

## 4. Known deviations

1. ~~**Q7.1 — the resolver/revocation pairing is convention, not type.**~~ — **CLOSED**, PR #673.
   The verifier takes one trust authority; `resolve_root` is `pub(crate)`; `resolve_issuer` fails
   closed on a revoked issuer without consulting the caller's revocation half.
2. ~~**Q6 — `delegation_issuer_kid` re-derives a verified fact from untrusted bytes.**~~ —
   **CLOSED.** `verify_delegated_accepted_202_pinned` compares the pin against
   `AcknowledgedDelegation::issuer_kid()`, the verified product's anchor, and the function's own
   doc records that it used to re-parse the header. Its negative control is in
   `delegated_tests` (pinned-to-chained-root accepts, pinned-to-other-root fails closed,
   pinning the rotating delegated kid is not what the pin means).
3. **Q11 — the public-field carriers.** `DelegationPolicy` closed earlier;
   `ResponseExpectation` closed for the in-process half at the Phase-9 re-run (see Q11).
   `TrustedIssuerSet`'s current/retired contradiction remains representable and is resolved at
   read time — ruled correct and fail-safe, not a defect.
4. **Q12 — zero theorems over this crate.** Unchanged, and deliberately untouched: theorem work
   is frozen until the ADR-MCPRE-067 closure lands.
5. **`enforce_expected_server_signer` is documented "direct-root mode only"** — and the Phase-9
   re-measurement sharpened the question rather than answering it. It is not merely at odds with
   the governing delegated-required rule: it is **unreachable**, because its only caller
   `verify_signed_response` has no caller anywhere, and `verify_and_classify_response` has none
   either. `mcp-re-host` deliberately does not re-export the direct-root verifier and justifies
   keeping it reachable at `mcp_re_client_core::verify_signed_response` for *"negative-test
   fixtures"* — a stated purpose no fixture exercises. Deleting the two functions,
   `enforce_expected_server_signer` and the direct-root half of `ResponseExpectation`'s pin is a
   change to a published crate's public API, so **this remains the one owner decision this
   census hands up**, now with the measurement it was missing.
6. **The unbound-receipt binding is a BYTE binding, not an instance binding** — two transmissions
   of identical bytes share it. Correctly disclosed to the caller as `bound: false`; recorded here
   so no consumer treats it as instance-level.
7. **ADR-MCPRE-067 relevance: none found.** No mechanism/provider vocabulary (AWS, GCP, PKCS#11,
   Redis, TLS) appears above the mechanism boundary in this unit. `RevocationSource` is already the
   ontology-neutral shape ADR-067 §7 asks for: a narrow trait whose in-memory implementation is
   replaceable by a networked one without touching the verifier.

---

## 5. Outcome — decomposition

Not a §14 exception: eight authorities, three of them independent of the file's subject.

| move | why |
|---|---|
| **`TrustedIssuerSet` → its own module** (trust-anchor lifecycle) | ~215 lines, four states, its own contradiction rule; the master-key analogue of revocation, not a response-verification concern |
| **`ExecutionContract` + `rejection_receipt` → their own module** | ~165 lines reading a *verified* body; no cryptography, no dependency on any other authority here |
| **`RevocationSource` + `StaticRevocationList` → beside the trust-anchor lifecycle** | a seam trait and its in-memory implementation |
| **Seal the resolver/revocation pairing (Q7.1)** | make the unpaired combination unconstructible instead of documented |
| **Take the issuer kid from the verified product on the 202 path (Q6)** | one fact, one derivation |

Follow-up work gets its own issues, per this census's own terms. **No code changes in #580.**

### 5.1 — status of the five moves, re-measured at the ADR-MCPRE-067 Phase-9 closure

Measured with `scripts/module_size_gate.py::production_lines` on the Phase-9 tip; `response.rs`
was **1114** at the census (`def5de1`), 1105 in the implementation map, 1021 after PR #673.

| move | status | where it landed | prod lines |
|---|---|---|---|
| `TrustedIssuerSet` → its own module | **done** | `delegated_trust/anchors.rs` + `manifest_validity.rs` | 195 + 45 |
| `ExecutionContract` + `rejection_receipt` → their own module | **done** | `execution_contract.rs` | 162 |
| `RevocationSource` + `StaticRevocationList` → beside the lifecycle | **done** | `delegated_trust/revocation.rs` + `mod.rs` | 87 + 117 |
| seal the resolver/revocation pairing (Q7.1) | **done**, PR #673 | `delegated_trust/mod.rs` | — |
| take the issuer kid from the verified product on the 202 path (Q6) | **done** | `response.rs::verify_delegated_accepted_202_pinned` | — |

Two further extractions the census did not name also landed: `DelegationPolicy` →
`delegation_policy.rs` (149), result classification → `result_classification.rs` (93), and at
this closure `ResponseExpectation` → `response_expectation.rs` (86).

**`response.rs` is now 435 production lines**, out of ADR-MCPRE-061 §5.3's band-3 (>1,000)
range entirely. Of the eight authorities in Q2, A and B remain in the file alongside G and H;
A is the unreachable direct-root path of deviation 5, and removing it is the owner decision,
not a size question.

---

## 6. Completion criteria

- [x] All twelve questions answered
- [x] Blueprint committed and linked from `docs/architecture/README.md`
- [x] Implementation map measured with `scripts/module_size_gate.py` at a stated SHA (`def5de1`, 1105 lines); re-measured at the ADR-MCPRE-067 Phase-9 closure — see §5.1
- [x] Theorem inventory distinguishes *in registry* / *gap* honestly
- [x] Test/evidence inventory names the lane and confirms it is not vacuous
- [x] Outcome recorded: **decomposition**
- [x] No code changes
