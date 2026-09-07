# The client correctness slice — 2026-09-07

The v0.17 objective's Campaign A: finish the client-side security path, then stop. Three
items were named for it. **One was already closed in the tree**, and the measurement of that
is recorded here rather than assumed, because the other direction of the same mistake —
reading an issue's checklist as the state of the code — is a false green this repository has
already committed against itself.

## Item 1 — `delegation_issuer_kid` on the 202 path: ALREADY CLOSED, re-measured

[#672](https://github.com/matssun/mcp-re/issues/672)'s backlog names it as *next, not
started*: the bodyless-202 path re-parses the credential's issuer kid from raw untrusted
headers after another authority has already verified it.

It does not. `verify_delegated_accepted_202_pinned` compares the route's pin against
`AcknowledgedDelegation::issuer_kid()` — the VERIFIED product — and its doc states the chain
that makes that the anchor the response provably chained to: the credential header is a
COVERED component of the 202's signature, the root signature covers the JWS header, and the
credential verifier requires `header.kid == claims.issuer_kid`. There is no second reader of
the raw bytes to disagree with the first.

It closed in `75c0144c` ("the pin rule is one function"), whose own message records the
re-census that found the pin rule stated twice and made `check_expected_issuer` take the
coordinate. The negative control is
`response.rs::delegated_tests::a_pinned_route_refuses_a_202_from_another_root`.

**No work was done for this item, and none was needed.** The backlog row is stale; the issue
should be updated rather than the code.

## Item 2 — `verified_outcome.rs`: real controls, and one defect they exposed

Classified `ACTION_REQUIRED` by the ownership-remainder packet: the sharpest unowned client
proposition, needing new controls because registering a unit here would otherwise have to
cite another unit's.

**Five controls, over a real signing round trip.** `read_outcome` takes a
`VerifiedDelegatedResponse`, which is obtainable only from a verification that SUCCEEDED — so
every control drives a server-side delegated signature under a credential issued by the test
root and a client-side verification through the shipped verifier. Nothing constructs the
verdict by hand, which is what makes these statements about the deployed path.

| control | what it refuses to let happen |
|---|---|
| `a_verified_terminal_reply_is_success` | — (the positive case) |
| `a_verified_input_required_reply_surfaces_its_continuation_state` | "fails closed" being satisfied by refusing every non-terminal leg |
| `a_verified_input_required_reply_with_no_usable_state_fails_closed` | an elicitation reaching an application as a completed tool result |
| `a_verified_unrecognized_result_type_never_becomes_terminal` | a newer server's extension ending an exchange this client cannot classify |
| `a_verified_rejection_receipt_is_an_answer_and_never_a_success` | a provable denial read as a transport failure, or as a success |

**The defect the controls exposed: the message was classified TWICE.** `read_outcome` derived
the plain reply from the verified bytes, classified `plain.get("result")` with
`classify_result`, and then — inside the `InputRequired` arm — called `continuation_state` over
`response.body`, which PARSES THE MESSAGE AGAIN and classifies it AGAIN. That is the exact
shape `input_required_state_of` was introduced to remove; its own doc says re-parsing the
bytes to ask the question again "is how two readers of one message end up disagreeing about
what it says".

The second reader also made the composition's own refusal unreachable: the `.ok_or(...)`
guarding "input-required with no state" could never fire, because `continuation_state`
returns `Err` for that shape before the `Option` is ever inspected. A refusal that cannot
execute is not a control.

Repaired by asking once, over the `result` already in hand:

```rust
let kind = match continuation_state_of(result)? {
    None => ResponseKind::Success,
    Some(request_state) => ResponseKind::InputRequired { request_state },
};
```

`continuation_state_of` is the typed client-side face of
`mcp_re_http_profile::result_class::input_required_state_of`, added beside the existing
byte-shaped face rather than replacing it — the SDK bindings hold bytes and this caller holds
a parsed reply, and one classifier with two input shapes is not two classifiers. A control in
`client.execution_contract`'s battery pins that:
`the_parsed_face_and_the_byte_face_answer_the_same_question`.

Observable behaviour is unchanged in every case, including the error identity: the refusal a
malformed continuation produced was always `MalformedEvidence("input_required requestState")`,
from the reader that ran first.

Registered as `client.verified_outcome` / **THM-0126**, which depends on THM-0061 (what a
receipt's words mean) and is now in **THM-0076**'s closure — what a verified answer entitles a
caller to conclude is part of what that root promises.

## Item 3 — `startup.rs`: exercise the deployable composition

Also `ACTION_REQUIRED`. THM-0120 establishes what a refresh cycle DOES; that the deployable
always starts one was unmeasured, and the refresher is the only place anchors are WITHDRAWN
once the manifest in force has lapsed.

The refresher was **not** moved into a library to make it testable — the mandate ruled that
out, and it is not independently the right architecture: `startup.rs` is a module of the
BINARY crate because what the invocation asked for and what running means are the CLI shell's
own facts.

So the control drives `serve_until_shutdown` itself and observes the one effect only a
running refresher produces: the anchors in force become the EMPTY set. Two details make it a
statement rather than a coincidence:

- the manifest file is REMOVED after the startup load, so every refresh fails to read a
  document — which past the expiry is precisely the case where keeping last-good is wrong;
- the trust question is asked at the LOAD-TIME instant, before the manifest's own expiry, so
  "no longer trusted" cannot be an artefact of the clock having passed `expires_at`. At that
  instant the seeded set trusts the root, and only a withdrawal makes it stop.

**Measured load-bearing, not assumed.** Deleting the `AnchorRefresher::start` call from
`serve_until_shutdown` fails the control with its own message; the healthy path takes 2.2s.

Registered as `client.serving_lifetime` / **THM-0127**, depending on THM-0120.

### The lane could not reach a binary crate, and now can

`tested_symbols` accepted `lib#`, `doc#` and `tests/<name>#`. A deployable's own crate is
none of those, so this control could be written, run by `cargo test`, and named by no
declaration — the assurance platform had no way to say anything about the artifact an
operator runs.

`bin/<name>#` joins the family, in the three places that decide what a selector means:

- `_ecosystems.valid_target` / `test_argv` — `--bin <name>`, exactly selected;
- `_manifest._validate_in_crate_selectors` — a binary crate's modules live under the same
  `<pkg>/src` tree, so it carries the IDENTICAL obligation to declare the module in `paths`.
  Exempting it would put a deployable's controls outside every fingerprint component;
- `_fingerprint` — in-crate, therefore not a `test_sources` entry, for the reason the
  bullet above makes a checked fact rather than a hope.

Controls: `test_ecosystems.py::test_an_unknown_target_is_malformed_rather_than_skipped` and
`::test_each_ecosystem_selects_exactly_the_declared_symbols`,
`test_measured_inputs.py::test_in_crate_selectors_are_covered_by_the_units_own_paths`.
All fourteen `tools/verification/test_*.py` suites re-run.

## What this slice did NOT do

Items 3–6 of #672 — extracting the trust-anchor lifecycle, the execution contract, the
theorem gaps, the public-field carriers — are architectural decomposition, not defects on the
shipping path. The v0.17 objective is explicit that only the former blocks the release, and
the `response.rs` re-census belongs after those moves rather than before them.

## The client-response census, re-run on the remainder

The v0.17 objective asks one question of what is left: *is anything remaining a
security/correctness defect on the shipping path, or is it architectural improvement?*
**Architectural.** Three measurements support that, and the third corrects this packet's own
first draft.

### 1. Item 6's named carrier is already sealed

The census names `DelegationPolicy::max_clock_skew` as a self-documented public field. It is
not one: every field of `DelegationPolicy` is private, `new()` clamps the skew to the
profile's `0..=MAX_CLOCK_SKEW_BOUND`, and `with_expectations` is the whole projection. The
module documents why all four fields are private rather than only the invariant-bearing one —
"a type whose invariant-bearing field is private while its siblings are `pub` tells a reader
nothing about which is which". The row is dated evidence.

### 2. `response.rs` is 360 production lines, not 1105

The census figure counts the whole file. ADR-MCPRE-061 counts production lines — a test region
opens at `#[cfg(test)]` and counting resumes after it — and the module-size registry measures
it that way. Both figures are true of different things; only one of them is the threshold the
rule states.

### 3. The seal claim in this packet's first draft was too strong

It said `VerifiedDelegatedResponse` "is obtainable only from a verification that succeeded".
That is true of the TREE and false of the TYPE.

`verify_delegated_response` is the only producer in the workspace — measured, three
construction sites, all inside it, and no test anywhere assembles one. But
`VerifiedDelegatedResponse`, `VerifiedDelegatedMcpResponse` and
`VerifiedDelegatedUnboundResponse` all carry `pub` fields, deliberately, so the prover can
name them; `VerifiedMcpResponse::from_block` says in its own words that this is *"a
convenience, not a seal"*. A caller outside this workspace can assemble one.

The distinction is the one R-SEAL is about, and getting it wrong in a theorem's scope is worse
than leaving the seal open: *"this constructor checks X"* quantifies over sites, *"every
inhabitant satisfies X"* quantifies over the type, and only the second is a theorem. THM-0126's
scope now states the first, which is what the controls establish.

**Whether that chain should be sealed is `client.response_acceptance`'s question**, not this
unit's — and the answer is not obviously yes: the fields are `pub` for the prover, and a
Verus-proved postcondition outranks a seal. It is recorded as an open architectural question,
not as a defect.

### What that leaves

Items 3–5 of #672 are extraction and theorem allocation. Item 6's first carrier is closed and
its remainder is the question above. Item 7 is a question for its owner. **No security or
correctness defect remains on the client shipping path**, which is the condition the v0.17
objective set for moving to the release candidate.

## One edge is PROPOSED, not taken — a ratification question for the owner

THM-0126's first draft was recorded as a premise of **THM-0076**, and the local gate refused
it before anything was pushed:

```
claim-surface gate: FAIL
  §2 claims THM-0076, whose specification review is STALE_DEPENDENCY_CLAIM:
  changed since review: theorem_dependencies.
```

The gate is right, and the refusal is the useful outcome. THM-0076 is a **published** claim in
[`docs/spec/security-boundary.md`](../../../docs/spec/security-boundary.md) §2; adding a
premise republishes it in a form the owner has approved in no version now on the tree.
Ratification is an event, not an inference, and a root's decomposition is owner-ratified under
ADR-MCPRE-059 §21.1.

So the edge is out, THM-0076 stands exactly as ratified, and THM-0126 stands as an owned local
claim — which the registry explicitly tolerates.

**The question, in one line:** THM-0076 promises that *"what the client may conclude about
whether the work ran is what the receipt states"*. THM-0126 establishes the neighbouring
proposition — that a **verified** answer this client cannot classify never becomes *the call
finished*. Should it be a premise of that root?

Arguments both ways, so that the answer is a decision rather than a default:

- **For.** The root's subject is what the shipped client proxy hands an application as this
  call's answer, and an unclassifiable `resultType` resolved to terminal is exactly such a
  handing-over. The root already depends on THM-0061, which is the classification rule this
  composes.
- **Against.** THM-0076's own scope names *response acceptance* — whether these bytes are
  genuine and answer this request. Whether a genuine answer means the exchange is finished is
  arguably the next question rather than part of that one, and #834's sibling THM-0091 was
  kept out of THM-0076 on precisely that reasoning ("that root's subject is response
  acceptance, and this attack completes before any answer exists").

Adding it costs a re-review of a published root claim; leaving it out costs a root whose
closure does not mention a proposition its consequence arguably depends on. Either is
defensible and neither is mine.
