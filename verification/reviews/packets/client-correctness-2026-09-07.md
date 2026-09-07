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
