<!-- SPDX-License-Identifier: Apache-2.0 -->
# Owner review packet — THM-0094, the shipped Python SDK root

**One subject.** ADR-MCPRE-059 §14.7 / §28, issue #746. Layer 1: evidence about the tree,
not an approval and not authoritative state.

THM-0095 is deliberately absent at the owner's instruction: THM-0094 is a declared
supported-client root, and its exchange semantics, bounded-reader obligations, assumptions
and evidence are to be reviewed independently before the reasoning is mirrored onto
TypeScript. THM-0042 is not in this packet either.

---

## 1. The claim

### Title

The shipped Python SDK accepts only an answer to its own request

### Statement

> For the shipped Python SDK, an application is not handed, as this call's answer, a response
> from another exchange or signer, or one that verified only unbound — and is not led to
> repeat a side effect by reading silence as *it did not run*.
>
> Every reply is taken from the correlation entry the request created, and a reply binding to
> nothing outstanding, arriving late, or repeating one already answered is refused rather than
> delivered. A response is accepted only under the configured trust anchor, epoch, audience and
> revocation posture, measured against a RECORDED delegated session rather than a constructed
> one. A notification is delivered only against a signed acknowledgement. An elicitation pauses
> a call rather than ending it, so a reply that is not terminal — including one whose result
> type this SDK does not recognise — is refused rather than surfacing as the call's answer.
> A verified reply that is not an answer to this request — one carrying a method, or one with
> neither result nor error — is refused rather than dispatched. What the application is told
> about execution is what the receipt said: whether the receipt was bound to THIS transmission,
> the execution and retry contract a post-dispatch rejection stated, no member the receipt did
> not carry, and a local failure under the SDK's own prefix rather than a wire code the peer
> never sent.

### Security consequence

> An application driving MCP through this SDK cannot be handed another exchange's answer, an
> answer from a signer this deployment does not trust, or a refusal that verified only unbound
> — and cannot be told that an operation did not run when the SDK does not know that.
>
> The last is the one a byte-level fixture cannot reach. Parity fixtures pin what this SDK
> EMITS; whether it invents `not_executed` for a receipt that stated nothing is behaviour, and
> the two SDKs have diverged there before.

### The four propositions, separated

The statement is one sentence per authority rather than one composite promise, and the review
question is whether each is the lowest honest form:

| # | proposition | what would falsify it |
|---|---|---|
| 1 | **correlation** — every reply comes from the entry this request created; nothing outstanding, late, or already answered is delivered | a reply matched by id alone, or a duplicate delivered as a second answer |
| 2 | **authenticity** — accepted only under the configured anchor, epoch, audience and revocation posture, against a RECORDED delegated session | a constructed session standing in for a recorded one; an out-of-epoch or wrong-audience response accepted |
| 3 | **terminality** — a non-terminal or unrecognised reply pauses or is refused, never surfaces as the call's answer | an unrecognised result type read as terminal; an elicitation ending the call |
| 4 | **execution honesty** — what the application is told about execution is what the receipt said | inventing `not_executed` for a receipt that stated nothing; a local failure wearing a wire code |

Proposition 4 is the one the ruling should read hardest: it is the only one a byte-level
parity fixture cannot reach, and it is where the two SDKs have actually diverged.

### Scope, verbatim on the two boundaries that matter

> It is one MEMBER of a root family, not the family. THM-0076 is the Rust member and THM-0095
> the TypeScript one; none of the three establishes anything about the others, and a green
> parity fixture is not a substitute — it compares bytes, and every divergence this family
> exists for is behavioural.

> CONCURRENCY AND THROUGHPUT ARE OUTSIDE IT. The exchange bound is a resource ceiling, and a
> difference from the TypeScript member there changes nothing about authenticity, correlation
> or execution. Deadline behaviour enters only where a timeout changes the client's conclusion
> about whether the remote side may have executed.

### Dependencies and owner

`depends_on = []`. `owner = "sdk_python.exchange_path"`,
`review_requirement = "Owner security-specification review"`,
`supported_by = ["unit://sdk_python.exchange_path"]`. Declared in `root_theorems` beside
THM-0095 and THM-0076 as a member of the supported-client root family.

---

## 2. The bounded-reader obligation — registered, not claimed

This is the part of the packet that asks for a decision rather than a reading.

**The fact.** `_read_bounded` evaluates the aggregate wall-clock bound BETWEEN completed
`response.read(want)` calls, and `http.client` fills to `amt`. A peer trickling under the
per-recv socket timeout keeps ONE call outstanding, and the aggregate deadline is not
consulted while it does. The docstring's cap claim was false, and R9-C010 (high) recorded it
as `SURVIVES_AND_MAPPED`.

**What the theorem does with it.** It states the consequence and no more: for such an
exchange the SDK reports NOTHING rather than reporting that the call did not execute. An
inert deadline yields no conclusion, not a wrong one. The looseness reaches the root only
where a caller's own outer timeout produces a retry whose execution status the SDK never
determined — and the scope states that condition rather than assuming it away.

**The registration.** ASM-0042, scoped to `unit://sdk_python.exchange_path`, owner
`mats@sundvall.name`, mechanism `foreign-dependency`, introduced by §28 / #746 (D7).

```
ASM-0042 digest  sha256:cc634daf6e6d42aac2cba992638869690fb16c2e1cae26157a09a0198fdb8f36
review_requirement  Owner review; any change to `_read_bounded`, to the bounds it is given,
                    or to what the SDK reports for a read that ended on the caller's clock.
```

Its justification names its own discharge condition — it stops being acceptable if the SDK
begins to REPORT an outcome for a read the deadline did not bound, or if `http.client` gains
short-read semantics — and it names the evidence defect it does not repair: **R9-C094**, the
test pinning the bound uses a fake whose short-read semantics `http.client` lacks, so that
control cannot fail. The premise does not launder that; it records it.

**Three things the owner may want to rule on separately:**

1. Whether registering the premise is the right disposition, versus fixing `_read_bounded`
   to bound a single read and discharging ASM-0042 outright.
2. Whether "reports NOTHING" is the honest ceiling for proposition 4 under an inert deadline,
   or whether the root should say less.
3. Whether the R9-C094 evidence defect — a control that cannot fail — is acceptable INSIDE a
   root's support closure while the premise stands.

**Assumption-axis status: UNREVIEWED.** `verification/reviews/assumption/` does not exist;
no assumption in the registry carries a record on its own axis. A specification approval of
THM-0094 alone leaves the assumption axis open, so the theorem stays unestablished on the
conjunction either way. If the intent is to close both, this packet is where ASM-0042's
digest is, and the record is a separate file on a separate axis.

**The R9 rows predate the root and are not edited.** Both dispositions still read
`"theorem": null` / `"node": "no THM (SDK unrooted)"`, which was true when they were measured
and is not now. `r9-dispositions.json` is layer-1 raw measurement, kept permanently and never
edited into truth, so the correction belongs in a later re-derivation, not in that file.

---

## 3. Evidence

One unit, `unit://sdk_python.exchange_path`, class V0, evidence
`test://sdk_python/exchange_path/root_battery`, no unit-declared assumptions (ASM-0042 reaches
it through the assumption's own `scope`).

Declared paths: `transport.py`, `correlation.py`, `authorization.py`, `custody.py`,
`mtls.py` under `sdk/python/python/mcp_re_sdk/`.

**31 controls, and the lane that ran them.** The verification workflow's macOS-host job at the
merge of #788 reported, for this unit:

```
verify-tests: sdk_python.exchange_path
    sdk/python pytest: 31 test(s)
  PASS: pytest: 31 passed
```

That is the lane actually reaching this battery — `cargo test --workspace` and
`bazel test //...` say nothing about it. The controls map onto the four propositions:

| proposition | controls |
|---|---|
| correlation | outstanding-entry teardown on failure and on close, one exchange's network error not taking down the session, and the three `TestFailsClosed` cases — binds to nothing outstanding, late, duplicate-as-replay |
| authenticity | recorded delegated session verifies and arrives as plain MCP; one appended body byte fails closed; untrusted root anchor; outside the accepted epoch; wrong audience; revoked delegated key; unsigned acknowledgement; a non-202 answer to a notification |
| terminality | the adapter drives the answer leg to a terminal result; an unanswerable elicitation refused rather than delivered; a declined elicitation refused; a non-terminal reply without usable state; an unrecognised result type not read as terminal |
| execution honesty | an unbound rejection receipt reported as not request-bound; a post-dispatch rejection reporting its execution and retry contract; a verified reply carrying a method refused; one with neither result nor error refused; a verified rejection receipt delivered as an error not a result; a wire failure delivered as a correlated JSON-RPC error; a local signer failure and an unexpected exception delivered without claiming a wire code |

Two controls are negative controls over the fixtures themselves —
`test_the_fixture_is_otherwise_genuine_evidence` in both the malformed-elicitation and
unrecognised-result-type files — so a fixture that fails for an unrelated reason cannot pass
as evidence for the property.

**What the evidence does not cover**, stated rather than implied: the aggregate read bound
(§2, and its control cannot fail), concurrency and throughput, anything below the transport
beyond what ASM-0042 names, and any application that bypasses this adapter.

---

## 4. Fingerprint and status

```
THM-0094  sha256:d265298b6282bba0e9f418b3ebbb8a37a84e9cf5fbd1c39fae4d42a02b754dde
  theorem_claim         sha256:a6d3dac2dcb2a0245e3deb4bfc29e359fad018e806cf11582e1a5909c1bfcbb3
  theorem_dependencies  {}
  review_requirement    Owner security-specification review
```

Measured at merged main `e725e9b7`.

Specification review: `UNREVIEWED` — never reviewed. Assumption axis: `UNREVIEWED` for
ASM-0042. Unit evidence: measured PASS by the macOS-host verification lane; the local
attestation store is per-machine and gitignored, so `review` prints `UNKNOWN` on any fresh
clone.
