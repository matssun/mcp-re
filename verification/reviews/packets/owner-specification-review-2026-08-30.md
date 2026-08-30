<!-- SPDX-License-Identifier: Apache-2.0 -->

# Owner security-specification review — the consolidated packet set

ADR-MCPRE-059 §14.7. Thirty-seven registered theorems, thirty-six of them never reviewed,
prepared as **five family packets in dependency order** rather than as thirty-six
conversations.

A review record is evidence about a *fingerprint*, never a field on the object approved. To
record a ruling, write `verification/reviews/specification/THM-NNNN.json` naming the
fingerprint in this document — get it fresh with
`tools/verification/review --fingerprint THM-NNNN` — and commit it. There is deliberately
no command that writes one.

**Nothing in this document is an approval.** No review record was written and none may be
derived from this file. What is here is the preparation: the questions answered where a
machine can answer them, and the reviewer's decision isolated where it cannot.

---

## What the reviewer is being asked

Eight questions per theorem (ADR-MCPRE-059 §14):

1. Is the statement literally true of the current code?
2. Does the security consequence follow from the statement?
3. Is the scope honest about what it does **not** prove?
4. Is the semantic owner the correct owner?
5. Are the dependencies logical dependencies rather than implementation nesting?
6. Do the supporting units actually measure the relevant implementation?
7. Are the assumptions explicit and no stronger than necessary?
8. Does negative evidence make every important V0 conjunct load-bearing?

**Questions 5, 6 and 8 have been answered mechanically for every theorem, and where the
answer was "no" it has been fixed rather than reported.** Those repairs are §7 below. What
remains for a human is questions 1–4 and 7, and for most theorems the honest preparation
finding is *nothing is at issue* — so each family below lists only its **decision points**.

A family may be ruled as a batch. A NEEDS CHANGE on one theorem does not block its
siblings unless the dependency graph says it does, and where it does that is stated.

---

## Reading order, and why

```
C1  time / freshness            THM-0002, THM-0001
        │  THM-0001 is consumed by nine verifier-result theorems
        ▼
C2  admission · artifact · continuation · lifecycle
        │  THM-0007 → THM-0008 → (THM-0015)
        ▼
C3  verifier results            the deepest single-owner family, nine theorems
        ▼
C4  communication / TLS         twelve theorems, one chain 0023→0024→0029→0031→0033→0034
        ▼
C5  trust / revocation / composition
```

The order is dependency order, so a NEEDS CHANGE is discovered before the claims that
stand on it are read. It is not a priority order.

---

## C1 — time and freshness (2 theorems)

| THM | fingerprint | state |
|---|---|---|
| 0002 | `sha256:8f620c3a…f4a2da6` | **already REVIEWED** — unchanged |
| 0001 | `sha256:1ac67880…07446f7` | for review |

### THM-0002 needs no new ruling

Its fingerprint is byte-identical to the one reviewed at issue #540. MCPRE-176 split
`time.rs` into `time/{mod,format}.rs`, which moved the unit's `source_inputs` and
`proof_dependencies` and left the theorem claim untouched — **which is the design working**:
a review record is over the claim, so source refactoring does not cost owner reviews.
Statement edits do.

**One mechanical defect, reported not fixed** (it would move the reviewed fingerprint and
cost the one review the registry has): THM-0002's scope says

> *"that `format_rfc3339_utc` round-trips a value in this range is a different proposition"*

and the function is named `unix_to_rfc3339_utc`. There is no `format_rfc3339_utc` in the
tree. **Decision:** repair the name and re-review (the claim is unchanged, so a re-ruling is
a formality), or leave it until the next substantive edit. Recommend repairing it in the
same change that lands #541's formatting-direction theorem, since that theorem is what the
sentence is pointing at.

### THM-0001 — decision points

* **Q7, the skew accessor.** The scope says the window is stated relative to `skew_of(policy)`,
  an opaque accessor, and that the theorem "does not establish that the configured skew is
  bounded or sane". That is honest, and it is also the whole of the claim's exposure: a
  deployment configuring a skew of a year satisfies THM-0001 and admits year-old requests.
  **The reviewer decides whether that residue wants its own bound-on-skew claim**, or
  whether the delegation battery's `configured_skew_above_the_hard_cap_does_not_widen_the_credential_window`
  already covers the case that matters.
* Everything else in this theorem is machine-checked: it is V1, `check_params` carries the
  proved postcondition, and the Verus lane re-establishes it on every change.

---

## C2 — admission, artifact verification, continuation, lifecycle (9 theorems)

| THM | fingerprint | owner |
|---|---|---|
| 0003 | `sha256:0dfcfbd7…9fb9e81d` | `http_profile.admission_currency` |
| 0004 | `sha256:8467be1b…62c60576` | `http_profile.admission_currency` |
| 0005 | `sha256:57f8fa5e…5e4fce6e` | `http_profile.admission_currency` |
| 0006 | `sha256:a4fdf6b0…efbccb74` | `http_profile.admission_currency` |
| 0007 | `sha256:9066c057…9cccd2c8` | `http_profile.artifact_typing` |
| 0008 | `sha256:893f38b3…02fd76e4` | `http_profile.artifact_verification_boundary` |
| 0009 | `sha256:38c93d25…11b0718a` | `http_profile.continuation_unbypassability` |
| 0010 | `sha256:bf760d7a…0bb025ec` | `http_profile.continuation_binding` |
| 0012 | `sha256:403ab4d7…646dd9b4` | `proxy.runtime_lifecycle` |

### Decision points

**THM-0004 — a caller obligation the theorem cannot discharge.** Its scope states plainly
that `AuthoritativeAdmission` carries a generation and a status and *no workload identity*,
so the proof quantifies over whatever record the caller supplied; generations are small
integers and collide across workloads by construction. The registered security consequence
— *"a workload whose admission has been superseded or revoked cannot buy a call"* — is
therefore true only if the enforcement point looks the record up under the very
`binding.admission_id` that was checked.

The scope says the serving path does that today and that nothing in the type forbids a
future caller from deriving the id from a header, a session field or a cache.

> **This is the sharpest question in the campaign.** Under R-SEAL the invariant belongs to
> the value: "every known construction site does the lookup correctly" is not a theorem, it
> is a remembered convention. **The reviewer decides** whether THM-0004 is (a) correctly
> stated with an honest caller obligation, or (b) a claim whose consequence outruns its
> statement and should either be narrowed or backed by making the unsafe call
> unconstructible — a lookup that takes the checked `admission_id` rather than accepting
> any record.
>
> I have not proposed a code change. It would introduce a materially new owner, which is
> outside the campaign authorization.

**THM-0008 — restated in Step A, first review.** The statement was FALSE against `main`
before this campaign and has been rewritten over the closed dispatch relation. The reviewer
should read it as a *new* claim, not as a re-approval:
* is *"matched one of MCP-RE's explicitly supported typed verification branches and
  satisfied that branch's required binding form"* the right spine, with the branch list as
  implementation fact rather than as the claim?
* is `http_profile.artifact_verification_boundary` the right owner, or should the dispatch
  relation live with `http_profile.artifact_typing` after all? (Step A's position: no —
  widening `artifact_typing` weakens THM-0007's proved postcondition, which ADR-MCPRE-065
  Slice 2 went out of its way to protect.)

**THM-0007 — unchanged, and deliberately not widened.** The reviewer is asked to confirm
the *non-widening*: `verify_artifact_binding`'s postcondition still says an `Ok` result is
one of the three OAuth types, and the pdp-decision verifier was built beside it rather than
inside it.

**THM-0009 — a WITNESS, not a control.** The scope says `continuation_verified` is
informational and that "a reader who greps for consumers, finds none, and concludes the
check is unwired has read it backwards". That is the right classification under the
produced-but-not-consumed rule — the producer made the unsafe state unreachable — but it is
a judgement the owner should confirm rather than inherit.

**THM-0012 — now has negative evidence.** It had none (§7.2). Three probes were added; M60
probes the registered consequence directly. Nothing else is at issue.

---

## C3 — the verifier-result family (9 theorems, one owner)

| THM | fingerprint | reads |
|---|---|---|
| 0014 | `sha256:f88e7b44…d350f94b` | request floor |
| 0015 | `sha256:668e1493…74d79cc6` | full request |
| 0021 | `sha256:4af426ca…1a950c84` | shared bound response |
| 0022 | `sha256:26250e9c…8f0813f2` | shared unbound response |
| 0016 | `sha256:72e76db6…dd3badb9` | bound floor, trust seam |
| 0017 | `sha256:077bfbfc…730613d1` | unbound floor, trust seam |
| 0018 | `sha256:671796d5…03e72090` | full bound response |
| 0019 | `sha256:0a94d825…126bc8cb` | delegated bound |
| 0020 | `sha256:a176280b…001a7ef1f` | delegated unbound |

This family is the best-instrumented in the registry: 27 mutation probes, and every scope
already carries the "characterizes values successfully returned by, not arbitrary
possession of" disclaimer.

### Decision points

**THM-0015 — restated in Step A.** Its artifact conjunct said every binding "was resolved to
credential material and verified", which the carried-decision branch makes false. It now
names the supported branch and both evidence sources, and a new scope paragraph says a
verified `pdp-decision` binding establishes *nothing about what the document authorizes*.
Read as a changed claim.

**THM-0018 — two unrelated request inputs.** The scope says so explicitly: the operation
receives a concrete request (for `;req` resolution) and separately a `RequestEvidence`
handle (for the block comparison), and *nothing here establishes that the handle was derived
from that request*. **The reviewer decides** whether that gap wants its own claim. It is the
same shape as THM-0004's: a relation the caller is trusted to maintain.

**THM-0019/0020 — the deliberate non-dependency.** Their scopes state they do NOT establish
and do not depend on THM-0016/0018, because on the delegated path the signing keyid was
never resolved through the trust seam — the seam answered for the credential's *root issuer*.
Confirm that this is a logical independence and not an omission (Q5).

**THM-0022/0020 — "must never be read as a weaker form of THM-0021".** The registry states
this as scope prose. There is no mechanism preventing a consumer from treating an unbound
result as a bound one; the types are distinct, which is the mechanism. Worth confirming the
type separation is what the reviewer thinks it is.

---

## C4 — communication, TLS and the identity chain (12 theorems)

| THM | fingerprint |
|---|---|
| 0023 | `sha256:72c13626…04378111` |
| 0024 | `sha256:1b56049b…59085703` |
| 0025 | `sha256:73971324…2e591e91` |
| 0026 | `sha256:6211e20e…771c7507` |
| 0027 | `sha256:6d9b496d…2770866c` |
| 0028 | `sha256:0630767e…5d3a0514` |
| 0029 | `sha256:98d57267…f826a9ef` |
| 0030 | `sha256:2bf3c037…a10b2375` |
| 0031 | `sha256:4845a2f6…a025464a` |
| 0032 | `sha256:ebdabeb7…d48b8e19` |
| 0033 | `sha256:f59c20bd…387c2cdd` |
| 0034 | `sha256:ad5f93e9…6f2f9e919` |

The deepest chain in the registry: `0023 → 0024 → 0029 → 0031 → 0033 → 0034`, with
`0025 → 0026 → 0027` and `0028 → {0029, 0030, 0032}`. **A NEEDS CHANGE on THM-0023 or
THM-0028 cascades**, so read those two first.

### Decision points

**The whole family's discipline is worth confirming once rather than twelve times.** Every
scope in it says some version of *this is NOT authentication, and two deliberately weaker
facts do not compose into a stronger one*. THM-0029's is the clearest: "Naming the product
Authenticated…" — the family is built around refusing to let a name imply a fact. **The
reviewer is asked to ratify that discipline as the family's shared reading**, after which
the individual scopes are applications of it.

**THM-0033 has no production caller.** Its scope discloses this and compares it to
ADR-MCPRE-063 Slice 5 and Slice 2, which also had none when built. Under the
produced-but-not-consumed rule this needs a classification: is
`current_authenticated_peer` a CONTROL awaiting a consumer, or a WITNESS whose producer
already made the unsafe state unreachable? **The reviewer decides**; the registry currently
implies the former without saying so.

**THM-0025/0026 changed shape in MCPRE-176 without changing meaning.** `interpret_rfc8410_spki`
was rewritten from a total-length test plus two slices into `strip_prefix` + fixed-width
`try_from`. The proposition is unchanged and is now *structurally* enforced — the length
equality that used to be a separate assertion is a consequence of the conversion. Probes
M32/M35 were re-adjudicated to the new anchor with the same defect shape. Nothing to rule
beyond confirming that "structurally enforced" is not a quiet strengthening of the claim.

**THM-0024's ASM-0030 boundary.** The claim divides at the parser boundary: that the
interpreted field set faithfully reports what the DER encodes is an assumed foreign
dependency, *not* part of the claim — "a wrong parser yields a faithful interpretation of
the wrong fields and this theorem still holds." That is the correct containment, and it is
also the family's largest trusted premise. Q7 should be answered deliberately here.

---

## C5 — trust, revocation and composition (5 theorems)

| THM | fingerprint | owner |
|---|---|---|
| 0013 | `sha256:222ff157…8ef7880e` | `proxy.online_ocsp_reachability` |
| 0035 | `sha256:3002efa5…868ca246` | `proxy.trust_configuration_state` |
| 0036 | `sha256:2a2ac674…c85eb2eb` | `proxy.trust_configuration_state` |
| 0037 | `sha256:bdb81b32…f458a0074` | `proxy.trust_plan` |
| 0038 | `sha256:b65b17d7…c7b74d41b` | `proxy.trust_composition_root` |

### Decision points

**THM-0013 — restated in Step A.** Same proposition, expressed over ADR-MCPRE-067's
`PeerRevocationRequest` / `OnlineRevocationEvidenceRequest` instead of the removed flat
`client_ocsp` field, plus a sentence noting the refusal is over the *selection* and
therefore already covers every responder parameter it carries. No policy change, no OCSP
wiring, no change to the retained RFC 6960 implementation. Read as a restatement.

**THM-0038's negative evidence is in the battery, not the probe registry.** Its control
`the_rule_would_catch_a_new_raw_read` is a self-test of the inventory mechanism — a mutation
probe written as a test. It was deliberately *not* duplicated into
`mutation-probes.toml` (§7.2). Confirm that reading, or ask for the probe.

**THM-0035–0037 now have negative evidence** where they had none. Four probes; see §7.2.

---

## Findings from the mechanical passes

### §7.1 — repaired: the trigger set no longer covered the fingerprint set

Step A added `deployment_request/revocation/*.rs` to `proxy.online_ocsp_reachability`'s
closure. No `paths:` filter in `verification.yml` matched them, so a change there would
dirty the unit and the lane would then not re-measure it — **a too-narrow trigger stops
asking rather than going red**. Repaired, plus the same gap for
`config_state/validation/mod.rs` introduced by §7.2's closure repair.

Worth the reviewer's attention as a process fact, not a theorem fact:
`scripts/verification_trigger_gate.py` runs in `local_gate.sh` and **in no CI lane**, so a
PR that narrows the trigger set below the fingerprint set passes every check.

### §7.2 — repaired: five V0 units carrying seven theorems had no negative evidence

`proxy.runtime_lifecycle`, `proxy.online_ocsp_reachability`,
`proxy.trust_configuration_state` and `proxy.trust_plan` declared `test://` only. A passing
battery is not evidence that a production check is load-bearing, and THM-0012's own scope
says its central argument is *"a match a reviewer reads, not a proof a prover checked"* —
exactly when the question must be asked.

Nine probes added, each observed turning a declared control red. Two are worth naming:

* **M60** probes THM-0012's registered consequence directly: collapse `FailedToStart` into
  `Stopped` and a runtime that never bound a listener records a clean drained shutdown.
* **M62 could not previously be asked.** `proxy.online_ocsp_reachability`'s battery called
  `online_ocsp_refusal` directly, so deleting the *boundary's* clause left every control
  green — a correct predicate that nothing calls establishes nothing, which is precisely
  the distinction the unit's own comment claims to draw. The unit now names the end-to-end
  control driving `app::run` with a programmatically built request, and its closure names
  the clause list.

### §7.3 — repaired in Step A: two provenance gaps and one false statement

THM-0008 FALSE and repaired at its ownership defect; THM-0015's "credential material"
corrected; `http_profile.verifier_results` gained the pdp-decision files a successful
`verify_request` depends on, with probe M57 for the conjunct they contribute; THM-0013
restated and its closure given the file holding `is_required()`.

### §7.4 — reported, not repaired

* THM-0002's scope names `format_rfc3339_utc`, which does not exist (C1 above).
* THM-0004's consequence rests on a caller obligation its statement does not discharge (C2).
* THM-0018's two request inputs are related only by caller discipline (C3).
* THM-0033 has no production consumer and no recorded classification (C4).

The last three are specification decisions, which is why they are here rather than fixed.
