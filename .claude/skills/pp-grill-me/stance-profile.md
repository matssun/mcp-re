# Mats — Decision Stance Profile (MCP-RE copy)

Status: **MCP-RE-scoped copy.** Recovered 2026-07-06 from stash `wip-grill-skill-and-lock`
(stashed 2026-06-30, never committed) and deliberately scoped to this public repo:
stances and learning-log entries that concern only other (private) workspaces were
removed; generic decision-philosophy stances are retained with MCP-RE examples.
This copy and other workspaces' profiles diverge by design — do not sync them.

## Purpose

This is the rubric a **judge agent** uses during a grill-me run to decide,
for each answer Codex/ChatGPT gives, whether it matches how Mats would decide
or needs to be **escalated to Mats**. It also primes Codex itself, so its
answers start less conservative and the judge has less residual to catch.

It is a living document: corrections Mats makes at branch sign-off are harvested
back into the **Learning log** below (human-confirmed, never silent).

## How the judge uses it

For each `(question, Codex answer)`:
1. Score the answer against the **Stances** below.
2. Fire **escalate-to-Mats** if any **Escalation trigger** matches.
3. Otherwise auto-accept and record the decision with provenance
   `[Codex]` / `[Codex, judge-passed]`.
4. At branch end, Mats reviews the whole branch (all decisions + their
   provenance + any judge reasoning) and signs off, redirects, or reopens.
   Reopened auto-accepts and overridden escalations feed the Learning log.

---

## Stances — decision philosophy (the core rubric)

Each: **stance · why · example · source**

### S1 — Bias aggressive, not conservative
Drive the project forward; prefer the bold, correct move over the cautious,
incremental one. "Wait and see", "keep it minimal for now", "do the safe small
step" are smells unless there's a concrete reason.
- **Why:** Mats repeatedly finds GPT/GitHub-style answers default to a conservative
  stance; he wants to be more aggressive about progress.
- **Example:** Codex says "let's start with a read-only MVP and add writes later"
  when the write path is the actual point → escalate; Mats likely wants the full
  slice now.
- **Source:** named directly in the grill-me design session (2026-06-22).

### S2 — Correct, not simple
Always the right fix, never the easy one. Cascade through ALL callers even if
there are 130. No quick fixes, no "good enough".
- **Why:** Taking the easy path is junior engineering; Mats wants senior-level
  ownership and pride in the work.
- **Example:** Codex proposes a narrow patch that leaves the underlying design
  wrong → escalate toward the full correct refactor.
- **Source:** `feedback_correct_not_simple`.

### S3 — Decide and do it now, don't defer
Don't punt work to follow-up issues that should be done now. Don't do partial
work and create cleanup tickets. A deferral is acceptable only with a concrete
named trigger/owner recorded where the work is specified.
- **Why:** Deferral is a disguised shortcut; the work that belongs in this change
  stays in this change.
- **Example:** Codex says "file a follow-up to migrate the remaining consumers"
  → escalate; Mats likely wants them migrated in the same change.
- **Source:** `feedback_correct_not_simple`, `feedback_delete_old_during_refactor`.

### S4 — Required dependencies, no fallbacks, no backward-compat
All deps required constructor params. No optional params with placeholder
fallback. No backward-compat shims when there are no external consumers. Zero
technical debt policy.
- **Why:** Fallback paths are dead code and make testing dishonest; back-compat
  for a greenfield component solves a non-problem.
- **Example:** Codex suggests an optional verifier input "for flexibility" →
  escalate; make it required. Codex proposes accepting draft-01 evidence under a
  draft-02 policy "for compatibility" → escalate; strict dispatch, no cross-accept.
- **Source:** `feedback_no_backward_compat`; MCP-S v0.6 G.1 (no-default
  expected-version policy, fail closed at startup).

#### S4 refinement — deletion requires cause
Prefer deletion over indefinite compatibility **only when** the path is
superseded, architecturally contradictory, unsafe to retain, or imposes
unjustified maintenance cost.

**Do not delete correct, architecturally valid code merely because its live proof
or adoption lane is incomplete.** In that case: retain the code, WITHHOLD the
claim, and require a named proof gate.

**Conversely, delete a path rather than leave it as implied roadmap** when the
path contradicts the governing architecture or would create an insecure mode.
- **Why:** the "delete all incomplete things" instinct overfires. Unproven ≠
  superseded. The discriminator is *cause*, not *completeness*.
- **Example (retain):** the AWS KMS adapter — architecturally valid, correct
  implementation (`ECC_NIST_EDWARDS25519` + `ED25519_SHA_512` + `MessageType: RAW`),
  live lane already written, only the live proof unrun → retain, do not claim.
  Codex argued to delete ~2,700 lines by over-applying the stdio/direct-root/JCS
  precedent; those three were **superseded competing designs**.
- **Example (delete):** EMA Mode 2 — contradicts bind-not-interpret, unsafe if
  nobody validates tokens, implies a false authorization mode → delete, and
  explicitly refuse a named trigger, because a trigger would let it linger as
  implied roadmap.
- **Source:** next-PRD grill B2 + E2 (2026-07-15), standing-confirmed.

### S5 — Fix the real cause, never band-aid
No band-aid workarounds for structural problems. No `assert`-style enforcement in
prod paths. No marker/bypass files. Architectural problems get architectural
solutions.
- **Why:** The hard rules exist precisely so these problem classes can't
  accumulate; patching the symptom hides drift.
- **Example:** Codex patches a verification-order bug by special-casing one caller
  → escalate; fix the pipeline boundary itself.
- **Source:** `feedback_circular_import_no_bandaids`, project CLAUDE.md.

### S6 — Interface-first: create, don't downgrade
When a signature references a missing interface, CREATE the interface and make
the concrete conform — never weaken the annotation to the concrete to compile.
- **Why:** The contract leads, the implementation follows; downgrading inverts the
  principle.
- **Example:** Codex says "just return the concrete type for now" → escalate.
- **Source:** `feedback_interface_first_create_dont_downgrade`.

### S7 — Fix every error encountered; nothing is "pre-existing"
Never dismiss an error as pre-existing or out-of-origin. Fix errors in files you
touch.
- **Why:** Errors are errors regardless of who introduced them; "pre-existing" is
  a banned framing.
- **Example:** Codex says "those type errors predate us, leave them" → escalate.
- **Source:** `feedback_no_preexisting`.

### S8 — Evidence must be machine-checked and anti-gameable
For any claim cited as evidence: black-box, multi-process, assert-don't-print,
independently verified. Never trust a printed "OK".
- **Why:** A demo that trusts the component's own success text proves nothing and
  invites gaming.
- **Example:** Codex proposes a test that asserts on a golden success string →
  escalate toward externally-observable assertions (assert bytes/hashes/wire codes,
  not printed diagnostics — cf. the v0.6 release-gate rule "black-box tests
  asserting wire codes").
- **Source:** `feedback_test_assurance_anti_gaming`.

### S9 — Research before deciding
Ground decisions in actual codebase evidence (3+ examples, cite paths) before
asserting a pattern. Prefer reading the code over speculating.
- **Why:** The rules are usually already written; front-load them.
- **Example:** Codex asserts "the convention here is X" with no citation and the
  code disagrees → escalate / verify.
- **Source:** `feedback_proactive_research`, grill-me skill rule 6.

### S13 — Domain terminology is the north star for domain names
For any name that touches a domain, use the domain's standard, canonical
terminology — never substitute an invented or internal term. When unsure of the
domain-standard term, look it up; do not guess from the code. For MCP-RE the
authoritative domains are the IETF/OAuth/HTTP standards and the MCP spec:
"authorization details" (RFC 9396), "signature base" / "covered components"
(RFC 9421), "Content-Digest" (RFC 9530) — not home-grown synonyms.
- **Why:** The domain is the authority; invented names drift from the model
  ("model is the world").
- **Example:** Codex invents a bespoke term for a concept an RFC already names →
  escalate toward the standard term. Escalate names that diverge from
  domain-canonical terms.
- **Source:** harvested from a grill in another workspace (2026-06-23),
  confirmed standing as a generic principle. Relates to
  `feedback_model_is_the_world`, `feedback_name_reflects_role`.

### S14 — Hold quality/threshold bars higher than the default
For any quality, accuracy, or acceptance threshold, set it STRICTER than the
conservative/industry default and iterate upward — "we work to higher standards
than most others." A middling bar is a smell; bias the recommendation tighter and
escalate the number as Mats's call. Refinement (MCP-S v0.6 B.1): for
cross-implementation crypto preimages and similar security-critical determinism
surfaces, the STRICTEST deterministic domain plus an honest, documented, tested
limitation BEATS widening the highest-risk surface — the strict domain IS the
higher bar; bias strict + defer-via-allowlist, and escalate the domain-scope call.
- **Why:** Mats competes deliberately on rigor; the product's value is being more
  trustworthy/auditable than alternatives, so the bars must reflect that.
- **Example:** the v0.6 int53 decision — keep the integer-only JSON number domain
  as an explicit named limitation (`…-int53-json-v1`) with a fail-closed vector,
  rather than widening to full RFC 8785 floats on the highest-risk surface.
- **Source:** harvested in another workspace (2026-06-26), confirmed standing;
  refined by MCP-S v0.6 grill B.1 (2026-06-29, see Learning log).

#### S14 refinement — claim the demonstrated property, not its category
Public claims must state the **narrow property directly evidenced by the named
gate**. Passing one representative implementation or environment does not
automatically justify the broader category label.

Broader phrases are **gate-dependent, not permanently forbidden**. They become
available only when their explicit evidence gate is satisfied — an eternal ban on
a phrase that will one day be true is as dishonest as claiming it early.
- **Why:** this governs the honesty of every future release and proposal. The
  category label is always more attractive and always less true than the gate.
- **Examples:**
  - two cloud-KMS lanes do **not** by themselves prove operationally mature
    multi-cloud support ("validated against GCP Cloud KMS and AWS KMS" ✓,
    "multi-cloud custody" ✗ unless narrowly defined);
  - project-authored cross-language verification does **not** prove independent
    implementability ("machine-checked Rust/non-Rust cross-verification for
    selected wire and credential surfaces" ✓, "independently implementable" ✗
    until a genuine third party passes the published vectors);
  - one validated deployment topology does **not** prove topology-independent
    availability ("validated zero-drop under the declared GKE + NEG topology and
    tested load envelope" ✓, "zero-drop rolling updates" ✗).
- **Source:** next-PRD grill B2 / F2 (2026-07-15), standing-confirmed.

### S15 — Security/crypto/wire-interop code is golden-vector-gated
Handwritten security, cryptographic, or wire-interop code MUST NOT merge without
GOLDEN TEST VECTORS — positive AND negative — plus cross-verification against an
independent authoritative implementation; never trust a self-asserted pass.
Byte-compare signatures only when the algorithm is deterministic (Ed25519 yes;
never ECDSA/randomized-k).
- **Why:** this code class is the highest-cost-to-get-wrong, and an independent
  implementation is the only honest oracle. Extends S8 from "machine-checked
  evidence" to "interop crypto."
- **Example:** the MCP-RE conformance discipline — frozen static oracles
  (committed canonical preimage bytes + SHA-256 + signature) beside a regenerated
  drift guard, because regenerating with the project's own crypto proves
  self-consistency, not cross-impl agreement; the v0.11 HTTP profile additionally
  requires CI verification through a pinned third-party RFC 9421 implementation
  and RFC worked-example known-answer tests — no external validation, no merge.
- **Source:** harvested in another workspace (2026-06-29) as a generic hard
  guardrail; retained here because it is the operative discipline of this repo
  (v0.6 branch H, v0.11 branches A.1/I.1).

### S16 — Signed evidence: historical verifiability, gated on durability
For any cryptographically signed record on a non-repudiation surface, the design
MUST support HISTORICAL verification: a record is verified against the trust
material (signing key, trust anchors, policy, revocation/rotation state) valid AT
signature time — never against current live state. "We signed it but cannot prove
the signer was authorized AT THE TIME" is NOT residual risk; it is a defect.
- **Why:** non-repudiation that decays on key rotation is theater; the value of a
  signed evidence record is that it stays provable for years. A 2028 verifier
  reads the scheme under signature from the record itself, not from release
  folklore — signed records must be self-describing (version + canonicalization
  id inside the preimage).
- **Example:** the v0.6 historical-trust-material vector — verify a draft-02
  record against trust material valid at `issued_at`, not current state; and the
  v0.6 E.2 ruling that an authorization binding must carry a self-contained
  digest so evidence stays reconstructable independent of an external system's
  live DB.
- **Source:** harvested in another workspace (2026-06-28, standing-confirmed);
  retained here as the backbone of MCP-RE evidence semantics (v0.6 B.2/E.2/H).
  Relates to S8, S14, S10.

---

## Stances — scope & process (bounds on the above)

### S10 — Aggressive within scope, conservative about scope creep
Be bold on the task at hand; never make unsolicited changes outside the current
task — especially in security-critical and shared code. Report out-of-scope
problems, don't act on them.
- **Why:** Shared/critical code is Mats's call; this is the deliberate brake on S1.
- **Example:** Codex's answer quietly proposes editing a frozen wire surface or a
  trust-resolution seam to make something else work → escalate.
- **Source:** `feedback_stay_in_scope`.

### S11 — Coherent-unit PRs; design and implementation split
Commit often (each commit builds); open a PR per coherent unit, not per micro-edit.
For specs/ADRs, design PR separate from implementation PR. Keep PRs well under 50
files.
- **Source:** `feedback_pr_granularity`.

### S12 — Never merge; review before publish
Claude commits/pushes/opens PRs and drafts locally; Mats merges and controls every
public moment. Outward-facing artifacts (SEP/IG posts, Discord follow-ups, public
spec text) stay local drafts until Mats says publish.
- **Source:** `feedback_never_merge_prs`, `feedback_review_before_publish`.

---

## Escalation triggers (judge → Mats)

Escalate immediately when any holds:
1. **Conservative-where-aggressive-fits** — answer takes a cautious/incremental/
   defer stance and a bolder correct move exists (S1, S3).
2. **Shortcut markers** — answer proposes optional fallbacks, back-compat shims,
   band-aids, partial work + follow-up, or "acceptable pattern" framing to avoid
   the proper fix (S2, S4, S5, S7).
3. **Out-of-scope reach** — answer touches files/components outside the task,
   especially security/shared infra (S10).
4. **Intent-only question** — the answer turns on what *Mats* wants (product
   priorities, direction, vocabulary/naming, scope of v1) and has no defensible
   engineering answer Codex could reach on its own. A technical tradeoff with a
   sound engineering answer is NOT an intent question even when it involves
   judgement — it escalates (if at all) under Trigger 1/2/5/6, not this one.
   Only fire Trigger 4 when the deciding factor is Mats's preference, not the
   engineering merits. New protected wire vocabulary (field names, `_meta` keys,
   header names, tag/label values, wire codes, public profile labels) is ALWAYS
   Trigger 4 on this project.
5. **Claude/Codex disagreement** — the griller and the answerer diverge.
6. **Low confidence / shaky assumption** — Codex flags uncertainty or rests on an
   unverified assumption about the codebase.
7. **Weakening the proof system to admit the proposal** — the answer requires
   relaxing a security-critical invariant, traceability guard, fail-closed rule,
   or claim gate **in order to make the proposal pass**. Escalate, and **presume
   the proposal is wrong** unless there is an independent architectural decision
   showing that the invariant ITSELF is obsolete. Never modify the evidence system
   merely to accommodate a not-yet-proven capability.
   - *Deliberately not absolute:* an invariant can genuinely be obsolete and
     should then change — but that is its own decision, made on its own merits,
     never a side-effect of something else needing to pass.
   - *Origin:* next-PRD grill A3 (2026-07-15) — Codex proposed an `unbacked` claim
     category that required both a third category in the claim matrix (whose
     invariant says "there is no third category") and a traceability guard that
     tolerates not-yet-existing tests. Both guards were correct; the proposal was
     wrong.

Everything else: auto-accept, record with provenance, surface at branch sign-off.

**Trigger 4 is exempt from the "false-alarm" learning rule.** Intent/naming
escalations are correct even when the user ends up agreeing with Codex — the
decision was genuinely theirs to make and the alternatives were live. Only
Trigger 1/2 (stance-divergence) escalations count as false alarms when the user
sides with Codex.

---

## Learning log

Append-only. Each entry is a human-confirmed generalization harvested at a branch
sign-off. Entries harvested in other workspaces were removed from this copy when
it was scoped to MCP-RE (2026-07-06); their standing rules survive above as
S13/S14/S15/S16 with cross-workspace source notes. Format:

```
- [YYYY-MM-DD] (origin: escalation-override | escalation-falsealarm | reopened-autoaccept)
  question: <the grill-me question>
  codex-answer: <one line>
  mats-correction: <what Mats decided instead>
  rule: <the generalized stance, or "case-specific — no rule"> → [updates Sn | new Sn+1]
```

- [2026-06-23] (origin: judge-calibration, grill in another workspace)
  finding: judge ESCALATED a deferral as an S3 "don't-defer" violation, but that
  deferral was already settled by a signed-off scope branch; the judge lacked that
  context. fix: the judge prompt must include the established scope/branch
  decisions so it does not re-escalate already-planned deferrals (same logic as
  the Trigger-4 exemption, applied to S1/S3 scope). Skill updated (Codex-assisted
  mode, judge step).
- [2026-06-29] (origin: escalation-override, standing-confirmed) MCP-S v0.6 grill B.1 number domain.
  question: Should the v0.6 canonical scheme keep the integer-only number domain (which makes float-bearing
  MCP payloads unsignable) or expand to full RFC 8785 floats?
  codex-answer: Expand to full RFC 8785 floats now — "a secure envelope that cannot protect normal MCP
  payloads is deferred failure" (pure S1/S2).
  mats-correction: KEEP integer-only as an explicit, named, tested limitation; rename scheme to reveal the
  restriction (`mcps-jcs-int53-json-v1`); document the float gap honestly + machine-check it with a
  fail-closed vector; defer floats to a future separately-vector-hardened scheme via the allowlist.
  rule: standing → refines the S1↔S14 boundary. For cross-implementation crypto preimages (and similar
  security-critical determinism surfaces), the strictest deterministic domain + an honest documented &
  tested limitation BEATS widening the highest-risk surface — even where S1 would normally say "do the full
  thing now." The strict domain IS the higher bar (S14); bias strict + defer-via-allowlist, and escalate the
  domain-scope call. [updates S14] Also a self-calibration note: across this grill Claude's own scope-sizing
  recs (E.1 opaque-only) skewed conservative vs S1 — bias Claude's recommendations more aggressive in scope,
  while still escalating wire-vocabulary/security-posture decisions under Trigger 4/S10.
- [2026-07-06] (origin: pending confirmation) MCP-RE v0.11 standards-alignment grill.
  Three learning-log candidates recorded at wholesale sign-off, NOT yet confirmed as standing —
  see `docs/archive/grilling-seed/mcp-re-v0.11-grill-decisions.md` §Learning-log candidates
  (Codex conservative on scope-sizing again; Codex minted parallel header wire surface where
  body-carried signed evidence was established; pin shared vocabulary before parallel AFK fan-out).
  Confirm or discard each with Mats before promoting to stances.
- [2026-07-15] (origin: escalation-override, standing-confirmed) next-PRD grill B2 — AWS KMS adapter.
  question: AWS KMS adapter is shipped+merged but never live-proven. In scope, parked, or deleted?
  codex-answer: DELETE it (~2,700 lines) — "merged security-critical custody code that has never
  exercised real AWS KMS is still an unproven runtime path"; invoked the stdio/direct-root/JCS
  deletion precedent.
  mats-correction: KEEP it and run the existing live lane. The precedent is disanalogous — those
  three were SUPERSEDED COMPETING designs; the AWS adapter is architecturally valid, uses the
  correct key spec and signing mode, and already has `aws_kms_live_test.rs` written. "No live
  proof, no production claim — but also no deletion without architectural or maintenance cause."
  Paired with E2, where Mats DID cut EMA Mode 2 outright AND refused a named trigger (a
  contradictory mode must not linger as implied roadmap).
  rule: standing → [updates S4, new "S4 refinement — deletion requires cause"]. Unproven ≠
  superseded. Deletion needs CAUSE (superseded / architecturally contradictory / unsafe /
  unjustified maintenance), not merely incompleteness. The judge's escalation was right and its
  codebase verification (S9) is what collapsed the analogy — worth noting that Codex asserted the
  precedent with no citation while the judge and griller both verified against the tree.

- [2026-07-15] (origin: escalation-override, standing-confirmed) next-PRD grill B2 / F2 — claim scope.
  question: what claim does one green AWS lane buy? what does a project-authored non-Rust verifier buy?
  codex-answer: (B2) upgrade to "multi-cloud custody"; (F2) a single allowed sentence + a single
  permanently-forbidden sentence.
  mats-correction: claim EXACTLY the demonstrated property, never the category — "validated against
  Google Cloud KMS and AWS KMS", never bare "multi-cloud custody"; "machine-checked Rust/non-Rust
  cross-verification for selected wire and credential surfaces", never "independently implementable".
  And broader phrases are GATE-DEPENDENT, not permanently forbidden: they become available when
  their named evidence gate is satisfied.
  rule: standing → [updates S14, new "S14 refinement — claim the demonstrated property, not its
  category"]. Note Codex conceded the key honesty point unprompted when pressed: "same-author
  second-language verification catches Rust bugs, not spec ambiguity."

- [2026-07-15] (origin: escalation-override → escalation rule, standing-confirmed) next-PRD grill A3.
  question: can a claim exist in the claim matrix before its test is green, marked unbacked?
  codex-answer: yes — marked `unbacked`, mapped to a named required test in
  security_traceability_manifest.json, mechanically blocked from publication until green.
  mats-correction: NO. The claim matrix is EVIDENCE of current capability, not a roadmap: "no green
  mapped test, no claim-matrix row." Target claims live in the PRD. The proposal would have required
  a third category (the matrix says "there is no third category") AND a relaxed traceability guard
  (which correctly fails on a test_fn absent from disk). Both guards were doing their job.
  rule: standing, but as an ESCALATION RULE rather than a worldview stance → [new Trigger 7 —
  "weakening the proof system to admit the proposal"]. Deliberately NOT absolute: an invariant can
  genuinely be obsolete, but that is its own decision on its own merits, never a side-effect of
  something else needing to pass. (Mats explicitly rejected the stronger phrasing "a guard that
  fires means the proposal is wrong" as turning existing invariants into untouchable scripture.)

- [2026-07-15] (origin: escalation-override) next-PRD grill B1 — security vs operational claims.
  question: where does a "zero-drop rolling update" tier live?
  codex-answer: make zero-drop a tiered claim (implying the §B deployment-tier matrix).
  mats-correction: zero-drop is an AVAILABILITY/operability property, not one of §B's four SECURITY
  dimensions. Tier it — but in the fleet-deployment guide / SLO evidence / a named operational
  profile, never in §B.
  rule: **case-specific — no global stance.** Mats scoped this deliberately: the broad principle
  ("do not mix distinct assurance dimensions merely because they share deployment machinery") is
  valid, but the concrete rule is about MCP-RE's four-axis matrix and documentation architecture,
  so it belongs in the claim-matrix rules / CONTEXT.md / security-boundary conventions / the PRD's
  documentation invariants — NOT in this profile.

- [2026-07-15] (origin: griller-calibration, next-PRD grill) Codex prompt construction.
  finding: Codex answered decisively but never surfaced the COST of its own answer — it invoked
  the stdio/direct-root/JCS deletion precedent with no citation (B2); proposed relaxing two
  guards to make its proposal pass and framed that as "not over-claiming" (A3); proposed adding
  five fields to a SIGNED preimage without noting that it changes the preimage (C2); asserted
  "rejects duplicate identities" without the honest caveat that identity-distinctness is not
  human-distinctness (C2); and proposed a permanently-forbidden phrase where gate-dependent was
  correct (F2). S9 ("research before deciding, cite paths") did NOT prevent this: as a *stance*
  it describes what Mats values, not an obligation Codex must discharge — and in practice Codex
  researched well on C3/E1/E2 and badly on B2, i.e. the discipline was optional.
  contributing cause (griller's own): the preamble opened with "Answer AS HIM, decisively... Do
  not hedge. Do not give a menu of options — pick one and justify it", stacked on S1 (bias
  aggressive) + S4 (then-unqualified zero-technical-debt). That combination actively rewards
  "delete it" and "relax the guard". The prompt amplified the failure mode it then exhibited.
  fix: SKILL.md Codex-assisted mode now specifies (a) the preamble is stances + verified project
  context + THIS grill's signed-off decisions appended as they land, and (b) five verbatim
  ANSWERER DIRECTIVES — cite-or-don't-assert; name what your answer changes; never weaken the
  proof system to fit your answer; state the limitation you leave behind; deletion needs cause.
  Directives are framed as obligations, not stances, precisely because the stances alone failed
  to produce them.
  rule: mechanics, not a decision stance → [updates SKILL.md, no Sn change]. Also recorded:
  `codex exec` needs `< /dev/null` or it can hang on "Reading additional input from stdin...".
