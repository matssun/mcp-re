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
  see `docs/grilling-seed/mcp-re-v0.11-grill-decisions.md` §Learning-log candidates
  (Codex conservative on scope-sizing again; Codex minted parallel header wire surface where
  body-carried signed evidence was established; pin shared vocabulary before parallel AFK fan-out).
  Confirm or discard each with Mats before promoting to stances.
