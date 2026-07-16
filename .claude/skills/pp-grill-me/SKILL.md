---
name: pp-grill-me
description: This skill should be used when the user asks to "grill me", "pp-grill-me", "stress-test this plan", "interview me about this design", "poke holes in my plan", or wants relentless questioning to reach shared understanding on a plan or design before implementation. Part of the pp- (project-planning) skill bundle that feeds pp-write-a-prd and pp-write-an-adr.
---

# Grill Me

Interview the user relentlessly about every aspect of a plan or design until reaching shared understanding. Walk down each branch of the decision tree, resolving dependencies between decisions one by one.

## When to use

Trigger when the user wants their plan stress-tested before implementation — phrases like "grill me", "interview me on this", "poke holes", "stress-test the design", or any request for adversarial questioning of a proposal.

## How to conduct the interview

1. **Map the decision tree first.** Before asking anything, identify the major branches of the plan: data model, API surface, persistence, error handling, deployment, migration, etc. List them briefly so both sides see the territory.

2. **Walk one branch at a time.** Resolve all open questions in a branch before moving to the next. Do not jump around — context-switching loses the thread.

3. **Resolve dependencies in order.** If decision B depends on A, settle A first. Surface the dependency explicitly when it appears.

4. **One question per turn.** Do not stack multiple questions. Wait for the answer, then drill in or move on.

5. **Always provide a recommended answer.** For every question, state the recommendation and the reasoning. The user reacts to a concrete proposal faster than to an open prompt.

6. **Prefer codebase evidence over questions.** If a question can be answered by reading the code (existing patterns, conventions, prior art), explore the codebase instead of asking. Cite file paths and line numbers.

7. **Track resolution.** After each answer, restate the decision in one line so it is captured. Move to the next question.

8. **Push back on hand-waving.** If an answer is vague ("we'll figure it out later", "it depends"), drill in until it is concrete or explicitly deferred with a named owner/trigger.

9. **End when the tree is resolved.** Conclude with a compact summary of the decisions made, in the order they were resolved.

## Codex-assisted mode (AFK with judge-gated oversight)

Optional mode. When the user asks to run grill-me "with Codex", "AFK", or "have ChatGPT answer", the *answerer* is Codex/ChatGPT instead of the user, and oversight is preserved by a judge plus a per-branch human sign-off. The user is freed from being the copy/paste transport but still controls every branch.

**Three roles:** Claude is the **griller** (drives the decision tree, asks one question per turn as usual). Codex is the **answerer** (stands in for the user on objective/technical questions). A **judge agent** decides, per answer, whether it matches how the user decides or must be escalated to the user.

**Calibration source:** the user's decision stances live in `.claude/skills/pp-grill-me/stance-profile.md` (this repo's MCP-RE-scoped copy; deliberately divergent from other workspaces' profiles). Read it at session start. It is the judge's only rubric and is also used to prime Codex.

**Per-question loop** (replaces waiting for the user's answer):

1. **Ask** — Claude forms the question per the normal rules (recommendation + reasoning, codebase evidence first).
2. **Answer** — send it to Codex, primed with the profile and read-only so it cannot mutate the repo:
   ```bash
   codex exec --skip-git-repo-check --sandbox read-only "<preamble>\n\nQuestion: <Q>" < /dev/null
   ```
   Redirect stdin (`< /dev/null`) — without it `codex exec` can block on "Reading additional input from stdin…" and never return (observed 2026-07-15). Runs take 2–15 min; fire them with `run_in_background` and wait on the process, don't foreground them.

   The **preamble** is three parts, in order: (a) the stances from `stance-profile.md`; (b) verified project context; (c) **the decisions already signed off in THIS grill** — append each one as it is signed off, or Codex will contradict settled branches and re-assert scope you have already cut.

   Then append the **answerer directives** verbatim. These are not restatements of the stances — they are obligations that exist because the stances alone did not produce them (see the Learning log, 2026-07-15):

   ```text
   ANSWERER DIRECTIVES (obey these even when they slow the answer down):
   1. CITE OR DON'T ASSERT. Before invoking a precedent, convention, or "the pattern here is X",
      verify it against the repo and cite file:line. If you cannot verify it, say "unverified"
      and answer without leaning on it. An uncited precedent is not an argument.
   2. NAME WHAT YOUR ANSWER CHANGES. If it adds or alters a signed preimage, wire field, tier
      name, guard, invariant, claim wording, or public vocabulary, say so explicitly and flag it
      as the owner's call. Do not let a consequential change ride along inside a technical answer.
   3. NEVER WEAKEN THE PROOF SYSTEM TO FIT YOUR ANSWER. If your proposal needs an invariant,
      guard, fail-closed rule, or claim gate relaxed in order to pass, that is evidence your
      proposal is wrong. Say so instead of proposing the relaxation.
   4. STATE THE LIMITATION YOU LEAVE BEHIND. Every answer ends with what it does NOT prove,
      detect, or cover. "None" is an acceptable answer only if you actually checked.
   5. DELETION NEEDS CAUSE, NOT MERELY INCOMPLETENESS. Unproven-but-correct is not superseded.
      See the S4 refinement before proposing any removal.
   ```
3. **Judge** — spawn a judge agent (general-purpose) whose only rubric is the profile; pass the `(question, Codex answer)` pair **plus the already-decided scope/branch context** (what earlier sign-offs put in/out, and which deferrals route to existing planned slices). Without that context the judge re-escalates settled deferrals as S1/S3 "don't-defer" violations (observed 2026-06-23 in another workspace's grill; recorded in the stance profile's Learning log). It returns `AUTO-ACCEPT` or `ESCALATE` + triggers + reason.
4. **Branch:**
   - `AUTO-ACCEPT` → record the decision with provenance `[Codex, judge-passed]` and move on. No user interruption.
   - `ESCALATE` → ask the user via `AskUserQuestion`, surfacing the question, Codex's answer, and the judge's reason/triggers. Record with provenance `[user]` or `[Codex, user-confirmed]`.
5. Continue until the branch is resolved.

**Per-branch sign-off (mandatory).** At the end of each branch — before dependent branches build on it — present the whole branch's decisions with provenance and any judge reasoning, and require the user to sign off, redirect, or reopen. This is the safety net that catches a judge that wrongly auto-accepted: reopening an auto-accepted decision here is the highest-value learning signal.

**Two artifacts.** Maintain (a) a full Claude↔Codex transcript file (skim-able) and (b) the compact decision summary with per-decision provenance tags. Decisions are never posted to a PRD/ADR until the user approves the summary (see [[review-before-publish]]).

**Learning loop (human-confirmed, never silent).** At each branch sign-off, harvest corrections into the profile's Learning log:
- escalation where the user overrode Codex → the firing stance was right; consider sharpening it.
- escalation where the user sided with Codex → false alarm; consider loosening that trigger.
- reopened auto-accept → a missing stance; add it.
For each, ask the user one question: *was this case-specific, or a standing preference?* Only standing preferences become new/updated stances. Append entries in the Learning log's defined format; never mutate stances silently.

## Domain awareness — grill against the Ubiquitous Language

Language precision is part of grilling, not a separate concern. Imprecise terms produce imprecise designs, so the interview challenges the user's vocabulary alongside their decisions. The shared vocabulary for the whole monorepo lives in `CONTEXT.md` at the repo root.

**At session start:** read `CONTEXT.md`. If it doesn't exist, that's fine — create it lazily when the first term gets resolved. Treat it as the canonical glossary for every term the user uses during the session.

1. **Challenge fuzzy or overloaded terms.** When the user says "account", "user", "order", "job", "task" — ask which concept they mean. Propose a precise canonical term and explicitly list the aliases to avoid.

2. **Surface terminology conflicts with `CONTEXT.md`.** If a user's usage conflicts with the existing glossary, call it out immediately: "the glossary defines `Account` as X — you seem to mean Y. Which is it, and does the glossary need updating?"

3. **Homonyms are a smell, not a fact.** If the user introduces a term already used elsewhere with a different meaning, do not accept "different context." Flag it as a rename candidate. The monorepo has one Ubiquitous Language — distinct concepts get distinct names (`sort_order`, `purchase_order`, `delivery_order`), never overloaded into one word.

4. **Probe boundaries with concrete scenarios.** When a relationship between concepts is asserted, invent an edge-case scenario that forces precision. "You said an Order has many Invoices — what happens to the Invoices when the Order is partially cancelled?" Scenarios beat abstract questions.

5. **Surface code-vs-claim contradictions.** When the user states how something works, verify against the actual code before accepting. If the code disagrees, surface it directly: "you said partial cancellation is supported, but `OrderService.cancel()` only accepts a whole Order — which is right?"

6. **Update `CONTEXT.md` inline as terms resolve.** Don't batch glossary updates to the end — capture each term in the moment it's sharpened. Add it under `## Language`, list aliases under `_Avoid_`, and record any flagged homonym under `## Flagged ambiguities` as a rename TODO. Keep definitions to one sentence; `CONTEXT.md` is a glossary, not a spec.

## Question categories to cover

Work through these systematically; not every plan needs every category, but check each one:

- **Scope & non-goals** — what is explicitly out
- **Data model & invariants** — types, IDs, constraints, what cannot be true
- **API & boundaries** — contracts, versioning, wire format
- **Persistence** — schema, migrations, backfill, rollback
- **Error handling** — failure modes, retries, fallbacks (or absence thereof)
- **Concurrency & ordering** — races, locks, idempotency
- **Observability** — logs, metrics, alerts
- **Migration & rollout** — staged delivery, feature flags, kill switch
- **Testing** — what proves it works, what proves it didn't break neighbors
- **Operational ownership** — who pages, who maintains

## Tone

Direct, specific, adversarial-but-collegial. The goal is to surface unstated assumptions, not to score points. When the user gives a good answer, accept it and move on — do not manufacture doubt.
