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
