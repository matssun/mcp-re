---
description: "Derive sprint plans from ADRs. Use when the user says 'plan from ADRs', 'what should we implement next', 'ADR sprint plan', 'derive next sprint', or when sprint-runner needs to determine the next phase of work based on Architecture Decision Records."
---

# ADR Planner — Sprint Plan Derivation from ADRs

Reads ADRs from GitHub Discussions, determines what to implement next, produces a structured sprint plan.

## Overview

ADRs (Architecture Decision Records) are stored as GitHub Discussions under project-specific categories. Each project has its own ADR Index discussion.

You are the planning engine. You read ADRs, assess implementation status, and produce prioritized sprint plans.

## Project Configuration

| Project | Category ID | Category Slug | ADR Index | Prefix | Repo |
|---------|-------------|---------------|-----------|--------|------|
| CodeGraphait | `DIC_kwDOPlpqrs4C39fv` | `codegraphait-architecture` | Discussion #1347 | CG- | matssun/ws_b |
| Gloso | `DIC_kwDOPlpqrs4C5ZQ5` | `gloso` | Discussion #1934 | GL- | matssun/code |

Detect the target project from:
1. **User instruction** — "plan from ADRs for Gloso"
2. **Current directory** — `applications/gloso_backend/` → Gloso, `applications/codegraphait/` → CodeGraphait
3. **Ask the user** if ambiguous

## Step 1 — Fetch the ADR Index

Always start from the project's ADR Index:

```bash
# CodeGraphait
gh api graphql -f query='
  query {
    repository(owner: "matssun", name: "ws_b") {
      discussion(number: 1347) {
        title
        body
      }
    }
  }'

# Gloso
gh api graphql -f query='
  query {
    repository(owner: "matssun", name: "code") {
      discussion(number: 1934) {
        title
        body
      }
    }
  }'
```

Parse the index to get the full list of ADR numbers, titles, and statuses.

## Step 2 — Fetch Individual ADRs

Fetch all ADRs from the project's discussion category:

```bash
# CodeGraphait
gh api graphql -f query='
  query {
    repository(owner: "matssun", name: "ws_b") {
      discussions(categoryId: "DIC_kwDOPlpqrs4C39fv", first: 50) {
        nodes {
          number
          title
          body
          labels(first: 10) { nodes { name } }
        }
      }
    }
  }'

# Gloso
gh api graphql -f query='
  query {
    repository(owner: "matssun", name: "code") {
      discussions(categoryId: "DIC_kwDOPlpqrs4C5ZQ5", first: 50) {
        nodes {
          number
          title
          body
          labels(first: 10) { nodes { name } }
        }
      }
    }
  }'
```

For each ADR, extract:
- **Number and title**
- **Status**: Accepted, Proposed, Superseded, Deprecated
- **Layer/dependency info**: Which architectural layer it belongs to
- **Implementation requirements**: What needs to be built
- **Dependencies on other ADRs**: Which ADRs must be implemented first

## Step 3 — Assess Implementation Status

For each Accepted ADR, check if its requirements are already implemented:

1. **Check GitHub issues** — are there closed issues referencing this ADR?
   ```bash
   gh issue list --state all --limit 200 --json number,title,state,body \
     --jq '[.[] | select(.body | test("ADR.*#NNN|Discussion.*#NNN"))]'
   ```
2. **Check codebase** — do the files/components specified in the ADR exist?
3. **Check deferred issues** — are there open issues from prior sprints referencing this ADR?

Classify each ADR as:
- **IMPLEMENTED** — all requirements met, issues closed, code exists
- **PARTIALLY_IMPLEMENTED** — some requirements met, open issues remain
- **NOT_STARTED** — no corresponding issues or code
- **BLOCKED** — depends on unimplemented ADRs

## Step 4 — Prioritize

Apply this priority algorithm to determine what goes into the next sprint:

1. **Deferred issues from previous phases** (carry-forward) — highest priority
2. **PARTIALLY_IMPLEMENTED ADRs** — finish what was started
3. **Lowest unimplemented architectural layer** (bottom-up) — foundations first
4. **Accepted ADRs with most dependents** — unblock the most future work
5. **Proposed ADRs** — skip (not yet accepted)
6. **Superseded/Deprecated ADRs** — skip entirely

**Sprint sizing:** Target 5-10 issues per sprint. If an ADR requires more, split across multiple sprints.

## Step 5 — Produce the Sprint Plan

Output a structured sprint plan:

```
## Sprint Plan: Phase N — [Title]

### Source ADRs
- ADR #NNN — [title] (status: PARTIALLY_IMPLEMENTED)
- ADR #NNN — [title] (status: NOT_STARTED)

### Carried Forward
- #NNN — [title] (from Phase N-1)

### Issues to Create

1. **PREFIX-NNN — [title]**
   - ADR: #NNN
   - Acceptance criteria:
     - [ ] [specific deliverable]
     - [ ] [tests required]
   - Files: `path/to/file.py`
   - Depends on: (none | #NNN)

2. **PREFIX-NNN — [title]**
   ...

### Dependency Order
#A (no deps) → #B (depends on #A) → #C, #D (parallel)

### ADR Coverage After This Sprint
- Fully implemented: N/24
- Partially implemented: N/24
- Not started: N/24
```

## Step 6 — Present or Proceed

**In supervised mode:** Present the plan to the user for approval. Wait for confirmation before creating issues.

**In autonomous mode:** Log the plan as a GitHub issue comment on the Epic (or create a planning issue) and proceed directly to issue creation via the `create-sprint` skill.

## ADR Reading Rules

- **ADRs are read-only** — never modify Discussions
- **ADR Index is always the entry point** — #1347 for CodeGraphait, #1934 for Gloso
- **Filter by project prefix** — CG- for CodeGraphait, GL- for Gloso
- **Accepted status only** for implementation — Proposed ADRs are informational
- **Layer ordering matters** — implement lower layers before higher layers
- **Never mix projects** — a sprint plan targets exactly one project

## Empty Plan (Done Condition)

If all Accepted ADRs are IMPLEMENTED and no deferred issues remain:

```
## Sprint Plan: COMPLETE

All 24 ADRs are fully implemented.
No deferred issues remain.
No further sprints needed.
```

This signals the completion loop in sprint-runner to stop.
