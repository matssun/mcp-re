---
name: pp-create-sprint
description: "This skill should be used when the user asks to 'create sprint', 'pp-create-sprint', 'create issues for phase N', 'make this plan concrete', 'break down the epic', or when a plan, ADR, or PRD-derived backlog (often produced by pp-prd-to-issues) needs to become a phased sprint with Epic and Project board entry. Relabels `phase:unscheduled` → `phase:N` on selected issues and sets the `Sprint` iteration field on each item's Project entry. Part of the pp- (project-planning) skill bundle; pulls from existing backlog into one iteration."
---

# Create Sprint Workflow

Turn a plan (from a Discussion, Epic issue, or plan file) into concrete sprint issues.

## Pipeline position

```
pp-write-a-prd → pp-write-an-adr (0..N) → pp-prd-to-issues → pp-create-sprint → code
                                                  ↓                 ↓
                                              [Project]  ──────►  (Sprint field set per item; phase:unscheduled → phase:N)
```

This skill has two modes:

- **Mode A — PRD-derived sprint (preferred):** issues already exist on the Project (added by `pp-prd-to-issues`) and are labeled `phase:unscheduled` + `prd-<N>`. Sprint creation = select a subset, relabel to `phase:N`, set the `Sprint` iteration field on each Project item.
- **Mode B — ADR/plan-derived sprint (legacy):** issues are created from scratch from an ADR Index or plan file. Optionally attach the new issues to a Project the user picks.

## Step 0 — Identify the target project

**CRITICAL: All issues MUST be created within a single project scope. Never mix projects.**

Determine the project from:
1. **User instruction** — "create sprint for CodeGraphait phase 7"
2. **Current directory** — if inside `applications/codegraphait/`, it's CodeGraphait
3. **Plan file content** — the plan will reference specific application paths

Map to project conventions:
- `applications/codegraphait/` → prefix `CG-`, labels `phase:N, area:xxx`
- `applications/gloso_backend/`, `applications/gloso_web/`, `applications/gloso_ios/`, `applications/gloso_android/` → prefix `GL-`, labels `phase:N`
- `applications/door_access/` → prefix `DA-`, labels `phase:N`
- `applications/energy/` → prefix `EN-`, labels `phase:N`
- `applications/ai/` or `applications/laigo/` → prefix `AI-`, labels `phase:N`
- `applications/accounting*` → prefix `AC-`, labels `phase:N`
- Other → derive 2-3 letter prefix from app name, confirm with user

**Before creating any issues, confirm the project with the user if ambiguous.**

## Step 0.5 — Locate the GitHub Project and Sprint iteration

This step applies to both modes. In Mode A (PRD-derived), the Project usually exists already and you discover it. In Mode B (plan-derived), the user picks one or skips.

**Mode A — discover Project from PRD or existing issues:**

1. If the user names a PRD, fetch its body and parse `**Project:** <url>` (same lookup as `pp-prd-to-issues` Step 1).
2. Otherwise pick one of the existing `prd-<N>`-labeled issues from this run's scope, fetch its `projectItems`, and use the first Project:

```bash
gh api graphql -f query='query($owner:String!,$name:String!,$num:Int!){
  repository(owner:$owner,name:$name){
    issue(number:$num){
      projectItems(first:5){ nodes{ project{ id url number title } } }
    }
  }
}' -F owner=matssun -F name=code -F num=$REFERENCE_ISSUE_NUMBER
```

**Mode B — prompt the user:**

```bash
gh api graphql -f query='{
  viewer{ projectsV2(first:50){ nodes{ id url number title closed } } }
}' | jq '.data.viewer.projectsV2.nodes[] | select(.closed==false) | {number, title, id, url}'
```

User picks; capture `PROJECT_ID`. If "skip", the sprint runs without Project updates (issues still get `phase:N` label).

**Once `PROJECT_ID` is known, resolve the `Sprint` iteration field:**

```bash
gh api graphql -f query='query($projectId:ID!){
  node(id:$projectId){
    ... on ProjectV2 {
      field(name:"Sprint"){
        ... on ProjectV2IterationField {
          id name
          configuration{
            iterations{ id title startDate duration }
            completedIterations{ id title startDate duration }
          }
        }
      }
    }
  }
}' -f projectId="$PROJECT_ID"
```

Show the active and upcoming iterations to the user. Ask which iteration this sprint belongs to (typically the current or next one). Cache `SPRINT_FIELD_ID` and `SPRINT_ITERATION_ID`.

If no `Sprint` iteration field exists on the Project, the seed Project is misconfigured — fall back to using only the `phase:N` label and warn the user.

## Find the plan source

Check these locations in priority order:

1. **User-specified** — if the user points to a Discussion, Epic, or document
2. **ADR-derived plan** — see `references/from-adrs.md` for the full ADR-Index → sprint-plan procedure:
   - Fetches ADR Index (Discussion #1347 for CodeGraphait, #1934 for Gloso)
   - Assesses implementation status of each ADR
   - Produces prioritized sprint plan with issue titles, acceptance criteria, and file paths
   - This is the preferred source for CodeGraphait (CG-) and Gloso (GL-) sprints
3. **Active plan file** — check `~/.claude/plans/*.md` for recent plans
4. **Open epics for this project** — filter by project prefix:
   ```bash
   gh issue list --label epic --state open --json number,title,body \
     --jq '[.[] | select(.title | test("PROJECT_NAME|PREFIX"))]'
   ```
5. **GitHub Discussions** — `gh api repos/{owner}/{repo}/discussions` (if enabled)

## Analyze the plan

Read the plan and identify:
- **Sprint/phase number** — what are we creating issues for?
- **Work items** — each concrete task that needs an issue
- **Dependencies** — which issues block others
- **Labels** — phase label, area labels from the plan
- **Previous phase issues** — check for open/deferred issues from prior phases OF THIS PROJECT ONLY:
  ```bash
  gh issue list --state open --json number,title,labels \
    --jq '[.[] | select(.title | test("^PREFIX-"))]'
  ```

## Create the issues

### Mode A — promote existing backlog issues (PRD-derived)

Issues already exist (created by `pp-prd-to-issues`, labeled `phase:unscheduled` + `prd-<N>`). For each selected issue:

```bash
# 1. Relabel: remove phase:unscheduled, add phase:N
gh issue edit $ISSUE_NUMBER --remove-label "phase:unscheduled" --add-label "phase:$N"

# 2. Find the Project item ID for this issue
ITEM_ID=$(gh api graphql -f query='query($owner:String!,$name:String!,$num:Int!,$projectId:ID!){
  repository(owner:$owner,name:$name){
    issue(number:$num){
      projectItems(first:10){ nodes{ id project{ id } } }
    }
  }
}' -F owner=matssun -F name=code -F num=$ISSUE_NUMBER -f projectId="$PROJECT_ID" \
   --jq ".data.repository.issue.projectItems.nodes[] | select(.project.id==\"$PROJECT_ID\") | .id")

# 3. Set Sprint iteration on the Project item
gh api graphql -f query='mutation($projectId:ID!,$itemId:ID!,$fieldId:ID!,$iterId:String!){
  updateProjectV2ItemFieldValue(input:{
    projectId:$projectId, itemId:$itemId, fieldId:$fieldId,
    value:{ iterationId:$iterId }
  }){ projectV2Item{ id } }
}' -f projectId="$PROJECT_ID" -f itemId="$ITEM_ID" -f fieldId="$SPRINT_FIELD_ID" -f iterId="$SPRINT_ITERATION_ID"
```

Per issue: 1 `gh issue edit` + 2 GraphQL calls. For a 10-issue sprint = ~30 calls.

### Mode B — create new issues from a plan

For each work item, use the project's prefix:

```bash
gh issue create \
  --title "PREFIX-NNN — [concise title]" \
  --label "phase:N,area:xxx" \
  --body "## Context
[What this issue is about and why]

## ADR Reference
ADR: #NNN — [ADR title]
[Key decisions from this ADR that apply to this issue]

## Acceptance criteria
- [ ] [specific deliverable]
- [ ] [tests required]
- [ ] [documentation if needed]

## Dependencies
Depends on: #NNN (if any)
Blocks: #NNN (if any)

## Files likely involved
- \`applications/app_name/src/...\`
"
```

**ADR traceability:** Every issue created from an ADR-derived plan MUST include the `## ADR Reference` section linking back to the source ADR Discussion number. This enables coverage tracking when re-running the ADR-derivation flow (see `references/from-adrs.md`).

**Use sequential IDs within the project prefix** (e.g., if last was CG-671, next is CG-680 for a new sprint).

## Create or update the Epic

If an Epic doesn't exist for this phase:
```bash
gh issue create --title "Phase N — [title]" --label "epic,phase:N" --body "..."
```

Update the Epic body with a task list linking to all created issues:
```markdown
- [ ] #NNN — Title
- [ ] #NNN — Title
```

GitHub will auto-render this as a progress bar and auto-check items when issues close.

### ADR Traceability in Epic

When creating from ADR-derived plans, include an ADR traceability section in the Epic body:

```markdown
## ADR Traceability
This sprint implements requirements from:
- ADR #NNN — [title] (status: PARTIALLY_IMPLEMENTED → target: IMPLEMENTED)
- ADR #NNN — [title] (status: NOT_STARTED → target: PARTIALLY_IMPLEMENTED)

### Coverage
| ADR | Pre-Sprint | Post-Sprint (target) |
|-----|-----------|----------------------|
| #NNN | Not started | Implemented |
| #NNN | Partial | Implemented |
```

## Add to Project board (Mode B only)

In Mode A, items are already on the Project from `pp-prd-to-issues`; this section is skipped.

In Mode B, if a Project was picked in Step 0.5, add each newly-created issue to it and set the Sprint iteration:

```bash
# For each issue created in Mode B:
ITEM_ID=$(gh api graphql -f query='mutation($projectId:ID!,$contentId:ID!){
  addProjectV2ItemById(input:{projectId:$projectId, contentId:$contentId}){ item{ id } }
}' -f projectId="$PROJECT_ID" -f contentId="$ISSUE_NODE_ID" --jq '.data.addProjectV2ItemById.item.id')

# Set Sprint
gh api graphql -f query='mutation($projectId:ID!,$itemId:ID!,$fieldId:ID!,$iterId:String!){
  updateProjectV2ItemFieldValue(input:{
    projectId:$projectId, itemId:$itemId, fieldId:$fieldId,
    value:{ iterationId:$iterId }
  }){ projectV2Item{ id } }
}' -f projectId="$PROJECT_ID" -f itemId="$ITEM_ID" -f fieldId="$SPRINT_FIELD_ID" -f iterId="$SPRINT_ITERATION_ID"
```

If no Project was picked in Step 0.5, skip this section entirely — the sprint runs label-only.

## Carry forward deferred issues

Check for open issues from previous phases of THIS PROJECT:
```bash
gh issue list --state open --json number,title,labels \
  --jq '[.[] | select(.title | test("^PREFIX-")) | select(.labels[].name | test("phase:PREV"))]'
```

For each: either re-label to the new phase or reference in the new Epic. If carried forward to `phase:N`, also update the Sprint field on the Project item to the new iteration (same GraphQL mutation as Mode A step 3 above).

## Report

Output a summary:
```
Mode: A (promoted from backlog) | B (created from plan)
Project (issue prefix): PREFIX-
GitHub Project: <title> (#NNN) — <url>          ← omitted if no Project in scope
Sprint iteration: <iteration title> (#id)        ← omitted if no Project in scope

Phase N created/promoted:
- Epic: #NNN (Sprint field set: yes/no)
- Issues: #NNN, #NNN, #NNN, ... (X total)
  Relabeled phase:unscheduled → phase:N: X       ← Mode A
  Newly created: X                                ← Mode B
  Sprint field set on Project items: X/X
- Carried forward from Phase N-1: #NNN, #NNN (Sprint updated: yes/no)
- Dependencies: #A blocks #B, #C blocks #D
```

## What this skill does NOT do

- Does not create new GitHub Projects. The Project is either discovered from the PRD (Mode A) or picked by the user from existing Projects (Mode B).
- Does not change `Area`, `PRD`, or other Project fields set earlier by `pp-prd-to-issues`. Only sets `Sprint` (and the `phase:N` label on the issue itself).
- Does not mix Mode A and Mode B in one run. If the user wants to both promote backlog items and add new plan-derived ones, run the skill twice.

## Creating iterations when more are needed

If the Sprint field doesn't have enough iterations for the sprints you need, the API **can** create them via `updateProjectV2Field` with `iterationConfiguration`. **The mutation REPLACES the entire iterations list (not additive)** — always pass existing iterations alongside new ones in a single call.

**Critical sequence**:
1. Query existing iterations on the Sprint field.
2. Construct the full new iterations list = existing (preserved verbatim) + new entries.
3. Issue the mutation in one call.
4. **All iteration IDs change** after the mutation — old IDs are orphaned. Re-bind every Project item whose Sprint field referenced the old IDs.

**Caveat — `gh api -f` cannot pass the `iterationConfiguration` input as a JSON object via a GraphQL variable** (it sends the string literal, not parsed JSON, and the mutation rejects it). Use inline literal values in the query string instead:

```bash
gh api graphql -f query='mutation{updateProjectV2Field(input:{
  fieldId:"<SPRINT_FIELD_ID>",
  iterationConfiguration:{
    startDate:"2026-05-24",duration:14,
    iterations:[
      {startDate:"2026-05-24",duration:14,title:"Sprint 1"},
      {startDate:"2026-06-07",duration:14,title:"Sprint 2"},
      {startDate:"2026-06-21",duration:14,title:"Sprint 3"},
      {startDate:"2026-07-05",duration:14,title:"Sprint 4"}
    ]
  }
}){projectV2Field{... on ProjectV2IterationField {configuration{iterations{id title startDate duration}}}}}}'
```

The response returns every iteration with its new ID. Capture them and re-bind affected Project items.

If you prefer not to risk re-binding (e.g., production Project with many scheduled items), ask the user to add iterations in the UI instead — that path is additive and preserves existing iteration IDs.

## Important rules

- **NEVER create issues for one project with another project's prefix or labels**
- Use consistent ID prefixes — confirm the numbering scheme with the user if unsure
- Always check for deferred issues from prior phases of the SAME project
- Keep issue titles under 80 characters
- Include file references when known — this helps future coding sessions
- Label consistently: phase:N, area:xxx, epic (for epics only)
- If the plan references multiple projects, create issues separately per project
