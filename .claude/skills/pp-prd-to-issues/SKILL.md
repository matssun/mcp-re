---
name: pp-prd-to-issues
description: This skill should be used when the user asks to "break down a PRD", "pp-prd-to-issues", "turn this PRD into issues", "decompose the PRD", or wants to produce the full backlog of GitHub Issues needed to deliver a PRD. Uses vertical slices (tracer bullets), classifies HITL vs AFK, and posts directly to GitHub Issues with the project's prefix convention. If the parent PRD is attached to a GitHub Project (v2), every created issue and the Epic are added to that Project with `prd-<N>` label, Area, and PRD link pre-populated. Part of the pp- (project-planning) skill bundle; runs once per PRD, downstream of pp-write-a-prd, upstream of pp-create-sprint.
---

# pp-prd-to-issues

Decompose a PRD into the full backlog of independently-workable GitHub Issues. Each issue is a **vertical slice** (tracer bullet) cutting through every layer end-to-end, not a horizontal slice of one layer. Run this once per PRD; later, `pp-create-sprint` selects subsets of these issues into iterations.

## When to use

Trigger on "break this PRD into issues", "pp-prd-to-issues", "decompose the PRD", or after a PRD Discussion has been posted and needs to become actionable work. Skip this skill for technical-only work with no PRD — go directly to `pp-create-sprint`.

## Pipeline position

```
pp-write-a-prd  →  pp-write-an-adr (0..N)  →  pp-prd-to-issues  →  pp-create-sprint  →  code
       ↓                       ↓                       ↓
   [Project] ─────────────────────────────────►  (every issue + Epic added to the Project)
```

`pp-prd-to-issues` produces the **unscheduled backlog**. `pp-create-sprint` later assigns `phase:N` to a subset. When the PRD body carries a `**Project:** <url>` line (set by `pp-write-a-prd` Step 7.5), this skill adds every created issue and the Epic to that Project, applies the same `prd-<N>` label, and pre-populates the Area and PRD custom fields on each item.

## Procedure

### 1. Locate the PRD

Ask the user for the PRD Discussion URL or number. Fetch it with id, labels, and body:

```bash
PRD_N="<discussion-number>"
gh api graphql -f query='query($n:Int!){
  repository(owner:"matssun",name:"code"){
    discussion(number:$n){
      id title body url category{name}
      labels(first:20){ nodes{ id name } }
    }
  }
}' -F n=$PRD_N
```

Cache:
- `PRD_URL`, `PRD_NUMBER`, `PRD_TITLE` — go into every issue body.
- `PRD_DISCUSSION_ID` — used to update the PRD body in Step 9.
- `PRD_LABEL_NAME` — the `prd-<N>` label on the PRD (if present). Every issue created by this run will carry it.
- `PRD_PROJECT_URL` — parse the `**Project:** <url>` line from `body` (if present). If found, this run will add every issue and the Epic to that Project.

If the PRD has no `prd-<N>` label and no Project link, this skill creates issues without Project attachment — the user can backfill later.

### 1.5. Resolve the Project (if PRD has one)

If `PRD_PROJECT_URL` was found, resolve the Project node ID and field metadata once up front so the per-issue loop is cheap:

```bash
PROJECT_NUMBER=$(echo "$PRD_PROJECT_URL" | sed -E 's|.*/projects/([0-9]+).*|\1|')

# Project node ID
PROJECT_ID=$(gh api graphql -f query='query($login:String!,$num:Int!){
  user(login:$login){ projectV2(number:$num){ id } }
}' -F login=matssun -F num=$PROJECT_NUMBER --jq '.data.user.projectV2.id')

# Field IDs (PRD = text field, Area = single-select)
gh api graphql -f query='query($projectId:ID!){
  node(id:$projectId){
    ... on ProjectV2 {
      fields(first:30){
        nodes{
          ... on ProjectV2Field { id name dataType }
          ... on ProjectV2SingleSelectField { id name options{ id name } }
        }
      }
    }
  }
}' -f projectId="$PROJECT_ID"
```

Cache `PRD_FIELD_ID`, `AREA_FIELD_ID`, and the Area option IDs by name.

Ask the user which `Area` value to apply to all issues created in this run (default: inherit whatever the parent PRD item has, if discoverable; otherwise prompt). All issues in one PRD share an Area — if a slice belongs in a different Area, that is a sign the PRD should be split.

### 2. Identify the project and prefix

The PRD's category often implies the project. Confirm prefix and labels with the user. Conventions (from `pp-create-sprint`):

| Application path | Prefix | Default labels |
|---|---|---|
| `applications/codegraphait/` | `CG-` | `area:xxx` |
| `applications/gloso_*` | `GL-` | `area:xxx` |
| `applications/door_access/` | `DA-` | `area:xxx` |
| `applications/energy/` | `EN-` | `area:xxx` |
| `applications/ai/`, `applications/laigo/` | `AI-` | `area:xxx` |
| `applications/accounting*` | `AC-` | `area:xxx` |
| Other | derive 2-3 letters | confirm with user |

**All issues created by this skill get `phase:unscheduled`.** `pp-create-sprint` re-labels to `phase:N` when scheduled.

### 3. Find the next ID number

```bash
gh issue list --state all --search "PREFIX- in:title" --json number,title \
  --jq '[.[] | .title | capture("PREFIX-(?<n>\\d+)") | .n | tonumber] | max'
```

Take the highest existing `PREFIX-NNN` number and continue from there.

### 4. Explore the codebase

Read the PRD's user stories and Linked ADRs. Cross-reference with the codebase to understand current state. Cite file paths when proposing slices that touch existing code.

### 5. Draft vertical slices

Break the PRD into tracer bullets. Each slice MUST:

- Cut through every layer the feature touches (schema → persistence → service → API → adapter → UI/client → tests).
- Be demoable or verifiable on its own.
- Cover one or more user stories from the PRD.
- Be small enough that one engineer can complete it without coordinating mid-flight.

Prefer many thin slices over few thick ones.

Classify each slice:

- **AFK** (away-from-keyboard) — can be implemented and merged without human interaction. Default.
- **HITL** (human-in-the-loop) — requires a decision, design review, or manual verification mid-flight. Use sparingly; if a slice is HITL because of an unresolved architectural choice, consider writing an ADR first via `pp-write-an-adr` to convert it to AFK.

### 6. Quiz the user

Present the proposed breakdown as a numbered list. For each slice, show:

- **Title** (will become `PREFIX-NNN — <title>`)
- **Type**: HITL / AFK
- **Blocked by**: which other slices must complete first (by proposed `PREFIX-NNN` or list position)
- **User stories covered** (numbers from the PRD)
- **Layers touched** (one line)

Ask:

- Granularity: too coarse, too fine, just right?
- Dependency relationships correct?
- Any slices to merge or split?
- HITL/AFK classifications correct?
- Are user stories fully covered? Any unmapped stories?

Iterate until the user approves.

### 7. Create issues in dependency order

Create blockers first so real GitHub issue numbers exist when referencing them in dependents. For each slice, run the create + Project-add + field-set sequence below.

**Per-slice flow:**

1. `gh issue create` (capture both issue number and `--json id` for the node ID).
2. If `PROJECT_ID` exists: `addProjectV2ItemById` → capture `ITEM_ID`.
3. If `PROJECT_ID` exists: set `Area` and `PRD` fields on the item via `updateProjectV2ItemFieldValue`.

**Issue create (include `prd-<N>` label when applicable):**

```bash
ISSUE_LABELS="phase:unscheduled,area:xxx,type:afk"
[ -n "$PRD_LABEL_NAME" ] && ISSUE_LABELS="$ISSUE_LABELS,$PRD_LABEL_NAME"

ISSUE_JSON=$(gh issue create \
  --title "PREFIX-NNN — <concise title>" \
  --label "$ISSUE_LABELS" \
  --body "$(cat /tmp/issue-body.md)" \
  --json number,id,url)

ISSUE_NUMBER=$(echo "$ISSUE_JSON" | jq -r .number)
ISSUE_NODE_ID=$(echo "$ISSUE_JSON" | jq -r .id)
```

**Issue body template:**

```markdown
## Parent PRD

[Title](DISCUSSION_URL) — Discussion #NNNN

## What to build

Concise description of this vertical slice. Describe end-to-end behavior, not layer-by-layer implementation. Reference user stories by number rather than duplicating PRD content.

## Layers touched

- Schema / persistence: ...
- API / adapter: ...
- UI / client: ...
- Tests: ...

## Acceptance criteria

- [ ] ...
- [ ] ...
- [ ] Tests covering the criteria above

## Blocked by

- #NNN (or 'None — can start immediately')

## Linked ADRs

- ADR-<TAG>-<NNN>: <title> — Discussion #NNNN (if applicable)

## User stories addressed

From PRD #NNNN:
- User story 3
- User story 7
```

Substitute `DISCUSSION_URL` and `NNNN` from the cached `PRD_URL` / `PRD_NUMBER`. Use the `type:afk` or `type:hitl` label to mark the classification.

**Add the issue to the Project (if `PROJECT_ID` is set):**

```bash
ITEM_ID=$(gh api graphql -f query='mutation($projectId:ID!,$contentId:ID!){
  addProjectV2ItemById(input:{projectId:$projectId, contentId:$contentId}){ item{ id } }
}' -f projectId="$PROJECT_ID" -f contentId="$ISSUE_NODE_ID" --jq '.data.addProjectV2ItemById.item.id')

# Set Area (single-select)
gh api graphql -f query='mutation($projectId:ID!,$itemId:ID!,$fieldId:ID!,$optId:String!){
  updateProjectV2ItemFieldValue(input:{
    projectId:$projectId, itemId:$itemId, fieldId:$fieldId,
    value:{ singleSelectOptionId:$optId }
  }){ projectV2Item{ id } }
}' -f projectId="$PROJECT_ID" -f itemId="$ITEM_ID" -f fieldId="$AREA_FIELD_ID" -f optId="$AREA_OPTION_ID"

# Set PRD link (text field)
gh api graphql -f query='mutation($projectId:ID!,$itemId:ID!,$fieldId:ID!,$txt:String!){
  updateProjectV2ItemFieldValue(input:{
    projectId:$projectId, itemId:$itemId, fieldId:$fieldId,
    value:{ text:$txt }
  }){ projectV2Item{ id } }
}' -f projectId="$PROJECT_ID" -f itemId="$ITEM_ID" -f fieldId="$PRD_FIELD_ID" -f txt="$PRD_URL"
```

Total per issue: 1 `gh issue create` + 3 GraphQL calls = ~4 calls. For a 20-issue PRD this is ~80 calls; acceptable for AFK.

### 8. Create or update the PRD epic

Create one Epic per PRD, linking all the issues. Include the `prd-<N>` label if set, and add the Epic to the Project too.

```bash
EPIC_LABELS="epic,phase:unscheduled"
[ -n "$PRD_LABEL_NAME" ] && EPIC_LABELS="$EPIC_LABELS,$PRD_LABEL_NAME"

EPIC_JSON=$(gh issue create \
  --title "PREFIX-NNN — Epic: <PRD title>" \
  --label "$EPIC_LABELS" \
  --body "$(cat /tmp/epic-body.md)" \
  --json number,id,url)

EPIC_NUMBER=$(echo "$EPIC_JSON" | jq -r .number)
EPIC_NODE_ID=$(echo "$EPIC_JSON" | jq -r .id)
```

**Epic body template:**

```markdown
## Parent PRD

[Title](DISCUSSION_URL) — Discussion #NNNN

## Vertical slices

- [ ] #NNN — <title> (AFK)
- [ ] #NNN — <title> (AFK)
- [ ] #NNN — <title> (HITL)

## Dependencies

- #A blocks #B
- #C blocks #D

## Coverage

This epic covers user stories 1–N from the PRD.
```

GitHub auto-renders the task list as a progress bar and auto-checks items when they close.

**Add Epic to the Project (if `PROJECT_ID` is set):** same three calls as in Step 7 (`addProjectV2ItemById` + Area + PRD field). The Epic shares the PRD's Area.

### 9. Update the PRD's "Linked Issues" section (optional)

If the PRD body has a "Linked Issues" or similar section, edit the Discussion to add the Epic link. Use `updateDiscussion`:

```bash
gh api graphql -f query='mutation($id:ID!,$body:String!){updateDiscussion(input:{discussionId:$id,body:$body}){discussion{url}}}' \
  -f id="$PRD_DISCUSSION_ID" \
  -f body="$(cat /tmp/prd-body-updated.md)"
```

### 10. Report

```
PRD: <title> (Discussion #NNNN)
Prefix: PREFIX-
Project: <name> (#NNN) — <url>          ← omitted if PRD had no Project
Epic: #NNN (added to Project: yes/no)
Issues created: #NNN, #NNN, ... (X total)
  AFK: X
  HITL: Y
  Added to Project: X/X
  Area set: <value>
  PRD link set: yes
Dependencies: #A blocks #B; #C blocks #D
All labeled phase:unscheduled and prd-<N> — run pp-create-sprint to schedule.
```

## What this skill does NOT do

- Does not assign `phase:N`. Always `phase:unscheduled`. `pp-create-sprint` is responsible for scheduling.
- Does not pick the prefix. Always asks (unless cwd or PRD content makes it unambiguous, in which case proposes and asks for confirmation).
- Does not write ADRs. If a slice is HITL because an architectural decision is missing, recommend invoking `pp-write-an-adr` first.
- Does not modify the PRD's product content. Only adds links.
- Does not create issues outside the prefix's project — never mix projects in one run.
- Does not create new GitHub Projects. Only adds to the Project the PRD already references. If the PRD has no Project, this skill still creates the issues but skips Project attachment — re-run `pp-write-a-prd` Step 7.5 to add a Project later and add items manually or by re-running an attachment step.
- Does not change the Area mid-run. One Area per PRD run. If slices belong to different Areas, that is a signal to split the PRD.

## Tone

Concrete, slice-oriented, dependency-aware. The output is a backlog another engineer can pick up without further context beyond the PRD link.
