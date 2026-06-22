---
name: pp-write-a-prd
description: This skill should be used when the user asks to "write a PRD", "pp-write-a-prd", "create a PRD", "turn this into a PRD", or wants to capture product intent (problem, users, stories, success metrics) for a feature. Posts the PRD directly as a GitHub Discussion and optionally creates or attaches a GitHub Project (v2) by copying the `_PRD-Seed` Project, applying the `prd-<N>` label convention used by downstream skills. Part of the pp- (project-planning) skill bundle; chains with pp-grill-me upstream and pp-write-an-adr downstream.
---

# pp-write-a-prd

Capture product intent for a feature as a structured PRD and post it directly as a GitHub Discussion. The PRD describes **what** and **why** for users — not **how**. Architectural decisions belong in ADRs (see `pp-write-an-adr`), not in the PRD.

## When to use

Trigger on "write a PRD", "create a PRD", "pp-write-a-prd", or any request to formalize a product idea before issues are cut. Skip this skill for pure technical work with no user-facing change — that goes straight to `pp-write-an-adr`.

## Pipeline position

```
pp-grill-me  →  pp-write-a-prd  →  [Project: create / attach / skip]
                       ↓                       ↓ (label: prd-<N>)
                pp-write-an-adr (0..N)  →  pp-prd-to-issues  →  pp-create-sprint
                                                    ↑
                          (downstream skills add their artifacts to the same Project)
```

The PRD is the upstream artifact. ADRs are linked from the PRD as they get written. The Project (if created) becomes the overview lens — downstream skills explicitly add issues, PRs, and related discussions to it via API (no label-based auto-add workflow is used; see Step 7.5).

## Procedure

### 1. Gather raw input

Ask the user for a long, detailed description of the problem and any solution ideas. Do not start drafting on a one-line prompt.

### 2. Verify against the codebase

Before accepting any factual claim about current behavior, capabilities, or constraints, explore the repo to verify. Cite file paths and line numbers when correcting or confirming.

### 3. Decide if grilling is needed

Inspect the gathered input against the PRD template (below). If any of these are vague, missing, or contradictory, **invoke `pp-grill-me`** before drafting:

- Who the user is (actor)
- What problem they hit, in their words
- What "done" looks like measurably
- What is explicitly out of scope

Resume here only after `pp-grill-me` reports a resolved decision tree.

### 4. Confirm category

Ask the user which GitHub Discussion category to post under. **Do not assume a default.** Common categories in this repo include `Project Planning`, `tax`, `LAIgo`, `Security`, `Crisis Management`, `CodeGraphait Architecture`, `Energy`, `Gloso`, `Nautilus Trader`, `Performance & Scale`, `CPG Architecture`, `Graph Model`, `Language Frontends`, `Ideas`, `Q&A`. List available categories if the user is unsure (see "Listing categories" below).

### 5. Draft the PRD body

Use the template in "PRD template" verbatim. Fill every section. If a section is genuinely empty, write `_None._` — do not delete the heading.

Constraints:
- **No implementation details, file paths, or code snippets.** They rot. Push them to ADRs.
- **No technology choices** unless they are user-visible (e.g. "supports Excel export" is fine; "uses pandas" is not).
- User stories are numbered and use the form `As an <actor>, I want <feature>, so that <benefit>`.

### 6. Show the draft

Render the full draft in the conversation. Wait for explicit user confirmation before posting. Edits are cheap before posting and noisy after.

### 7. Post the Discussion

Post directly using `gh api graphql` with the `createDiscussion` mutation. Title format: `PRD: <feature name>`. See "Posting" below.

### 7.5. Create or attach a Project (optional)

After the Discussion is posted, prompt the user with three options:

1. **Create new Project** — copies `_PRD-Seed` (custom fields and status workflows already configured). Title: `PRD-<N>: <feature name>` where `<N>` is the Discussion number.
2. **Attach to existing Project** — list active Projects under `matssun` and let the user pick.
3. **Skip** — no Project. Can be added later.

If 1 or 2:

- Create the repo label `prd-<N>` if missing (idempotent).
- Apply that label to the Discussion via `addLabelsToLabelable`.
- Edit the Discussion body to insert `**Project:** <project-url>` immediately under the title.
- Add a **Draft Issue proxy** for the Discussion to the Project via `addProjectV2DraftIssue` (see "Why a Draft Issue proxy" below) and set the `Area` field on the returned `projectItem.id` if the user can pick a value.

**Why a Draft Issue proxy (and not `addProjectV2ItemById` for the Discussion).** GitHub's `ProjectV2ItemContent` union is `DraftIssue | Issue | PullRequest` only — Discussion is **not accepted** by `addProjectV2ItemById`, even though the web UI now lets you add a Discussion to a Project manually. Calling `addProjectV2ItemById` with a Discussion node ID returns `Could not resolve to ProjectV2ItemContent node` (verified by schema introspection 2026-05). The workaround is a one-line Draft Issue whose body links back to the Discussion. Issues and PRs created by downstream skills (`pp-prd-to-issues`, etc.) still use `addProjectV2ItemById` directly — only Discussion content needs the proxy.

This skill does **not** configure any auto-add label workflow on the Project. GitHub's auto-add filter does not support label wildcards (e.g., `label:prd-*` is invalid), and per-PRD filter editing via API is unreliable. Instead, downstream skills explicitly add their artifacts to the Project they read from the PRD body. The only workflows enabled on `_PRD-Seed` are status-driven (item closed → Done, PR merged → Done, auto-archive Done after N days), which copy with the Project and need no per-PRD configuration.

### 8. Report back

Return the Discussion URL and number, plus the Project URL and number if one was created or attached. Suggest next step: write any needed ADRs with `pp-write-an-adr` (it applies the same `prd-<N>` label and adds itself to the Project) and link them from the PRD's "Linked ADRs" section. For major initiatives, remind the user to create or update the initiative's status document to track ADR/PRD delivery (e.g., `/docs/architecture/orch-status.md`).

## PRD template

```markdown
## Problem Statement

The problem the user faces, from the user's perspective. Concrete, observable, no jargon.

## Users / Actors

Who experiences this problem. Distinguish primary actor from secondary actors.

## Solution Overview

What the user will be able to do once this is built. From the user's perspective. No implementation.

## User Stories

A numbered list, extensive, covering the full surface of the feature. Format:

1. As a <actor>, I want <feature>, so that <benefit>.
2. ...

## Success Metrics

How we will know this worked. Prefer measurable outcomes (numbers, rates, times) over feelings.

## Out of Scope

Things this PRD explicitly does **not** cover. Be specific — vague exclusions cause scope creep later.

## Open Questions

Unresolved product questions, with a named owner or a trigger for when they must be resolved.

## Linked ADRs

Architectural decisions that flow from this PRD. Populated as ADRs are written. Format:

- [ADR-<TAG>-<NNN>: <title>](<discussion-url>)

## Further Notes

Anything else relevant — prior art, related discussions, stakeholder context.
```

## Listing categories

Run this when the user is unsure which category to pick:

```bash
gh api graphql -f query='{repository(owner:"matssun",name:"code"){discussionCategories(first:30){nodes{name slug id}}}}'
```

Cache the category `id` for the chosen name — `createDiscussion` requires the category ID, not the name.

## Posting

Get the repository ID and category ID, then post:

```bash
# Get repo + category IDs (one shot)
gh api graphql -f query='{repository(owner:"matssun",name:"code"){id discussionCategories(first:30){nodes{name id}}}}'

# Post the discussion (substitute REPO_ID, CATEGORY_ID, TITLE, BODY)
gh api graphql -f query='mutation($repoId:ID!,$catId:ID!,$title:String!,$body:String!){createDiscussion(input:{repositoryId:$repoId,categoryId:$catId,title:$title,body:$body}){discussion{url number}}}' \
  -f repoId="$REPO_ID" \
  -f catId="$CATEGORY_ID" \
  -f title="PRD: <feature name>" \
  -f body="$(cat /tmp/prd-body.md)"
```

Write the body to a temp file first to avoid shell escaping issues with multi-line markdown.

## Project setup

The seed Project `_PRD-Seed` lives under user `matssun` and is pre-configured with custom fields (`PRD`, `Area`, `Priority`, `Sprint`, `ADRs`) and status workflows. `Area` is a single-select with values: Cross Cutting, CodeGraphait, Energy, Finance, Health Care, Gloso, Laigo, Personal Apps, Platform, Security, SSB.

### Resolve viewer + seed Project IDs (once per run)

```bash
gh api graphql -f query='{
  viewer{
    id
    login
    projectsV2(first:50, query:"_PRD-Seed"){
      nodes{ id title number url }
    }
  }
}'
```

Cache `viewer.id` as `OWNER_ID` and the matching `projectsV2.nodes[0].id` as `SEED_PROJECT_ID`.

### Option 1 — Create new Project from seed

```bash
gh api graphql -f query='mutation($ownerId:ID!,$projectId:ID!,$title:String!){
  copyProjectV2(input:{ownerId:$ownerId, projectId:$projectId, title:$title, includeDraftIssues:false}){
    projectV2{ id url number }
  }
}' -f ownerId="$OWNER_ID" -f projectId="$SEED_PROJECT_ID" -f title="PRD-<N>: <feature name>"
```

The copy preserves custom fields and status workflows (verified manually).

### Option 2 — List active Projects to attach to

```bash
gh api graphql -f query='{
  viewer{
    projectsV2(first:50){
      nodes{ id url number title closed }
    }
  }
}' | jq '.data.viewer.projectsV2.nodes[] | select(.closed==false) | {number, title, id, url}'
```

Present the list to the user; capture the chosen `id` as `PROJECT_ID`.

### Apply label, add Discussion to Project, update body

```bash
# 1. Create the repo label if missing (idempotent)
gh label create "prd-<N>" --description "Artifacts belonging to PRD-<N>" --color "0E8A16" 2>/dev/null || true

# 2. Get the label node ID
LABEL_ID=$(gh api graphql -f query='{
  repository(owner:"matssun",name:"code"){ label(name:"prd-<N>"){ id } }
}' --jq '.data.repository.label.id')

# 3. Apply label to the Discussion
gh api graphql -f query='mutation($id:ID!,$labelIds:[ID!]!){
  addLabelsToLabelable(input:{labelableId:$id,labelIds:$labelIds}){ clientMutationId }
}' -f id="$DISCUSSION_ID" -f labelIds="$LABEL_ID"

# 4. Add a Draft Issue proxy for the Discussion to the Project.
#    addProjectV2ItemById does NOT accept Discussion nodes
#    (ProjectV2ItemContent = DraftIssue | Issue | PullRequest only).
#    Capture the returned projectItem.id for the Area field call below.
DRAFT_TITLE="💬 Discussion: $PRD_TITLE"
DRAFT_BODY="This item tracks the team discussion. Join the conversation here: $PRD_URL"
ITEM_ID=$(gh api graphql -f query='mutation($projectId:ID!,$title:String!,$body:String!){
  addProjectV2DraftIssue(input:{projectId:$projectId, title:$title, body:$body}){ projectItem{ id } }
}' -f projectId="$PROJECT_ID" -f title="$DRAFT_TITLE" -f body="$DRAFT_BODY" \
  --jq '.data.addProjectV2DraftIssue.projectItem.id')

# 5. Re-edit the Discussion body to prepend the Project link
gh api graphql -f query='mutation($id:ID!,$body:String!){
  updateDiscussion(input:{discussionId:$id,body:$body}){ discussion{ url } }
}' -f id="$DISCUSSION_ID" -f body="$(cat /tmp/prd-body-with-project.md)"
```

### Set the Area field (optional but recommended)

If the user picks an Area value, set it on the newly-added item. `$ITEM_ID` here is the `projectItem.id` returned by `addProjectV2DraftIssue` in step 4 above (Draft Issue proxy for the Discussion). For Issues / PRs added directly via `addProjectV2ItemById`, `$ITEM_ID` is similarly the item id returned by that mutation.

```bash
# Get Area field ID + option IDs
gh api graphql -f query='query($projectId:ID!){
  node(id:$projectId){
    ... on ProjectV2 {
      field(name:"Area"){
        ... on ProjectV2SingleSelectField { id options{ id name } }
      }
    }
  }
}' -f projectId="$PROJECT_ID"

# Set the value
gh api graphql -f query='mutation($projectId:ID!,$itemId:ID!,$fieldId:ID!,$optId:String!){
  updateProjectV2ItemFieldValue(input:{
    projectId:$projectId, itemId:$itemId, fieldId:$fieldId,
    value:{ singleSelectOptionId:$optId }
  }){ projectV2Item{ id } }
}' -f projectId="$PROJECT_ID" -f itemId="$ITEM_ID" -f fieldId="$AREA_FIELD_ID" -f optId="$AREA_OPTION_ID"
```

## What this skill does NOT do

- Does not draft to a local file. Posts go directly to GitHub Discussions on user confirmation.
- Does not write ADRs. Implementation/architectural decisions are deferred to `pp-write-an-adr`.
- Does not create issues. Use `pp-prd-to-issues` once the PRD and any ADRs are posted.
- Does not pick a category. Always ask.
- Does not configure Project workflows or fields. Those are managed once in `_PRD-Seed` via the GitHub UI, not per-PRD via API. Label-based auto-add workflows are intentionally not used (filter syntax does not support wildcards); downstream skills add items to the Project explicitly via `addProjectV2ItemById`.

## Tone

Concise, user-facing, free of implementation language. The reader of a PRD should understand the user value without knowing the codebase.
