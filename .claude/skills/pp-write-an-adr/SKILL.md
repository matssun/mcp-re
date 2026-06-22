---
name: pp-write-an-adr
description: This skill should be used when the user asks to "write an ADR", "pp-write-an-adr", "create an ADR", "record this decision", or wants to capture an architectural decision as a GitHub Discussion. Pre-loads codebase defaults (ABC interfaces, opaque IDs, OpenAPI-first, DI container, etc.) so the user mostly confirms rather than designs from scratch. If derived from a parent PRD, inherits the PRD's `prd-<N>` label and adds itself to the PRD's Project. Part of the pp- (project-planning) skill bundle; chains downstream of pp-write-a-prd.
---

# pp-write-an-adr

Capture a single architectural decision as a GitHub Discussion. Most decisions in this codebase are already settled by global rules in `CLAUDE.md` — this skill pre-fills those defaults as the recommended choice and asks the user to confirm or override per decision. The result: ADR authoring becomes ratification, not design.

## When to use

Trigger on "write an ADR", "create an ADR", "record this decision", "pp-write-an-adr", or after a PRD is posted and one or more architectural choices need to be locked in. Also use for pure tech-debt or infra decisions with no upstream PRD.

**One ADR = one decision.** If the user describes multiple decisions, write multiple ADRs. Do not bundle.

## Pipeline position

```
pp-grill-me  →  pp-write-a-prd  →  pp-write-an-adr (0..N)  →  pp-prd-to-issues  →  code
                       ↓                       ↓
                  [Project]  ────────────►  (ADR joins same Project via prd-<N> label + Draft Issue proxy)
```

Most PRDs need zero to three ADRs. Routine features need none — the defaults cover them. When a parent PRD exists, this skill applies the parent's `prd-<N>` label to the ADR Discussion and adds a Draft Issue proxy for the ADR to the PRD's Project (resolved from the `**Project:**` line in the PRD body). The proxy is required because GitHub's `ProjectV2ItemContent` union is `DraftIssue | Issue | PullRequest` only — Discussion nodes are not accepted by `addProjectV2ItemById`. Standalone ADRs (no parent PRD) may optionally be attached to an existing Project the user picks, via the same proxy.

## Procedure

### 1. Identify the decision

Ask the user what single decision they want to record. Phrase it as a question with a recommended answer. Example: "Decision: should the tax service use Postgres or DynamoDB for evidence storage? Recommended: Postgres."

If the user describes multiple decisions, list them and offer to author one ADR per decision.

### 1.5. Identify the parent PRD (if any)

Ask: "Does this ADR derive from a PRD?" If yes, get the PRD Discussion number (or URL).

Then fetch the PRD up front — its label and Project link are needed downstream:

```bash
PRD_N="<discussion-number>"
gh api graphql -f query='query($n:Int!){
  repository(owner:"matssun",name:"code"){
    discussion(number:$n){
      id title url body
      labels(first:20){ nodes{ id name } }
    }
  }
}' -F n=$PRD_N
```

From the result, capture:
- `PRD_DISCUSSION_ID` — used later to edit "Linked ADRs".
- `PRD_LABEL_NAME` — the `prd-<N>` label on the PRD (if present). This ADR will inherit it.
- `PRD_PROJECT_URL` — parse the `**Project:** <url>` line from `body` (if present). Used to resolve the Project node ID.

If no parent PRD, this is a standalone ADR. Skip Step 7.5's PRD-linked branch; offer the user the option to attach to any existing Project at Step 7.5.

### 2. Check the defaults table

Walk through "Codebase defaults" below. For each row that applies to the decision, present the default as the recommendation. The user will typically confirm; sometimes they will override with reasoning. Capture both the choice and the reasoning — the reasoning is what makes the ADR useful.

If the decision is genuinely novel (not covered by defaults), state that explicitly and proceed to interview the user. Consider invoking `pp-grill-me` if the decision space is wide.

### 3. Pick the tag and number

ADRs follow the convention `ADR-<TAG>-<NNN>: <title>`. Tags seen in this repo: `TAX`, `LAIGO`, `SEC`, `NT` (Nautilus Trader). Ask the user for the tag.

Find the next number for that tag:

```bash
gh api graphql -f query='{search(query:"repo:matssun/code ADR-TAX-",type:DISCUSSION,first:50){nodes{... on Discussion{title}}}}'
```

Replace `TAX` with the chosen tag. Take the highest existing number and add 1. Confirm with the user.

### 4. Confirm category

Ask which Discussion category. **Do not assume a default.** Domain ADRs typically go in their domain category (`tax`, `Security`, `LAIgo`, `Nautilus Trader`). Cross-cutting decisions go in `Project Planning`.

### 5. Draft the ADR body

Use the template in "ADR template" verbatim. Fill every section. The Decision section must be a single concrete sentence — no waffle.

Constraints:
- **No PRD content.** User stories, success metrics, and product framing belong in the PRD. Link the PRD; do not duplicate it.
- **Cite codebase evidence.** When the choice follows existing patterns, link the file or rule (e.g. "follows the ABC convention in `CLAUDE.md`"). When it diverges, explain why.
- **Consequences must include negative ones.** A decision with only upsides is under-considered.

### 6. Show the draft

Render the full draft in the conversation. Wait for explicit user confirmation before posting.

### 7. Post the Discussion

Post directly using `gh api graphql` with the `createDiscussion` mutation. Title format: `ADR-<TAG>-<NNN>: <title>`. See "Posting" below.

### 7.5. Apply label and attach to Project

Two branches depending on what Step 1.5 found:

**A. Parent PRD exists** (most common):

- If `PRD_LABEL_NAME` exists, apply it to the new ADR Discussion via `addLabelsToLabelable`.
- If `PRD_PROJECT_URL` was found in the PRD body, resolve the Project node ID (see "Project attachment" below) and add a **Draft Issue proxy** for the ADR to the Project via `addProjectV2DraftIssue` (see "Why a Draft Issue proxy" in `pp-write-a-prd` §7.5 — same reason applies here). Optionally set the proxy item's `Area` field to match the PRD's `Area`.
- Edit the PRD Discussion to append the new ADR under "Linked ADRs" (this was already part of Step 8 — pull it forward to here so the PRD is updated before reporting back).

**B. No parent PRD** (standalone ADR):

- Prompt the user: "Attach this ADR to a Project? (list active / skip)". If the user picks a Project, add a Draft Issue proxy for the ADR via `addProjectV2DraftIssue`. No `prd-<N>` label is applied.

### 8. Report back

Return the Discussion URL and number, plus the Project URL/number if attached, plus a confirmation that the PRD's "Linked ADRs" was updated (if applicable). If this ADR is part of a larger architectural initiative (e.g., ORCH, LAIGO), suggest updating the initiative's status document (e.g., `/docs/architecture/orch-status.md`) to track implementation progress.

## Codebase defaults

Walk through these. For each that applies, present as recommended; user confirms or overrides. Source: `CLAUDE.md` and prior ADRs.

| Decision area | Default (recommended) | Override implies |
|---|---|---|
| Interface definition | `abc.ABC` + `@abstractmethod` | Strong reason; **never** `typing.Protocol` |
| Interface filename | `i<name>.py` (no underscore after `i`) | Not negotiable — rename if found wrong |
| One class per file | One top-level class; nested helpers OK | Strong reason |
| ID types in domain/service | Opaque ID types (`IUserID` etc.) | Strong reason; never plain `str` outside `adapters/`, `generated/`, `tests/` |
| API contract | OpenAPI-first → generated models → adapter (`APIBoundary`) → domain | Strong reason |
| Persistence | SQLAlchemy under `persistence/`, extends `Base`; mappers translate to domain | Strong reason |
| Cross-entity ORM relationships | Peer `I<Entity>Entity` interfaces | Strong reason |
| Database engine | Postgres | Workload-specific reason (e.g. timeseries → consider TimescaleDB) |
| Error handling | `error_handling` module; `VerificationRuleOrchestartor` only at entry points | Strong reason |
| Configuration | `config_management` module | Strong reason |
| Dependency injection | Production DI container; no `app.state` patterns | Strong reason |
| Build / dependency mgmt | Bazel + central uv via `infrastructure/config/dependency/dependencies-dev.toml`; no PYTHONPATH | Not negotiable |
| `assert` in production | Forbidden; use explicit guards raising errors | Tests only |
| `@classmethod` | Only for alternative constructors returning `cls(...)` | Strong reason |
| Import aliasing (`as`) | Forbidden | Not negotiable |
| Stub implementations (`NotImplementedError`-only) | Forbidden | Not negotiable |
| Frontend | React SPA + FastAPI backend (per ADR-TAX-002) | Domain-specific reason |
| File placement | Application-specific code under `applications/`; reusable libs under `components/`; never mix | Not negotiable |

When the user's choice matches the default, write "Follows codebase default per `CLAUDE.md`" in the Decision rationale. When it overrides, write the reasoning in full — that is the load-bearing content of the ADR.

## ADR template

```markdown
## Status

Proposed | Accepted | Superseded by ADR-<TAG>-<NNN>

## Context

The forces at play: the problem, constraints, prior art, and why a decision is needed now. Cite the PRD (if any) and any superseded ADRs. Reference codebase rules from `CLAUDE.md` where relevant.

## Decision

A single concrete sentence stating what was decided. No hedging.

## Rationale

Why this choice. If it follows the codebase default, say so and stop. If it overrides a default, explain in full.

## Alternatives Considered

Each alternative with one line on why it was rejected. Include "do nothing" if applicable.

## Consequences

### Positive
- ...

### Negative
- ...

### Neutral
- ...

## Compliance and Enforcement

How this decision is enforced (tests, hooks, lints, manual review). If there is no enforcement, say so explicitly — that is a known risk.

## Related

- PRD: <discussion-url> (if applicable)
- Prior ADRs: ADR-<TAG>-<NNN>, ...
- Code: file paths or modules touched (best-effort; expect rot)
```

## Listing categories and existing ADRs

```bash
# Categories
gh api graphql -f query='{repository(owner:"matssun",name:"code"){discussionCategories(first:30){nodes{name id}}}}'

# Existing ADRs for a tag (substitute TAG)
gh api graphql -f query='{search(query:"repo:matssun/code ADR-TAG-",type:DISCUSSION,first:50){nodes{... on Discussion{title number url}}}}'
```

## Posting

```bash
# Get repo + category IDs (one shot)
gh api graphql -f query='{repository(owner:"matssun",name:"code"){id discussionCategories(first:30){nodes{name id}}}}'

# Write body to temp file to avoid shell escaping
# /tmp/adr-body.md

gh api graphql -f query='mutation($repoId:ID!,$catId:ID!,$title:String!,$body:String!){createDiscussion(input:{repositoryId:$repoId,categoryId:$catId,title:$title,body:$body}){discussion{url number}}}' \
  -f repoId="$REPO_ID" \
  -f catId="$CATEGORY_ID" \
  -f title="ADR-<TAG>-<NNN>: <title>" \
  -f body="$(cat /tmp/adr-body.md)"
```

## Editing the PRD's Linked ADRs

After posting, if this ADR derives from a PRD, edit the PRD Discussion to add the link. Use `updateDiscussion`:

```bash
gh api graphql -f query='mutation($id:ID!,$body:String!){updateDiscussion(input:{discussionId:$id,body:$body}){discussion{url}}}' \
  -f id="$PRD_DISCUSSION_ID" \
  -f body="$(cat /tmp/prd-body-updated.md)"
```

Get the PRD's body first, append the ADR link under "Linked ADRs", then update.

## Project attachment

When `PRD_PROJECT_URL` was extracted from the parent PRD body (or the user picked a Project for a standalone ADR), apply the `prd-<N>` label and add the ADR Discussion as a Project item.

### Resolve Project node ID from URL

The URL has the shape `https://github.com/users/matssun/projects/<NUMBER>`. Convert to a node ID:

```bash
PROJECT_NUMBER=$(echo "$PRD_PROJECT_URL" | sed -E 's|.*/projects/([0-9]+).*|\1|')
PROJECT_ID=$(gh api graphql -f query='query($login:String!,$num:Int!){
  user(login:$login){ projectV2(number:$num){ id } }
}' -F login=matssun -F num=$PROJECT_NUMBER --jq '.data.user.projectV2.id')
```

For standalone ADRs, list the user's active Projects and ask the user to pick:

```bash
gh api graphql -f query='{
  viewer{ projectsV2(first:50){ nodes{ id url number title closed } } }
}' | jq '.data.viewer.projectsV2.nodes[] | select(.closed==false) | {number, title, id, url}'
```

### Apply `prd-<N>` label (PRD-derived ADRs only)

```bash
LABEL_ID=$(gh api graphql -f query='{
  repository(owner:"matssun",name:"code"){ label(name:"'"$PRD_LABEL_NAME"'"){ id } }
}' --jq '.data.repository.label.id')

gh api graphql -f query='mutation($id:ID!,$labelIds:[ID!]!){
  addLabelsToLabelable(input:{labelableId:$id,labelIds:$labelIds}){ clientMutationId }
}' -f id="$ADR_DISCUSSION_ID" -f labelIds="$LABEL_ID"
```

### Add a Draft Issue proxy for the ADR to the Project

GitHub's `ProjectV2ItemContent` union is `DraftIssue | Issue | PullRequest` only — `addProjectV2ItemById` does NOT accept Discussion nodes, so a one-line Draft Issue proxy is used. Capture the returned `projectItem.id` for any field updates below.

```bash
DRAFT_TITLE="💬 Discussion: $ADR_TITLE"
DRAFT_BODY="This item tracks the team discussion. Join the conversation here: $ADR_URL"
ITEM_ID=$(gh api graphql -f query='mutation($projectId:ID!,$title:String!,$body:String!){
  addProjectV2DraftIssue(input:{projectId:$projectId, title:$title, body:$body}){ projectItem{ id } }
}' -f projectId="$PROJECT_ID" -f title="$DRAFT_TITLE" -f body="$DRAFT_BODY" \
  --jq '.data.addProjectV2DraftIssue.projectItem.id')
```

### (Optional) Set the Area field on the ADR item

Useful when adding a standalone ADR to a Project. For PRD-derived ADRs, inherit the Area from the parent PRD's item. See the `pp-write-a-prd` skill's "Set the Area field" subsection for the field-lookup and `updateProjectV2ItemFieldValue` calls — the pattern is identical.

## What this skill does NOT do

- Does not bundle multiple decisions into one ADR. One decision per ADR.
- Does not draft to a local file. Posts go directly to GitHub Discussions on user confirmation.
- Does not invent codebase rules. When the default table does not cover a decision, say so and interview.
- Does not pick a category or a tag. Always asks.
- Does not create new Projects. Only attaches the ADR to the PRD's existing Project (or a Project the user picks for standalone ADRs). New Projects are created only via `pp-write-a-prd`.

## Tone

Concrete, decisive, evidence-based. ADRs are read by future engineers asking "why did we do this?" — answer that question and nothing else.
