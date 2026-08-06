# Round-7 security audit — handoff record

Start at [`HANDOFF.md`](HANDOFF.md).

## What is here, and what is not

This directory is the tracked record of round 7 of the security-audit funnel: the
per-finding dispositions, the process notes, and the gate evidence. It is **not** the
raw scan output.

The raw output — the stage-1/2 findings, the file-by-file report that was the fix input,
the per-agent result files, the clustering scripts — stays in the gitignored
`work/security-audit-2026-08-03/`, which is **deliberately not tracked**.
`scripts/tracked_secrets_gate.py` requires `work/` in both `.dockerignore` and
`.gcloudignore` precisely because it is where a developer is told to put real
credentials. Committing it onto a branch would defeat that control, so what is preserved
here is the subset a later reader actually needs.

One redaction was applied on the way in: `triage.json` quotes the PEM armor strings that
`tracked_secrets_gate.py` matches on, in a finding *about that gate*. Tracked, they trip
the gate they describe. They are rendered `<PEM private-key armor>`. No key material was
involved, and nothing else was changed.

| file | what it is |
|---|---|
| `HANDOFF.md` | base and checkpoint SHAs, changed-file inventory, every gate command with its unfiltered exit status, the five findings that were open at checkpoint, and the decisions taken about them |
| `triage.json` | all 153 findings with disposition, evidence, action, and — where one was recorded — an `owner_correction` or `resolution` |
| `PROCESS-NOTES.md` | how the round was run, the quota-kill recovery, and the two process rules it cost |
| `gate-checkpoint-stage12.log` | stage 1–2 on the pre-checkpoint tree |
| `gate-checkpoint-stage34.log` | stage 3–4 on the pre-checkpoint tree, including the SLO A/B |
| `gate-checkpoint-rerun.log` | stage 1–3 re-run against the committed tree |
| `gate-revision.log` | stage 1–3 on the C080/C082/C114 contract revision |
