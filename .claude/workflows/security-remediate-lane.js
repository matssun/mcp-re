export const meta = {
  name: 'security-remediate-lane',
  description: 'Remediate a batch of files: a read-only evaluator judges each file once, a worker applies its decisions behind a single-writer lane, the evaluator reviews the diff',
  whenToUse: 'One tick of the security-remediate Phase-B loop over a batch from next_file.py --top N. The caller selects the files; this runs evaluate -> fix -> review and returns one verdict per file.',
  phases: [
    { title: 'Evaluate', detail: 'read-only: confirm every finding from source, dispose what needs no code change, emit an executable work package' },
    { title: 'Fix', detail: 'single-writer lane: apply the package, run the gate' },
    { title: 'Review', detail: 'judge the diff against the package that ordered it' },
  ],
}

// ---------------------------------------------------------------------------
// Inputs (args)
//   files       [{file, related[], findings[], gate_tier, importers}]  <- next_file.py --top N
//   ledger      path to the finding ledger
//   packets_dir directory of per-file audit packets (finding evidence/remediation)
//   out_dir     where evaluators/workers write packages and reports
//   pyright_baseline_errors  Python files only: whole-repo pyright error count the `wide` gate compares against (default 0)
//   rulings     path(s) to the campaign's binding owner rulings (string or list)
//   epoch       policy epoch stamped on every journal event (optional)
//   dry_run     true = evaluate only, never dispatch a worker
//
// The gate is no longer passed as prose. `check.py` derives the src root, the
// owning tree and the dependents' trees from the file and its tier, so the
// former `prescan_cmd` / `gate` args are ignored if given.
// ---------------------------------------------------------------------------
const A = args || {}
const FILES = A.files || []
const LEDGER = A.ledger
const PACKETS = A.packets_dir
const OUT = A.out_dir
const PYRIGHT_BASELINE = Number.isInteger(A.pyright_baseline_errors) ? A.pyright_baseline_errors : 0
const EPOCH = A.epoch || A.policy_epoch || ''
const DRY = A.dry_run === true
const RULINGS = [].concat(A.rulings || [])
const SCRIPTS = 'python3 .claude/skills/security-remediate/scripts/'
// The tailable record of the run. Every role appends its own events; the caller
// reconciles at batch end so a died agent shows up as `lost` rather than as a
// shorter log. Defaults beside the packages so a run is self-contained.
const PROGRESS = A.progress_log || ((A.out_dir || '.') + '/progress')
// Where per-tree bazel baselines live. The gate compares failing-target SETS
// against these; without one it refuses rather than comparing against zero.
const GATES_STORE = A.gates_store || ((A.out_dir || '.') + '/gates')
// The subagent registry is read at session start, so an agent definition added
// during a session is not yet a valid `agentType`. Until the session restarts,
// run the same roles on `general-purpose` and have each agent read its own
// definition file first — the definition stays the single source of truth either
// way. Pass `registered_agents: true` once the types resolve natively.
const REGISTERED = A.registered_agents === true

// ---------------------------------------------------------------------------
// Per-role model and effort. Tiered by the BLAST RADIUS OF BEING WRONG, not by
// how hard the task looks:
//   evaluator (senior)  writes TERMINAL ledger statuses. A wrong close retires a
//                       real defect permanently behind an authoritative reason.
//                       Nothing downstream re-opens it. Most expensive failure.
//   evaluator (cheap)   admitted only on files whose findings are all mechanical
//                       and none severe — and it may NOT close one (see the
//                       agent's tier contract). It can act; it can't close.
//   worker              mechanical ONLY BECAUSE the package carries an exact
//                       anchor, an accept check, and an independent reviewer.
//                       Remove any of those three and this tier is unsafe.
//   reviewer            cheap task, expensive failure: a rubber-stamp accept
//                       marks findings `fixed`, and a `fixed` finding that
//                       reappears is logged as a REGRESSION, misdirecting work.
// Override any of them via args.roles.
// ---------------------------------------------------------------------------
const ROLES = Object.assign({
  evaluator_senior: { model: 'opus', effort: 'high' },
  evaluator_senior_critical: { model: 'opus', effort: 'max' },
  evaluator_cheap: { model: 'sonnet', effort: 'medium' },
  worker: { model: 'sonnet', effort: 'medium' },
  reviewer: { model: 'opus', effort: 'medium' },
}, A.roles || {})

function evaluatorRole(item) {
  if (item.eval_tier === 'cheap') return ['evaluator_cheap', 'cheap']
  const hasCritical = (item.findings || []).some(f => String(f.severity).toLowerCase() === 'critical')
  return [hasCritical ? 'evaluator_senior_critical' : 'evaluator_senior', 'senior']
}
const EVALUATOR_DEF = '.claude/agents/security-fix-evaluator.md'
const WORKER_DEF = '.claude/agents/security-fix-worker.md'

// `model/effort` as stamped on every journal event. The transcripts record the
// model but not the effort, so without this no later measurement can say what
// `max` bought over `high`.
function modelTag(roleKey) {
  const r = ROLES[roleKey] || {}
  return (r.model || '?') + (r.effort ? '/' + r.effort : '')
}

function roleOpts(def, label, phaseName, schema, roleKey) {
  const o = { label: label, phase: phaseName, schema: schema }
  if (REGISTERED) o.agentType = def === EVALUATOR_DEF ? 'security-fix-evaluator' : 'security-fix-worker'
  else o.agentType = 'general-purpose'
  const r = ROLES[roleKey] || {}
  if (r.model) o.model = r.model
  if (r.effort) o.effort = r.effort
  return o
}

function withDef(def, body) {
  if (REGISTERED) return body
  return 'You are acting as the subagent defined in ' + def + '. READ THAT FILE FIRST and follow it exactly — '
    + 'it defines your role, your constraints and your output format. Then carry out the task below.\n\n' + body
}

if (!FILES.length) return { error: 'no files given', files: 0 }

function base(p) { return p.split('/').slice(-1)[0] }

// One attempt = one file-processing pass, shared by every event it emits.
// Deliberately NOT the file path: a retry of a file that died must stay
// distinguishable from the attempt it replaced, or per-file tallies silently
// overwrite each other (observed on state.py in tick 0).
const RUN_ID = A.run_id || 'run-' + Date.now().toString(36)
function attemptId(i) { return 'att-' + RUN_ID + '-' + String(i).padStart(3, '0') }
const PROGRESS_CLI = 'python3 .claude/skills/security-remediate/scripts/progress.py'
function pkgPath(i) { return OUT + '/' + String(i).padStart(3, '0') + '-' + base(FILES[i].file) + '.package.json' }

// The single-writer lane. Two workers editing one tree make every gate result
// meaningless — a dependent-tree run while another agent writes shows up as
// FAILED TO BUILD, and a type check reads a half-written tree. Evaluation and
// review are read-only and stay concurrent; only apply+gate is serialized.
let lane = Promise.resolve()
function serialized(fn) {
  const next = lane.then(fn, fn)
  lane = next.then(() => {}, () => {})
  return next
}

const EVAL_SCHEMA = {
  type: 'object',
  properties: {
    file: { type: 'string' },
    work_items: { type: 'number' },
    disposed: { type: 'number' },
    escalated: { type: 'number' },
    delete_or_wire: { type: 'number' },
    package_written: { type: 'boolean' },
    blocked_on: { type: 'string', description: 'only when blocked: one line; else omit' },
  },
  required: ['file', 'work_items', 'disposed', 'escalated', 'package_written'],
}

const WORK_SCHEMA = {
  type: 'object',
  properties: {
    file: { type: 'string' },
    applied: { type: 'array', items: { type: 'string' }, description: 'work ids applied' },
    not_applied: {
      type: 'array',
      items: { type: 'object', properties: { id: { type: 'string' }, reason: { type: 'string' } },
               required: ['id', 'reason'] },
      description: 'work ids NOT applied, each with a short reason — the only free text a worker writes',
    },
    gate_exit: { type: 'number' },
    // The VERDICT, not the exit code. `bazel test` exits nonzero on this tree
    // whatever the source says, so an exit code cannot decide anything — that is
    // the whole point of bazel_gate.py's baseline delta. Required, because a
    // MISSING field must never be read as failure: in tick 2 three files were
    // reported `gate-failed` purely because `gate_exit` came back undefined and
    // `undefined !== 0` is true. Every one of those changes was fine.
    gate_verdict: {
      type: 'string',
      description: 'ok | new-failures | infra | no-baseline | not-run',
    },
    files_touched: { type: 'array', items: { type: 'string' } },
    problem: { type: 'string', description: 'ONLY when something went wrong that the other fields cannot say: one line' },
  },
  required: ['file', 'applied', 'not_applied', 'gate_exit', 'gate_verdict', 'files_touched'],
}

// Only a NEW failure is attributable to the change, and only it may skip review.
//   infra       -> bazel could not judge the code at all; the diff is still
//                  reviewable, and skipping review would lose the one signal
//                  left. Three tick-2 files hit this because their trees have
//                  ZERO test targets, before and after.
//   no-baseline -> the gate refused to compare against zero. Not a failure.
//   not-run     -> nothing ran; say so rather than implying a pass.
function blocksReview(w) {
  return (w && w.gate_verdict) === 'new-failures'
}

const REVIEW_SCHEMA = {
  type: 'object',
  properties: {
    file: { type: 'string' },
    verdict: { type: 'string', description: 'accept | reject | partial' },
    items_accepted: { type: 'array', items: { type: 'string' } },
    items_rejected: {
      type: 'array',
      items: { type: 'object', properties: { id: { type: 'string' },
                                             cause: { type: 'string', description: 'scope | evidence | wrong-fix | anchor | other' },
                                             why: { type: 'string', description: 'one short line' } },
               required: ['id', 'cause'] },
    },
    unordered_changes: { type: 'array', items: { type: 'string' }, description: 'paths or hunks changed without an order; empty when none' },
  },
  required: ['file', 'verdict', 'items_accepted', 'items_rejected', 'unordered_changes'],
}

// Every role writes only what the next actor consumes, and free text only where
// something went wrong. Everything an agent writes is paid for as output tokens,
// and prose nobody reads — summaries, restated reasons, narrative notes — was a
// measurable share of the lane's output.
const QUIET = 'QUIET: write nothing that no actor reads. No prose summary, no narration, no restating what a command printed. Return ONLY the structured result; free text appears only where something went wrong.'

// `platform` (>50 importers) gates like `wide` — the dependents' crates are
// linted with the file's — unless args.platform_needs_ruling holds the file for
// a human before any edit.
const PLATFORM_RULING = A.platform_needs_ruling === true
function holdsForRuling(item) { return PLATFORM_RULING && item.gate_tier === 'platform' }

function evalPrompt(item, i, tier, model) {
  // A file held for a ruling never reaches a worker, so its evaluation IS the
  // whole attempt: it must end in its own terminal event, or reconciliation
  // reports a false `lost`.
  const evalOnly = DRY || holdsForRuling(item)
  const disposeCmd = SCRIPTS + 'dispose.py --ledger ' + LEDGER + ' --log ' + PROGRESS +
    ' --package ' + pkgPath(i) + ' --file ' + item.file +
    ' --attempt ' + attemptId(i) + ' --run ' + RUN_ID + ' --tier ' + tier +
    ' --model ' + (model || '?') + (EPOCH ? ' --epoch ' + EPOCH : '') + (evalOnly ? ' --dry-run' : '')
  return [
    'MODE: EVALUATE.',
    'TIER: ' + tier + '.' + (tier === 'cheap'
      ? '  You may order fixes, mark duplicates, mark superseded and escalate — but you may NOT close a finding as false-positive or accepted-risk. Follow the can\'t-close rule in your definition: set `needs-senior-eval` with a one-line proposal instead, which promotes this file to the senior tier.'
      : '  You may close a finding as false-positive or accepted-risk, with a one-line reason. If a finding on this file is already `needs-senior-eval`, a cheap evaluator proposed a closure in its note — decide it.'),
    'This file was tiered ' + item.eval_tier + ' because: ' + (item.eval_tier_reason || 'n/a') + '.',
    RULINGS.length ? 'BINDING owner rulings — read the parts that touch this file before disposing anything; never re-open one: ' + RULINGS.join(', ') : '',
    '',
    'file: ' + item.file,
    'related (files that import this one): ' + ((item.related || []).join(', ') || '(none)'),
    'importers across the monorepo: ' + item.importers + '  -> gate tier: ' + item.gate_tier,
    '',
    'TURN BUDGET. Every turn re-sends your whole context, so the mechanical work is done for you in two calls. Spend the turns between them on judgment only.',
    '',
    'STEP 1 — run this FIRST, once. It prints the findings (ledger x audit packet), where each evidence excerpt sits in the CURRENT source, the owning BUILD target and candidate test modules, a usage map (who imports / constructs / subclasses each symbol this file defines), and the whole source, line-numbered:',
    '  ' + SCRIPTS + 'prepare.py --ledger ' + LEDGER + ' --packets ' + PACKETS + ' --file ' + item.file,
    'Do NOT re-`cat` the file or re-run `file_findings.py`; it is all in that output. Grep further only for a question the usage map cannot answer — and it says when it was truncated and what it cannot see.',
    'Every finding it lists is actionable, and ALL of them must reach a disposition or a work item — including the low ones, which are a decision to make, not a backlog to defer. `liveness` is a hint, never proof of dead code.',
    'These came from an UNVERIFIED Stage-2 review. Confirm or refute each from source; anchor on the evidence excerpt, never the line number.',
    '',
    'STEP 2 — write the package (the schema in your definition) to: ' + pkgPath(i),
    '  Exactly the schema in your definition, written once. `disposed[]` carries a one-line `reason` ONLY for false-positive, accepted-risk, escalated and needs-senior-eval; a duplicate carries `duplicate_of` and nothing else. `work[]` items: id (or `finding_ids`), anchor, change, accept, standard. Nothing more.',
    '  WHEN YOU ESCALATE, GROUP IT: give escalations that one architectural decision would discharge together the same `ruling` id. 30 escalations collapsing onto 4 questions is 4 decisions, not 30. Invent a stable, descriptive id if none exists yet.',
    '',
    'STEP 3 — apply it with ONE call. It validates the whole package against the ledger (every actionable finding covered, reasons present, tier rules) and writes NOTHING if anything is wrong; otherwise it writes every ledger disposition, every `close` event, the `evaluate` event with counts DERIVED from your identities, and ' + (evalOnly ? 'the `dry-run` terminal event (' + (DRY ? 'dry run' : 'platform tier: no worker runs until a human rules') + ')' : 'the `no-code-change` terminal event when work=0') + ':',
    '  ' + disposeCmd,
    '  On REFUSED: fix the package and re-run the same command. Do NOT call `ledger.py set` or `progress.py` yourself — that is the path this replaces.',
    '',
    '',
    QUIET,
  ].join('\n')
}

function workPrompt(item, i, model) {
  const related = (item.related || []).join(',')
  const common = ' --file ' + item.file + ' --tier ' + item.gate_tier + ' --store ' + GATES_STORE +
    (related ? ' --related ' + related : '')
  return [
    'Apply the evaluator\'s work package.',
    '',
    'package: ' + pkgPath(i),
    'primary file: ' + item.file,
    'EDITABLE SCOPE: this file PLUS every path in the package\'s `required_scope` —',
    'typically its test module and the owning BUILD.bazel. Read that field first.',
    'Anything outside the set is `needs_wider_change`; name it, do not touch it.',
    'An ordered test that was not written is NOT a partial success: it leaves an',
    'unpinned guard, which reads as protection while proving nothing. Deliver the',
    'pin with the guard or report the item unapplied.',
    '',
    'TURN BUDGET. Every turn re-sends your whole context; the gate and the journal are two calls, not ten.',
    '',
    'STEP 1 — BEFORE editing anything, make sure every tree your gate compares against has a baseline. A baseline taken after the edit would record your own breakage as pre-existing debt:',
    '  ' + SCRIPTS + 'check.py pre' + common,
    '',
    'STEP 2 — apply ONLY the ordered items. An item whose anchor is absent or ambiguous goes back unapplied with that reason — that is the correct outcome, not a failure.',
    '',
    'STEP 3 — ONE call runs the whole gate and writes your journal events (`fix`, `gate`, and `gate-failed` exactly when a gate blames the change):',
    '  ' + SCRIPTS + 'check.py post' + common + ' --log ' + PROGRESS +
      ' --attempt ' + attemptId(i) + ' --run ' + RUN_ID + ' --work-dir ' + OUT +
      ' --model ' + (model || '?') + (EPOCH ? ' --epoch ' + EPOCH : '') +
      (item.file.endsWith('.py') ? ' --pyright-baseline-errors ' + PYRIGHT_BASELINE : '') +
      ' --touched <comma-separated files you edited> --applied <n> --not-applied <n> --tests-added <n>' +
      (item.file.endsWith('.rs') ? ' --it <comma-separated integration-test targets (tests/<name>.rs) your accept criteria name; omit when none>' : ''),
    '  It prints `gate_verdict` (new-failures > infra > no-baseline > ok), each gate\'s result, and any prescan hit on a touched or related file. Judge a prescan hit yourself: it may predate your change.',
    '  Do NOT call `progress.py`, `bazel_gate.py`, `cargo_gate.py`, cargo, pyright or prescan separately.',
    '  On `new-failures` check.py has ALREADY saved your change as a patch and reverted it; the tree is clean. Report and stop — do not re-apply.',
    '',
    'Copy `gate_verdict` and `gate_exit` from its output into your structured result — `gate_verdict` is REQUIRED and is what the lane branches on. The gate evidence is in the journal, written by check.py; do not restate it.',
    '',
    'You hold the single-writer lane while you run: no other agent is editing the tree, so a gate failure is attributable to your change. Do not start anything in the background and do not leave a process running when you return.',
    '',
    QUIET + ' No report file: your structured result goes straight to the reviewer.',
  ].join('\n')
}

function reviewPrompt(item, i, w) {
  const worker = { applied: w.applied, not_applied: w.not_applied, files_touched: w.files_touched,
                   gate_verdict: w.gate_verdict, ...(w.problem ? { problem: w.problem } : {}) }
  return [
    'MODE: REVIEW.',
    '',
    'file: ' + item.file,
    'package: ' + pkgPath(i),
    'worker result: ' + JSON.stringify(worker),
    'gate evidence: the `gate` event for attempt ' + attemptId(i) + ' in ' + PROGRESS + '.jsonl (written by check.py, not by the worker).',
    'progress_log: ' + PROGRESS,
    'attempt_id: ' + attemptId(i) + '   run_id: ' + RUN_ID,
    '  Append your `review` event with `--attempt ' + attemptId(i) + ' --run ' + RUN_ID + ' --counts rejected=<n> --reject-causes <cause,...>`; add `--note` only when the verdict is not accept.',
    '  `review` is the TERMINAL event for this attempt — without it reconciliation reports the file as lost.',
    '',
    'Read `git diff -- ' + (w.files_touched && w.files_touched.length ? w.files_touched.join(' ') : item.file) + '`. Judge whether each ordered item landed and whether anything unordered was changed. A gate verdict with no matching journal event is a FAIL, not a pass.',
    'Do not edit anything.',
    '',
    QUIET,
  ].join('\n')
}

log('progress journal: ' + PROGRESS + '.jsonl   (human view: progress.py render --log ' + PROGRESS + '; anomalies: tail -f it | progress.py watch)')
log('batch of ' + FILES.length + ' file(s); ' + (DRY ? 'DRY RUN — evaluate only' : 'single-writer lane for apply+gate'))

phase('Evaluate')
const out = await pipeline(
  FILES.map((f, i) => ({ item: f, i })),

  // 1. Evaluate — read-only, fully concurrent.
  ({ item, i }) => {
    const [roleKey, tier] = evaluatorRole(item)
    return agent(withDef(EVALUATOR_DEF, evalPrompt(item, i, tier, modelTag(roleKey))),
      roleOpts(EVALUATOR_DEF, 'eval[' + tier + ']:' + base(item.file), 'Evaluate', EVAL_SCHEMA, roleKey))
  },

  // 2. Fix — serialized through the writer lane.
  (ev, { item, i }) => {
    if (!ev) return { file: item.file, stage: 'evaluate', verdict: 'agent-failed' }
    if (!ev.package_written || ev.work_items === 0) {
      return { file: item.file, stage: 'evaluate', verdict: 'no-code-change', ev }
    }
    if (DRY) return { file: item.file, stage: 'evaluate', verdict: 'dry-run', ev }
    if (holdsForRuling(item)) {
      // Held for a human ruling before any edit: the old prose gate said STOP,
      // and a worker could still start. Now it cannot.
      return { file: item.file, stage: 'fix', verdict: 'blocked-platform', ev }
    }
    return serialized(() => agent(withDef(WORKER_DEF, workPrompt(item, i, modelTag('worker'))),
      roleOpts(WORKER_DEF, 'fix:' + base(item.file), 'Fix', WORK_SCHEMA, 'worker')))
      .then(w => ({ file: item.file, stage: 'fix', ev, w }))
  },

  // 3. Review — read-only again, concurrent with the next file's fix.
  (r, { item, i }) => {
    if (!r || !r.w) return r
    if (blocksReview(r.w)) {
      return { ...r, stage: 'review', verdict: 'gate-failed' }   // do not review a red tree
    }
    return agent(withDef(EVALUATOR_DEF, reviewPrompt(item, i, r.w)),
      roleOpts(EVALUATOR_DEF, 'review:' + base(item.file), 'Review', REVIEW_SCHEMA, 'reviewer'))
      .then(rv => ({ ...r, stage: 'review', rv, verdict: rv ? rv.verdict : 'review-failed' }))
  },
)

const rows = out.filter(Boolean)
const tally = rows.reduce((a, r) => {
  const v = r.verdict || (r.rv && r.rv.verdict) || 'unknown'
  a[v] = (a[v] || 0) + 1
  return a
}, {})
log('verdicts: ' + JSON.stringify(tally))
return {
  files: FILES.length,
  progress_log: PROGRESS + '.jsonl',
  // The caller MUST run this after the batch, or a died agent is invisible:
  //   progress.py reconcile --log <PROGRESS> --files <the batch's files>
  reconcile_cmd: 'python3 .claude/skills/security-remediate/scripts/progress.py reconcile --log '
    + PROGRESS + ' --files "' + FILES.map(f => f.file).join(',') + '"',
  // Then write this return value to a file and close the batch with ONE call:
  //   finalize.py --results <file> --ledger <LEDGER> --work-dir <OUT>
  // It commits what review accepted, reverts what it did not, and records `fixed`.
  finalize_cmd: 'python3 .claude/skills/security-remediate/scripts/finalize.py --results <this result as JSON> --ledger '
    + LEDGER + ' --work-dir ' + OUT,
  tally,
  // One line per file — the orchestrator keeps this, not the findings.
  roles: ROLES,
  results: rows.map(r => ({
    file: r.file,
    eval_tier: (FILES.find(f => f.file === r.file) || {}).eval_tier || 'senior',
    verdict: r.verdict || (r.rv && r.rv.verdict) || 'unknown',
    work_items: r.ev ? r.ev.work_items : 0,
    disposed: r.ev ? r.ev.disposed : 0,
    escalated: r.ev ? r.ev.escalated : 0,
    applied: r.w ? (r.w.applied || []).length : 0,
    not_applied: r.w ? (r.w.not_applied || []) : [],
    gate_exit: r.w ? r.w.gate_exit : null,
    accepted: r.rv ? r.rv.items_accepted : [],
    rejected: r.rv ? r.rv.items_rejected : [],
    unordered_changes: r.rv ? (r.rv.unordered_changes || []) : [],
    files_touched: r.w ? (r.w.files_touched || []) : [],
    package: pkgPath(FILES.indexOf(FILES.find(f => f.file === r.file))),
    blocked_on: r.ev ? (r.ev.blocked_on || '') : '',
  })),
}
