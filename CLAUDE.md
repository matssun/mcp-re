<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-RE — code base standards

## Rust Code Quality & Architecture Rules

### Module & File Structure

1. **One Main Type Per File**: Every major `struct`, `enum`, or `trait` must reside in its own file under a domain module (e.g., `src/domain/user_repository.rs`).
2. **File Size Limit**: 200 lines of code (excluding unit tests) is the threshold for a
   `.rs` file. Crossing it is a **mandatory design-review trigger, not an automatic
   split** — see "Thresholds are review triggers" below. Let responsibility boundaries
   drive a file split; never create arbitrary files merely to get under the number.
   **Mechanically enforced** by `scripts/module_size_gate.py` as a ratchet: a new file over
   the threshold fails, and a file already in `config/module-size-debt.toml` may not grow.
   Production lines are every line **not inside a test region** — a region opens at an
   attribute matching `^#[cfg((all()?test` and closes with the module it introduces, and
   counting resumes afterwards. Not "lines before the first test module": that rule
   discards production code below the tests and measured `trust_plane.rs` at 134 lines
   when it is 690.
3. **Module Re-exports**: Use `mod.rs` to encapsulate module internals and re-export public interfaces using `pub use`.

### Function Boundaries & Security

1. **Function Line Limit**: 60 lines of code is the threshold for a function. Crossing it
   is a **mandatory design-review trigger, not an automatic split** — see "Thresholds are
   review triggers" below. The usual outcome is decomposition into private helper
   functions (`pub(crate)` or `fn`) or pipeline stages. **Mechanically enforced** by
   `clippy::too_many_lines`, run and ratcheted by `scripts/clippy_ratchet_gate.py`.
   Note that `.clippy.toml` alone does **not** enforce it: the lint is allow-by-default,
   so a threshold there with nothing switching the lint on is inert.
2. **Nesting Depth**: Avoid nested `match` or `if let` statements deeper than 2 levels. Use
   early returns (`?` operator or `let-else` statements). **Mechanically enforced** by
   `clippy::excessive_nesting` at `excessive-nesting-threshold = 3` (the threshold names the
   depth that is *rejected*), configured in `config/clippy-strict/.clippy.toml` and run by
   `scripts/clippy_ratchet_gate.py`. Do not move that threshold into the root
   `/.clippy.toml`: this lint is warn-by-default, so a value there is enforced immediately
   against all targets by every `-D warnings` lane.
3. **Security Code**: Parsing, authentication, and execution MUST be isolated into distinct types/functions. Do not combine I/O operations with cryptographic or authorization logic in the same function.
4. **Explicit Arithmetic Semantics**: production arithmetic whose overflow/panic semantics
   are not statically evident MUST make those semantics explicit. A bare `x + y` can mean
   mathematical addition, addition proven bounded elsewhere, panic on overflow, or wrap on
   overflow — and which one it means depends on build mode. Pick the true one:

   | situation | write |
   |---|---|
   | overflow is a real possibility | `checked_add` / `checked_sub` / `checked_mul`, failure handled |
   | wrapping or saturating IS the intended algebra | `saturating_add` / `wrapping_add` |
   | provably bounded, and `a + b` is clearer | keep it, with a narrow `#[allow(clippy::arithmetic_side_effects)]` naming the invariant |

   **Mechanically enforced** by `clippy::arithmetic_side_effects`, ratcheted from a
   124-site baseline by `scripts/clippy_ratchet_gate.py`. The lint already excludes
   `Wrapping`, `Saturating`, floats, constants, and operations it can prove bounded, so a
   hit means the semantics really are unstated.

### Visibility is part of the architecture

Mirrors ADR-MCPRE-061 §4. Pick the narrowest level that lets the legitimate consumer work:

| level | meaning |
|---|---|
| `fn` / private | local implementation detail |
| `pub(super)` | visible only to the parent authority |
| `pub(in crate::path)` | visible only inside a declared ancestor subtree |
| `pub(crate)` | crate-wide capability — only when crate-wide access is genuinely intended |
| `pub` | external API — must correspond to an explicitly supported contract |

Two rules on top of the ladder:

- **Never widen production visibility so a test can inspect a representation.** Move the
  test to the owner instead. A `pub(crate)` that exists for a test is a production API with
  a test-shaped justification.
- **Widening needs a reason at the point of widening.** Whenever a security-relevant item is
  `pub(crate)` or `pub`, answer why the broader authority is legitimate.

### Exceptions are narrow and justified

An `#[allow(...)]` of an ADR-MCPRE-061 §6 lint (`unwrap_used`, `expect_used`,
`indexing_slicing`, `too_many_lines`, `excessive_nesting`, `arithmetic_side_effects`) is an
exception, and **`scripts/clippy_ratchet_gate.py` enforces its shape**:

- **Never crate-wide or module-wide.** `#![allow(...)]`, or an `#[allow(...)]` on a `mod`,
  covers code not yet written — that turns a proof obligation back into remembered policy.
  It is also a ratchet bypass: suppressing a lint across a crate makes the count fall, and a
  falling count is otherwise a legitimate reason to lower the baseline, so a one-line
  attribute would launder a permanent exemption as progress. Scope it to the item.
- **Always justified.** The allow must carry a comment naming the invariant that makes the
  ordinary form safe — the owning type, check, or theorem. "Cannot overflow" restates the
  lint; it does not justify the exception.
- **No `arithmetic-side-effects-allowed*` type exemption** in any clippy config. It is
  global and unbounded.

The worked example is `mcp-re-proxy/src/app.rs::run_validated`: it states what the function
owns, what most recently left it and why, the three pieces of compensating evidence, and
why the allowance sits on the function rather than the module.

Two limits on what visibility buys, both measured — see
[`docs/dev/sealed-owners.md`](docs/dev/sealed-owners.md):

- Privacy is worth adding only where **the owner is the sole legitimate producer**. Where a
  trait or closure seam lets outside code produce the value, a private field only forces a
  public constructor taking the same arguments with the same absence of checking. Ask *if
  this value is illegal, whose bug is it?* — if the answer is "whoever implemented the
  seam", privacy is theatre.
- A Verus-proved postcondition outranks a seal.

No lint enforces this. It is a review rule, and the compile errors you get while narrowing
a field are the boundary detector, not an obstacle.

### The twelve questions — investigating an oversized or suspicious unit

Mirrors ADR-MCPRE-061 §8. When a gate flags a unit, or when a unit looks wrong regardless
of size, the investigation must answer all twelve before it is closed:

1. What single security/control fact does this unit own?
2. How many independently describable authorities exist inside it?
3. What does it decide?
4. What does it merely execute?
5. What does it merely transport?
6. What facts does it reconstruct that another owner already decided?
7. What security relationship exists only through call ordering or local variables?
8. What public interface exists only because tests need it?
9. What branches are unreachable under the current legality model?
10. What facts are represented more than once?
11. What inconsistent values can callers construct?
12. Which test/build/proof lane actually establishes each claimed property?

Question 2 decides the outcome; size only decides the order in which units are examined. An
answer to question 1 that needs an "and" is evidence of a shallow authority boundary.

**The investigation is not closed by** "LOC is not architecture", "the logic is
complicated", "tests are green", "the functions inside the file are individually small",
"decomposition is not the goal", or "the module has always been this size". It is closed by
answering the twelve, by recording an ADR-MCPRE-061 §14 exception, or by a measurement
correction. Never self-grant an exception for a unit over 1,000 production lines.

### Ownership: the constructed value owns the invariant

> **R-SEAL.** A security check is not structurally owned merely because every known
> construction site performs it. If the invariant belongs to a value, the value's public
> construction and projection boundary must make violating the invariant impossible or
> explicitly fallible.

> **R-COMPOSE.** A composition root may combine owner-provided facts; it must not recreate
> an owner's security semantics by destructuring its representation.

The invariant belongs to the value, not to the code that builds it. Possession is the
proof: holding a value must mean its invariant holds, with no trailing clause about what
callers remembered. *Validation exists* in most of the cases this rule catches — the defect
is that correctness depends on remembering where and how to construct the value.

The difference is a quantifier. "This constructor checks X" quantifies over one site and is
silent about the next one added. "Every inhabitant satisfies X" quantifies over the type,
and only the second is a theorem.

**The operational test:** *can the check be deleted and still leave an invalid value
unconstructible?* If yes, the value owns it. If deleting a check elsewhere can bring an
invalid inhabitant into existence, the check was being remembered, not owned.

An owner is **sealed** when four things hold:

1. Illegal local state cannot be publicly constructed.
2. Required validation happens before construction of the owned state, or construction
   itself performs it.
3. Downstream cannot mutate or reconstruct the invariant by destructuring the private
   representation.
4. Downstream obtains only named semantic projections or capabilities.

**`#[non_exhaustive]` and `pub(crate)` do not seal anything here.** Both bind only other
crates, and in this workspace an owner's consumers — `app.rs`, `startup_plan.rs`,
`cli.rs`, `http_profile_serve.rs` — live in the owner's own crate. The lever that works
inside one crate is **module privacy**: the representation is private to the owner's
module, which exposes projections. A type documenting a seal that holds only "outside this
crate" is documenting a seal that holds against none of its actual callers.

**A compile failure caused by making a security field private is a boundary detector, not
an obstacle.** It is the compiler reporting that the supposed owner does not own its
representation. Let the failures guide the work; never work around one with
`#[non_exhaustive]`, a runtime re-check, or a doc note — those consume the signal. For each
failure ask **what does the consumer actually need to know?** The answer is normally much
narrower than the destructured representation: `replay_state.materialization_plan()`, not
`ReplayState::Shared { url, quorum, timeout_ms, .. }`.

Do not answer "the root can see every owner's internals" with one wide struct carrying
everything the root needs. That relocates flat authority instead of removing it. The root
composes narrow per-owner projections.

Which owners are sealed, what each projects, and the procedure for the next one:
[`docs/dev/sealed-owners.md`](docs/dev/sealed-owners.md).

### Thresholds are review triggers, not laws

The 60-line function and 200-line file limits are **not** unconditional architectural
laws. Crossing one creates a **mandatory review obligation**, not an automatic
refactoring obligation. Above the threshold, do one of two things:

- **A — decompose.** Identify the natural responsibilities and split along them. This is
  the normal outcome, and it is the outcome whenever real seams exist.
- **B — document an exception.** Explain why keeping the unit intact makes the
  security/control argument materially clearer and safer.

**"It is complicated" is not an exception.** A B-case must state concretely: why
decomposition would damage the reasoning, what invariant requires locality, why the
subordinate responsibilities cannot be separated, and what tests or review evidence
compensate for the size.

**Never split code merely to satisfy a number.** A rule that forces a split where one
would destroy clarity produces the very thing these rules exist to prevent —
architecture distorted to satisfy a metric.

Note what an exception costs: using one where a sensible decomposition exists weakens
the rule exactly where it was working. A threshold's job is to force you to look. When
looking finds real seams, split; the threshold has then done its job.

One coherent security invariant does **not** have to be one large function. Keep the
overarching argument in the module documentation and let the subordinate checks be
separately testable predicates — that usually makes the invariant easier to
substantiate, not harder.

**The ratchet runs while you decide.** The thresholds being review triggers does not make
them advisory: `scripts/module_size_gate.py` and `scripts/clippy_ratchet_gate.py` hold the
current debt at a baseline, so the campaign fixes yesterday's units while new ones cannot
be created. Two registries carry that debt:

- `config/module-size-debt.toml` — files over 200 production lines at the baseline SHA;
- `config/clippy-debt.toml` — per-crate counts of the adopted lints.

An entry means **"over the threshold and not yet investigated"** — it is a debt register,
not an exception mechanism. A unit that has been investigated and deliberately kept intact
gets `status = "reviewed-exception"` plus an `exception_ref` naming the B-case record in
[`docs/architecture/exceptions.md`](docs/architecture/exceptions.md); the gate fails if the
named document does not exist, because a reviewed exception must point at a record rather
than at a memory of one. A registry may only shrink: a file that grows fails — whatever its
status, an exception is not a licence to grow — and a file that drops to the threshold fails
until its entry is removed.

**Review granularity equals exception granularity.** A function-level exception does not
make its file a reviewed exception. `parse_args` is a reviewed exception; `cli.rs` is not.
`run_validated` is a reviewed exception; `app.rs` is not — its file-level census is
complete and *declined* to grant one, because the audit-drain teardown authority is
separable and has an owner next door. §14 records a decision to keep something whole; it is
not a place to park work.

### Testing Requirements

1. Every file must include a `#[cfg(test)] mod tests` block at the bottom containing unit tests for the types defined in that specific file.
2. Run `cargo clippy -- -D warnings` after every edit. Do not mark a task complete if Clippy
   emits warnings or functions exceed complexity thresholds. Note the scope: `-D warnings`
   does **not** cover the five ADR-MCPRE-061 §6 lints (`unwrap_used`, `expect_used`,
   `indexing_slicing`, `too_many_lines`, `excessive_nesting`) — they are allow-by-default
   and are switched on by `scripts/clippy_ratchet_gate.py` over production targets only. Run
   that gate before claiming a unit is clean.

## Working rules

Read [`docs/AGENT_INSTRUCTIONS.md`](docs/AGENT_INSTRUCTIONS.md) before editing any ADR,
spec, or design doc. It states the current worldview (RFC 9421 + RFC 9530 is the one
carrier; Native JCS is dead; stdio is out of scope).

## Run everything locally, first

```sh
scripts/local_gate.sh          # add --with-kind before any cloud run
```

One command, cost-ordered, stops at the first failure: structural gates → both cargo
suites → `bazel test //...` → the ADR-MCPRE-051 §7 SLO lane → (opt-in) the fleet proofs
on kind. It is the precondition for every PR, every `gcloud builds submit`, every GKE
cluster, and every baseline declaration. Details and rationale:
[`docs/dev/local-gate-order.md`](docs/dev/local-gate-order.md).

Neither half is the whole battery on its own — `cargo test --workspace` does not
compile the non-default feature backends, and `bazel test //...` excludes the
`manual`-tagged infra lane.

## Do not report a green that measured nothing

A command that exits 0 having run no tests is worse than a red one. Before calling a
lane green, confirm it ran what you think it ran.

The known instance: `tls_load_harness_bench` (the SLO load harness) is **not** an
`#[ignore]` test — the file is gated to the `redis_replay` feature lane instead. So
`-- --ignored` selects **zero** tests, exits **0**, and writes no report. That form had
propagated into four documented places before anyone noticed. Use
`scripts/local_slo_lane.sh`; `scripts/slo_invocation_gate.py` fails the build if the
bad form comes back.

**The second instance was configuration that enforced nothing.** `/.clippy.toml` carried
`too-many-lines-threshold = 60`, `cargo clippy -- -D warnings` ran in CI and in the local
gate, and the project described the 60-line function rule as mechanically enforced. It was
not: `clippy::too_many_lines` is allow-by-default, so the threshold parameterised a lint
nobody had switched on, and an 80-line function produced no warning at all. A threshold is
not an enforcement; the thing that turns the lint on is.
`scripts/clippy_ratchet_gate.py --activation-probe` compiles a deliberately violating file
and fails the build if the lints stop firing.

**Never read a gate's result through a pipe.** `scripts/local_gate.sh --fast | tail`
reports `tail`'s exit status, not the gate's — a failed gate reads as a clean pass, and
this has already happened. Run gates unpiped and read the exit status, or read the
`LOCAL GATE: PASS` / `LOCAL GATE: FAIL` line the script prints exactly once per run. No
such line means the run did not finish.

The general rule that instance is one case of:

> **A test property includes the build/feature lane the test actually exists in.** A
> passing lane that compiles the relevant test to zero tests is not evidence for that
> property.

Second known instance: `mcp-re-proxy/tests/async_drain_test.rs` is
`#![cfg(feature = "async_serve")]`. A plain `cargo test --workspace` compiles it to
**zero** tests and reports green, so cargo says nothing whatsoever about bounded drain
or teardown ordering. Only `bazel test //...` runs it — the target sets
`crate_features = ["async_serve"]` and `RUST_TEST_THREADS=1`. Before citing a drain or
lifecycle result, confirm it came from the Bazel lane.

## Measure on a quiet box

The local SLO lane co-locates the load generator with the proxy, so an unrelated build
on the same machine halves throughput — an environmental FAIL that says nothing about
the code, and one that already cost a full A/B/B/A investigation. The lane refuses to
measure when load is high; do not paper over it with `ALLOW_NOISY_BOX=1` and then quote
the number.

## Other standing rules

- **No hardcoded ports.** `config/ports.toml` is the source; the Helm mirror is
  CI-gated (`scripts/check_port_registry.py`).
- **Image tags come from `VERSION`**, never retyped (`scripts/deploy_image_tag_gate.py`).
- **Comments describe current code only** — no change narration, no history.

## AWS Guidance

Installed by the AWS Agent Toolkit (`aws/agent-toolkit-for-aws`, `rules/aws-agent-rules.md`).

- Prefer the AWS MCP Server for AWS interactions — it provides sandboxed
  execution, observability, and audit logging. If unavailable, use the
  AWS CLI directly.
- Before starting a task, check whether a relevant AWS skill is available.
  Load the skill with `retrieve_skill` and prefer its guidance over
  general knowledge.
- When uncertain about specific AWS details (API parameters, permissions,
  limits, error codes), verify against documentation rather than guessing.
  State uncertainty explicitly if you cannot confirm.
- When creating infrastructure, prefer infrastructure-as-code (AWS CDK or
  CloudFormation) over direct CLI commands.
- When working with infrastructure, follow AWS Well-Architected Framework
  principles.
- Do not use em dashes in AWS resource names or descriptions. Use
  hyphens instead.

### Secret Safety

- MUST load the `aws-secrets-manager` skill first for any secret,
  credential, API key, token, or password task. MUST NOT call
  `secretsmanager get-secret-value` or `batch-get-secret-value`, and MUST
  NOT hit the Secrets Manager Agent daemon directly. MUST use
  `{{resolve:secretsmanager:secret-id:SecretString:json-key}}` with
  `asm-exec` so the secret resolves at runtime without entering context.
