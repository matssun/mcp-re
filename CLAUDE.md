<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-RE — code base standards

## Rust Code Quality & Architecture Rules

### Module & File Structure

1. **One Main Type Per File**: Every major `struct`, `enum`, or `trait` must reside in its own file under a domain module (e.g., `src/domain/user_repository.rs`).
2. **File Size Limit**: 200 lines of code (excluding unit tests) is the threshold for a
   `.rs` file. Crossing it is a **mandatory design-review trigger, not an automatic
   split** — see "Thresholds are review triggers" below. Let responsibility boundaries
   drive a file split; never create arbitrary files merely to get under the number.
3. **Module Re-exports**: Use `mod.rs` to encapsulate module internals and re-export public interfaces using `pub use`.

### Function Boundaries & Security

1. **Function Line Limit**: 60 lines of code is the threshold for a function. Crossing it
   is a **mandatory design-review trigger, not an automatic split** — see "Thresholds are
   review triggers" below. The usual outcome is decomposition into private helper
   functions (`pub(crate)` or `fn`) or pipeline stages.
2. **Cognitive Complexity**: Avoid nested `match` or `if let` statements deeper than 2 levels. Use early returns (`?` operator or `let-else` statements).
3. **Security Code**: Parsing, authentication, and execution MUST be isolated into distinct types/functions. Do not combine I/O operations with cryptographic or authorization logic in the same function.

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

### Testing Requirements

1. Every file must include a `#[cfg(test)] mod tests` block at the bottom containing unit tests for the types defined in that specific file.
2. Run `cargo clippy -- -D warnings` after every edit. Do not mark a task complete if Clippy emits warnings or functions exceed complexity thresholds.

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
