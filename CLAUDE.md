<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-RE — code base standards

## Rust Code Quality & Architecture Rules

### Module & File Structure

1. **One Main Type Per File**: Every major `struct`, `enum`, or `trait` must reside in its own file under a domain module (e.g., `src/domain/user_repository.rs`).
2. **File Size Limit**: No single `.rs` file may exceed 200 lines of code (excluding unit tests). If a file exceeds this, split it into sub-modules.
3. **Module Re-exports**: Use `mod.rs` to encapsulate module internals and re-export public interfaces using `pub use`.

### Function Boundaries & Security

1. **Function Line Limit**: No function may exceed 60 lines of code. Split complex logic into private helper functions (`pub(crate)` or `fn`), or pipeline stages.
2. **Cognitive Complexity**: Avoid nested `match` or `if let` statements deeper than 2 levels. Use early returns (`?` operator or `let-else` statements).
3. **Security Code**: Parsing, authentication, and execution MUST be isolated into distinct types/functions. Do not combine I/O operations with cryptographic or authorization logic in the same function.

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
