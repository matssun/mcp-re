<!-- SPDX-License-Identifier: Apache-2.0 -->

# MCP-RE — working rules

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
