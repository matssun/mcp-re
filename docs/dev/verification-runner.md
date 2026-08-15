# The verification runner (dev1)

The ADR-MCPRE-059 verification lanes do not run on GitHub-hosted runners. Verus is
pinned to an install root under `/opt/verification`, and the extraction pipeline runs a
digest-pinned Linux container through the host's Docker. Both live on a persistent
self-hosted Mac mini, `dev1`.

This file records what that host must provide. It is operational configuration, not
workstation trivia: if the runner is rebuilt or re-registered without it, the
verification lane stops producing evidence.

## Registration

The runner is registered **to the `mcp-re` repository**, with labels `self-hosted`,
`macOS`, `ARM64`, and installed as a service so it survives a reboot:

```sh
cd ~/dev/actions-runner-mcp-re
./config.sh --url https://github.com/matssun/mcp-re --labels self-hosted,macOS,ARM64
./svc.sh install && ./svc.sh start
```

A runner registered to a *different* repository under the same account is the failure
mode with no error message: the runner reports online and idle, the workflow's jobs
queue against labels nothing in this repository offers, and the checks sit at *pending*
until they expire. Nothing goes red. `gh run view --json jobs` shows a job that never
started, which is the signal to check `.runner` for the registered repository rather
than to look for a fault in the lane.

## Job PATH

The runner service does not inherit the operator's login shell. Its job environment
comes from the `.env` file next to `svc.sh`:

```
PATH=/Users/mats/.cargo/bin:/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
```

Two requirements are load-bearing, and both were discovered by the lane failing:

- **`/Users/mats/.cargo/bin` must come first.** Verus ships its own Z3 but no compiler;
  it shells out to `rustup` to resolve the pinned channel. This box also has Homebrew's
  `rust` formula, whose `cargo` is a real binary rather than a rustup shim — if it wins
  the PATH race, toolchain pinning silently does not apply, and a proof gets checked by
  a compiler the lock file never named. The symptom was
  `verus: rustup not found, or not executable`.
- **A Python with `tomllib` must precede `/usr/bin`.** Both lanes parse
  `verification/policy/toolchains.lock.toml` with the standard library. macOS ships a
  3.9 at `/usr/bin/python3` that satisfies `python3` and fails only on import. The
  symptom was `ModuleNotFoundError: No module named 'tomllib'`.

After editing `.env`, restart the service — a running runner keeps its old environment:

```sh
./svc.sh stop && ./svc.sh start
```

`scripts/verification_runner_preflight.sh` checks both requirements and prints this
remedy. It is the first step of both jobs in `.github/workflows/verification.yml`, so a
host missing either one reports the missing prerequisite rather than a downstream tool's
confusion. It also runs locally, which is how to test a runner rebuild before pushing
anything at it.

The rustup check resolves the pinned channel rather than inspecting PATH layout. A
directory-prefix heuristic calls the developer MacBook healthy while its `cargo` is
Homebrew's — the question is not whether the PATH looks right but whether `rustup run
<channel> rustc` hands back the pinned compiler.

## Required-check health has two independent dimensions

**Execution validity** — the runner can invoke the pinned verifier correctly. This is
what the preflight establishes, and it is the only half that lives in the repository.

**Scheduling validity** — the repository can actually dispatch the required job to that
runner. A verifier that *would* pass if run is still unavailable evidence while its
required job cannot be scheduled. Nothing in the tree can check this: the runner's
registration is machine state on `dev1`, and a job that never starts runs no code that
could object.

Both must hold, and they fail in opposite directions. Broken execution is loud — a red
job with a stack trace. Broken scheduling is silent: the check sits at *pending*, which
reads as transient and can persist indefinitely without anyone treating it as a fault.

> A required check pending for an implausibly long time is a runner availability or
> scope failure signature, not a slow verifier.

Check it directly rather than waiting: `gh run view <id> --json jobs` shows a job that
never started, and `.runner` on the host names the repository it is actually registered
to.

## A passing run is evidence only for its own run context

Branch protection does not evaluate `(commit, result)`. It evaluates
`(commit, event, workflow, job, result)`. The same commit can therefore carry a green
`workflow_dispatch` run and a red `pull_request` required check at the same moment —
that is exactly what happened here after the PATH fix, because a verdict belongs to the
run that produced it and is never retroactively applied to an earlier one.

> Do not infer merge readiness from a manually triggered equivalent run. Inspect the
> required PR-context checks themselves.

`gh pr checks <n>` reports the contexts branch protection reads. Re-run the PR-context
job (`gh run rerun <id> --failed`) rather than dispatching a fresh equivalent.

## Two rules this host earned

**A verification pipeline is not alive because its configuration exists.** It is alive
only if the verifier executes against the current tree and its assumption boundary is
checked. The workflow file, the lock file, and the assumption registry were all complete
and reviewed while the lane had never run once.

**Restoring the infrastructure is not evidence that the code is sound.** The first
successful execution after an assurance lane has been unavailable is a fresh security
review event, not a return to a known-good state. When this lane first ran, it
immediately found three `uninterp spec fn` declarations sitting in the trusted computing
base with no registered owner (now ASM-0024/0025/0026). Those had been there the whole
time; the lane's absence, not their absence, was what made the boundary look clean.
