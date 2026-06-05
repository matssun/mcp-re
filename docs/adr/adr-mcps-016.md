<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-016: Inner-Server Isolation Boundary

## Status

Proposed

## Context

PRD (stories 7–10) requires the sidecar proxy to harden how it launches the inner MCP server on a single node. Today the proxy spawns the inner server inheriting the proxy's entire environment, with no working-directory control and `stderr` discarded — so any env-loaded key material leaks into an untrusted inner server. The original brief's WS7 listed filesystem and network allowlists as "required." But a plain parent process cannot honestly enforce fs/net allowlists by configuration alone: a child running as the same OS user can open files and sockets unless a kernel/container mechanism (seccomp, Landlock, namespaces, chroot, container) mediates. Claiming fs/net containment without that mechanism would be a dishonest security claim, which the project's security-honesty principle forbids. A decision is needed on the enforcement floor and what is deferred.

## Decision

`mcps-proxy` implements portable parent-process launch hardening only — environment minimization (no inheritance by default plus an explicit allowlist), working-directory control, stdout/stderr hygiene (bounded captured `stderr`, protocol-clean `stdout`), structured inner-lifecycle logging, and best-effort Unix `setrlimit` resource limits — and explicitly does NOT claim kernel/filesystem/network containment; fs/net allowlists and syscall/namespace sandboxing are deferred to a separate OS-sandbox profile.

## Rationale

The proxy can honestly enforce, as the parent process, only what it controls at spawn time: what environment the child receives, where it runs, how its output is handled, and coarse resource ceilings. These are portable across Unix-likes, cheap, and truthfully claimable. Environment minimization alone closes a real present leak (full env inheritance). Filesystem/network containment is qualitatively different — it requires kernel mediation — so bundling fs/net allowlists with the OS mechanism that actually enforces them keeps the claim honest. A configured resource limit that cannot be applied fails closed when required (never silently ignored), so the hardening cannot become a false sense of security.

## Alternatives Considered

- **Implement config-only fs/net allowlists now** — rejected: unenforceable by a plain parent; security theater; dishonest claim.
- **Require an OS sandbox (seccomp/Landlock/container) as part of this project** — rejected: Linux-specific, kernel-version-gated, its own threat model and platform matrix; would expand the single-node baseline and can break legitimate servers.
- **Do nothing (keep full env inheritance)** — rejected: leaks secrets (including env-loaded keys) into untrusted inner servers.
- **Treat `setrlimit` as sandboxing** — rejected: it bounds resource abuse, not access; mislabeling it would overstate the guarantee.

## Consequences

### Positive
- Closes the environment-inheritance leak; controlled, documented launch surface.
- Honest, portable claim: the proxy controls what the inner server *sees*, not what it *can do* to the host.
- No platform-specific kernel dependencies in the single-node baseline.

### Negative
- A malicious or compromised inner server can still access files/network/OS resources available to its OS user until the deferred OS sandbox is configured — must be stated plainly in the security-boundary document.
- An inner command launched via `bazel run` may need a non-trivial env allowlist (runfiles/cwd); discovered and fixed via allowlist, not by disabling minimization.

### Neutral
- `setrlimit` is Unix-only; on unsupported platforms it fails-if-required or warns in explicit best-effort mode.

## Compliance and Enforcement

Tests must prove: env cleared + allowlist applied; explicit working directory; `stderr` captured-not-leaked and the protocol stream clean; lifecycle events emitted; rlimits applied and fail-closed-when-required; caller-supplied `.verified` stripped; injected verified context reaches the inner server. The security-boundary document (a release gate per the PRD) must state the non-containment boundary explicitly. fs/net containment is tracked as a separate OS-sandbox issue.

## Related

- PRD: (author's private monorepo)
- Prior ADRs: ADR-MCPS-008 (verified-context propagation), ADR-MCPS-014 (transport hardening — the proxy as Policy Enforcement Point)
- Code: `components/mcps/mcps-proxy` (best-effort; expect rot)
