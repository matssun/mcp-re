# MCP-RE Sidecar Deployment Guide

**Audience:** an operator who wants to put the MCP-RE production sidecar in front
of an MCP server — including an ordinary **stdio** MCP server — so requests are
verified before they reach the inner server and responses are signed.

This guide explains **how to run** the `mcp-re-proxy` production CLI and, for a
stdio-only inner server, the companion `mcp-re-stdio-bridge`. The rules the proxy
enforces are in the [MCP-RE Core Specification](spec/mcp-re-core-spec.md); the
rationale is in ADR-MCPS-014 ([view](adr/adr-mcps-014.md), transport hardening),
ADR-MCPS-016 ([view](adr/adr-mcps-016.md), inner-server isolation boundary) and
ADR-MCPRE-051 ([view](adr/adr-mcpre-051.md), high-throughput serving
architecture). The proofs are the `//mcp-re-proxy:*` test targets (see the
[conformance manifest](../mcp-re-conformance/conformance_manifest.json)).

For TLS/mTLS, transport binding, key sources, and the replay cache in depth, read
the companion [Transport Hardening Guide](transport-hardening-guide.md). For a
horizontally-scaled replica fleet read the
[Fleet Deployment Guide](fleet-deployment-guide.md).

## What the PEP does

Source: [`cli.rs`](../mcp-re-proxy/src/cli.rs), [`main.rs`](../mcp-re-proxy/src/main.rs),
[`http_inner.rs`](../mcp-re-proxy/src/http_inner.rs).

The `:mcp_re_proxy_cli` binary is the **policy-enforcement point (PEP)** — a
cryptographic trust boundary. For each connection it: terminates TLS itself,
verifies the mTLS client certificate, verifies the MCP-RE object signature,
optionally evaluates authorization (Phase 5) and transport binding (Phase 6), and
only then forwards the verified, context-injected request to an inner MCP server,
signing the response.

Two things changed with ADR-MCPRE-051 and matter to operators:

- **The serving path is async, thread-per-core.** The PEP runs one worker per
  core (auto-sized from `available_parallelism`), each with its own
  `SO_REUSEPORT` listener; connections keep-alive and multiplex (HTTP/1.1 + H2).
  The old blocking, single-threaded, one-request-at-a-time serve loop is gone.
- **The inner plane is stateless Streamable-HTTP, not a subprocess.** The PEP
  **no longer launches, sandboxes, or speaks stdio to a child process.** Its sole
  inner plane is a pooled, keep-alive `hyper` client to one or more HTTP MCP
  backends named by `--inner-http-url`. The entire ~3k-line subprocess/sandbox
  surface (subprocess lifecycle, environment allow-listing, Landlock/seccomp,
  `setrlimit`) has been **removed from the PEP's Trusted Computing Base** and
  relocated to the separate, un-privileged `mcp-re-stdio-bridge` adapter
  (MCPRE-118). See [Wrapping a stdio server](#wrapping-a-stdio-server-with-mcp-re-stdio-bridge).

An invalid request never reaches the inner server — verification happens first,
and a failure returns a signed/`mcp-re.*` error instead of dispatching.

## The proxy flags

Run `:mcp_re_proxy_cli` via Bazel. Flags are parsed by `cli::parse_args`; defaults
shown are the real defaults from that parser.

### Core / required

| Flag | Meaning |
| --- | --- |
| `--bind` | Listen address, e.g. `127.0.0.1:8600` (the `mcp_re_proxy` port in `config/ports.toml`, the repo's reserved 8600-8699 band). |
| `--audience` | This server's identity (expected request audience). |
| `--server-signer` / `--server-key-id` | Response-signing identity + key id. |
| `--signing-key-seed`, `--tls-cert`, `--tls-key`, `--client-ca` | Key-material locations (paths for `file`, env-var names for `env`). |
| `--trust` | Path to the JSON trust file (request signers + authorization issuers). |
| `--inner-http-url <url>` | The Streamable-HTTP inner MCP backend the PEP forwards to. **Required.** Repeat or comma-separate for a backend fleet (round-robin). |

`--max-clock-skew` defaults to `300` seconds.

### Inner plane (`http_inner.rs`)

| Flag | Meaning |
| --- | --- |
| `--inner-http-url <url>` | An absolute backend endpoint, e.g. `http://10.0.0.5:8080/mcp`. At least one is required (the PEP fails closed at startup with none). |

Repeated and/or comma-separated values add backends; the PEP spreads requests
across them round-robin over a per-core keep-alive connection pool. A dead,
non-2xx, or timed-out backend fails that request closed with a synthesized
`mcp-re.*` JSON-RPC error — it never returns an unsigned or unverified body. To
front a **stdio-only** server, point `--inner-http-url` at a local
`mcp-re-stdio-bridge` (below).

### KeySource (`key_source.rs`)

| Flag | Meaning |
| --- | --- |
| `--key-source file` (default) | Read material from files on disk. |
| `--key-source env` | Read from environment variables. **Dev/CI only.** |
| `--allow-env-keysource` | Required to use `env`; without it `env` is refused. |

Environment variables are visible to the whole process tree and can leak via
crash dumps, `ps e`, and `/proc/<pid>/environ` — so `env` is gated behind an
explicit opt-in and loudly warned. Use `file` with `0600` permissions in
production (the CLI warns if a key file is group/world-readable). A Cloud-KMS /
PKCS#11-backed source keeps the signing key off-host — see the Transport
Hardening Guide and the Helm chart's `keySource: gcpKms` path.

### Trust resolver

`--trust` points at a JSON array of `{ "signer", "key_id", "public_key" }`
entries (public key Base64URL-no-pad). It carries both request-signer keys and
authorization-issuer keys. A bad key fails startup closed.

### Authorization (Phase 5)

| Flag | Meaning |
| --- | --- |
| `--authz off` (default) | No authorization policy. |
| `--authz reference` | Enable the Reference Signed Authorization Profile (ADR-MCPS-013). |

### Transport binding (Phase 6)

| Flag | Meaning |
| --- | --- |
| `--transport-binding exact` (default) | Request `signer` must equal the verified mTLS identity. |
| `--transport-binding none` | No binding (the mTLS identity is ignored). |
| `--transport-identity-source uri_san` (default) / `dns_san` / `cn_legacy` | Which client-cert field is the authoritative identity. `cn_legacy` is deprecated and warns. |
| `--max-client-cert-lifetime 1h` (default) | The v1 revocation posture. Accepts `1h`/`30m`/`3600`/`none`; `none` or `0` disables (warned). |

### Replay cache (`durable_replay.rs`)

| Flag | Meaning |
| --- | --- |
| `--replay-cache memory` (default) | In-memory; lost on restart; single-replica only. |
| `--replay-cache file` | Durable, single-node, file-backed. Requires `--replay-path`. |
| `--replay-cache shared` | The authoritative shared tier (Redis/etcd); **required under `--fleet`.** See the Fleet Deployment Guide. |
| `--replay-path <path>` | State-file path for the `file` cache. |
| `--replay-redis-url` / `--replay-durability-tier` | Shared-tier endpoint + durability class (e.g. `redis-wait-quorum:2:2000`). |

### Connection limits (DoS defense)

`--max-header-bytes` (64 KiB), `--max-body-bytes` (16 MiB),
`--max-connections` (256), `--read-timeout-secs` / `--write-timeout-secs` (30s;
`0` disables). Every limit fails closed. The per-core in-flight admission ceiling
returns `503` at saturation rather than queuing unbounded.

## Wrapping a stdio server with `mcp-re-stdio-bridge`

The PEP speaks HTTP to its inner plane. A stdio-only MCP server (JSON-RPC over a
child's stdin/stdout) is fronted by the **out-of-TCB** `mcp-re-stdio-bridge`,
which the PEP reaches over loopback HTTP like any other backend:

```text
  client ──mTLS──▶  mcp-re-proxy (PEP, signs)  ──HTTP──▶  mcp-re-stdio-bridge  ──stdio──▶  unmodified MCP server
                    └ cryptographic TCB ──────┘            └ subprocess + launch hygiene live HERE, outside the TCB ┘
```

A compromise of the bridge **cannot forge a signature or defeat replay** — those
guarantees live entirely in the PEP. The bridge's only job is to launch and
contain the child; keeping it out here is what shrinks the PEP's TCB.

### The bridge flags (`mcp-re-stdio-bridge`)

| Flag | Meaning |
| --- | --- |
| `--listen <addr>` | **Required.** The loopback HTTP address the bridge serves on (e.g. `127.0.0.1:8080`). Point `--inner-http-url` at it. Keep it on `127.0.0.1` so the un-TLS'd inner hop never leaves the host/pod. |
| `--inner-mode oneshot` (default) | A fresh child per request (stateless). |
| `--inner-mode persistent` | One long-lived child; requests serialized over it (stateful servers). |
| `--inner-working-dir <dir>` | Controlled **start** directory for the child. Omit for the hardened default (never silently the bridge's cwd). |
| `-- <cmd> [args...]` | Everything after the `--` separator is the inner command + argv, verbatim. **Required.** |

### The inner-server boundary (be honest about it)

The bridge applies **launch hygiene** to the child — it is **NOT** a kernel,
filesystem, or network sandbox (ADR-MCPS-016):

- The controlled working directory is a controlled **start** directory, not a
  filesystem jail — the child can still `chdir` and open any path its OS
  credentials allow.
- The `setrlimit` ceilings the bridge applies are **resource hardening**, not
  access control.
- Bounded stderr capture is size-bounded, not secrets-safe.

If you need true isolation, run the bridge + inner server inside an OS sandbox
(container, namespace, jail) — that is the deployment operator's responsibility.

### Current hardening surface (honest status)

The bridge applies its secure launch defaults today: an **empty child
environment**, a controlled working directory, bounded stderr, and resource
ceilings (sandbox off by default). The **richer per-flag hardening surface** the
in-proxy sidecar once exposed — `--inner-env` / `--inner-env-allow`,
`--inner-rlimit-*`, explicit sandbox profiles — is **not yet exposed on the bridge
CLI**; it is a tracked Phase-B follow-up (the modules are already relocated into
`mcp-re-stdio-bridge`). Until then, tune child environment and limits at the OS /
container layer (systemd unit, container `securityContext`, cgroup limits).

## Worked example

Two processes: the bridge wrapping a stdio server, and the PEP in front of it.

```bash
# 1. Front the stdio MCP server with the out-of-TCB bridge on loopback.
bazel run //mcp-re-stdio-bridge:mcp_re_stdio_bridge -- \
  --listen 127.0.0.1:8080 \
  --inner-mode oneshot \
  --inner-working-dir /srv/inner \
  -- /usr/local/bin/my-mcp-server --config /etc/mcp.toml &

# 2. Run the PEP; its inner plane is the bridge's HTTP endpoint.
#    Port 8600 = mcp_re_proxy in config/ports.toml (reserved 8600-8699 band).
bazel run //mcp-re-proxy:mcp_re_proxy_cli -- \
  --bind 127.0.0.1:8600 \
  --audience did:example:server-1 \
  --server-signer did:example:server-1 \
  --server-key-id server-key-1 \
  --key-source file \
  --signing-key-seed /etc/mcp-re/signing.seed \
  --tls-cert /etc/mcp-re/server-chain.pem \
  --tls-key /etc/mcp-re/server-key.pem \
  --client-ca /etc/mcp-re/client-ca.pem \
  --trust /etc/mcp-re/trust.json \
  --authz reference \
  --revocation-list /etc/mcp-re/revoked.txt \
  --transport-binding exact \
  --transport-identity-source uri_san \
  --max-client-cert-lifetime 1h \
  --replay-cache file --replay-path /var/lib/mcp-re/replay.json \
  --inner-http-url http://127.0.0.1:8080/mcp
```

The `--` separator on the bridge is what makes the inner command unambiguous:
everything after it is the child command and its arguments, not bridge flags.

For a native Streamable-HTTP inner backend (no stdio, no bridge), skip step 1 and
point `--inner-http-url` straight at the backend (or repeat it across a fleet).

On startup the bridge emits its listen address labelled "stdio inner, out of the
PEP TCB"; the PEP emits its async-fleet listen line with the worker count and the
configured HTTP inner backends. The Kubernetes form of this two-container pattern
is the Helm chart's `inner.stdioBridge` sidecar
([`deploy/helm/mcp-re-proxy`](../deploy/helm/mcp-re-proxy)).

## Always use Bazel

Build and run only through Bazel (`bazel run` / `bazel test`). Do not invoke the
binary directly outside the Bazel-managed environment.
