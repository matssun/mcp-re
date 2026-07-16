# MCP-RE Sidecar Deployment Guide

**Audience:** an operator who wants to put the MCP-RE production sidecar in front
of a **Streamable-HTTP** MCP server so requests are verified before they reach the
inner server and responses are signed. MCP-RE is HTTP-profile only; a stdio-only
inner server is out of scope — front it with an EXTERNAL plain-MCP adapter (e.g.
FastMCP's stdio↔HTTP proxy) that exposes HTTP, and point the PEP at that adapter.

This guide explains **how to run** the `mcp-re-proxy` production CLI. The rules the
proxy enforces are in the [MCP-RE Core Specification](spec/mcp-re-core-spec.md); the
rationale is in ADR-MCPS-014 ([view](https://github.com/matssun/mcp-re/discussions/363), transport hardening),
ADR-MCPS-016 ([view](https://github.com/matssun/mcp-re/discussions/365), inner-server isolation boundary) and
ADR-MCPRE-051 ([view](https://github.com/matssun/mcp-re/discussions/399), high-throughput serving
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
verifies the mTLS client certificate, verifies the RFC 9421 HTTP message
signature (with the RFC 9530 `Content-Digest`),
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
  `setrlimit`) has been **removed** — MCP-RE is HTTP-profile only and owns no stdio
  serving or bridge. A stdio-only inner server is fronted by an external plain-MCP
  adapter that exposes HTTP; see [Fronting a stdio-only inner server](#fronting-a-stdio-only-inner-server-out-of-scope-for-mcp-re).

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
front a **stdio-only** server, point `--inner-http-url` at an external plain-MCP
stdio↔HTTP adapter (below).

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
| `--transport-binding exact` (default) | Request `signer` must equal the verified mTLS identity. (Binding is mandatory — there is no `none` option; a decoupled channel↔signer posture is refused.) |
| `--transport-identity-source uri_san` (default) / `dns_san` | Which client-cert field is the authoritative identity. (`cn_legacy` is refused.) |
| `--max-client-cert-lifetime 1h` (default) | The v1 revocation posture. Accepts `1h`/`30m`/`3600` up to the 1h ceiling; `none`/`0` (disabled) and any value over the ceiling are refused. |

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

## Fronting a stdio-only inner server (out of scope for MCP-RE)

MCP-RE is HTTP-profile only: the PEP speaks HTTP to its inner plane and MCP-RE
ships **no stdio bridge**. A stdio-only MCP server (JSON-RPC over a child's
stdin/stdout) is fronted by an **external** plain-MCP adapter that exposes HTTP —
for example [FastMCP](https://github.com/jlowin/fastmcp)'s stdio↔HTTP proxy — run
as your own process/sidecar. The PEP reaches that adapter over loopback HTTP like
any other backend:

```text
  client ──mTLS──▶  mcp-re-proxy (PEP, signs)  ──HTTP──▶  external stdio↔HTTP adapter (e.g. FastMCP)  ──stdio──▶  unmodified MCP server
                    └ cryptographic TCB ──────┘            └ NOT part of MCP-RE; run + isolate it yourself ┘
```

A compromise of that adapter **cannot forge a signature or defeat replay** — those
guarantees live entirely in the PEP. Running and isolating the adapter (its child
environment, working directory, resource limits, and any OS sandbox) is the
deployment operator's responsibility, exactly as for any inner backend.

## Worked example

Run the PEP in front of a Streamable-HTTP inner backend (a native HTTP MCP server,
or an external stdio↔HTTP adapter exposing HTTP):

```bash
# The PEP; its inner plane is the HTTP backend on loopback.
# Port 8600 = mcp_re_proxy in config/ports.toml (reserved 8600-8699 band).
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

Repeat `--inner-http-url` to round-robin across a backend fleet. On startup the PEP
emits its async-fleet listen line with the worker count and the configured HTTP
inner backends. The Kubernetes form sets `inner.httpUrls` on the Helm chart
([`deploy/helm/mcp-re-proxy`](../deploy/helm/mcp-re-proxy)).

## Always use Bazel

Build and run only through Bazel (`bazel run` / `bazel test`). Do not invoke the
binary directly outside the Bazel-managed environment.
