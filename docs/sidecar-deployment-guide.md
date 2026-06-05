# MCP-S Sidecar Deployment Guide

**Audience:** an operator who wants to wrap an ordinary stdio MCP server with the
MCP-S production sidecar so requests are verified before they reach the inner
server.

This guide explains **how to run** the `mcps-proxy` production CLI. The rules it
enforces are in the [MCP-S Core Specification](spec/mcps-core-spec.md);
the rationale is in ADR-MCPS-014
([view](adr/adr-mcps-014.md), transport hardening)
and ADR-MCPS-016 ([view](adr/adr-mcps-016.md),
inner-server isolation boundary). The proofs are the
`//mcps-proxy:*` test targets (see the
[conformance manifest](../mcps-conformance/conformance_manifest.json)).

For TLS/mTLS, transport binding, key sources, and the replay cache in depth, read
the companion [Transport Hardening Guide](transport-hardening-guide.md). This
guide focuses on **wrapping a server** and the inner-launch flags.

## What the sidecar does

Source: [`cli.rs`](../mcps-proxy/src/cli.rs), [`main.rs`](../mcps-proxy/src/main.rs),
[`inner_launch.rs`](../mcps-proxy/src/inner_launch.rs).

The `:mcps_proxy_cli` binary is the **policy-enforcement point**. For each
connection it: terminates TLS itself, verifies the mTLS client certificate,
verifies the MCP-S object signature, optionally evaluates authorization (Phase 5)
and transport binding (Phase 6), and only then forwards the verified request to
an inner MCP server **subprocess**, signing the response. The inner server's
stdin receives the request bytes and its **stdout** is read back as the protocol
response. The serve loop is blocking and single-threaded (no async).

An invalid request never reaches the inner server — verification happens first,
and a failure returns a signed/`mcps.*` error instead of dispatching.

## The inner-server boundary (be honest about it)

The sidecar applies **launch hygiene** to the inner subprocess. It is **NOT** a
kernel, filesystem, or network sandbox (ADR-MCPS-016). Specifically:

- The controlled working directory is a controlled **start** directory, not a
  filesystem jail — the inner server can still `chdir` and open any path its OS
  credentials allow.
- The Unix `setrlimit` ceilings are **resource hardening** (bounding fds, CPU,
  memory, core/file size), not access control — the inner server can still reach
  any file or socket its OS credentials permit.
- The bounded stderr capture is size-bounded, not secrets-safe.

If you need true isolation, run the sidecar + inner server inside an OS sandbox
(container, namespace, jail) — that is out of MCP-S's scope and is the deployment
operator's responsibility.

## The flags

Run `:mcps_proxy_cli` via Bazel. Required and optional flags below are parsed by
`cli::parse_args`; defaults shown are the real defaults from that parser.

### Core / required

| Flag | Meaning |
| --- | --- |
| `--bind` | Listen address, e.g. `127.0.0.1:8443`. |
| `--audience` | This server's identity (expected request audience). |
| `--server-signer` / `--server-key-id` | Response-signing identity + key id. |
| `--signing-key-seed`, `--tls-cert`, `--tls-key`, `--client-ca` | Key-material locations (paths for `file`, env-var names for `env`). |
| `--trust` | Path to the JSON trust file (request signers + authorization issuers). |
| `--inner-command <cmd> [args...]` | The inner MCP server command. **Consumes the rest of argv**, so put it last. |

`--max-clock-skew` defaults to `300` seconds.

### KeySource (`key_source.rs`)

| Flag | Meaning |
| --- | --- |
| `--key-source file` (default) | Read material from files on disk. |
| `--key-source env` | Read from environment variables. **Dev/CI only.** |
| `--allow-env-keysource` | Required to use `env`; without it `env` is refused. |

Environment variables are visible to the whole process tree and can leak via
crash dumps, `ps e`, and `/proc/<pid>/environ` — so `env` is gated behind an
explicit opt-in and loudly warned. Use `file` with `0600` permissions in
production (the CLI warns if a key file is group/world-readable). An HSM/KMS-
backed source is a documented future `KeySource` implementation, not present
today.

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
| `--replay-cache memory` (default) | In-memory; lost on restart. |
| `--replay-cache file` | Durable, single-node, file-backed. Requires `--replay-path`. |
| `--replay-path <path>` | State-file path for the durable cache. |

### Connection limits (DoS defense)

`--max-header-bytes` (64 KiB), `--max-body-bytes` (16 MiB),
`--max-connections` (256), `--read-timeout-secs` / `--write-timeout-secs` (30s;
`0` disables). Every limit fails closed.

### Inner-server environment minimization (MCPS-035)

The child environment is **cleared by default** and only an explicit allowlist is
passed through, so env-loaded key material is not visible to the inner server
unless you explicitly allow it.

| Flag | Meaning |
| --- | --- |
| `--inherit-env false` (default) / `true` | `true` passes the proxy's ENTIRE environment to the inner server (re-opens the leak; loudly warned). |
| `--inner-env KEY=VALUE` | Set one explicit variable on the child (repeatable; the value may itself contain `=`). |
| `--inner-env-allow NAME` | Pass through one variable from the proxy's env (repeatable). A name absent from the proxy env fails startup. |

### Inner-server working dir + stderr bounds (MCPS-036)

| Flag | Meaning |
| --- | --- |
| `--inner-working-dir <dir>` | Controlled start directory. Default is the system temp dir — **never** silently the proxy's cwd. A missing dir fails startup. |
| `--inner-stderr-cap-bytes` / `--inner-stderr-cap-lines` | Bound the separately-captured inner stderr (must be `> 0`). Inner stderr goes to the proxy's structured log only, never onto stdout (the protocol stream) and never into MCP content. |

### Inner-server resource limits (MCPS-037, Unix `setrlimit`)

| Flag | Meaning |
| --- | --- |
| `--inner-rlimit-nofile` | Max open file descriptors. |
| `--inner-rlimit-cpu-seconds` | CPU-time ceiling. |
| `--inner-rlimit-as-bytes` | Address-space ceiling. |
| `--inner-rlimit-data-bytes` | Data-segment ceiling. |
| `--inner-rlimit-core-bytes` | Core-dump size (default `0` = core dumps disabled). |
| `--inner-rlimit-fsize-bytes` | Max written-file size. |
| `--inner-rlimit-best-effort true`/`false` (default `false`) | When `false` (strict), a ceiling the kernel refuses **fails the spawn** closed. When `true`, an unappliable ceiling is downgraded to a logged no-op (warned). |

Each ceiling accepts a non-negative integer (`0` is a valid, very tight ceiling),
or the literal `none` to clear the ceiling and leave that resource at the OS
default (e.g. to re-enable core dumps). On a non-Unix platform a configured limit
is a hard startup error unless best-effort is opted in.

## Worked example

Wrap an inner stdio server (`/usr/local/bin/my-mcp-server --config /etc/mcp.toml`)
behind a fully-hardened sidecar:

```bash
bazel run //mcps-proxy:mcps_proxy_cli -- \
  --bind 127.0.0.1:8443 \
  --audience did:example:server-1 \
  --server-signer did:example:server-1 \
  --server-key-id server-key-1 \
  --key-source file \
  --signing-key-seed /etc/mcps/signing.seed \
  --tls-cert /etc/mcps/server-chain.pem \
  --tls-key /etc/mcps/server-key.pem \
  --client-ca /etc/mcps/client-ca.pem \
  --trust /etc/mcps/trust.json \
  --authz reference \
  --transport-binding exact \
  --transport-identity-source uri_san \
  --max-client-cert-lifetime 1h \
  --replay-cache file --replay-path /var/lib/mcps/replay.json \
  --inner-working-dir /srv/inner \
  --inner-env MCP_MODE=prod \
  --inner-env-allow PATH \
  --inner-rlimit-nofile 256 \
  --inner-rlimit-cpu-seconds 30 \
  --inner-command /usr/local/bin/my-mcp-server --config /etc/mcp.toml
```

Note `--inner-command` is last: everything after it is the inner command and its
arguments, not proxy flags.

On startup the proxy emits the listen address, the effective inner working dir
(explicitly labelled "controlled start dir, NOT a filesystem sandbox"), the
stderr caps, and any configured resource limits (labelled "RESOURCE HARDENING,
NOT a sandbox"). Heed the warnings — they mark the honest boundaries above.

## Always use Bazel

Build and run only through Bazel (`bazel run` / `bazel test`). Do not invoke the
binary directly outside the Bazel-managed environment.
