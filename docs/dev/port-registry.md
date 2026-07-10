<!-- SPDX-License-Identifier: Apache-2.0 -->

# Port registry — how mcp-re avoids machine-wide port collisions

MCP-RE is developed on a machine that runs many other services. To guarantee it
never binds a port another app owns — and vice versa — every port this repo uses
is declared in **one** place and drawn from a **reserved band**.

## The two pieces

1. **Reserved band (machine-wide).** The mcp-re repo owns **8600–8699** in the
   machine-wide service registry
   (`ws_f: infrastructure/config/services/service_registry.toml`). That registry
   is the single authority that stops two repos claiming the same number. The
   reservation lives there; mcp-re does **not** read it at runtime (see below).

2. **In-repo registry (this repo).** [`config/ports.toml`](../../config/ports.toml)
   is the single source of truth for the concrete ports mcp-re binds, all inside
   the reserved band. Every consumer resolves from it; none restates a literal:
   - local proxy launch → `--bind 127.0.0.1:{mcp_re_proxy.port}`
     (dogfood + sidecar guides)
   - Helm `bindPort` → a **mirrored** copy in
     `deploy/helm/mcp-re-proxy/values.yaml`, held equal by
     [`scripts/check_port_registry.py`](../../scripts/check_port_registry.py)
     (Helm can't read TOML at template time, so the value is mirrored and
     CI-staleness-gated — the ADR-MCPS-048 idiom, not a hopeful comment)
   - validation harness → `docs/security/gke-multi-replica-validation.sh`

## Why mcp-re keeps its own copy instead of importing `ServiceRegistry`

mcp-re is a standalone, clean-room repo with its own Bazel / crate universe and
ships independently of the monorepo. Importing the monorepo's Python
`ServiceRegistry` at runtime would couple the security proxy to a private repo
and break that isolation. So we **mirror the pattern, self-contained**: the
machine-wide registry holds the *reservation* (collision safety across repos);
`config/ports.toml` holds the *values* (resolved at runtime, no cross-repo dep).

## Current allocation (8600–8699)

| Key | Port | Purpose |
| --- | --- | --- |
| `mcp_re_proxy` | 8600 | TLS-terminating PEP bind port (prod: `0.0.0.0:8600`; dev: `127.0.0.1:8600`) |
| `mcp_re_validation_fwd_a` | 8610 | GKE validation harness — local forward to replica A |
| `mcp_re_validation_fwd_b` | 8611 | GKE validation harness — local forward to replica B |

Add a new port by editing `config/ports.toml` (must stay inside 8600–8699; the
gate enforces the band), then run `python3 scripts/check_port_registry.py`.

## Reservation to add to the machine-wide registry (ws_f)

Paste this into `infrastructure/config/services/service_registry.toml` so no
other app on the machine claims the band. mcp-re binds via `--bind`/Helm, not
via that registry, so these entries are a **reservation record** — they carry
`owner`/`notes` and the band; the live values stay in `config/ports.toml`.

```toml
# ==========================================
# mcp-re repo (reserved band 8600-8699)
# Reservation only — the live values are in the mcp-re repo's config/ports.toml.
# The mcp-re proxy binds via --bind / Helm bindPort, not via this registry
# (standalone clean-room repo; no runtime ServiceRegistry dependency).
# ==========================================
[services.mcp_re_proxy]
port = 8600
scheme = "https"
service_type = "security_proxy"
owner = "mcp-re"
notes = "TLS-terminating MCP-RE PEP (ADR-MCPS-014 / ADR-MCPRE-051). Reserved; live value in mcp-re repo config/ports.toml."

[services.mcp_re_validation_fwd_a]
port = 8610
owner = "mcp-re"
notes = "Reserved: gke-multi-replica-validation.sh local forward A. Live value in mcp-re repo config/ports.toml."

[services.mcp_re_validation_fwd_b]
port = 8611
owner = "mcp-re"
notes = "Reserved: gke-multi-replica-validation.sh local forward B. Live value in mcp-re repo config/ports.toml."
```

Also extend the "Port Allocation Strategy" comment block in that file with the
new band, e.g. `# - 8600-8699: mcp-re repo (security proxy + validation harness)`.
