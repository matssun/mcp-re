#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Port-registry staleness gate.

`config/ports.toml` is the single source of truth for every port this repo
binds (see its header). Other artifacts that must carry a port — the Helm
chart's `bindPort` — hold a MIRRORED copy for tooling that cannot read the
registry at template time. A mirror that is only "asked to stay equal" by a
comment drifts; this gate makes the equality mechanical (ADR-MCPS-048:
generated/mirrored values are CI-staleness-gated, not trusted).

It also enforces the band invariant: every registered port must fall inside the
reserved band, so nothing in this repo can bind outside the machine-wide
reservation.

Exit 0 = registry, mirror, and band all consistent. Non-zero = drift.
"""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PORTS_TOML = REPO / "config" / "ports.toml"
HELM_VALUES = REPO / "deploy" / "helm" / "mcp-re-proxy" / "values.yaml"


def fail(msg: str) -> None:
    print(f"port-registry gate: FAIL — {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    reg = tomllib.loads(PORTS_TOML.read_text())

    # --- Band invariant: every service port is inside the reserved band -------
    band = reg["metadata"]["band"]
    lo, hi = (int(x) for x in band.split("-"))
    for name, svc in reg.get("services", {}).items():
        port = svc.get("port")
        if port is None:
            continue
        if not (lo <= port <= hi):
            fail(f"service '{name}' port {port} is outside the reserved band {band}")

    proxy_port = reg["services"]["mcp_re_proxy"]["port"]

    # --- Mirror check: Helm bindPort must equal the registry proxy port -------
    # values.yaml is plain YAML; read the `bindPort:` scalar without a YAML dep.
    m = re.search(r"^\s*bindPort:\s*(\d+)\s*(?:#.*)?$", HELM_VALUES.read_text(), re.M)
    if not m:
        fail(f"could not find a `bindPort:` scalar in {HELM_VALUES.relative_to(REPO)}")
    helm_port = int(m.group(1))
    if helm_port != proxy_port:
        fail(
            f"Helm bindPort ({helm_port}) != registry mcp_re_proxy.port "
            f"({proxy_port}). Update deploy/helm/mcp-re-proxy/values.yaml to match "
            f"config/ports.toml (the source of truth)."
        )

    print(
        f"port-registry gate: OK — band {band}, mcp_re_proxy={proxy_port}, "
        f"Helm bindPort mirrors it."
    )


if __name__ == "__main__":
    main()
