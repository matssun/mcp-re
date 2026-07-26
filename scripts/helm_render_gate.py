#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Helm chart render gate — the fail-closed guards must actually refuse (CI gate).

`deploy/helm/mcp-re-proxy/templates/_helpers.tpl` carries the chart's security
guards: refuse a fleet on a node-local replay cache, refuse a plaintext Redis hop
carrying admitted nonces, refuse the shipped `did:example:` / `example.com` /
`epoch-1` placeholders, refuse a transport binding that cannot start, refuse an
admission ceiling of zero. Each is a `{{- fail ... }}` that runs at render time.

None of them had a test. A guard whose only proof is that someone read it is one
`{{- if }}` edit away from silently admitting, and the failure mode is quiet: the
chart renders, the pods start, and the property is gone. Worse, several of these
guards key on values Helm treats as FALSY (`0`, `""`), so an inverted condition
does not error — it omits a flag, and an omitted flag is the permissive default.

This gate renders the chart under a matrix of value sets and asserts, for each,
whether rendering must SUCCEED or must FAIL — and when it must fail, that the
refusal message names the value at fault. It also pins the rendered argv for the
cases where "renders successfully" is not the whole property: a flag that must be
present, and a flag that must be ABSENT.

Requires the `helm` binary. Absence is a hard error, not a skip: a gate that
skips itself on the machine where it matters is the same defect it exists to
catch.

Run:  python3 scripts/helm_render_gate.py
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CHART = REPO / "deploy" / "helm" / "mcp-re-proxy"

# A values set that overrides every guard-tripping default, so the BASE render is
# expected to succeed. Each case below perturbs exactly one thing from here, which
# is what makes a failure attributable.
BASE = {
    "inner": {"httpUrls": ["http://inner-mcp.default.svc.cluster.local:8080/mcp"]},
    "identity": {
        "audience": "did:web:proxy.internal",
        "serverSigner": "did:web:proxy.internal",
        "serverKeyId": "server-key-1",
        "targetUri": "https://proxy.internal:8600/mcp",
        "trustDomain": "proxy.internal",
        "route": "",
        "delegatedTrustEpoch": "epoch-2026-07",
    },
}


def merged(*overlays: dict) -> dict:
    """BASE with `overlays` applied, one nesting level deep (all this chart needs)."""
    out = {key: (dict(value) if isinstance(value, dict) else value) for key, value in BASE.items()}
    for overlay in overlays:
        for key, value in overlay.items():
            if isinstance(value, dict) and isinstance(out.get(key), dict):
                out[key].update(value)
            else:
                out[key] = value
    return out


def render(values: dict) -> tuple[bool, str]:
    """Render the chart with `values`. Returns (succeeded, combined output)."""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
        json.dump(values, handle)  # JSON is valid YAML; avoids a yaml dependency
        path = handle.name
    try:
        proc = subprocess.run(
            ["helm", "template", "gate", str(CHART), "-f", path],
            capture_output=True,
            text=True,
        )
        return proc.returncode == 0, proc.stdout + proc.stderr
    finally:
        Path(path).unlink(missing_ok=True)


def container_args(output: str) -> list[str]:
    """The rendered container argv, read back off the manifest text.

    Deliberately textual rather than a YAML parse: the assertion is about the
    exact strings the chart emitted, and a parse would let a quoting change
    through unnoticed.
    """
    args: list[str] = []
    inside = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped == "args:":
            inside = True
            continue
        if inside:
            if stripped.startswith("- "):
                args.append(stripped[2:].strip().strip('"'))
            elif stripped and not stripped.startswith("#"):
                break
    return args


# (name, values, must_render, message_fragment_required_on_failure)
#
# `must_render=False` means the chart MUST refuse. The fragment is asserted so a
# guard cannot pass this gate by failing for an unrelated reason (a YAML typo
# elsewhere also makes `helm template` non-zero).
CASES: list[tuple[str, dict, bool, str]] = [
    ("base values render", merged(), True, ""),
    # --- inner plane ---
    (
        "no inner backend is refused",
        merged({"inner": {"httpUrls": []}}),
        False,
        "inner plane required",
    ),
    # --- fleet vs node-local replay ---
    (
        "fleet with no shared replay store is refused",
        merged({"replay": {"redisUrl": "", "durabilityTier": "redis-wait-quorum:2:2000"}}),
        False,
        "requires replay.redisUrl",
    ),
    (
        "fleet with a node-local durability tier is refused",
        merged({"replay": {"redisUrl": "rediss://r:6379", "durabilityTier": "redis-async"}}),
        False,
        "requires replay.durabilityTier",
    ),
    # --- plaintext Redis on the nonce / epoch hops ---
    (
        "plaintext replay redis is refused under fleet",
        merged({"replay": {"redisUrl": "redis://r:6379", "durabilityTier": "linearizable"}}),
        False,
        "replay.redisUrl is plaintext",
    ),
    (
        "plaintext trust-epoch redis is refused under fleet",
        merged({"revocation": {"tier": "push:60", "trustEpochRedisUrl": "redis://r:6379",
                               "trustEpochKey": "mcp-re:trust:epoch"}}),
        False,
        "trustEpochRedisUrl is plaintext",
    ),
    (
        "plaintext replay redis renders with the named opt-out",
        merged({"replay": {"redisUrl": "redis://r:6379", "durabilityTier": "linearizable",
                           "allowPlaintextRedis": True}},
               {"revocation": {"tier": "push:60", "trustEpochRedisUrl": "",
                               "trustEpochKey": "mcp-re:trust:epoch"}}),
        True,
        "",
    ),
    # --- shipped placeholders (one dispatch boundary per install) ---
    (
        "did:example: audience placeholder is refused",
        merged({"identity": {"audience": "did:example:server-1"}}),
        False,
        "did:example:",
    ),
    (
        "example.com trust-domain placeholder is refused",
        merged({"identity": {"trustDomain": "example.com"}}),
        False,
        "example.com placeholder",
    ),
    (
        "epoch-1 delegated-epoch placeholder is refused",
        merged({"identity": {"delegatedTrustEpoch": "epoch-1"}}),
        False,
        "epoch-1 placeholder",
    ),
    (
        "the shipped defaults render ONLY under allowExampleFixtures",
        merged({"identity": {"audience": "did:example:server-1",
                             "serverSigner": "did:example:server-1",
                             "trustDomain": "example.com",
                             "delegatedTrustEpoch": "epoch-1",
                             "allowExampleFixtures": True}}),
        True,
        "",
    ),
    (
        "empty targetUri is refused",
        merged({"identity": {"targetUri": ""}}),
        False,
        "identity.targetUri is required",
    ),
    # --- transport binding: only "" and exact can start ---
    ("transportBinding=none is refused", merged({"transportBinding": "none"}), False, "cannot start"),
    (
        "transportBinding=lb-assertion is refused",
        merged({"transportBinding": "lb-assertion"}),
        False,
        "cannot start",
    ),
    ("transportBinding=exact renders", merged({"transportBinding": "exact"}), True, ""),
    # --- key custody ---
    (
        "keySource=gcpKms with no keyVersion is refused",
        merged({"keySource": "gcpKms"}),
        False,
        "requires gcpKms.keyVersion",
    ),
    (
        "an unknown keySource is refused",
        merged({"keySource": "vault"}),
        False,
        "keySource must be",
    ),
    # --- admission ceilings (MCPRE-114) ---
    (
        "admission ceiling of 0 is refused, not read as unset",
        merged({"admission": {"maxInFlight": 0, "maxInFlightTotal": ""}}),
        False,
        "must be a positive integer",
    ),
    (
        "admission total of 0 is refused",
        merged({"admission": {"maxInFlight": "", "maxInFlightTotal": 0}}),
        False,
        "must be a positive integer",
    ),
    (
        "a non-numeric admission ceiling is refused",
        merged({"admission": {"maxInFlight": "many", "maxInFlightTotal": ""}}),
        False,
        "must be a positive integer",
    ),
    (
        "both admission ceilings set is refused (one would be discarded)",
        merged({"admission": {"maxInFlight": 32, "maxInFlightTotal": 256}}),
        False,
        "not both",
    ),
]

# (name, values, args that MUST appear as an adjacent pair, args that must NOT appear)
ARGV_CASES: list[tuple[str, dict, list[tuple[str, str]], list[str]]] = [
    (
        "unset admission ceilings omit both flags",
        merged(),
        [],
        ["--max-in-flight", "--max-in-flight-total"],
    ),
    (
        "maxInFlight renders the per-core flag only",
        merged({"admission": {"maxInFlight": 32, "maxInFlightTotal": ""}}),
        [("--max-in-flight", "32")],
        ["--max-in-flight-total"],
    ),
    (
        "maxInFlightTotal renders the fleet-wide flag only",
        merged({"admission": {"maxInFlight": "", "maxInFlightTotal": 256}}),
        [("--max-in-flight-total", "256")],
        ["--max-in-flight"],
    ),
    (
        "gcpKms custody never passes a signing-key seed",
        merged({"keySource": "gcpKms",
                "gcpKms": {"keyVersion": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
                           "useMetadata": True, "endpoint": "", "tlsKeyVersion": "",
                           "accessTokenSecretName": ""}}),
        [("--key-source", "gcp-kms")],
        ["--signing-key-seed"],
    ),
    (
        "file custody does pass the signing-key seed",
        merged(),
        [("--key-source", "file")],
        [],
    ),
    (
        "delegated TLS custody omits the exported TLS key",
        merged({"keySource": "gcpKms",
                "gcpKms": {"keyVersion": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
                           "tlsKeyVersion": "projects/p/locations/l/keyRings/r/cryptoKeys/t/cryptoKeyVersions/1",
                           "useMetadata": True, "endpoint": "", "accessTokenSecretName": ""}}),
        [("--gcp-kms-tls-key-version",
          "projects/p/locations/l/keyRings/r/cryptoKeys/t/cryptoKeyVersions/1")],
        ["--tls-key"],
    ),
]


def main() -> int:
    if shutil.which("helm") is None:
        print("FAIL: helm not found on PATH; this gate cannot verify the chart guards")
        return 2
    if not CHART.is_dir():
        print(f"FAIL: chart not found at {CHART}")
        return 2

    failures: list[str] = []

    for name, values, must_render, fragment in CASES:
        ok, output = render(values)
        problem = ""
        if must_render and not ok:
            problem = f"expected a successful render, got:\n{output.strip()[-600:]}"
        elif not must_render and ok:
            problem = "the chart RENDERED but the guard must refuse it"
        elif not must_render and fragment not in output:
            problem = (
                f"refused, but the message does not name the fault ({fragment!r} absent) — "
                f"it may be failing for an unrelated reason:\n{output.strip()[-400:]}"
            )
        if problem:
            failures.append(f"{name}: {problem}")
        print(f"  {'FAIL' if problem else 'ok  '} {name}")

    for name, values, required_pairs, forbidden in ARGV_CASES:
        ok, output = render(values)
        if not ok:
            failures.append(f"{name}: render failed:\n{output.strip()[-400:]}")
            print(f"  FAIL {name}")
            continue
        args = container_args(output)
        problems = []
        for flag, value in required_pairs:
            if flag not in args:
                problems.append(f"{flag} missing")
            elif args[args.index(flag) + 1] != value:
                problems.append(f"{flag} carries {args[args.index(flag) + 1]!r}, expected {value!r}")
        for flag in forbidden:
            if flag in args:
                problems.append(f"{flag} present but must be omitted")
        if problems:
            failures.append(f"{name}: " + "; ".join(problems))
        print(f"  {'FAIL' if problems else 'ok  '} {name}")

    if failures:
        print("\nhelm render gate FAILED:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"\nhelm render gate: {len(CASES) + len(ARGV_CASES)} cases pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
