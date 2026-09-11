"""Verify the live measurement plane IS the environment the declared class names.

WHY THIS EXISTS
===============

`[[context.class]] dev1-slo-v1` declares the VM, the endpoint, the CPU and memory
allocation, the storage medium and the Redis image its numbers were measured under. A
declaration nobody checks is evidence-starved: it reads as a guarantee while permitting
exactly the drift it names. This module is the check.

It closes a hole that is live rather than hypothetical. `measurement_context()` folds
`container_runtime_class`, which is derived from the Docker SERVER VERSION -- and both
`colima-db` and `colima-slo` report `docker-29.2`. A durable PASS at 15,447.96 rps exists,
measured on `colima-db`. Had the lane simply been pointed at the new daemon under the old
class name, the context digest would have been byte-identical and that PASS would have been
silently reused for a VM it was never measured in.

THE ENDPOINT IS RESOLVED FROM THE DECLARATION, NEVER FROM AMBIENT STATE
======================================================================

Every docker invocation here passes `-H <declared socket>` explicitly. Not `--context`, not
the ambient default, not `DOCKER_HOST`. Creating the `slo` profile silently switched the
user's default context to it, and the same mechanism can silently switch it away -- so a
lifecycle that trusted the ambient context could reconcile one daemon, measure on another,
and tear down a third. `-H` outranks both `DOCKER_CONTEXT` and `DOCKER_HOST`, which is why
it is the form used.

THE IDLE PLANE IS AN EXACT BASELINE, NOT "ROUGHLY EMPTY"
=======================================================

Because nothing else is permitted to use this daemon, "clean" is decidable exactly rather
than filtered by label. The baseline admits:

    the VM and its daemon          persistent infrastructure
    docker's built-in networks     bridge / host / none, created by the daemon itself
    the pinned infrastructure images   declared in the class, deliberately kept warm

and admits nothing else. Anything outside it is one of two things, and they have different
dispositions -- an owned leftover is reconciled, an unowned occupant is refused. We do not
destroy what we did not create.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
SURFACE_TOML = REPO / "config" / "performance-surface.toml"

#: Networks the Docker daemon creates for itself. Their presence is not contamination.
BUILTIN_NETWORKS = frozenset({"bridge", "host", "none"})

EXIT_OK, EXIT_REFUSED, EXIT_UNAVAILABLE = 0, 1, 2


def declared_class(name: str | None = None) -> dict:
    """The class entry, read from the one declaration. Never a literal in a second place."""
    declared = tomllib.loads(SURFACE_TOML.read_text(encoding="utf-8"))["context"]["class"]
    if name is None:
        claimed = [e for e in declared if e.get("github_actions_runner")]
        if len(claimed) != 1:
            raise SystemExit(
                f"error: exactly one [[context.class]] must set github_actions_runner = "
                f"true; {len(claimed)} do"
            )
        return claimed[0]
    for entry in declared:
        if entry["name"] == name:
            return entry
    raise SystemExit(f"error: no [[context.class]] named {name!r}")


def declared_environment(entry: dict) -> dict:
    env = entry.get("environment")
    if not env:
        raise SystemExit(
            f"error: class {entry['name']!r} declares no [context.class.environment]. A "
            f"class used for authoritative measurement must state the environment its "
            f"numbers were taken in, or nothing can verify that a later run matches it."
        )
    return env


def endpoint(entry: dict) -> str:
    """The declared socket. The single place the lifecycle learns which daemon it owns."""
    return declared_environment(entry)["docker_endpoint"]


def docker(host: str, *args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    """Every docker call in the SLO lifecycle goes through here, with an explicit -H.

    The environment is scrubbed of DOCKER_HOST and DOCKER_CONTEXT as well as passing -H,
    belt and braces: a lifecycle that can be redirected by an exported variable is not a
    lifecycle that owns its plane.
    """
    env = {k: v for k, v in os.environ.items() if k not in ("DOCKER_HOST", "DOCKER_CONTEXT")}
    return subprocess.run(["docker", "-H", host, *args],
                          capture_output=True, text=True, env=env, timeout=timeout)


def colima(profile: str, *args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    colima_bin = os.environ.get("MCP_RE_ARBITER_COLIMA", "/opt/homebrew/bin/colima")
    return subprocess.run([colima_bin, "ssh", "-p", profile, "--", *args],
                          capture_output=True, text=True, timeout=timeout)


# ==========================================================================================
# is this the declared environment?
# ==========================================================================================


def verify_environment(entry: dict) -> dict:
    """Compare every declared environment field against the live plane."""
    want = declared_environment(entry)
    host = want["docker_endpoint"]
    profile = want["colima_profile"]
    observed: dict[str, object] = {}
    mismatches: list[str] = []

    reachable = docker(host, "version", "--format", "{{.Server.Version}}", timeout=60)
    if reachable.returncode != 0:
        return {"verified": False, "reachable": False, "observed": {},
                "mismatches": [f"the declared endpoint {host} is not reachable: "
                               f"{(reachable.stderr or '').strip()[:160]}"]}
    observed["docker_server_version"] = reachable.stdout.strip()

    vm = colima(profile, "sh", "-c",
                "echo $(nproc);"
                " echo $(grep MemTotal /proc/meminfo | tr -dc 0-9);"
                " echo $(uname -m)", timeout=90)
    lines = [x for x in (vm.stdout or "").split() if x]
    if len(lines) >= 3:
        observed["vm_cpus"] = int(lines[0])
        # /proc/meminfo is kB and the guest never sees quite the whole allocation, so this
        # rounds up to the nearest GiB rather than comparing raw bytes -- a strict equality
        # here would fail on every host for a reason that says nothing about drift.
        observed["vm_memory_gib"] = int(lines[1]) // 1024 // 1024 + 1
        observed["vm_arch"] = lines[2]
    else:
        mismatches.append(f"could not read VM facts from colima profile {profile!r}")

    digests = docker(host, "images", "--digests", "--format", "{{.Repository}}:{{.Tag}} {{.Digest}}",
                     want["redis_image"], timeout=60)
    parts = (digests.stdout or "").split()
    observed["redis_image_digest"] = parts[1] if len(parts) >= 2 else "<absent>"

    for field in ("docker_server_version", "vm_cpus", "vm_memory_gib", "vm_arch",
                  "redis_image_digest"):
        if field in observed and observed[field] != want.get(field):
            mismatches.append(
                f"{field}: declared {want.get(field)!r}, observed {observed[field]!r}")

    return {"verified": not mismatches, "reachable": True,
            "endpoint": host, "declared": want, "observed": observed,
            "mismatches": mismatches}


# ==========================================================================================
# is the plane at its exact declared baseline?
# ==========================================================================================


def inspect_plane(entry: dict) -> dict:
    """Everything on the daemon, sorted into the baseline and what falls outside it."""
    want = declared_environment(entry)
    host = want["docker_endpoint"]
    approved_images = {want["redis_image"]}

    containers = []
    listing = docker(host, "ps", "-a", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Labels}}")
    for line in (listing.stdout or "").splitlines():
        if not line.strip():
            continue
        cid, name, image, labels = (line.split("\t") + ["", "", ""])[:4]
        containers.append({"id": cid, "name": name, "image": image, "labels": labels})

    networks = [n for n in (docker(host, "network", "ls", "--format", "{{.Name}}").stdout or "").split()
                if n not in BUILTIN_NETWORKS]
    volumes = [v for v in (docker(host, "volume", "ls", "-q").stdout or "").split() if v]
    images = [i for i in (docker(host, "images", "--format", "{{.Repository}}:{{.Tag}}").stdout or "").split() if i]
    unapproved_images = [i for i in images if i not in approved_images]

    return {
        "endpoint": host,
        "containers": containers,
        "networks": networks,
        "volumes": volumes,
        "images": images,
        "unapproved_images": unapproved_images,
        "at_baseline": not containers and not networks and not volumes and not unapproved_images,
    }


def classify(plane: dict, run_label: str = "com.mcp-re.slo") -> dict:
    """Split what is outside the baseline into OWNED leftovers and UNKNOWN occupants.

    The two have different dispositions and must never be collapsed. An owned leftover is
    ours to reconcile; an unknown occupant is somebody else's process and is not ours to
    destroy -- that condition is INFRASTRUCTURE_UNAVAILABLE and no benchmark runs.
    """
    owned, unknown = [], []
    for c in plane["containers"]:
        (owned if run_label in (c.get("labels") or "") else unknown).append(c)
    # A network or volume on this daemon can only have come from an SLO run, because
    # nothing else is permitted to use it -- but an UNLABELLED one predates the labelling
    # mechanism or was made by something unexpected, so it is reported rather than assumed.
    return {"owned_containers": owned, "unknown_containers": unknown,
            "networks": plane["networks"], "volumes": plane["volumes"],
            "unapproved_images": plane["unapproved_images"]}


def preflight(entry: dict | None = None) -> dict:
    entry = entry or declared_class()
    env = verify_environment(entry)
    plane = inspect_plane(entry) if env["reachable"] else {"at_baseline": False}
    result = {
        "class": entry["name"],
        "environment_verified": env["verified"],
        "environment": env,
        "plane": plane,
        "at_baseline": bool(plane.get("at_baseline")),
    }
    if env["reachable"] and not plane["at_baseline"]:
        result["disposition"] = classify(plane)
    result["ready_to_measure"] = env["verified"] and bool(plane.get("at_baseline"))
    return result


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    name = argv[0] if argv and not argv[0].startswith("-") else None
    result = preflight(declared_class(name))
    print(json.dumps(result, indent=2, default=str))
    if not result["environment"]["reachable"]:
        return EXIT_UNAVAILABLE
    if not result["environment_verified"]:
        return EXIT_REFUSED
    return EXIT_OK if result["ready_to_measure"] else EXIT_REFUSED


if __name__ == "__main__":
    raise SystemExit(main())
