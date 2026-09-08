#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Heavy-lane disk preflight — refuse BEFORE a lane turns a full disk into a security verdict.

THE FAILURE CLASS. Twice during the v0.17 release the Docker VM disk reached 100% and the
condition surfaced as a lane result rather than as an environment fact: the Redis sidecars
could not create their append-only directories, so the SLO bench's Redis fleet died, and
the kind fleet harness reported `PROOF FAILED: load generator did not complete` for a proof
that had never run. `docs/releases/v0.17.0-provenance.md` records the measurement — "the
Docker VM disk was 98 GB, 100% full, 0 available".

A RED that measured nothing is the inverse of the green that measured nothing, and it costs
more: it is read as a regression in the code under test. The lanes must therefore say
INFRASTRUCTURE_UNAVAILABLE before they start, on a floor declared in
`config/heavy-lane-floors.toml` — never on a number restated here.

WHAT IT MEASURES, and why it takes two measurements:

  * the HOST filesystem holding the repository — `target/`, the bazel cache, image build
    contexts;
  * the CONTAINER RUNTIME's own filesystem, which on Docker Desktop is inside a VM and is
    therefore invisible to `df` on the host. It is measured from inside a container, using
    an image ALREADY PRESENT locally: pulling an image to discover whether there is room to
    pull images is the wrong order, and on the disk state this exists to catch, it fails.

WHAT IT IS NOT. It is not a control and decides nothing about a change; it decides whether
a measurement is worth starting. It never deletes anything unless `--reclaim` is passed,
and even then only images this repository built and no longer references.

Exit codes, distinct on purpose — "could not decide" is not "passed" and neither is
"the box is too full to ask":

    0   PASS                        every declared floor is met
    20  INFRASTRUCTURE_UNAVAILABLE  a floor is not met; the lane must not start
    21  UNMEASURED                  a floor could not be measured at all

Run:  python3 scripts/heavy_lane_disk_preflight.py --lane kind
      python3 scripts/heavy_lane_disk_preflight.py --lane kind --reclaim
      python3 scripts/heavy_lane_disk_preflight.py --selftest
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FLOORS = REPO / "config" / "heavy-lane-floors.toml"

PASS, UNAVAILABLE, UNMEASURED = 0, 20, 21
GIB = 1024**3


@dataclass(frozen=True)
class Measurement:
    """One filesystem, its declared floor, and what was actually seen — or why not."""

    what: str
    floor_gib: float
    free_gib: float | None = None
    unmeasured: str | None = None

    def verdict(self) -> int:
        if self.free_gib is None:
            return UNMEASURED
        return PASS if self.free_gib >= self.floor_gib else UNAVAILABLE

    def line(self) -> str:
        if self.free_gib is None:
            return f"  {self.what}: UNMEASURED — {self.unmeasured}"
        state = "ok" if self.free_gib >= self.floor_gib else "BELOW FLOOR"
        return f"  {self.what}: {self.free_gib:.1f} GiB free / {self.floor_gib:g} GiB floor — {state}"


def adjudicate(measurements: list[Measurement]) -> tuple[str, int]:
    """UNAVAILABLE outranks UNMEASURED: a floor known to be missed is a decided answer."""
    verdicts = {m.verdict() for m in measurements}
    if UNAVAILABLE in verdicts:
        return "INFRASTRUCTURE_UNAVAILABLE", UNAVAILABLE
    if UNMEASURED in verdicts:
        return "UNMEASURED", UNMEASURED
    return "PASS", PASS


def measure_host(path: Path, floor_gib: float) -> Measurement:
    try:
        usage = shutil.disk_usage(path)
    except OSError as exc:  # pragma: no cover - the repo path is always statable
        return Measurement("host filesystem", floor_gib, unmeasured=str(exc))
    return Measurement("host filesystem", floor_gib, free_gib=usage.free / GIB)


def _present_image(candidates: list[str]) -> str | None:
    for image in candidates:
        probe = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            text=True,
            check=False,
        )
        if probe.returncode == 0:
            return image
    return None


def measure_container_runtime(candidates: list[str], floor_gib: float) -> Measurement:
    what = "container runtime filesystem"
    if shutil.which("docker") is None:
        return Measurement(what, floor_gib, unmeasured="docker is not installed")
    image = _present_image(candidates)
    if image is None:
        return Measurement(
            what,
            floor_gib,
            unmeasured=f"none of {', '.join(candidates)} is present locally; "
            "the preflight never pulls one",
        )
    run = subprocess.run(
        ["docker", "run", "--rm", image, "df", "-P", "/"],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if run.returncode != 0:
        reason = (run.stderr or run.stdout).strip().splitlines()
        return Measurement(what, floor_gib, unmeasured=f"`docker run` failed: {reason[-1] if reason else '?'}")
    free_gib = _parse_df_available_gib(run.stdout)
    if free_gib is None:
        return Measurement(what, floor_gib, unmeasured="could not parse `df -P /` output")
    return Measurement(what, floor_gib, free_gib=free_gib)


def _parse_df_available_gib(output: str) -> float | None:
    """`df -P` guarantees one record per filesystem, Available in 1024-byte blocks."""
    for line in output.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 4 and fields[3].isdigit():
            return int(fields[3]) * 1024 / GIB
    return None


def reclaim(version: str) -> list[str]:
    """Remove ONLY images this repository built at a version it no longer references.

    Deliberately narrow. A full disk is not a licence to prune another project's images,
    and the running kind cluster's node images are not ephemeral. Everything else — build
    cache, dangling layers, volumes — is the operator's call, not this script's.
    """
    listed = subprocess.run(
        ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}", "mcp-re-*"],
        capture_output=True,
        text=True,
        check=False,
    )
    stale = [
        ref
        for ref in listed.stdout.split()
        if ref.count(":") == 1 and not ref.endswith(f":{version}") and not ref.endswith(":<none>")
    ]
    for ref in stale:
        subprocess.run(["docker", "rmi", ref], capture_output=True, check=False)
    return stale


def run_lane(lane: str, do_reclaim: bool) -> int:
    config = tomllib.loads(FLOORS.read_text(encoding="utf-8"))
    if lane not in config["lanes"]:
        print(f"unknown lane '{lane}'; {FLOORS.name} declares {', '.join(config['lanes'])}", file=sys.stderr)
        return UNMEASURED
    declared = config["lanes"][lane]
    print(f"disk preflight — lane '{lane}': {declared['description']}")

    if do_reclaim:
        version = (REPO / "VERSION").read_text(encoding="utf-8").strip()
        removed = reclaim(version)
        print(f"  reclaimed {len(removed)} superseded mcp-re image(s): {' '.join(removed) or 'none'}")

    measurements = [
        measure_host(REPO, declared["host_free_gib"]),
        measure_container_runtime(config["probe"]["images"], declared["container_runtime_free_gib"]),
    ]
    for measurement in measurements:
        print(measurement.line())
    name, code = adjudicate(measurements)
    print(f"DISK PREFLIGHT: {name} (lane {lane})")
    sys.stdout.flush()
    if code == UNAVAILABLE:
        print(
            f"  the floor is declared in {FLOORS.relative_to(REPO)} with its derivation.\n"
            "  Free space and re-run; `--reclaim` removes superseded mcp-re images only.",
            file=sys.stderr,
        )
    return code


def selftest() -> int:
    """The adjudication is the whole decision, so it is what the selftest pins."""
    below = Measurement("x", 20, free_gib=5.0)
    above = Measurement("y", 20, free_gib=25.0)
    exact = Measurement("z", 20, free_gib=20.0)
    blind = Measurement("w", 20, unmeasured="no probe image")
    cases = [
        ([above, exact], ("PASS", PASS)),
        ([above, below], ("INFRASTRUCTURE_UNAVAILABLE", UNAVAILABLE)),
        ([above, blind], ("UNMEASURED", UNMEASURED)),
        # A decided miss outranks an unmeasured half: the lane must not start either way,
        # and the actionable message is the floor that is known to be short.
        ([blind, below], ("INFRASTRUCTURE_UNAVAILABLE", UNAVAILABLE)),
    ]
    for measurements, expected in cases:
        got = adjudicate(measurements)
        assert got == expected, f"{[m.what for m in measurements]}: expected {expected}, got {got}"
    assert _parse_df_available_gib("Filesystem 1024-blocks Used Available Capacity Mounted\nov 10 5 5013888 95% /") is not None
    assert _parse_df_available_gib("") is None
    config = tomllib.loads(FLOORS.read_text(encoding="utf-8"))
    for lane, declared in config["lanes"].items():
        for key in ("description", "host_free_gib", "container_runtime_free_gib", "derivation"):
            assert key in declared, f"lane {lane} declares no {key}"
    assert config["probe"]["images"], "no probe image candidates declared"
    print(f"selftest OK — 4 adjudication cases, {len(config['lanes'])} declared lanes")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lane", help="the lane whose floors to check")
    parser.add_argument("--reclaim", action="store_true", help="first remove superseded mcp-re images")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if not args.lane:
        parser.error("--lane is required (or --selftest)")
    return run_lane(args.lane, args.reclaim)


if __name__ == "__main__":
    sys.exit(main())
