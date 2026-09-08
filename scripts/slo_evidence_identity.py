#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SLO evidence identity — make a performance result content-addressed, twice over.

THE DEFECT. The SLO lane was the only evidence in this repository that was not
content-addressed. `.verification/attestations` are keyed on a fingerprint and are never
re-derived while their inputs are unchanged; `scripts/local_slo_lane.sh` re-measured
unconditionally. An unchanged tree object was therefore asked to prove itself twice, and
the second attempt failed on host contention — costing hours on a release with no code
delta at all.

THE CORRECTION, and why it is two identities rather than one.

A proof result is a theorem about the tree, so `(tree, toolchain)` identifies it completely.
A performance result is not that. It is a claim about a tree RUNNING ON SOMETHING, and the
something drifts underneath an unchanged source tree: kernels, container runtimes, and the
harness's own configuration. Keying a throughput number on the source alone would make an
old number permanently reusable, which is the opposite error to re-measuring every time.

    performance surface   the declared inputs in config/performance-surface.toml — serving
                          source, build configuration, harness, envelope, image definition.
                          A change here INVALIDATES the result.

    measurement context   hardware class, OS class, container-runtime class, CPU count and
                          the benchmark configuration. A different context does not
                          invalidate the old result: it means the old result answers a
                          different question, so this one must be measured.

Reuse requires all three of: same surface, same context, and a record no older than the
declared window. The decision always says which of the three failed, because "re-measure"
with no reason is how unconditional re-measurement comes back.

EVERY DECLARED INPUT MUST BE GIT-TRACKED, and this refuses an untracked one. A fingerprint
input outside the tree makes one commit fingerprint two ways depending on whose working copy
computed it — already a real defect in this repository once.

Run:  python3 scripts/slo_evidence_identity.py                 # validate the declaration
      python3 scripts/slo_evidence_identity.py --emit
      python3 scripts/slo_evidence_identity.py --decide        # 0 = REUSE, 10 = REMEASURE
      python3 scripts/slo_evidence_identity.py --record target/slo-local/rep1.json ...
      python3 scripts/slo_evidence_identity.py --selftest
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SURFACE_TOML = REPO / "config" / "performance-surface.toml"
STORE = REPO / ".verification" / "slo"
BASELINE = REPO / "docs" / "bench" / "adr-051-baseline-local.json"
SCHEMA = "mcp-re-slo-evidence/v1"

REUSE, REMEASURE = 0, 10

#: The surface sections, in the order they are folded. Named explicitly so that adding a
#: section to the TOML without adding it here cannot silently leave inputs unfingerprinted.
SECTIONS = ("source", "build_configuration", "harness", "envelope", "images")


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _tracked(paths: list[Path]) -> set[Path]:
    """The subset git tracks. One call, not one per file: this runs on ~400 paths."""
    listing = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "-z", "--", *[str(p.relative_to(REPO)) for p in paths]],
        capture_output=True,
        text=True,
        check=False,
    )
    return {REPO / name for name in listing.stdout.split("\0") if name}


def declared_inputs() -> list[Path]:
    """Every file the declaration names, expanded, sorted, deduplicated."""
    config = tomllib.loads(SURFACE_TOML.read_text(encoding="utf-8"))
    found: set[Path] = set()
    for section in SECTIONS:
        for entry in config["surface"][section]:
            target = REPO / entry
            if target.is_dir():
                found |= {p for p in target.rglob("*") if p.is_file()}
            elif target.is_file():
                found.add(target)
            else:
                raise SystemExit(f"error: config/performance-surface.toml declares {entry!r}, which does not exist")
    return sorted(found)


def performance_surface() -> tuple[str, dict[str, str]]:
    """`(fingerprint, {relative path: digest})` over every declared input."""
    inputs = declared_inputs()
    tracked = _tracked(inputs)
    untracked = sorted(str(p.relative_to(REPO)) for p in inputs if p not in tracked)
    if untracked:
        raise SystemExit(
            "error: these declared performance-surface inputs are NOT tracked by git:\n  "
            + "\n  ".join(untracked)
            + "\n       A fingerprint input outside the tree makes one commit fingerprint two ways."
        )
    digests = {str(p.relative_to(REPO)): _sha256(p.read_bytes()) for p in inputs}
    fold = "\n".join(f"{path} {digest}" for path, digest in sorted(digests.items()))
    return _sha256(fold.encode()), digests


def _docker_class() -> str:
    probe = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        return "absent"
    return "docker-" + ".".join(probe.stdout.strip().split(".")[:2])


def measurement_context() -> dict[str, object]:
    """The class the measurement is about — never the machine, and never a timestamp.

    A timestamp belongs to the RECORD, not to the identity: two runs an hour apart on the
    same box answer the same question, and freshness is adjudicated separately.
    """
    anchor = json.loads(BASELINE.read_text(encoding="utf-8"))["anchor"]["config"]
    return {
        "hardware_class": os.environ.get("MCP_RE_LOADGEN_HW_CLASS", anchor["hardware_class"]),
        "os_class": f"{platform.system()}-{platform.release().split('.')[0]}-{platform.machine()}",
        "container_runtime_class": _docker_class(),
        "cpu_count": os.cpu_count(),
        "concurrency": anchor["concurrency"],
        "requests": anchor["requests"],
        "connection_mode": anchor["connection_mode"],
        "declared_cores": 1,
    }


def context_digest(context: dict[str, object]) -> str:
    declared = tomllib.loads(SURFACE_TOML.read_text(encoding="utf-8"))["context"]["fields"]
    missing = [field for field in declared if field not in context]
    if missing:
        raise SystemExit(f"error: the context declares {missing} but the measurement supplies none")
    return _sha256(json.dumps({k: context[k] for k in sorted(declared)}, sort_keys=True).encode())


def stale(recorded: datetime, window_days: int, now: datetime) -> bool:
    """Age is adjudicated on its own, because the context is a CLASS and not a machine.

    "arm64, 14 cores, macOS 25" is the same class before and after a firmware update, a
    thermal-paste year, or a background daemon nobody declared. The window is what keeps an
    identity from meaning "forever".
    """
    return (now - recorded) > timedelta(days=window_days)


def record_path(surface: str, context: str) -> Path:
    return STORE / f"{surface.split(':')[1][:16]}-{context.split(':')[1][:16]}.json"


def decide(max_age_days: int | None) -> tuple[str, str, int]:
    """`(verdict, reason, exit code)`. The reason is the point: it names which half moved."""
    surface, _ = performance_surface()
    context = measurement_context()
    digest = context_digest(context)
    path = record_path(surface, digest)
    if not path.is_file():
        prior = sorted(STORE.glob("*.json")) if STORE.is_dir() else []
        same_surface = [
            p for p in prior
            if json.loads(p.read_text())["performance_surface"] == surface
        ]
        # Three different reasons, and they are not interchangeable: one says nothing has
        # ever been measured, one says the code moved, one says the box did.
        if not prior:
            why = "no attested result exists for any performance surface"
        elif not same_surface:
            why = "the declared performance surface has MOVED since the last attested result"
        else:
            why = ("the surface is attested, but in a DIFFERENT measurement context — "
                   "a result measured elsewhere answers a different question")
        return "REMEASURE", why, REMEASURE

    record = json.loads(path.read_text(encoding="utf-8"))
    window = tomllib.loads(SURFACE_TOML.read_text(encoding="utf-8"))["freshness"]["max_age_days"]
    window = window if max_age_days is None else max_age_days
    recorded = datetime.fromisoformat(record["recorded_utc"])
    now = datetime.now(timezone.utc)
    age = now - recorded
    if stale(recorded, window, now):
        return "REMEASURE", f"the attested result is {age.days} days old, past the {window}-day window", REMEASURE
    if record["verdict"] != "PASS":
        return "REMEASURE", f"the attested result for this identity is {record['verdict']}", REMEASURE
    return (
        "REUSE",
        f"attested {recorded.date()} ({age.days}d old): {record['verdict']}, "
        f"median {record['median_throughput_rps']:.1f} rps over {len(record['reps'])} rep(s)",
        REUSE,
    )


def record(report_paths: list[str], verdict: str) -> int:
    surface, digests = performance_surface()
    context = measurement_context()
    digest = context_digest(context)
    reps = []
    for path in report_paths:
        results = json.loads(Path(path).read_text(encoding="utf-8"))["results"]
        reps.append({
            "throughput_rps": results["throughput_rps"],
            "successes": results["successes"],
            "failures": results["failures"],
            "p99_added_us": results["added_latency_us"]["p99"],
        })
    if not reps:
        raise SystemExit("error: --record needs at least one report")
    rates = sorted(rep["throughput_rps"] for rep in reps)
    median = rates[len(rates) // 2] if len(rates) % 2 else (rates[len(rates) // 2 - 1] + rates[len(rates) // 2]) / 2
    STORE.mkdir(parents=True, exist_ok=True)
    path = record_path(surface, digest)
    path.write_text(
        json.dumps(
            {
                "schema": SCHEMA,
                "performance_surface": surface,
                "measurement_context": context,
                "measurement_context_digest": digest,
                "recorded_utc": datetime.now(timezone.utc).isoformat(),
                "verdict": verdict,
                "median_throughput_rps": median,
                "reps": reps,
                "surface_inputs": digests,
            },
            indent=1,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"recorded {verdict} for {surface[:23]}… / context {digest[:23]}… -> {path.relative_to(REPO)}")
    return 0


def check() -> int:
    """Validate the declaration and every stored record. No measurement, no Docker."""
    surface, digests = performance_surface()
    stored = sorted(STORE.glob("*.json")) if STORE.is_dir() else []
    bad = []
    for path in stored:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            bad.append(f"{path.name}: not JSON ({exc})")
            continue
        if doc.get("schema") != SCHEMA:
            bad.append(f"{path.name}: schema {doc.get('schema')!r}, expected {SCHEMA!r}")
        elif record_path(doc["performance_surface"], doc["measurement_context_digest"]).name != path.name:
            bad.append(f"{path.name}: filename does not derive from the identity it carries")
    for line in bad:
        print(f"  ✗ {line}")
    if bad:
        print(f"slo-evidence-identity: FAILED ({len(bad)} bad record(s))")
        return 1
    print(
        f"slo-evidence-identity: OK — {len(digests)} declared input(s), all git-tracked; "
        f"surface {surface[:23]}…; {len(stored)} attested result(s)"
    )
    return 0


def selftest() -> int:
    surface, digests = performance_surface()
    assert surface.startswith("sha256:") and digests, "the surface fold produced nothing"
    again, _ = performance_surface()
    assert again == surface, "the fold is not deterministic"

    # The fold must be sensitive to CONTENT, not merely to the file list: a fold over paths
    # alone would report an unchanged surface across every edit ever made to the code.
    perturbed = dict(digests)
    first = sorted(perturbed)[0]
    perturbed[first] = "sha256:" + "0" * 64
    fold = "\n".join(f"{p} {d}" for p, d in sorted(perturbed.items()))
    assert _sha256(fold.encode()) != surface, "the fold ignores content"

    context = {field: field for field in
               tomllib.loads(SURFACE_TOML.read_text(encoding="utf-8"))["context"]["fields"]}
    digest = context_digest(context)
    moved = dict(context, hardware_class="something-else")
    assert context_digest(moved) != digest, "the context digest ignores the hardware class"
    # A field the declaration does not name must not move the digest — otherwise every
    # incidental key an environment adds would silently force a re-measurement.
    assert context_digest(dict(context, unnamed="x")) == digest, "the context digest reads undeclared fields"
    try:
        context_digest({"hardware_class": "x"})
        raise AssertionError("a context missing declared fields was accepted")
    except SystemExit:
        pass

    now = datetime(2026, 9, 8, tzinfo=timezone.utc)
    assert not stale(now - timedelta(days=89), 90, now), "a record inside the window went stale"
    assert not stale(now - timedelta(days=90), 90, now), "the boundary day is inside the window"
    assert stale(now - timedelta(days=91), 90, now), "a record past the window stayed fresh"

    a = record_path("sha256:" + "a" * 64, "sha256:" + "b" * 64)
    assert a != record_path("sha256:" + "a" * 64, "sha256:" + "c" * 64), "one surface collapses two contexts"
    print(f"slo_evidence_identity selftest: OK — {len(digests)} declared inputs, 9 identity cases")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit", action="store_true", help="print the current identity")
    parser.add_argument("--decide", action="store_true", help="REUSE (0) or REMEASURE (10)")
    parser.add_argument("--record", nargs="+", metavar="REPORT", help="attest these reports at the current identity")
    parser.add_argument("--verdict", default="PASS", choices=("PASS", "FAIL", "INCONCLUSIVE"))
    parser.add_argument("--max-age-days", type=int, help="override the declared reuse window")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    if args.emit:
        surface, _ = performance_surface()
        context = measurement_context()
        print(json.dumps({"performance_surface": surface,
                          "measurement_context": context,
                          "measurement_context_digest": context_digest(context)}, indent=1, sort_keys=True))
        return 0
    if args.record:
        return record(args.record, args.verdict)
    if args.decide:
        verdict, reason, code = decide(args.max_age_days)
        print(f"SLO EVIDENCE: {verdict} — {reason}")
        return code
    return check()


if __name__ == "__main__":
    sys.exit(main())
