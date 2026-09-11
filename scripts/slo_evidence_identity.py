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

THE DECLARED HARDWARE CLASSES live here too, in `[[context.class]]`. `hardware_class` is
the context field that decides WHICH QUESTION a number answers, so the vocabulary of legal
values, each class's own regression anchor, and whether a class may ever carry an absolute
production-SLO verdict are declared once and read by every consumer:
`scripts/adr051_slo_gate.py` resolves a report's anchor from it, `scripts/slo_gate.py`
resolves its refusal set from it, and `.github/workflows/slo.yml` resolves the class the
self-hosted runner measures as from it.

THE TRIGGER SET IS PART OF THE DECLARATION. `.github/workflows/slo.yml` is `paths:`-filtered,
and its filter and the declared surface are one dependency set written down twice. When the
surface grows past the filter the workflow does not go red — it stops running, and every
check stays green while nothing re-measures the changed serving path. `check()` therefore
refuses a filter narrower than the surface, on both the `pull_request` and `push` triggers.

Run:  python3 scripts/slo_evidence_identity.py                 # validate the declaration
      python3 scripts/slo_evidence_identity.py --emit
      python3 scripts/slo_evidence_identity.py --decide        # 0 = REUSE, 10 = REMEASURE
      python3 scripts/slo_evidence_identity.py --record target/slo-local/rep1.json ...
      python3 scripts/slo_evidence_identity.py --runner-class
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
#: Where a developer's records live when nothing else is configured. Inside the checkout,
#: which is right for a local run and WRONG for self-hosted Actions -- see evidence_store().
LOCAL_STORE = REPO / ".verification" / "slo"

#: The one authority naming the durable store. Named consistently with the existing
#: MCP_RE_LOADGEN_HW_CLASS convention in this file.
STORE_ENV = "MCP_RE_SLO_EVIDENCE_STORE"
BASELINE = REPO / "docs" / "bench" / "adr-051-baseline-local.json"
WORKFLOW = REPO / ".github" / "workflows" / "slo.yml"
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



def class_environment_digest(hardware_class: str) -> str:
    """A canonical digest of the class's declared environment.

    WHY THE CLASS NAME ALONE IS NOT ENOUGH.

    `hardware_class` distinguishes dev1-slo-v1 from its predecessor, which is what stops
    the old colima-db PASS being reused. It does NOT notice the declaration being edited
    underneath a stable name:

        environment A  -> PASS recorded under dev1-slo-v1
        edit [context.class.environment] in place
        environment B  -> preflight verifies B, name still dev1-slo-v1,
                          context digest unchanged -> A's PASS reused for B

    Folding this derived value into the context closes that path mechanically, so
    correctness does not depend on somebody remembering to bump v1 to v2. The human
    version in the name stays useful for reading; it is no longer load-bearing.

    The INDIVIDUAL fields are deliberately not copied into `measurement_context()`. The
    class declaration remains the one authority and this is a witness derived from it --
    restating the fields would create a second place they could drift.

    Canonical means sorted keys and fixed separators, so declaration key ORDER cannot move
    the digest: reordering a TOML table is not an environment change.
    """
    declared = tomllib.loads(SURFACE_TOML.read_text(encoding="utf-8"))["context"]["class"]
    entry = next((e for e in declared if e["name"] == hardware_class), None)
    environment = (entry or {}).get("environment") or {}
    canonical = json.dumps(environment, sort_keys=True, separators=(",", ":"))
    return _sha256(canonical.encode())


def measurement_context() -> dict[str, object]:
    """The class the measurement is about — never the machine, and never a timestamp.

    A timestamp belongs to the RECORD, not to the identity: two runs an hour apart on the
    same box answer the same question, and freshness is adjudicated separately.
    """
    anchor = json.loads(BASELINE.read_text(encoding="utf-8"))["anchor"]["config"]
    hardware_class = os.environ.get("MCP_RE_LOADGEN_HW_CLASS", anchor["hardware_class"])
    return {
        "hardware_class": hardware_class,
        # A witness derived from the class's own declaration, NOT a copy of its fields.
        # Without it, editing [context.class.environment] under a stable class name leaves
        # the identity unmoved and lets a PASS measured in the old environment be reused
        # in the new one.
        "hardware_class_environment_digest": class_environment_digest(hardware_class),
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




def _write_atomic(path: Path, text: str, encoding: str = "utf-8") -> None:
    """Write a durable record so a reader never observes a partial one.

    The store now outlives the process that writes it and is read by later, unrelated CI
    runs, so a truncated record is not a transient -- it is a permanently corrupt piece of
    evidence. `os.replace` is atomic within a filesystem, so a concurrent reader sees the
    old file or the new one.
    """
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    tmp.write_text(text, encoding=encoding)
    os.replace(tmp, path)


def is_authoritative_actions_slo() -> bool:
    """Is this the self-hosted Actions run of the SLO workflow itself?

    Identified by workflow IDENTITY rather than by a job title or a bare GITHUB_ACTIONS
    check, so that an unrelated workflow in CI keeps the ordinary developer default and
    only the authoritative lane is held to the durable-store requirement.
    """
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return False
    ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    return ref.split("@", 1)[0].endswith("/" + str(WORKFLOW.relative_to(REPO)))


def evidence_store() -> Path:
    """The one resolved SLO evidence-store path.

    WHY THIS IS NOT SIMPLY A CONSTANT
    =================================

    The store used to be `REPO/.verification/slo`, inside the checkout. On self-hosted
    Actions that directory is DISPOSABLE: the workspace is cleaned between runs, so a PASS
    was written and then destroyed, and the next run with an identical performance-surface
    fingerprint said REMEASURE where it should have said REUSE. The identity model was
    never wrong -- its storage was.

    Two callers, two correct answers, one authority:

        local developer run          -> REPO/.verification/slo   (the default)
        authoritative Actions SLO    -> whatever MCP_RE_SLO_EVIDENCE_STORE names, and it
                                        must be outside GITHUB_WORKSPACE

    The authoritative lane FAILS CLOSED rather than falling back. A silent fallback to the
    disposable path is precisely the defect being repaired: it would look like it worked,
    publish a record, and lose it -- indistinguishable from success until a later run
    re-measured for no reason.
    """
    configured = os.environ.get(STORE_ENV)
    store = Path(configured).expanduser() if configured else LOCAL_STORE
    if not is_authoritative_actions_slo():
        return store

    if not configured:
        raise SystemExit(
            f"error: the authoritative self-hosted SLO must name a durable store in "
            f"{STORE_ENV}. Refusing to write evidence into the Actions checkout, which is "
            f"cleaned between runs."
        )
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace:
        try:
            store.resolve().relative_to(Path(workspace).resolve())
        except ValueError:
            pass  # outside the workspace, which is what we require
        else:
            raise SystemExit(
                f"error: {STORE_ENV}={store} resolves INSIDE GITHUB_WORKSPACE "
                f"({workspace}), which Actions cleans between runs. A record written there "
                f"cannot survive to be reused."
            )
    return store


def record_path(surface: str, context: str) -> Path:
    return evidence_store() / f"{surface.split(':')[1][:16]}-{context.split(':')[1][:16]}.json"


def decide(max_age_days: int | None) -> tuple[str, str, int]:
    """`(verdict, reason, exit code)`. The reason is the point: it names which half moved."""
    surface, _ = performance_surface()
    context = measurement_context()
    digest = context_digest(context)
    path = record_path(surface, digest)
    if not path.is_file():
        store = evidence_store()
        prior = sorted(store.glob("*.json")) if store.is_dir() else []
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
    evidence_store().mkdir(parents=True, exist_ok=True)
    path = record_path(surface, digest)
    _write_atomic(path, 
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
    shown = path if not path.is_relative_to(REPO) else path.relative_to(REPO)
    print(f"recorded {verdict} for {surface[:23]}… / context {digest[:23]}… -> {shown}")
    return 0


#: The keys every `[[context.class]]` entry must carry. Named rather than inferred so that
#: a half-written entry fails here instead of at the gate that reads the missing key.
CLASS_KEYS = ("name", "kind", "slo_declarable", "regression_anchor", "github_actions_runner")


def hardware_classes() -> dict[str, dict[str, object]]:
    """The declared measurement contexts, by `hardware_class` value.

    The one vocabulary. `adr051_slo_gate.py` asks it which anchor a report may be compared
    against, `slo_gate.py` asks it which classes can never be an absolute SLO verdict, and
    the workflow asks it what the self-hosted runner measures as. A class absent from here
    is not an error in itself — an unrecognised class simply has no anchor and no
    declarability — but it is what those gates read instead of each keeping its own list.
    """
    declared = tomllib.loads(SURFACE_TOML.read_text(encoding="utf-8"))["context"]["class"]
    return {entry["name"]: entry for entry in declared}


def runner_class() -> str:
    """The class the self-hosted Actions runner measures as.

    Exactly one entry may claim it. The workflow reads this rather than restating the name,
    for the reason `config/ports.toml` exists: a literal in a second place is a fact that
    can drift, and a drifted class name would key a record to a context nobody declared.
    """
    claimed = [name for name, entry in hardware_classes().items() if entry["github_actions_runner"]]
    if len(claimed) != 1:
        raise SystemExit(
            f"error: exactly one [[context.class]] must set github_actions_runner = true; "
            f"{len(claimed)} do ({claimed})"
        )
    return claimed[0]


def class_defects() -> list[str]:
    """Shape problems in the declared class vocabulary."""
    declared = tomllib.loads(SURFACE_TOML.read_text(encoding="utf-8"))["context"]["class"]
    found: list[str] = []
    seen: set[str] = set()
    for entry in declared:
        missing = [key for key in CLASS_KEYS if key not in entry]
        if missing:
            found.append(f"[[context.class]] {entry.get('name', '?')!r} is missing {missing}")
            continue
        name = entry["name"]
        if name in seen:
            found.append(f"[[context.class]] declares {name!r} twice")
        seen.add(name)
        if not entry["slo_declarable"] and not entry.get("reason"):
            found.append(f"{name!r} is not slo_declarable and states no reason")
        anchor = entry["regression_anchor"]
        if anchor and not (REPO / anchor).is_file():
            found.append(f"{name!r} names regression_anchor {anchor!r}, which does not exist")
        elif anchor:
            anchor_class = json.loads((REPO / anchor).read_text(encoding="utf-8"))["anchor"]["config"]["hardware_class"]
            if anchor_class != name:
                found.append(
                    f"{name!r} names an anchor recorded on hardware_class {anchor_class!r} — "
                    f"an anchor for a class must be a measurement of that class"
                )
    claimed = [entry["name"] for entry in declared if entry.get("github_actions_runner")]
    if len(claimed) != 1:
        found.append(f"exactly one class must set github_actions_runner = true; {claimed} do")
    return found


def trigger_defects() -> list[str]:
    """Declared surface inputs the SLO workflow's `paths:` filters do not cover.

    The GitHub path-matching semantics come from `verification_trigger_gate.py` rather than
    from a second copy here: `**` crosses a separator and `*` does not, and two
    implementations of that rule are two chances to accept a filter narrower than GitHub
    actually applies. Imported inside the function so that the ordinary identity commands
    stay dependency-free.
    """
    if not WORKFLOW.is_file():
        return [f"{WORKFLOW.relative_to(REPO)} does not exist — the declared surface has no lane"]
    sys.path.insert(0, str(REPO / "scripts"))
    from verification_trigger_gate import glob_matches, trigger_paths  # noqa: PLC0415

    triggers = trigger_paths(WORKFLOW.read_text(encoding="utf-8"))
    inputs = [str(path.relative_to(REPO)) for path in declared_inputs()]
    found: list[str] = []
    for trigger in ("pull_request", "push"):
        patterns = triggers.get(trigger)
        if patterns is None:
            found.append(f"{WORKFLOW.name} declares no `{trigger}` trigger")
            continue
        if not patterns:
            continue  # no `paths:` filter at all means every change triggers it
        uncovered = [p for p in inputs if not any(glob_matches(g, p) for g in patterns)]
        found.extend(
            f"{trigger}: no path filter matches {path!r}, which is a declared performance-"
            f"surface input — a change to it would move the surface with nothing re-measuring"
            for path in uncovered[:5]
        )
        if len(uncovered) > 5:
            found.append(f"{trigger}: …and {len(uncovered) - 5} more uncovered surface input(s)")
    return found


def check() -> int:
    """Validate the declaration and every stored record. No measurement, no Docker."""
    surface, digests = performance_surface()
    store = evidence_store()
    stored = sorted(store.glob("*.json")) if store.is_dir() else []
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
    bad.extend(class_defects())
    bad.extend(trigger_defects())
    for line in bad:
        print(f"  ✗ {line}")
    if bad:
        print(f"slo-evidence-identity: FAILED ({len(bad)} defect(s))")
        return 1
    classes = hardware_classes()
    anchored = sum(1 for entry in classes.values() if entry["regression_anchor"])
    print(
        f"slo-evidence-identity: OK — {len(digests)} declared input(s), all git-tracked; "
        f"surface {surface[:23]}…; {len(stored)} attested result(s); {len(classes)} declared "
        f"hardware class(es), {anchored} anchored; the {WORKFLOW.name} trigger set covers "
        f"every surface input on both triggers"
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

    # The class vocabulary. The runner's class must resolve to exactly one name, and a class
    # that claims an anchor must claim one measured on ITSELF — the cross-class comparison
    # `adr051_slo_gate.py` now refuses is the same error one level up, made in the
    # declaration instead of in the gate.
    classes = hardware_classes()
    assert classes, "the declaration names no hardware class"
    assert runner_class() in classes, "the runner's class is not declared"
    assert not classes[runner_class()]["slo_declarable"], (
        "a co-located self-hosted runner was declared able to carry an absolute SLO verdict"
    )
    assert not class_defects(), f"the declared classes are malformed: {class_defects()}"

    # The trigger check must be sensitive to a NARROWER filter, not merely parse one: a
    # coverage check that passes on every input it is handed reports OK for having compared
    # nothing. Run against the real matcher with a filter that covers one input only.
    sys.path.insert(0, str(REPO / "scripts"))
    from verification_trigger_gate import glob_matches  # noqa: PLC0415

    assert glob_matches("mcp-re-proxy/src/**", "mcp-re-proxy/src/app.rs"), "`**` stopped matching"
    assert not glob_matches("mcp-re-proxy/*", "mcp-re-proxy/src/app.rs"), "`*` crossed a separator"
    assert not trigger_defects(), f"the SLO workflow's trigger set is narrower than the surface: {trigger_defects()}"

    print(
        f"slo_evidence_identity selftest: OK — {len(digests)} declared inputs, 9 identity "
        f"cases, {len(classes)} hardware classes, trigger coverage on both triggers"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit", action="store_true", help="print the current identity")
    parser.add_argument("--decide", action="store_true", help="REUSE (0) or REMEASURE (10)")
    parser.add_argument("--record", nargs="+", metavar="REPORT", help="attest these reports at the current identity")
    parser.add_argument("--verdict", default="PASS", choices=("PASS", "FAIL", "INCONCLUSIVE"))
    parser.add_argument("--max-age-days", type=int, help="override the declared reuse window")
    parser.add_argument("--runner-class", action="store_true",
                        help="print the hardware_class the self-hosted Actions runner measures as")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    if args.runner_class:
        print(runner_class())
        return 0
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
