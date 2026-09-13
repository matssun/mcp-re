"""Controls for the durable SLO evidence store (A5.4).

THE DEFECT UNDER REPAIR. The store was `REPO/.verification/slo` -- inside the checkout. The
Actions workspace is cleaned between runs, so an authoritative PASS was written and then
destroyed, and the next run with an IDENTICAL performance-surface fingerprint answered
REMEASURE where it should have answered REUSE. The two-identity model of #845 was never
wrong; only its storage was, and these controls exist to keep that distinction.

The headline control is cross-checkout reuse: write a record from one checkout, destroy
that checkout, and read the record back from a SECOND clean one. A test that only round-
trips within a single directory cannot see the defect at all -- it re-reads whatever it
just wrote, which is exactly what the disposable store did successfully every time.

No test writes /opt. Everything is temp directories.

Run:  /opt/homebrew/bin/python3 tools/slo/test_evidence_store.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO / "scripts" / "slo_evidence_identity.py"
PYTHON = os.environ.get("MCP_RE_TEST_PYTHON", "/opt/homebrew/bin/python3")

PASSED: list[str] = []
FAILED: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    (PASSED if condition else FAILED).append(name)
    mark = "ok  " if condition else "FAIL"
    print(f"  {mark} {name}" + (f"  [{detail}]" if detail and not condition else ""))


def run(args: list[str], env_extra: dict[str, str], cwd: Path | None = None):
    env = {**os.environ, **env_extra}
    return subprocess.run([PYTHON, str(SCRIPT), *args], capture_output=True, text=True,
                          env=env, cwd=str(cwd or REPO))


def identity(env_extra: dict[str, str]) -> dict:
    got = run(["--emit"], env_extra)
    return json.loads(got.stdout)


# ==========================================================================================
# store resolution
# ==========================================================================================


def test_store_resolution() -> None:
    print("\nstore resolution (§10)")
    store = Path(tempfile.mkdtemp()) / "durable"

    # A developer with nothing configured keeps the in-checkout default.
    local = run(["--emit"], {})
    check("a local run works with no store configured", local.returncode == 0)

    # The authoritative Actions lane must NAME a durable store; no silent fallback.
    ci_env = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_WORKFLOW_REF": "matssun/mcp-re/" + ".github/workflows/slo.yml" + "@refs/heads/main",
        "GITHUB_WORKSPACE": str(REPO),
    }
    unset = dict(ci_env)
    unset.pop("MCP_RE_SLO_EVIDENCE_STORE", None)
    got = run(["--decide"], unset)
    check("CI with NO durable store configured is refused",
          got.returncode not in (0, 10) and "durable store" in got.stderr,
          f"rc={got.returncode} err={got.stderr[:120]}")

    # ...and a store INSIDE the disposable workspace is refused rather than accepted.
    inside = run(["--decide"], {**ci_env,
                                "MCP_RE_SLO_EVIDENCE_STORE": str(REPO / ".verification" / "slo")})
    check("CI with a store inside GITHUB_WORKSPACE is refused",
          "GITHUB_WORKSPACE" in inside.stderr,
          f"rc={inside.returncode} err={inside.stderr[:140]}")

    # A store outside the workspace is accepted (0 REUSE / 10 REMEASURE are both fine here).
    outside = run(["--decide"], {**ci_env, "MCP_RE_SLO_EVIDENCE_STORE": str(store)})
    check("CI with a durable store outside the workspace proceeds",
          outside.returncode in (0, 10), f"rc={outside.returncode} err={outside.stderr[:140]}")


# ==========================================================================================
# the headline control: survive checkout destruction
# ==========================================================================================


def test_cross_checkout_reuse() -> None:
    print("\ncross-checkout REUSE — the acceptance test for the persistence fix (§12)")
    tmp = Path(tempfile.mkdtemp())
    store = tmp / "durable-store"
    store.mkdir(parents=True)

    hw = {"MCP_RE_LOADGEN_HW_CLASS": "dev1-macos-arm64"}
    env = {**hw, "MCP_RE_SLO_EVIDENCE_STORE": str(store)}

    ident = identity(env)
    surface = ident["performance_surface"]

    # A PASS at the current identity.
    report = tmp / "rep1.json"
    report.write_text(json.dumps({"results": {
        "throughput_rps": 15282.6, "successes": 100000, "failures": 0,
        "added_latency_us": {"p99": 900}}}))
    recorded = run(["--record", str(report), "--verdict", "PASS"], env)
    check("a PASS record is written to the durable store", recorded.returncode == 0,
          recorded.stderr[:160])
    written = list(store.glob("*.json"))
    check("the record landed OUTSIDE any checkout", len(written) == 1,
          f"{len(written)} files in {store}")

    before = run(["--decide"], env)
    check("the same checkout reads REUSE", before.returncode == 0,
          f"rc={before.returncode}")

    # DESTROY the checkout's own store, standing in for the Actions workspace clean. If the
    # record lived there, everything after this point would say REMEASURE.
    disposable = REPO / ".verification" / "slo"
    shutil.rmtree(disposable, ignore_errors=True)
    check("the in-checkout store is gone", not disposable.exists())

    after = run(["--decide"], env)
    check("a CLEAN checkout still reads REUSE from the durable store",
          after.returncode == 0, f"rc={after.returncode} out={after.stdout[:160]}")

    # And prove the same decision is genuinely reading the durable file, not a cache: point
    # at an empty store and the same identity must flip to REMEASURE.
    empty = tmp / "empty-store"
    empty.mkdir()
    flipped = run(["--decide"], {**hw, "MCP_RE_SLO_EVIDENCE_STORE": str(empty)})
    check("an EMPTY durable store returns REMEASURE for the same identity",
          flipped.returncode == 10, f"rc={flipped.returncode}")

    return store, surface, hw


# ==========================================================================================
# the identity model is preserved, not weakened (§11)
# ==========================================================================================


def test_identity_still_governs(store: Path, surface: str, hw: dict) -> None:
    print("\nthe two-identity model still governs reuse (§11)")
    env = {**hw, "MCP_RE_SLO_EVIDENCE_STORE": str(store)}

    # A different measurement context answers a DIFFERENT question, so it must re-measure
    # even though the surface is untouched and a fresh PASS exists.
    other_ctx = run(["--decide"], {**env, "MCP_RE_LOADGEN_HW_CLASS": "github-hosted-ubuntu"})
    check("a changed measurement context REMEASUREs", other_ctx.returncode == 10,
          f"rc={other_ctx.returncode}")

    record = json.loads(next(iter(store.glob("*.json"))).read_text())

    # A non-PASS record is not reusable, whatever its freshness or identity.
    for verdict in ("FAIL", "INCONCLUSIVE"):
        path = next(iter(store.glob("*.json")))
        path.write_text(json.dumps({**record, "verdict": verdict}))
        got = run(["--decide"], env)
        check(f"a {verdict} record REMEASUREs", got.returncode == 10, f"rc={got.returncode}")
    path = next(iter(store.glob("*.json")))
    path.write_text(json.dumps(record))

    # A stale PASS is not reusable either.
    stale = {**record, "recorded_utc": "2020-01-01T00:00:00+00:00"}
    path.write_text(json.dumps(stale))
    got = run(["--decide"], env)
    check("a stale PASS REMEASUREs", got.returncode == 10, f"rc={got.returncode}")

    # A moved performance surface REMEASUREs: same box, different code.
    #
    # The identity is the record's PATH -- `record_path()` folds the surface and context
    # digests into the filename -- so a moved surface is a record stored under a name the
    # current identity does not resolve to. Rewriting the `performance_surface` FIELD does
    # NOT simulate that: the lookup never reads the field, finds the file by name anyway,
    # and correctly reports REUSE. Measured while writing this control, and worth stating
    # because "vary the field the mechanism actually consumes" is the whole trick here.
    stored = next(iter(store.glob("*.json")))
    moved_name = stored.with_name("b" * 16 + stored.name[16:])
    stored.rename(moved_name)
    got = run(["--decide"], env)
    check("a moved performance surface REMEASUREs", got.returncode == 10,
          f"rc={got.returncode}")
    moved_name.rename(stored)

    # ...and the body is not the identity, which is why the control above renames.
    tampered = {**record, "performance_surface": "sha256:" + "b" * 64}
    stored.write_text(json.dumps(tampered))
    got = run(["--decide"], env)
    check("a body/name mismatch is NOT what moves the identity — the path is",
          got.returncode == 0, f"rc={got.returncode}")
    stored.write_text(json.dumps(record))

    # A corrupt durable record must FAIL SAFELY rather than read as absent. "Absent" is a
    # legitimate REMEASURE; "unreadable" is a broken store and must not be silently
    # equivalent to it.
    path.write_text("{ this is not json")
    got = run(["--decide"], env)
    check("a corrupt durable record does not read as merely absent",
          got.returncode not in (0,), f"rc={got.returncode}")
    check("and it does not report REUSE", got.returncode != 0)


def main() -> int:
    print(f"evidence-store controls — python={PYTHON}, temp dirs only, /opt untouched")
    test_store_resolution()
    store, surface, hw = test_cross_checkout_reuse()
    test_identity_still_governs(store, surface, hw)
    total = len(PASSED) + len(FAILED)
    print(f"\n{'=' * 74}\nexecuted {total} checks: {len(PASSED)} passed, {len(FAILED)} failed")
    for name in FAILED:
        print(f"  FAILED: {name}")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    raise SystemExit(main())
