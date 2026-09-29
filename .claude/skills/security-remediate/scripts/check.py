"""check.py — the worker's whole gate, and its journal events, in ONE call per phase.

(Invoked as `python3 check.py …`; no shebang — see reduce.py for why.)

WHY: the lane used to hand the worker its gate as prose with placeholders —
"<the nearest enclosing package src root>", "<//the/owning/tree/...>",
"<basename>" — plus four numbered steps. Each worker re-derived the paths, ran
prescan, pyright and `bazel_gate.py` as separate turns, read each output back,
then appended `fix`, `gate` and possibly `gate-failed` by hand. All of that is
mechanical, and every turn re-sent the agent's whole context.

Two phases, because a baseline is only honest if it is taken BEFORE the edit:

  pre   ensure a bazel baseline exists for every tree this file's gate will run
        (the owning tree; plus the dependents' trees at the `wide` tier). The
        worker holds the single-writer lane, so the tree is exactly "everything
        the lane has landed so far" — which is the right baseline. The previous
        instruction ("if no-baseline, run `baseline` first, then check") ran
        AFTER the edit, so any failure the edit caused was recorded as baseline
        debt and could never show up as `new-failures`.

  post  append `fix` with the worker's counts, then run
          1. prescan over every touched file's src root — only hits naming a
             touched or related file are reported; the rest of the root is not
             this change's business
          2. Python: whole-repo pyright (`wide`/`platform`), error count vs the
             baseline, and `bazel_gate.py check` per tree.
             Rust: `cargo_gate.py` — clippy in every lane that compiles the file
             (plus the related files' crates above `local`), the module-size gate,
             the file's own unit tests and any `--it` integration test.
        and append `gate` (plus `gate-failed` when a gate BLAMES the change).
        Prints one verdict: new-failures > infra > no-baseline > ok. On
        new-failures the change is saved as a patch and reverted, so the next
        writer starts on a tree whose failures are its own.

  Rust `pre` stores no baseline: the lane starts on a tree `batch_gate.py`
  measured green and every writer leaves it green or reverted. It refuses when
  the file already carries uncommitted changes, which would make the diff under
  judgment more than this change.

What it does NOT do: regenerate barrels (it cannot tell whether an export
changed), or judge whether a prescan hit predates the change. Both stay with the
worker, and the prescan hits are printed for exactly that reason.

Usage:
  check.py pre  --file F --tier local|wide --store <gates> [--related a,b]
  check.py post --file F --tier local|wide --store <gates> --log <progress> \\
                --attempt A --run R --work-dir <dir> \\
                --applied N --not-applied N --tests-added N \\
                [--touched a,b] [--related a,b] [--model M] [--epoch E] \\
                [--pyright-baseline-errors 0]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bazel_gate  # noqa: E402
import cargo_gate  # noqa: E402
import progress  # noqa: E402

GATE_SCRIPT = os.path.join(HERE, "bazel_gate.py")
PRESCAN_SCRIPT = os.path.join(HERE, "prescan.py")
PYRIGHT_SUMMARY = re.compile(r"(\d+) errors?, (\d+) warnings?")
# Worst first. `no-baseline` outranks `ok` because an unmeasured tree is not a pass.
RANK = {"new-failures": 0, "infra": 1, "no-baseline": 2, "ok": 3, "not-run": 4}


def _ids(spec: str) -> list[str]:
    return [x.strip() for x in (spec or "").split(",") if x.strip()]


def src_root(path: str) -> str | None:
    parts = path.split("/")
    return "/".join(parts[:parts.index("src") + 1]) if "src" in parts else None


def owning_tree(path: str) -> str:
    """`//<component root>/...` — the parent of `src`, else the file's directory."""
    parts = path.split("/")
    root = "/".join(parts[:parts.index("src")]) if "src" in parts else os.path.dirname(path)
    return "//%s/..." % root


def trees_for(a) -> list[str]:
    """Owning tree always; the dependents' trees too at `wide` (CLAUDE.md rule 15:
    a changed dependency-facing declaration is judged by what binds to it)."""
    files = [a.file] + (_ids(a.related) if a.tier != "local" else [])
    out: list[str] = []
    for f in files:
        t = owning_tree(f)
        if t not in out:
            out.append(t)
    return out


def _slug(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:10]


def _run_json(cmd: list[str], env: dict | None = None) -> tuple[int, dict, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    doc: dict = {}
    # The whole stdout, else its trailing JSON object if the tool printed prose
    # first. An unparseable result stays `{}`, which every caller reads as infra.
    for cand in (p.stdout, (re.search(r"(\{.*\})\s*$", p.stdout, re.S) or [None, ""])[1]):
        try:
            doc = json.loads(cand)
            break
        except (ValueError, TypeError):
            continue
    return p.returncode, doc, (p.stderr or "")[-600:]


def _dirty(paths: list[str]) -> list[str]:
    p = subprocess.run(["git", "status", "--porcelain", "--", *paths], capture_output=True, text=True)
    return [ln[3:] for ln in p.stdout.splitlines() if ln.strip()]


def cmd_pre(a) -> int:
    if a.file.endswith(".rs"):
        # No stored baseline for Rust: the lane starts on a tree batch_gate.py
        # measured green and every writer leaves it green or reverted. What `pre`
        # must establish is that the diff `post` judges will be this change alone.
        dirty = _dirty([a.file])
        print(json.dumps({"phase": "pre", "lang": "rust", "dirty_before_edit": dirty}, indent=1))
        return 1 if dirty else 0
    rows = []
    for t in trees_for(a):
        # The store layout is `bazel_gate`'s contract; ask it rather than restate it.
        bpath = bazel_gate._store_path(a.store, t, "baseline")
        if os.path.exists(bpath):
            rows.append({"tree": t, "baseline": "exists", "path": bpath})
            continue
        rc, doc, err = _run_json([sys.executable, a.gate_script, "baseline", "--tree", t,
                                  "--store", a.store])
        ok = rc == 0 and os.path.exists(bpath)
        rows.append({"tree": t, "baseline": "captured" if ok else "FAILED", "exit": rc,
                     "failing": doc.get("failing"), "total": doc.get("total"),
                     "infra_suspected": doc.get("infra_suspected"),
                     **({"stderr_tail": err} if not ok else {})})
    print(json.dumps({"phase": "pre", "trees": rows}, indent=1))
    return 0 if all(r["baseline"] != "FAILED" for r in rows) else 1


def _prescan(a, touched: list[str], related: list[str]) -> dict:
    watch = set(touched) | set(related) | {a.file}
    roots = sorted({r for r in (src_root(f) for f in touched) if r})
    hits, exits = [], {}
    for root in roots:
        out = os.path.join(a.work_dir, "prescan-%s.json" % _slug(root))
        p = subprocess.run([sys.executable, a.prescan_script, root, "--json", out],
                           capture_output=True, text=True)
        exits[root] = p.returncode
        try:
            doc = json.load(open(out, encoding="utf-8"))
        except (OSError, ValueError):
            hits.append({"root": root, "error": "prescan wrote no JSON (exit %d)" % p.returncode})
            continue
        for f in doc.get("findings", []):
            rel = os.path.join(root, f["file"]) if f.get("file") else None
            if rel in watch:
                hits.append({"file": rel, "line": f.get("line"), "kind": f.get("kind"),
                             "severity": f.get("severity"), "symbol": f.get("symbol")})
    return {"roots": roots, "exits": exits, "hits": hits,
            "state": "clean" if not hits else "hits"}


def _pyright(a) -> dict:
    log = os.path.join(a.work_dir, "pyright-%s.log" % _slug(a.file))
    env = dict(os.environ, NODE_OPTIONS="--max-old-space-size=12288")
    with open(log, "w", encoding="utf-8") as fh:
        p = subprocess.run(a.pyright_cmd.split(), stdout=fh, stderr=subprocess.STDOUT, env=env)
    text = open(log, encoding="utf-8", errors="replace").read()
    m = None
    for m in PYRIGHT_SUMMARY.finditer(text):
        pass
    if m is None:
        # No summary line at all: exit 250 is the node heap OOM, which reads like
        # "clean" if only the exit code or the tail is inspected.
        return {"verdict": "infra", "exit": p.returncode, "log": log,
                "why": "no pyright summary line (heap OOM or crash) — NOT a clean run"}
    errors, warnings = int(m.group(1)), int(m.group(2))
    verdict = "new-failures" if errors > a.pyright_baseline_errors else "ok"
    detail = [ln.strip() for ln in text.splitlines() if " - error:" in ln][:20] \
        if verdict != "ok" else []
    return {"verdict": verdict, "exit": p.returncode, "errors": errors, "warnings": warnings,
            "baseline_errors": a.pyright_baseline_errors, "log": log, "errors_head": detail}


def _bazel(a, tree: str) -> dict:
    rc, doc, err = _run_json([sys.executable, a.gate_script, "check", "--tree", tree,
                              "--store", a.store])
    v = doc.get("verdict") or "infra"
    return {"tree": tree, "verdict": v, "exit": rc,
            "new_failures": doc.get("new_failures", []),
            "executed": doc.get("executed"), "total": doc.get("total"),
            "infra_errors": doc.get("infra_errors", [])[:3],
            "note": ("no test targets ran — this tree's bazel half measured nothing"
                     if v == "infra" and not doc.get("total") else ""),
            **({"stderr_tail": err} if v == "infra" and err else {})}


def _revert(touched: list[str], work_dir: str) -> str:
    """Save the change as a patch, then return the touched paths to HEAD.

    A red change left in the tree makes the next writer's gate fail on it, and the
    lane's attribution — one writer, so a failure is that writer's — collapses. The
    patch keeps the work; the tree goes back to the state the next writer expects.
    """
    patch = os.path.join(work_dir, "gate-failed-%s.patch" % _slug(",".join(touched)))
    tracked = subprocess.run(["git", "ls-files", "--", *touched], capture_output=True,
                             text=True).stdout.split()
    with open(patch, "w", encoding="utf-8") as fh:
        fh.write(subprocess.run(["git", "diff", "HEAD", "--", *tracked], capture_output=True,
                                text=True).stdout)
        for f in touched:
            if f not in tracked and os.path.isfile(f):
                fh.write("\n# untracked %s\n" % f + open(f, encoding="utf-8", errors="replace").read())
    if tracked:
        subprocess.run(["git", "checkout", "HEAD", "--", *tracked], check=False)
    for f in touched:
        if f not in tracked and os.path.isfile(f):
            os.remove(f)
    return patch


def cmd_post(a) -> int:
    os.makedirs(a.work_dir, exist_ok=True)
    touched = _ids(a.touched) or [a.file]
    related = _ids(a.related)
    common = dict(log=a.log, file=a.file, role="worker", attempt=a.attempt, run=a.run,
                  epoch=a.epoch, tier="", model=a.model, work_ids="", escalation_ids="",
                  finding_ids="", ruling="", reject_causes="", evidence_ref="")

    progress.cmd_append(argparse.Namespace(
        **common, event="fix",
        counts="applied=%d,not_applied=%d,tests_added=%d" % (a.applied, a.not_applied, a.tests_added),
        note=(a.note or "")))

    pre = _prescan(a, touched, related)
    parts: list[dict] = []
    if a.file.endswith(".rs"):
        parts = cargo_gate.gate(a.file, related if a.tier != "local" else [], _ids(a.it), a.work_dir)
    else:
        if a.tier != "local":
            parts.append(dict(_pyright(a), gate="pyright"))
        for t in trees_for(a):
            parts.append(dict(_bazel(a, t), gate="bazel"))
    verdict = min((p["verdict"] for p in parts), key=lambda v: RANK.get(v, 1)) if parts else "not-run"
    raw_exit = max((p.get("exit") or 0 for p in parts), default=0)

    def summary(p: dict) -> str:
        if p["gate"] in ("clippy", "test", "module-size", "cargo"):
            what = p.get("lane") or p.get("target") or ""
            bad = p.get("errors_head") or p.get("failed") or p.get("head") or p.get("why") or ""
            return "%s%s %s%s" % (p["gate"], (":" + what) if what else "", p["verdict"],
                                  (" — " + str(bad)[:200]) if bad and p["verdict"] != "ok" else "")
        if p["gate"] == "pyright":
            return "pyright %s (%s errors vs %s)" % (p["verdict"], p.get("errors", "?"),
                                                      p.get("baseline_errors"))
        tail = (" new: " + ",".join(p["new_failures"][:5])) if p["new_failures"] else ""
        return "bazel %s %s%s%s" % (p["tree"], p["verdict"], tail,
                                    (" — " + p["note"]) if p.get("note") else "")

    note = "; ".join(summary(p) for p in parts) + "; prescan %s" % (
        pre["state"] if pre["state"] == "clean" else "%d hit(s)" % len(pre["hits"]))
    progress.cmd_append(argparse.Namespace(**common, event="gate",
                                           counts="exit=%d" % raw_exit, note=note))
    reverted = None
    if verdict == "new-failures":
        if not a.keep_on_fail:
            reverted = _revert(touched, a.work_dir)
            note += "; reverted, patch %s" % reverted
        # The reviewer is skipped on a red tree, so the worker owns the terminal
        # event. Emitting nothing here is how two tick-1 files were reported lost.
        progress.cmd_append(argparse.Namespace(**common, event="gate-failed",
                                               counts="exit=%d" % raw_exit,
                                               note="new-failures: " + note))

    print(json.dumps({"phase": "post", "gate_verdict": verdict, "gate_exit": raw_exit,
                      "gates": parts, "prescan": pre,
                      "terminal_event": "gate-failed" if verdict == "new-failures" else None,
                      "reverted_patch": reverted},
                     indent=1))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("pre", cmd_pre), ("post", cmd_post)):
        p = sub.add_parser(name)
        p.add_argument("--file", required=True)
        p.add_argument("--tier", required=True, choices=["local", "wide", "platform"])
        p.add_argument("--store", required=True)
        p.add_argument("--related", default="", help="comma-separated importers (wide: their trees are gated too)")
        p.add_argument("--gate-script", default=GATE_SCRIPT, help=argparse.SUPPRESS)
        p.set_defaults(fn=fn)
        if name == "post":
            p.add_argument("--log", required=True)
            p.add_argument("--attempt", required=True)
            p.add_argument("--run", required=True)
            p.add_argument("--work-dir", required=True, help="where logs and prescan JSON go")
            p.add_argument("--applied", type=int, required=True)
            p.add_argument("--not-applied", type=int, required=True)
            p.add_argument("--tests-added", type=int, required=True)
            p.add_argument("--touched", default="", help="comma-separated files edited (default: --file)")
            p.add_argument("--model", default="")
            p.add_argument("--epoch", default="")
            p.add_argument("--note", default="", help="one line for the `fix` event")
            p.add_argument("--pyright-baseline-errors", type=int, default=0)
            p.add_argument("--it", default="", help="Rust: integration test targets the package named")
            p.add_argument("--keep-on-fail", action="store_true",
                           help="leave a new-failures change in the tree instead of reverting it")
            p.add_argument("--pyright-cmd", default=".venv/bin/pyright", help=argparse.SUPPRESS)
            p.add_argument("--prescan-script", default=PRESCAN_SCRIPT, help=argparse.SUPPRESS)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
