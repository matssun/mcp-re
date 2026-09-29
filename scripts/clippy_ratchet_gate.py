#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Clippy debt ratchet — the adopted lints run over production code, and counts may only fall.

ADR-MCPRE-061 §6.4, implementing the §6.5 rulings on C-4 and C-5.

# What this gate is, and why it is a gate

Six lints are adopted (ADR-MCPRE-061 §6.5). Five of them cannot be flipped to `deny` in one
step — they have 60, 69, 27, 164 and 124 production sites — so the gate switches them on
itself, over production targets only, and holds the per-crate count against
`config/clippy-debt.toml`:

    baseline 0 for a crate/lint -> any occurrence FAILS (this is `deny` with a better message)
    count above baseline        -> FAIL
    count below baseline        -> FAIL, demanding the baseline be lowered to lock the gain
    count at baseline           -> PASS

`unwrap_used` is at **0 across all production code**, measured, so it has no debt entry and
is denied at zero by the same rule. There is nothing to ratchet.

# Why not `//bazel:workspace_lints`

Because the Rust lint lane (`bazel build --config=lint //...`) runs over every target with
warnings as errors. A policy entry at `warn` is therefore a hard error, applied to *all*
targets, which includes the thousands of `unwrap`/`expect`/indexing sites in test code that
the ruling explicitly exempts. Landing the lints that way is the "turns the build red
immediately" failure C-8 named.

Running them here, over the production library and binary flavors only, exempts test code
by construction rather than by an allowlist somebody has to maintain, and makes the
production count a number instead of a wall of warnings. Every flavor that ships is linted
— default, `async_serve`, the external backends, the auditor — and a site is counted once
however many flavors compile it.

The cost is stated rather than hidden: the lint lane does not show these lints. The gate is
where they run, and `--activation-probe` proves they run there.

# Why not a per-crate `#![allow(...)]`

A crate-level allow silences the lint for the whole crate, including code written tomorrow.
The debt becomes invisible and unbounded. A count keeps every existing site visible and
makes the 61st site an error.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]

REPO = Path(__file__).resolve().parent.parent
REGISTRY = REPO / "config" / "clippy-debt.toml"

# The ADR-MCPRE-061 §6 thresholds, kept OUT of the repository's `/.clippy.toml`.
# `clippy::excessive_nesting` is warn-by-default with a default threshold of 5, so a value
# in the root config is enforced immediately by every `--all-targets -- -D warnings` lane —
# 164 production sites plus test code, red on the first commit. Handing the aspect this
# directory's `.clippy.toml` confines the strict thresholds to this gate's production lane.
STRICT_CONF = REPO / "config" / "clippy-strict"

# The adopted lint set (ADR-MCPRE-061 §6.5, C-4 and C-5). THIS is what switches them on:
# they are allow-by-default and deliberately absent from `[workspace.lints.clippy]`, because
# every clippy lane in this repo runs `--all-targets -- -D warnings` and a workspace entry
# would turn thousands of existing TEST-code occurrences into hard errors on one commit.
# The ruling exempts test code; running the lints here, over production flavors only,
# exempts it by construction rather than by an allowlist somebody has to maintain.
ADOPTED = (
    "unwrap_used",              # measured at 0 production sites -> denied at zero
    "expect_used",              # 60  -> ratcheted
    "indexing_slicing",         # 69  -> ratcheted
    "too_many_lines",           # 27  -> ratcheted
    "excessive_nesting",        # 164 -> ratcheted
    "arithmetic_side_effects",  # 124 -> ratcheted
    # ADR-MCPRE-061 Amendment 1 §3, Group B. Zero PRODUCTION sites in both the default
    # and the full CI feature lane, but NOT zero in test code — so these cannot be a
    # crate-level `#![deny]` the way the Group A lints are (that would be red under
    # every `--all-targets` lane). This gate's production-only measurement is exactly
    # the mechanism the §6.4 ruling built for that case, so they land here and are
    # denied at zero. They carry no debt entry, for the same reason `unwrap_used` does
    # not: there is nothing to pay off.
    "panic_in_result_fn",       # 0 -> denied at zero
    "exit",                     # 0 -> denied at zero
    "create_dir",               # 0 -> denied at zero
    "assertions_on_result_states",  # 0 -> denied at zero
    "partial_pub_fields",       # 0 -> denied at zero
)

# The lints carrying a debt baseline. Every ADOPTED lint NOT listed here is denied at
# zero — it has no entry in the registry because it has nothing to pay off, and the
# first occurrence fails the gate.
RATCHETED = (
    "expect_used",
    "indexing_slicing",
    "too_many_lines",
    "excessive_nesting",
    "arithmetic_side_effects",
)

# Deliberately NOT adopted; see §6.5.
#   cognitive_complexity — 7 sites, 6 already reported by too_many_lines, and the 7th only
#   because that lint is locally allowed there. Zero independent signal.

LINT_FLAGS = [f"-W clippy::{lint}".split()[i] for lint in ADOPTED for i in (0, 1)]


#: The Bazel label of the strict thresholds, handed to the clippy aspect. Every clippy run in
#: this file uses it with LINT_FLAGS, so a probe cannot vouch for a configuration the
#: measurement did not use.
STRICT_CONF_LABEL = "//config/clippy-strict:.clippy.toml"

#: Library flavors that are test support rather than something that ships: the pre-052
#: fixture, test-fixture, fault-injection and dev-env key-source builds. The ruling exempts
#: test code, and these flavors exist to compile it.
NOT_PRODUCTION = re.compile(r"_(pre052|test_fixtures|fault|dev_env)$")


def clippy_diagnostics(targets: list[str], root: Path = REPO) -> tuple[int, str, list[dict]]:
    """Lint `targets` with the adopted lints on, and return every diagnostic clippy wrote.

    The diagnostics are CAPTURED to a file per target (`clippy_output_diagnostics`) rather
    than read off the console, because a cached action prints nothing: a second run over an
    unchanged tree would otherwise report zero occurrences of everything.
    """
    flags = [f"--@rules_rust//rust/settings:clippy_flag={f}"
             for f in (f"-Wclippy::{lint}" for lint in ADOPTED)]
    proc = subprocess.run(
        ["bazel", "build", "--aspects=@rules_rust//rust:defs.bzl%rust_clippy_aspect",
         "--output_groups=clippy_output",
         f"--@rules_rust//rust/settings:clippy.toml={STRICT_CONF_LABEL}",
         "--@rules_rust//rust/settings:clippy_output_diagnostics=True",
         "--@rules_rust//rust/settings:clippy_error_format=json",
         *flags, *targets],
        cwd=root, capture_output=True, text=True,
    )
    diagnostics: list[dict] = []
    for target in targets:
        pkg, name = target[2:].split(":", 1)
        out = root / "bazel-bin" / pkg / f"{name}.clippy.diagnostics"
        if not out.is_file():
            continue
        for line in out.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                m = json.loads(line)
            except json.JSONDecodeError:
                continue
            if m.get("$message_type") == "diagnostic":
                diagnostics.append(m)
    return proc.returncode, proc.stderr, diagnostics


def production_targets(root: Path = REPO) -> list[str]:
    """Every library and binary flavor that ships."""
    proc = subprocess.run(
        ["bazel", "query", "--output=label",
         'kind("^(rust_library|rust_binary) rule$", //...) except attr(tags, "\\bmanual\\b", //...)'],
        cwd=root, capture_output=True, text=True,
    )
    return [t for t in proc.stdout.split() if t.startswith("//") and not NOT_PRODUCTION.search(t)]


def measure(root: Path) -> tuple[Counter, int]:
    """Run clippy over the production targets and count primary spans per (crate, lint).

    A site is counted ONCE however many flavors compile it, and only in a crate's `src/`:
    examples, `tests/` and the probes are not production code.

    Returns (counter keyed by "crate::lint", number of compiler messages seen).
    """
    targets = production_targets(root)
    if not targets:
        raise RuntimeError("the build graph holds no production Rust target — nothing measured")
    rc, stderr, diagnostics = clippy_diagnostics(targets, root)
    # A non-zero status means the tree DID NOT COMPILE, and a clippy run that could not
    # compile a target has not measured it — it reports zero occurrences of every lint in
    # it. The gate would then say "down to 0 from a baseline of 40 — lower the baseline",
    # which is the worst possible instruction: it would erase the debt register for code
    # nobody linted. LINT_FLAGS are all `-W`, so warnings alone never set a non-zero status.
    if rc != 0:
        errors = [ln for ln in stderr.splitlines() if ln.startswith(("error", "ERROR"))]
        raise RuntimeError(
            f"clippy did not compile the production targets, so it measured nothing "
            f"(exit {rc}). A partial build reports ZERO occurrences for every target it "
            f"could not lint.\n" + ("\n".join(errors[:20]) or stderr[-4000:] or "(no stderr)")
        )
    sites: set[tuple[str, int, int, str]] = set()
    for m in diagnostics:
        code = (m.get("code") or {}).get("code") or ""
        if not code.startswith("clippy::"):
            continue
        spans = [x for x in m.get("spans", []) if x.get("is_primary")]
        if not spans or not re.match(r"^[^/]+/src/", spans[0]["file_name"]):
            continue
        sites.add((spans[0]["file_name"], spans[0]["line_start"], spans[0]["column_start"],
                   code.split("::", 1)[1]))
    counts: Counter = Counter()
    for path, _, _, lint in sites:
        counts[f"{path.split('/')[0]}::{lint}"] += 1
    return counts, len(diagnostics)


def load_registry(path: Path) -> dict[str, int]:
    if not path.exists():
        return {}
    data = tomllib.loads(path.read_text())
    out: dict[str, int] = {}
    for entry in data.get("debt", []):
        out[f"{entry['crate']}::{entry['lint']}"] = int(entry["count"])
    return out


def compare(counts: Counter, baseline: dict[str, int]) -> list[str]:
    problems = []
    for key, n in sorted(counts.items()):
        lint = key.split("::", 1)[1]
        # Every ADOPTED lint is compared. A lint outside RATCHETED has no registry entry,
        # so `baseline.get` yields 0 below and the first occurrence fails — which is what
        # "denied at zero" means here. Skipping non-RATCHETED lints would silently make
        # every zero-debt adoption inert.
        if lint not in ADOPTED:
            continue
        allowed = baseline.get(key, 0)
        if n > allowed:
            crate, lint = key.split("::", 1)
            problems.append(
                f"{crate}: {n} `clippy::{lint}` in production code, baseline {allowed} — "
                f"the ratchet only turns one way"
            )
    for key, allowed in sorted(baseline.items()):
        if counts.get(key, 0) < allowed:
            crate, lint = key.split("::", 1)
            problems.append(
                f"{crate}: `clippy::{lint}` is down to {counts.get(key, 0)} from a baseline "
                f"of {allowed} — lower the baseline in {REGISTRY.name} to lock the gain in"
            )
    return problems


# --------------------------------------------------------------------------------------
# allow discipline


ALLOW_INNER = re.compile(r"#!\[allow\(([^)]*)\)\]")
ALLOW_OUTER = re.compile(r"#\[allow\(([^)]*)\)\]")
# `arithmetic-side-effects-allowed*` exempts whole TYPES from the lint everywhere.
CONF_EXEMPTION = re.compile(r"^\s*arithmetic-side-effects-allowed[a-z-]*\s*=")


def adopted_in(attr_body: str) -> list[str]:
    return [l for l in ADOPTED if f"clippy::{l}" in attr_body]


def allow_discipline(root: Path) -> tuple[list[str], int]:
    """An exception must be narrow and must name its invariant.

    The ratchet counts occurrences, so anything that suppresses the lint over a whole crate
    or module makes the count fall — and a falling count is a legitimate reason to lower the
    baseline. Without this check, `#![allow(clippy::arithmetic_side_effects)]` in a crate
    root is a one-line permanent exemption that the ratchet would report as progress.

    Three rules, from the C-4 ruling:

    - no crate- or module-wide allow of an adopted lint;
    - an item-level allow must carry a justification comment naming the invariant;
    - no `arithmetic-side-effects-allowed*` type exemption in the clippy config, which is
      global and unbounded.
    """
    problems: list[str] = []
    files = 0
    for p in sorted(root.rglob("*.rs")):
        rel = p.relative_to(root)
        if any(part in {"target", "node_modules", ".git", "tests", "benches", "examples"}
               for part in rel.parts):
            continue
        files += 1
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        for i, line in enumerate(lines):
            m = ALLOW_INNER.search(line)
            if m:
                for lint in adopted_in(m.group(1)):
                    problems.append(
                        f"{rel}:{i + 1}: `#![allow(clippy::{lint})]` is crate- or "
                        f"module-wide. Scope the exception to the item it was granted for; "
                        f"a wide allow covers code not yet written and hides it from the "
                        f"ratchet."
                    )
                continue
            m = ALLOW_OUTER.search(line)
            if not m:
                continue
            lints = adopted_in(m.group(1))
            if not lints:
                continue
            nxt = lines[i + 1].lstrip() if i + 1 < len(lines) else ""
            if nxt.startswith("mod ") or nxt.startswith("pub mod "):
                for lint in lints:
                    problems.append(
                        f"{rel}:{i + 1}: `#[allow(clippy::{lint})]` on a module applies to "
                        f"every item inside it, including future ones. Move it to the item "
                        f"that needs it."
                    )
                continue
            # A justification is a trailing comment, or a comment line just above.
            trailing = "//" in line[m.end():]
            above = i > 0 and lines[i - 1].lstrip().startswith("//")
            if not (trailing or above):
                for lint in lints:
                    problems.append(
                        f"{rel}:{i + 1}: `#[allow(clippy::{lint})]` carries no justification. "
                        f"State the invariant that makes the ordinary form safe — name the "
                        f"owning type, check or theorem, not merely \"cannot overflow\"."
                    )

    for conf in (root / ".clippy.toml", STRICT_CONF / ".clippy.toml"):
        if not conf.exists():
            continue
        for i, line in enumerate(conf.read_text().splitlines()):
            if CONF_EXEMPTION.match(line):
                problems.append(
                    f"{conf.relative_to(root)}:{i + 1}: an "
                    f"`arithmetic-side-effects-allowed*` type exemption is global and "
                    f"unbounded. The C-4 ruling declines it until a genuinely algebraic "
                    f"type is found for which the exception is universally true."
                )
    return problems, files


# --------------------------------------------------------------------------------------
# probes and selftest


def nesting_probe() -> int:
    """Negative control for the nesting rule: depth <= 2 accepted, depth > 2 rejected.

    Required by the C-5 ruling. A configured lint is not an enforced rule until something
    demonstrates it fires on the far side of the boundary and stays silent on the near
    side. Without this, `excessive-nesting-threshold` could be off by one — and it is
    off-by-one-shaped: the threshold names the depth that is REJECTED, so "deeper than
    two levels" is threshold 3, not 2.
    """
    threshold = 3
    for line in (STRICT_CONF / ".clippy.toml").read_text().splitlines():
        if line.strip().startswith("excessive-nesting-threshold"):
            threshold = int(line.split("=")[1].strip())
    rc, stderr, diagnostics = clippy_diagnostics(["//config/clippy-strict:nest_probe"])
    if rc != 0 or not diagnostics:
        print(f"nesting probe: FAIL — the probe did not build under the gate's flags, so it "
              f"measured nothing (exit {rc}).\n{stderr[-1500:]}")
        return 1
    flagged = {s["line_start"] for m in diagnostics
               if (m.get("code") or {}).get("code") == "clippy::excessive_nesting"
               for s in m.get("spans", []) if s.get("is_primary")}
    # `depth_two` spans lines 5-12 of probes/nest.rs, `depth_three` lines 14-23.
    two_flagged = any(5 <= ln <= 12 for ln in flagged)
    three_flagged = any(14 <= ln <= 23 for ln in flagged)

    if two_flagged:
        print(
            f"nesting probe: FAIL — depth 2 was rejected at "
            f"excessive-nesting-threshold = {threshold}. The rule is 'deeper than 2', "
            f"so depth 2 must be accepted."
        )
        return 1
    if not three_flagged:
        print(
            f"nesting probe: FAIL — depth 3 was NOT rejected at "
            f"excessive-nesting-threshold = {threshold}. The lint is configured but "
            f"enforces nothing; this is the inert-configuration failure ADR-MCPRE-061 "
            f"§6.1 exists to prevent."
        )
        return 1
    print(
        f"nesting probe: PASS — at excessive-nesting-threshold = {threshold}, "
        f"depth 2 accepted and depth 3 rejected (ADR-MCPRE-061 §6.5, C-5)."
    )
    return 0


def activation_probe() -> int:
    """Negative control for §6.1: prove the size/nesting lints are actually ENABLED.

    `.clippy.toml` sets thresholds; it does not switch on allow-by-default lints. Before
    this probe existed the project claimed a mechanically enforced 60-line function rule on
    the strength of `too-many-lines-threshold = 60` plus a `-D warnings` lint lane,
    and an 80-line function produced no warning at all.

    The probe compiles a file that violates the size and nesting rules under the EXACT flag
    list `measure()` uses, so it cannot drift from the gate it vouches for.
    """
    rc, stderr, diagnostics = clippy_diagnostics(["//config/clippy-strict:activation_probe"])
    if rc != 0 or not diagnostics:
        print(f"activation probe: FAIL — the probe did not build under the gate's flags, so "
              f"it measured nothing (exit {rc}).\n{stderr[-1500:]}")
        return 1
    fired = set()
    arithmetic_lines = []
    for m in diagnostics:
        code = (m.get("code") or {}).get("code") or ""
        if not code.startswith("clippy::"):
            continue
        lint = code.split("::", 1)[1]
        fired.add(lint)
        if lint == "arithmetic_side_effects":
            spans = [x for x in m.get("spans", []) if x.get("is_primary")]
            arithmetic_lines.append(spans[0]["line_start"] if spans else None)
    missing = [
        x for x in ("too_many_lines", "excessive_nesting", "arithmetic_side_effects")
        if x not in fired
    ]
    if missing:
        print(
            "activation probe: FAIL — a file violating the size, nesting and arithmetic "
            f"rules did not trigger {missing}. `.clippy.toml` sets thresholds but does "
            "not switch on allow-by-default lints. These lints are enabled by this "
            "gate's ADOPTED list, which becomes the `-W` flags in LINT_FLAGS — NOT by "
            "`[workspace.lints.clippy]`, which ADR-MCPRE-061 §6.2 rejects because every "
            "clippy lane here runs `--all-targets -- -D warnings` and a workspace entry "
            "would turn the exempt test-code sites into hard errors. Check ADOPTED, and "
            "check the thresholds in config/clippy-strict/.clippy.toml."
        )
        return 1
    # The exclusions matter as much as the hits: if the lint ever started reporting
    # saturating, wrapping, `Wrapping`, float or const arithmetic, the 124-site baseline
    # would stop meaning what ADR-MCPRE-061 §6.6 says it means.
    arith_spans = sum(
        1 for ln in arithmetic_lines if ln is not None
    )
    if arith_spans != 1:
        print(
            f"activation probe: FAIL — clippy::arithmetic_side_effects fired on "
            f"{arith_spans} of 6 arithmetic expressions; exactly one (the unconstrained "
            f"`x + 1`) should fire. Saturating, wrapping, `Wrapping`, float and const "
            f"arithmetic are excluded by the lint's definition, and ADR-MCPRE-061 §6.6 "
            f"relies on those exclusions for what a hit MEANS."
        )
        return 1
    print(
        "activation probe: PASS — a 70-line function, a depth-3 block and an "
        "unconstrained `x + 1` fired; saturating, wrapping, `Wrapping`, float and const "
        "arithmetic did not (ADR-MCPRE-061 §6.1, §6.6)."
    )
    return 0


def selftest() -> int:
    base = {"crate-a::expect_used": 5}

    if compare(Counter({"crate-a::expect_used": 5}), base):
        print("selftest FAIL: a crate at its baseline reported a problem")
        return 1
    if not any("only turns one way" in p
               for p in compare(Counter({"crate-a::expect_used": 6}), base)):
        print("selftest FAIL: growth past the baseline was not caught")
        return 1
    if not any("lower the baseline" in p
               for p in compare(Counter({"crate-a::expect_used": 3}), base)):
        print("selftest FAIL: an improvement did not demand a lower baseline")
        return 1
    # A lint with no baseline entry is denied at zero.
    at_base = {"crate-a::expect_used": 5}
    if not any("baseline 0" in p
               for p in compare(Counter({**at_base, "crate-b::indexing_slicing": 1}), base)):
        print("selftest FAIL: an unbaselined lint occurrence was not denied at zero")
        return 1
    # unwrap_used is deny-at-zero and must be caught even though it is not in RATCHETED.
    if not any("unwrap_used" in p
               for p in compare(Counter({**at_base, "crate-b::unwrap_used": 1}), base)):
        print("selftest FAIL: unwrap_used was not denied at zero")
        return 1
    # Lints outside the adopted set are ignored, not silently counted.
    if compare(Counter({**at_base, "crate-b::cognitive_complexity": 99}), base):
        print("selftest FAIL: a lint outside the adopted set was counted")
        return 1
    # A baseline the tree no longer reaches must be lowered, not silently accepted.
    if not any("lower the baseline" in p for p in compare(Counter(), base)):
        print("selftest FAIL: a vanished baseline entry was accepted")
        return 1

    # allow discipline
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        src = root / "probe" / "src"
        src.mkdir(parents=True)
        f = src / "lib.rs"

        f.write_text("#![allow(clippy::arithmetic_side_effects)]\nfn a() {}\n")
        if not any("crate- or module-wide" in p for p in allow_discipline(root)[0]):
            print("selftest FAIL: a crate-wide allow was accepted")
            return 1

        f.write_text("#[allow(clippy::unwrap_used)]\nmod inner {}\n")
        if not any("on a module" in p for p in allow_discipline(root)[0]):
            print("selftest FAIL: a module-scoped allow was accepted")
            return 1

        f.write_text("#[allow(clippy::expect_used)]\nfn a() {}\n")
        if not any("no justification" in p for p in allow_discipline(root)[0]):
            print("selftest FAIL: an unjustified item allow was accepted")
            return 1

        f.write_text("// bounded by FreshnessWindow::verifier_accepts_until\n"
                     "#[allow(clippy::expect_used)]\nfn a() {}\n")
        if allow_discipline(root)[0]:
            print(f"selftest FAIL: a justified item allow was rejected: "
                  f"{allow_discipline(root)[0]}")
            return 1

        f.write_text("#[allow(clippy::expect_used)] // invariant: checked in classify()\n"
                     "fn a() {}\n")
        if allow_discipline(root)[0]:
            print("selftest FAIL: a trailing-comment justification was rejected")
            return 1

        # A lint outside the adopted set is none of this gate's business.
        f.write_text("#![allow(clippy::collapsible_if)]\nfn a() {}\n")
        if allow_discipline(root)[0]:
            print("selftest FAIL: an unadopted lint's allow was policed")
            return 1

        # An empty scan must not read as clean.
        if allow_discipline(root / "nonexistent")[1] != 0:
            print("selftest FAIL: empty scan reported files")
            return 1

    print("clippy-ratchet gate selftest: PASS (at-baseline, growth, improvement, "
          "deny-at-zero for unbaselined and for unwrap_used, unadopted lint ignored; "
          "allow discipline: crate-wide, module-scoped, unjustified, both justified forms, "
          "unadopted lint, empty scan)")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    if "--nesting-probe" in sys.argv:
        return nesting_probe()
    if "--activation-probe" in sys.argv:
        return activation_probe()
    if "--emit-registry" in sys.argv:
        counts, _ = measure(REPO)
        print("# Emitted by scripts/clippy_ratchet_gate.py --emit-registry")
        for key, n in sorted(counts.items()):
            crate, lint = key.split("::", 1)
            if lint not in RATCHETED:
                continue
            print("\n[[debt]]")
            print(f'crate = "{crate}"')
            print(f'lint = "{lint}"')
            print(f"count = {n}")
        return 0

    discipline, scanned = allow_discipline(REPO)
    if scanned == 0:
        print("clippy-ratchet gate: FAIL — scanned 0 production Rust files for allow "
              "discipline. A scan that examined nothing is not a pass.")
        return 1
    if discipline:
        print(f"clippy-ratchet gate: FAIL — {len(discipline)} allow-discipline problem(s)")
        for p in discipline:
            print(f"  - {p}")
        return 1

    baseline = load_registry(REGISTRY)
    counts, messages = measure(REPO)
    if messages == 0:
        print("clippy-ratchet gate: FAIL — clippy produced no messages at all. A lane that "
              "compiled nothing is not a pass.")
        return 1

    problems = compare(counts, baseline)
    if problems:
        print(f"clippy-ratchet gate: FAIL — {len(problems)} problem(s)")
        for p in problems:
            print(f"  - {p}")
        return 1

    total = sum(n for k, n in counts.items() if k.split("::", 1)[1] in RATCHETED)
    at_zero = [l for l in ADOPTED if l not in RATCHETED]
    print(
        f"clippy-ratchet gate: OK — production library and binary flavors only. "
        f"Denied at zero: {', '.join('clippy::' + l for l in at_zero)}; "
        f"{total} baselined occurrence(s) of "
        f"{', '.join(RATCHETED)} across {len(baseline)} crate/lint entries, none grew. "
        f"Allow discipline: {scanned} file(s) scanned, no crate/module-wide or "
        f"unjustified exception."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
