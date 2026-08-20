#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Clippy debt ratchet — the adopted lints run over production code, and counts may only fall.

ADR-MCPRE-061 §6.4, implementing the §6.5 rulings on C-4 and C-5.

# What this gate is, and why it is a gate

Four of the five adopted lints cannot be flipped to `deny` in one step: they have 60, 69,
27 and 164 production sites. So the gate switches them on itself, over production targets
only, and holds the per-crate count against `config/clippy-debt.toml`:

    baseline 0 for a crate/lint -> any occurrence FAILS (this is `deny` with a better message)
    count above baseline        -> FAIL
    count below baseline        -> FAIL, demanding the baseline be lowered to lock the gain
    count at baseline           -> PASS

`unwrap_used` is at **0 across all production code**, measured, so it has no debt entry and
is denied at zero by the same rule. There is nothing to ratchet.

# Why not `[workspace.lints.clippy]`

Because every clippy lane in this repository — `scripts/local_gate.sh` and four `ci.yml`
invocations — runs `--all-targets -- -D warnings`. A workspace-level entry at `warn` is
therefore a hard error in CI, applied to *all* targets, which includes the thousands of
`unwrap`/`expect`/indexing sites in test code that the ruling explicitly exempts. Landing
the lints that way is the "turns the build red immediately" failure C-8 named.

Running them here, over `--lib --bins`, exempts test code by construction rather than by an
allowlist somebody has to maintain, and makes the production count a number instead of a
wall of warnings.

The cost is stated rather than hidden: a bare `cargo clippy` does not show these five
lints. The gate is where they run, and `--activation-probe` proves they run there.

# Why not a per-crate `#![allow(...)]`

A crate-level allow silences the lint for the whole crate, including code written tomorrow.
The debt becomes invisible and unbounded. A count keeps every existing site visible and
makes the 61st site an error.
"""

from __future__ import annotations

import json
import os
import shutil
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
# 164 production sites plus test code, red on the first commit. Pointing CLIPPY_CONF_DIR
# here confines the strict thresholds to this gate's production-only lane.
STRICT_CONF = REPO / "config" / "clippy-strict"

# The adopted lint set (ADR-MCPRE-061 §6.5, C-4 and C-5). THIS is what switches them on:
# they are allow-by-default and deliberately absent from `[workspace.lints.clippy]`, because
# every clippy lane in this repo runs `--all-targets -- -D warnings` and a workspace entry
# would turn thousands of existing TEST-code occurrences into hard errors on one commit.
# The ruling exempts test code; running the lints here, over `--lib --bins`, exempts it by
# construction rather than by an allowlist somebody has to maintain.
ADOPTED = (
    "unwrap_used",          # measured at 0 production sites -> denied at zero
    "expect_used",          # 60 -> ratcheted
    "indexing_slicing",     # 69 -> ratcheted
    "too_many_lines",       # 27 -> ratcheted
    "excessive_nesting",    # 164 -> ratcheted
)

# `unwrap_used` is absent: it is denied at zero and carries no debt entry.
RATCHETED = ("expect_used", "indexing_slicing", "too_many_lines", "excessive_nesting")

# Deliberately NOT adopted; see §6.5.
#   arithmetic_side_effects — 124 sites, returned for a ruling
#   cognitive_complexity    — 7 sites, 6 already reported by too_many_lines

LINT_FLAGS = [f"-W clippy::{lint}".split()[i] for lint in ADOPTED for i in (0, 1)]


def strict_env() -> dict:
    """The process environment with clippy's config directory pointed at the strict
    thresholds. Every clippy invocation in this file uses it, so a probe cannot vouch for
    a configuration the measurement did not use."""
    env = dict(os.environ)
    env["CLIPPY_CONF_DIR"] = str(STRICT_CONF)
    return env


def cargo() -> list[str]:
    """The pinned toolchain. Homebrew's `cargo` shadows rustup on this machine and
    ignores `rust-toolchain.toml`, so the channel is named explicitly."""
    channel = "1.97.1"
    tc = REPO / "rust-toolchain.toml"
    if tc.exists():
        for line in tc.read_text().splitlines():
            if line.strip().startswith("channel"):
                channel = line.split("=")[1].strip().strip('"')
                break
    if shutil.which("rustup"):
        return ["rustup", "run", channel, "cargo"]
    return ["cargo"]


def measure(root: Path, extra_args: list[str] | None = None) -> tuple[Counter, int]:
    """Run clippy over production targets and count primary spans per (crate, lint).

    Returns (counter keyed by "crate::lint", number of compiler messages seen).
    """
    cmd = cargo() + [
        "clippy", "--workspace", "--lib", "--bins",
        "--message-format=json", "--quiet",
    ] + (extra_args or []) + ["--"] + LINT_FLAGS
    proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, env=strict_env())
    counts: Counter = Counter()
    messages = 0
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            m = json.loads(line)
        except json.JSONDecodeError:
            continue
        if m.get("reason") != "compiler-message":
            continue
        messages += 1
        msg = m["message"]
        code = (msg.get("code") or {}).get("code") or ""
        if not code.startswith("clippy::"):
            continue
        lint = code.split("::", 1)[1]
        spans = [s for s in msg.get("spans", []) if s.get("is_primary")]
        if not spans:
            continue
        path = spans[0]["file_name"]
        if "/tests/" in path or path.startswith("tests/"):
            continue
        crate = path.split("/")[0]
        counts[f"{crate}::{lint}"] += 1
    if proc.returncode != 0 and messages == 0:
        raise RuntimeError(
            "clippy did not run:\n" + (proc.stderr[-4000:] or "(no stderr)")
        )
    return counts, messages


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
        if lint not in RATCHETED and lint != "unwrap_used":
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
# probes and selftest


NEST_PROBE = """#![allow(clippy::collapsible_if)]
pub fn depth_two(a: bool, b: bool) -> u32 {
    if a { if b { return 2; } }
    0
}
pub fn depth_three(a: bool, b: bool, c: bool) -> u32 {
    if a { if b { if c { return 3; } } }
    0
}
"""


def nesting_probe() -> int:
    """Negative control for the nesting rule: depth <= 2 accepted, depth > 2 rejected.

    Required by the C-5 ruling. A configured lint is not an enforced rule until something
    demonstrates it fires on the far side of the boundary and stays silent on the near
    side. Without this, `excessive-nesting-threshold` could be off by one — and it is
    off-by-one-shaped: the threshold names the depth that is REJECTED, so "deeper than
    two levels" is threshold 3, not 2.
    """
    with tempfile.TemporaryDirectory() as tmp:
        crate = Path(tmp) / "nestprobe"
        (crate / "src").mkdir(parents=True)
        (crate / "Cargo.toml").write_text(
            '[package]\nname = "nestprobe"\nversion = "0.0.0"\nedition = "2021"\n'
            "[workspace]\n"
        )
        (crate / "src" / "lib.rs").write_text(NEST_PROBE)
        threshold = 3
        for line in (STRICT_CONF / ".clippy.toml").read_text().splitlines():
            if line.strip().startswith("excessive-nesting-threshold"):
                threshold = int(line.split("=")[1].strip())
        proc = subprocess.run(
            cargo() + ["clippy", "--quiet", "--message-format=json",
                       "--", "-W", "clippy::excessive_nesting"],
            cwd=crate, capture_output=True, text=True, env=strict_env(),
        )
        flagged = set()
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                m = json.loads(line)
            except json.JSONDecodeError:
                continue
            if m.get("reason") != "compiler-message":
                continue
            msg = m["message"]
            if (msg.get("code") or {}).get("code") != "clippy::excessive_nesting":
                continue
            for s in msg.get("spans", []):
                if s.get("is_primary"):
                    flagged.add(s["line_start"])

        two_flagged = any(2 <= ln <= 5 for ln in flagged)
        three_flagged = any(6 <= ln <= 9 for ln in flagged)

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
    the strength of `too-many-lines-threshold = 60` plus `cargo clippy -- -D warnings`,
    and an 80-line function produced no warning at all.

    The probe compiles a file that violates the size and nesting rules under the EXACT flag
    list `measure()` uses, so it cannot drift from the gate it vouches for.
    """
    body = "\n".join(f"    let x{i} = {i}; let _ = x{i};" for i in range(80))
    src = (
        "pub fn long_fn() {\n" + body + "\n}\n"
        "#[allow(clippy::collapsible_if)]\n"
        "pub fn deep(a: bool, b: bool, c: bool) -> u32 {\n"
        "    if a { if b { if c { return 3; } } }\n    0\n}\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        crate = Path(tmp) / "activation"
        (crate / "src").mkdir(parents=True)
        (crate / "Cargo.toml").write_text(
            '[package]\nname = "activation"\nversion = "0.0.0"\nedition = "2021"\n'
            "[workspace]\n"
        )
        (crate / "src" / "lib.rs").write_text(src)
        proc = subprocess.run(
            cargo() + ["clippy", "--quiet", "--message-format=json", "--"] + LINT_FLAGS,
            cwd=crate, capture_output=True, text=True, env=strict_env(),
        )
        fired = set()
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                m = json.loads(line)
            except json.JSONDecodeError:
                continue
            if m.get("reason") != "compiler-message":
                continue
            code = (m["message"].get("code") or {}).get("code") or ""
            if code.startswith("clippy::"):
                fired.add(code.split("::", 1)[1])
        missing = [x for x in ("too_many_lines", "excessive_nesting") if x not in fired]
        if missing:
            print(
                "activation probe: FAIL — an 80-line function with triple nesting did not "
                f"trigger {missing}. `.clippy.toml` sets thresholds but does not switch on "
                "allow-by-default lints; the lint must be listed in "
                "[workspace.lints.clippy] (ADR-MCPRE-061 §6.1)."
            )
            return 1
        print(
            "activation probe: PASS — an 80-line function and a depth-3 block both fired "
            "under this workspace's lint configuration (ADR-MCPRE-061 §6.1)."
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
    if compare(Counter({**at_base, "crate-b::arithmetic_side_effects": 99}), base):
        print("selftest FAIL: a lint outside the adopted set was counted")
        return 1
    # A baseline the tree no longer reaches must be lowered, not silently accepted.
    if not any("lower the baseline" in p for p in compare(Counter(), base)):
        print("selftest FAIL: a vanished baseline entry was accepted")
        return 1

    print("clippy-ratchet gate selftest: PASS (at-baseline, growth, improvement, "
          "deny-at-zero for unbaselined and for unwrap_used, unadopted lint ignored)")
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
    print(
        f"clippy-ratchet gate: OK — production targets only (--lib --bins). "
        f"clippy::unwrap_used denied at zero; {total} baselined occurrence(s) of "
        f"{', '.join(RATCHETED)} across {len(baseline)} crate/lint entries, none grew."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
