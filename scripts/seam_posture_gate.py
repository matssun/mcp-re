#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Seam-posture gate — every optional capability states ON or OFF at startup.

WHAT THIS PROVES, exactly: every variant of `startup_posture::Seam` appears in
`Seam::ALL`, and every variant is passed to `posture.declare(Seam::<X>, ..)` exactly once
in `app.rs`. That is a syntactic check over two files, and the claim stops there.

WHAT IT DOES NOT PROVE: that the declared state is the RIGHT one, that the ON and OFF
lines say anything useful, or that the branch producing them matches what was actually
wired. Two of those are already covered elsewhere and better:

  - `PostureLog::declare` takes a `SeamState` BY VALUE, so a decision written as an `if`
    must produce one on both arms. The OFF branch is a type obligation, not a convention,
    and no gate is needed for it.
  - `PostureLog::assert_complete` panics in a debug build when a seam went unstated. That
    is the runtime backstop, and it is strictly stronger than this gate where it runs.

WHY THIS GATE EXISTS ANYWAY: `assert_complete` only fires on a startup that actually
reaches the posture phase, and no HERMETIC configuration does — the phase sits after the
replay tier is established, and every replay tier that validation accepts needs a live
Redis or etcd. So in `cargo test --workspace` and `bazel test //...`, the runtime check
is never reached. A seam added without a declaration would therefore ship green and only
be caught by the Redis-gated lane. This gate is what makes the omission loud in every
lane.

WHY IT MATTERS. ADR-MCPRE-056 §5.4: an operator reading a startup transcript cannot
distinguish "this capability is off in this deployment" from "this build does not have
this capability" when a seam is silent. Those call for different responses — set a flag
versus replace the binary — and the cost of guessing wrong is that a security control
stays off. Four seams (verified-context carrier, online OCSP, MCP transport contract,
admission currency) announced only when enabled before §5.4 landed.

Run:  python3 scripts/seam_posture_gate.py
      python3 scripts/seam_posture_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

POSTURE_MODULE = "mcp-re-proxy/src/startup_posture.rs"
# The composition root. Declarations live at the decision sites, which are all here.
DECLARING_MODULE = "mcp-re-proxy/src/app.rs"

# `    SecurityAuditRecord,` inside `pub enum Seam { .. }`.
ENUM_BLOCK = re.compile(r"pub enum Seam \{(.*?)\n\}", re.S)
ENUM_VARIANT = re.compile(r"^\s{4}([A-Z][A-Za-z0-9]*),\s*$", re.M)

# `    pub const ALL: &'static [Seam] = &[ .. ];`
ALL_BLOCK = re.compile(r"const ALL: &'static \[Seam\] = &\[(.*?)\];", re.S)
ALL_ENTRY = re.compile(r"Seam::([A-Z][A-Za-z0-9]*)")

# `posture.declare(Seam::OnlineOcspClientRevocation, ocsp_state);`
DECLARE_CALL = re.compile(r"\.declare\(\s*Seam::([A-Z][A-Za-z0-9]*)")


def _find(pattern: re.Pattern[str], text: str, what: str, path: str) -> str:
    match = pattern.search(text)
    if match is None:
        raise SystemExit(f"seam-posture gate: cannot find {what} in {path}")
    return match.group(1)


def check(root: Path) -> list[str]:
    """Return a list of failures; empty means the gate passes."""
    posture_path = root / POSTURE_MODULE
    declaring_path = root / DECLARING_MODULE
    for path in (posture_path, declaring_path):
        if not path.is_file():
            return [f"missing {path.relative_to(root)}"]

    posture_src = posture_path.read_text(encoding="utf-8")
    declaring_src = declaring_path.read_text(encoding="utf-8")

    variants = ENUM_VARIANT.findall(
        _find(ENUM_BLOCK, posture_src, "`pub enum Seam`", POSTURE_MODULE)
    )
    listed = ALL_ENTRY.findall(
        _find(ALL_BLOCK, posture_src, "`Seam::ALL`", POSTURE_MODULE)
    )
    declared = DECLARE_CALL.findall(declaring_src)

    failures: list[str] = []

    if not variants:
        failures.append(f"`pub enum Seam` in {POSTURE_MODULE} has no variants")

    # `Seam::ALL` drives the runtime completeness check, so a variant missing from it is
    # invisible to `assert_complete` as well as to this gate.
    for variant in variants:
        if variant not in listed:
            failures.append(
                f"Seam::{variant} is not in Seam::ALL, so nothing checks that it is "
                f"ever declared ({POSTURE_MODULE})"
            )
    for name in listed:
        if name not in variants:
            failures.append(f"Seam::ALL lists Seam::{name}, which is not a variant")

    for variant in variants:
        count = declared.count(variant)
        if count == 0:
            failures.append(
                f"Seam::{variant} is never declared in {DECLARING_MODULE}: an operator "
                f"cannot tell whether the capability is off or absent from this build. "
                f"Add `posture.declare(Seam::{variant}, ..)` with a SeamState on BOTH "
                f"branches of the decision."
            )
        elif count > 1:
            failures.append(
                f"Seam::{variant} is declared {count} times in {DECLARING_MODULE}: the "
                f"transcript states one capability's posture more than once, and a "
                f"reader has no way to know which line governs."
            )

    for name in set(declared) - set(variants):
        failures.append(
            f"{DECLARING_MODULE} declares Seam::{name}, which is not a Seam variant"
        )

    return failures


_SELFTEST_POSTURE = """\
pub enum Seam {
    Alpha,
    Beta,
}

impl Seam {
    pub const ALL: &'static [Seam] = &[
        Seam::Alpha,
        Seam::Beta,
    ];
}
"""


def _selftest_tree(tmp: Path, declaring: str) -> Path:
    root = tmp / "tree"
    (root / "mcp-re-proxy" / "src").mkdir(parents=True)
    (root / POSTURE_MODULE).write_text(_SELFTEST_POSTURE, encoding="utf-8")
    (root / DECLARING_MODULE).write_text(declaring, encoding="utf-8")
    return root


def selftest() -> int:
    """A gate that cannot fail proves nothing, so prove it fails on each defect."""
    cases: list[tuple[str, str, str | None]] = [
        (
            "both seams declared",
            "posture.declare(Seam::Alpha, a);\nposture.declare(Seam::Beta, b);\n",
            None,
        ),
        (
            "a seam that is never declared",
            "posture.declare(Seam::Alpha, a);\n",
            "Seam::Beta is never declared",
        ),
        (
            "a seam declared twice",
            "posture.declare(Seam::Alpha, a);\nposture.declare(Seam::Alpha, a2);\n"
            "posture.declare(Seam::Beta, b);\n",
            "Seam::Alpha is declared 2 times",
        ),
        (
            "a declaration naming no variant",
            "posture.declare(Seam::Alpha, a);\nposture.declare(Seam::Beta, b);\n"
            "posture.declare(Seam::Gamma, g);\n",
            "which is not a Seam variant",
        ),
    ]

    failed = False
    with tempfile.TemporaryDirectory() as raw:
        for name, declaring, expected in cases:
            tmp = Path(raw) / name.replace(" ", "_")
            tmp.mkdir()
            failures = check(_selftest_tree(tmp, declaring))
            if expected is None:
                ok = not failures
            else:
                ok = any(expected in f for f in failures)
            print(f"  {'ok  ' if ok else 'FAIL'}  {name}")
            if not ok:
                failed = True
                print(f"        expected {expected!r}, got {failures}")

    # A variant absent from ALL is checked against the real enum shape rather than the
    # fixture, because the fixture's ALL is what the other cases keep honest.
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        root = tmp / "tree"
        (root / "mcp-re-proxy" / "src").mkdir(parents=True)
        (root / POSTURE_MODULE).write_text(
            _SELFTEST_POSTURE.replace("        Seam::Beta,\n", ""), encoding="utf-8"
        )
        (root / DECLARING_MODULE).write_text(
            "posture.declare(Seam::Alpha, a);\nposture.declare(Seam::Beta, b);\n",
            encoding="utf-8",
        )
        failures = check(root)
        ok = any("not in Seam::ALL" in f for f in failures)
        print(f"  {'ok  ' if ok else 'FAIL'}  a variant missing from Seam::ALL")
        if not ok:
            failed = True
            print(f"        got {failures}")

    if failed:
        print("seam-posture gate: SELFTEST FAILED")
        return 1
    print("seam-posture gate: selftest passed")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()

    failures = check(REPO)
    if failures:
        print("seam-posture gate: FAILED")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print("seam-posture gate: every Seam states its posture in app.rs")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
