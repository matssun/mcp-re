# SPDX-License-Identifier: Apache-2.0
"""Reading Verus's own report — ADR-MCPRE-059 §16.

`verus --output-json` emits, per crate compiled, a document carrying the fully qualified
name of every function it processed, the verified/error counts, whether it verified the
ENTIRE crate, and the prover's own version and commit. Everything the lane needs to decide
whether a unit's evidence exists is in there.

This module exists because the previous answer — scan the human-readable log for a
`verification results::` line — was wrong in four separate ways, each of which produced a
green that measured something other than what the gate claimed:

  * a crate with no specifications prints no results line and exits 0;
  * cargo's fingerprint cache reprints nothing at all on an unchanged crate;
  * `cargo verus verify -p X` also verifies X's dependencies, and the first results line
    found belongs to whichever crate compiled first, not to the unit under test;
  * cargo writes its crate banners to stderr while Verus writes results to stdout, so any
    attempt to repair the third by interleaving depends on capturing the streams together.

The structured report removes the guessing rather than improving it: names are qualified,
so attribution is read rather than inferred.

Three things it lets the lane check that the log never could:

  * **the prover's identity, as reported by the prover** — not the path the lane invoked.
    A binary at the pinned location that is not the pinned build now fails.
  * **whole-crate verification** — `is-verifying-entire-crate` distinguishes an
    authoritative run from a `focus`-style partial one (Operational Rule 5).
  * **the specific theorems the unit named** — `func-details` lists the functions the
    prover processed, so deleting the FUNCTION a unit claims fails the lane instead of
    leaving the crate's other proofs to answer for it.

What the report cannot answer, and what therefore is not claimed here: whether a listed
function still carries a specification. `func-details` names every function processed,
with or without a `requires`/`ensures`, and a Verus specification is a detachable
attribute — deleting it leaves the symbol in the report and the crate's verified count
healthy. That check is a property of the source, and it is `check-assumptions`, which
reads the declared unit's own files and fails on a proved symbol with no specification.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass(frozen=True)
class CrateReport:
    """One crate's verification report, as the prover described it."""

    symbols: frozenset[str] = field(default_factory=frozenset)
    verified: int = 0
    errors: int = 0
    success: bool = False
    entire_crate: bool = False
    commit: str = ""
    version: str = ""

    @property
    def crates(self) -> frozenset[str]:
        """The crate roots this report's symbols belong to, e.g. `mcp_re_core`."""
        return frozenset(name.split("::", 1)[0] for name in self.symbols if "::" in name)


def parse_reports(output: str) -> list[CrateReport]:
    """Every JSON document in `output`, in order, ignoring surrounding cargo chatter.

    Cargo's own lines share the stream, and one invocation emits one document per crate,
    concatenated. Decoding incrementally is what makes both facts harmless: anything that
    is not a JSON document is skipped, and every document is kept.
    """
    decoder = json.JSONDecoder()
    reports: list[CrateReport] = []
    index = 0
    length = len(output)
    while index < length:
        start = output.find("{", index)
        if start == -1:
            break
        try:
            document, index = decoder.raw_decode(output, start)
        except json.JSONDecodeError:
            index = start + 1
            continue
        if not isinstance(document, dict) or "verification-results" not in document:
            continue
        results = document.get("verification-results", {})
        verus = document.get("verus", {})
        reports.append(
            CrateReport(
                symbols=frozenset(document.get("func-details", {})),
                verified=int(results.get("verified", 0)),
                errors=int(results.get("errors", 0)),
                success=bool(results.get("success", False)),
                entire_crate=bool(results.get("is-verifying-entire-crate", False)),
                commit=str(verus.get("commit", "")),
                version=str(verus.get("version", "")),
            )
        )
    return reports


def evaluate_unit(
    reports: list[CrateReport],
    crate: str,
    proved_symbols: list[str],
    pinned_commit: str,
) -> tuple[bool, str]:
    """Did THIS unit's theorems get proved, by the PINNED prover, over the WHOLE crate?

    Every clause below corresponds to a way a previous version of this lane reported a
    pass it had not measured. Returns (ok, human-readable detail).
    """
    if not reports:
        return False, (
            "the prover emitted no report at all. An invocation that produces no JSON "
            "document discharged no proof obligations, whatever its exit status."
        )

    if not pinned_commit:
        return False, (
            "the toolchain lock pins no Verus commit, so the run's prover has no declared "
            "identity to be checked against. A proof attributed to an unidentified prover "
            "is not evidence."
        )

    for report in reports:
        # An ABSENT commit fails exactly as a wrong one does. Skipping the comparison when
        # the field is empty makes the check fail open on the single input an adversarial
        # or locally built prover most easily controls: its own self-report.
        if not report.commit:
            return False, (
                "the prover's report carries no commit. Identity is read from the report, "
                "so a report that declines to state one leaves the binary unidentified, "
                "and the install path agreeing proves nothing about the binary."
            )
        if report.commit != pinned_commit:
            return False, (
                f"prover identity mismatch: report says {report.commit[:12]}, the lock "
                f"pins {pinned_commit[:12]}. A proof checked by an unpinned prover is not "
                "evidence, and the install path agreeing proves nothing about the binary."
            )

    # Symbols are qualified with the crate root, which uses underscores where Cargo uses
    # hyphens. Attribution is read off the names rather than inferred from output order.
    crate_root = crate.replace("-", "_")
    mine = [r for r in reports if crate_root in r.crates]
    if not mine:
        seen = sorted({c for r in reports for c in r.crates}) or ["nothing"]
        return False, (
            f"no report for {crate} (reports seen for: {', '.join(seen)}). A crate with no "
            "specifications produces exactly this while its dependencies verify normally."
        )

    for report in mine:
        if report.errors or not report.success:
            return False, f"{report.errors} verification error(s) in {crate}"
        if not report.entire_crate:
            return False, (
                f"{crate} was verified only in part. A proof over part of a crate does not "
                "establish the crate's obligations (Operational Rule 5)."
            )

    verified = sum(r.verified for r in mine)
    if verified == 0:
        return False, f"0 verified in {crate}: the invocation proved nothing here"

    proved = {name for r in mine for name in r.symbols}
    missing = [symbol for symbol in proved_symbols if symbol not in proved]
    if missing:
        return False, (
            f"declared theorem(s) absent from the report: {', '.join(missing)}. The crate "
            "verified other things, which is exactly how a deleted specification keeps a "
            "lane green."
        )

    return True, f"{verified} verified in {crate}, {len(proved_symbols)} declared theorem(s) present"
