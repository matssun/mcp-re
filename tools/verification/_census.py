# SPDX-License-Identifier: Apache-2.0
"""The ADR-MCPRE-069 join: which controls a proposition claims, and which nothing claims.

`_controls` says what EXISTS. `verification.toml` says what is CLAIMED. This module is the
one place the two meet, and everything difficult about ADR-069 lives in the meeting:

# Claimed means selected, not adjacent

A control is claimed when some unit's declared evidence SELECTS it — its `tested_symbols`
entry resolves to this control in this unit's project — or, for a registry-carried control,
when the probe or measurement names a unit. It is not claimed because it sits in a file a
unit lists in `paths`. That distinction is the whole measurement: a unit's paths are its
source closure, and a test living inside that closure which no battery selects runs, passes
and moves no fingerprint.

# A parametrised family is ONE control, and the registry names its CASES

`test_a_sub_floor_override_is_refused_at_sign_time` is one function; pytest reports four
cases and the registry lists four selectors. Expanding the family here would mean
reimplementing pytest's and vitest's id algebras — both of which depend on values this
module never sees — so the direction is reversed: the control is the TEMPLATE the source
defines, and a registered selector is matched back to it. A template's wildcard is `%s` and
friends for a `.each` table and `${…}` for a JavaScript template literal, and a pytest case
is its function name with a trailing `[…]`.

Getting this wrong in the silent direction would be the campaign's worst failure: a
template nothing matched would read as an unclaimed control that is in fact the
best-curated battery in the repository, and the disposition campaign would then write a
`not-evidence` reason about a control that is somebody's declared evidence.

# The residue carries dispositions, and the claimed do not

ADR-069 D4: a registered control leaves the census by construction. So
`control-dispositions.toml` holds rows only for what is unclaimed — `not-evidence` and
`new-proposition` — and `register`/`reattribute` discharge by the symbol landing in a
battery. A row for a control that is now claimed is refused rather than ignored: it is a
disposition describing a control that no longer needs one, and leaving it would let the
registry disagree with the tree.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import tomllib

from _controls import Control, KINDS, POLICY, _registry, all_controls
from _ecosystems import test_project_for

#: The ADR-069 dispositions a row may carry. `register` and `reattribute` are dispositions
#: too, but they discharge in `verification.toml` — the symbol joins a battery — and a row
#: for one would be a second place the same fact is written.
#:
#: The FIELD is `decision` rather than `verdict` because `scripts/registry_approval_gate.py`
#: refuses a stored approval word in any policy registry, and it is right to: a `verdict`
#: key on a record is a bit on the object approved, which survives every edit to what it
#: approved. A disposition is not an approval — it says what a control IS — but the gate
#: enumerates its forbidden keys rather than reading intent, and a registry that needed an
#: exemption to hold an approval-shaped word would be arguing with a rule it agrees with.
RESIDUE_DECISIONS = ("not-evidence", "new-proposition")

#: What a `${…}` or `%s` stands for when a title TEMPLATE is matched against a reported
#: case name. Non-greedy nothing-or-more, because a template may end in one.
_WILDCARD = re.compile(r"\$\{[^}]*\}|%[sdifjo#%]")


def template_to_regex(template: str) -> re.Pattern[str]:
    """A case-name template as the pattern its expansions match."""
    parts = [re.escape(piece) for piece in _WILDCARD.split(template)]
    return re.compile(".*?".join(parts) + r"\Z")


@dataclass(frozen=True)
class Claim:
    """One unit's selection of one control."""

    unit: str
    control: Control
    selector: str


@dataclass(frozen=True)
class Disposition:
    """One ADR-069 row about an unclaimed control, or about a whole carrier.

    Two scopes, and the distinction is ADR-MCPRE-061's *review granularity equals exception
    granularity* applied here. A `control` row adjudicates one control. A `carrier` row
    adjudicates a FILE, and is admissible only where the reason is genuinely a property of
    the file's ROLE rather than of any control inside it — the assurance platform's own
    self-tests are the worked case: what makes them not evidence is that the file measures
    the instrument, which is true of every control in it and of the next one added.

    A carrier row is `not-evidence` only. A `new-proposition` is a statement about what a
    named set of controls establishes, and a file-wide one would be a claim nobody read.
    """

    id: str
    project: str
    control: str
    decision: str
    reason_family: str
    recorded: str
    proposition: str | None
    scope: str = "control"
    carrier: str = ""


def units() -> list[dict]:
    return tomllib.loads((POLICY / "verification.toml").read_text())["unit"]


def _resolve(index: dict[str, Control], selector: str) -> Control | None:
    """The control a `tested_symbols` entry selects inside one project."""
    exact = index.get(selector)
    if exact is not None:
        return exact
    if selector.startswith("pytest#"):
        base = re.sub(r"\[[^\]]*\]\Z", "", selector)
        parametrised = index.get(base)
        if parametrised is not None:
            return parametrised
    scheme = selector.split("#", 1)[0]
    for identity, control in index.items():
        if not identity.startswith(f"{scheme}#") or not _WILDCARD.search(identity):
            continue
        if template_to_regex(identity).match(selector):
            return control
    return None


def join(controls: list[Control] | None = None) -> tuple[list[Claim], list[tuple[str, str, str]]]:
    """Every claim the registry makes, and every selector that resolves to no control.

    The second list is not a curiosity: a selector naming nothing is a STALE identity, the
    lane's `--exact` selection would fail on it, and ADR-069's closure criterion forbids
    one. It is returned beside the claims rather than logged, so that no caller can report
    a census without having been handed the evidence that its input was well formed.
    """
    controls = all_controls() if controls is None else controls
    index: dict[str, dict[str, Control]] = {}
    for control in controls:
        index.setdefault(control.project, {})[control.identity] = control
    claims: list[Claim] = []
    stale: list[tuple[str, str, str]] = []
    for unit in units():
        project = test_project_for(unit)
        for selector in unit.get("tested_symbols", []):
            found = _resolve(index.get(project or "", {}), selector)
            if found is None:
                stale.append((unit["id"], project or "(no project)", selector))
            else:
                claims.append(Claim(unit=unit["id"], control=found, selector=selector))
        claims.extend(_gate_claims(unit, index.get("", {}), stale))
    claims.extend(_registry_claims(index.get("", {})))
    return claims, stale


def _gate_claims(unit: dict, index: dict[str, Control], stale: list) -> list[Claim]:
    """A unit's `gate_controls` — the source-text lane built in ADR-MCPRE-068 Phase 1.

    A gate is not selected through `tested_symbols`: it is neither a cargo target nor a
    pytest node, and a `.py` entry in `paths` collapses a cargo unit's ecosystem to None.
    It enters the fingerprint as its own component and is named here. That makes it a
    CLAIMED control by exactly the test this census applies everywhere else — some unit's
    declared evidence names it — and a census that only read `tested_symbols` would report
    the four gates ADR-068 Phase 1 registered as unclaimed, and invite a `not-evidence`
    reason to be written about the production carrier of a `critical` theorem.
    """
    out: list[Claim] = []
    for path in unit.get("gate_controls", []):
        identity = f"gate#{path}"
        control = index.get(identity)
        if control is None:
            stale.append((unit["id"], "(gate lane)", identity))
        else:
            out.append(Claim(unit=unit["id"], control=control, selector=identity))
    return out


def _registry_claims(index: dict[str, Control]) -> list[Claim]:
    """Probes and measurements claim their unit directly, by the record's `unit` field."""
    out: list[Claim] = []
    for name, table, scheme in (
        ("structural-probes.toml", "probe", "structural"),
        ("mutation-probes.toml", "probe", "mutation"),
        ("measurements.toml", "measurement", "measurement"),
    ):
        for entry in _registry(name, table):
            identity = f"{scheme}#{entry['id']}"
            control = index.get(identity)
            owner = entry.get("unit")
            if control is not None and owner:
                out.append(Claim(unit=owner, control=control, selector=identity))
            if scheme == "measurement" and owner:
                out.extend(_measurement_selected(entry, owner))
    return out


def _measurement_selected(entry: dict, owner: str) -> list[Claim]:
    """The libtest names a `[[measurement]]`'s own argv selects, as that unit's claims.

    A `measured` unit declares no `tested_symbols` — ADR-MCPRE-068 §4.1 gives it a protocol
    and an apparatus control instead — so a census reading only `tested_symbols` reports the
    controls the measurement RUNS as claimed by nothing. They are claimed: the registry
    names them, in argv, and `verify-measured` executes exactly them. Reading the protocol
    is the same join as reading a battery, and not reading it would invite a `not-evidence`
    reason to be written about a measurement's own apparatus.

    Matched by NAME against the controls of the unit's project, because an argv names a
    libtest filter rather than a `target#path` selector.
    """
    wanted: set[str] = set()
    for key in ("protocol", "control"):
        for token in entry.get(key, []):
            text = str(token)
            if text.startswith("-") or "/" in text or text in ("cargo", "test"):
                continue
            wanted.add(text)
    if not wanted:
        return []
    out: list[Claim] = []
    for control in _measurement_index():
        tail = control.identity.rsplit("::", 1)[-1].rsplit("#", 1)[-1]
        if tail in wanted:
            out.append(Claim(unit=owner, control=control, selector=f"measured-argv:{tail}"))
    return out


#: Filled once per process. A measurement's argv is matched against every control, and
#: re-walking the tree per measurement would make the census quadratic in the number of
#: measured units.
_MEASUREMENT_INDEX: list[Control] = []


def _measurement_index() -> list[Control]:
    if not _MEASUREMENT_INDEX:
        _MEASUREMENT_INDEX.extend(all_controls())
    return _MEASUREMENT_INDEX


#: Every key a `[[disposition]]` row may carry, and every key a `[[proposition]]` may. The
#: registry's header promises that an unknown key is a validation failure rather than a
#: silently ignored field; these are what lets `control-census --gate` keep that promise.
DISPOSITION_KEYS = frozenset(
    {"id", "project", "control", "decision", "reason_family", "proposition", "recorded",
     "scope", "carrier"}
)
PROPOSITION_KEYS = frozenset(
    {"id", "title", "carrier", "likely_owner", "consequence", "root_relationship", "record",
     "statement", "ratified_as"}
)


def raw_registry() -> dict:
    path = POLICY / "control-dispositions.toml"
    return tomllib.loads(path.read_text()) if path.is_file() else {}


def dispositions() -> list[Disposition]:
    path = POLICY / "control-dispositions.toml"
    if not path.is_file():
        return []
    raw = tomllib.loads(path.read_text())
    return [
        Disposition(
            id=row["id"],
            project=row.get("project", ""),
            control=row.get("control", ""),
            decision=row["decision"],
            reason_family=row.get("reason_family", ""),
            recorded=row.get("recorded", ""),
            proposition=row.get("proposition"),
            scope=row.get("scope", "control"),
            carrier=row.get("carrier", ""),
        )
        for row in raw.get("disposition", [])
    ]


def propositions() -> list[dict]:
    path = POLICY / "control-dispositions.toml"
    if not path.is_file():
        return []
    return tomllib.loads(path.read_text()).get("proposition", [])


@dataclass(frozen=True)
class Census:
    """One run of the ADR-069 measurement over one tree."""

    controls: list[Control]
    claims: list[Claim]
    stale: list[tuple[str, str, str]]
    dispositions: list[Disposition]

    @property
    def claimed(self) -> set[tuple[str, str]]:
        return {(c.control.project, c.control.identity) for c in self.claims}

    @property
    def unclaimed(self) -> list[Control]:
        seen = self.claimed
        return [c for c in self.controls if (c.project, c.identity) not in seen]

    @property
    def dispositioned(self) -> set[tuple[str, str]]:
        """Every control a row covers — by identity, or by the carrier a file row names."""
        by_control = {
            (d.project, d.control) for d in self.dispositions if d.scope == "control"
        }
        carriers = {d.carrier for d in self.dispositions if d.scope == "carrier"}
        return by_control | {
            (c.project, c.identity) for c in self.controls if c.carrier in carriers
        }

    @property
    def residue(self) -> list[Control]:
        """Unclaimed AND undispositioned — the population ADR-069 closes at zero."""
        decided = self.dispositioned
        return [c for c in self.unclaimed if (c.project, c.identity) not in decided]

    @property
    def orphan_dispositions(self) -> list[Disposition]:
        """Rows describing nothing, or describing something that no longer needs a row.

        A control row about a claimed control is D4: the control left the census when its
        battery selected it. A carrier row whose file holds no unclaimed control is the
        same fact one level up — the reason is still true and the row no longer decides
        anything, and a register that keeps such rows stops being readable as the residue.
        """
        existing = {(c.project, c.identity) for c in self.controls}
        claimed = self.claimed
        unclaimed_carriers = {c.carrier for c in self.unclaimed}
        out: list[Disposition] = []
        for row in self.dispositions:
            if row.scope == "carrier":
                if row.carrier not in unclaimed_carriers:
                    out.append(row)
                continue
            key = (row.project, row.control)
            if key not in existing or key in claimed:
                out.append(row)
        return out

    def by_kind(self, controls: list[Control]) -> dict[str, int]:
        counts = {kind: 0 for kind in KINDS}
        for control in controls:
            counts[control.kind] += 1
        return counts


def census(controls: list[Control] | None = None) -> Census:
    controls = all_controls() if controls is None else controls
    claims, stale = join(controls)
    return Census(controls=controls, claims=claims, stale=stale, dispositions=dispositions())
