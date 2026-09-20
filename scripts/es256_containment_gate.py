#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ES256 containment gate — receipt verification must not become a signing policy.

MCPRE-501 needs ECDSA P-256 for ONE reason: a SCITT transparency service is not ours
and signs its receipts with `ES256` (RFC 9942's own examples do). Verifying a receipt
therefore requires P-256.

MCP-RE's own request and response signatures are Ed25519, and the HTTP profile's
algorithm registry admits no other algorithm: `ProfileAlgorithm` has one variant and
`ecdsa-p256-sha256` resolves to no verifier. Those two facts must stay separate.
The failure this gate exists to prevent is quiet: someone reaches for the P-256
verifier already sitting in the workspace to "support ES256 clients", and MCP-RE's
message-signing policy widens without any decision being recorded. An algorithm
accepted for a countersignature by a third party is not thereby accepted for the
signatures MCP-RE's own authorization decisions rest on.

So P-256 is confined by construction:

1. `p256` is a dependency of exactly one crate — the HTTP profile.
2. Inside it, `p256` is referenced from exactly one module — the SCITT receipt
   verifier. Nothing on the serving path can reach it without editing this list.
3. `mcp-re-core` — which every signing path uses — must not depend on `p256` at all.
4. The HTTP profile's algorithm registry — `ProfileAlgorithm` and the tokens around it
   in `mcp-re-http-profile/src/policy.rs` — carries no ECDSA P-256 variant and no
   ECDSA P-256 token in its production region. That registry is the owner that decides
   which algorithm MCP-RE's own signatures may use: a variant exists only where an
   implemented verifier exists, and `VerifierPolicy::new` refuses a token that resolves
   to none.

Run:  python3 scripts/es256_containment_gate.py
      python3 scripts/es256_containment_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(REPO / "scripts"))

# The test-region rule is IMPORTED, not re-written. `module_size_gate.TEST_ATTR` only OPENS
# a region; where one ENDS is `production_source`'s answer, and a second copy of that scan
# would be a second opinion about which lines are production.
from module_size_gate import production_source  # noqa: E402

# The one crate permitted to depend on p256, and the modules permitted to use it.
#
# This list got TIGHTER when MCPRE-155 decomposed `scitt.rs`. It used to name one 1629-line
# file carrying seven authorities, so "confined to one module" meant confined to the whole
# SCITT unit. It now names the COSE-key owner and its verifier — the two modules whose
# subject IS what a receipt signature is checked under — plus the SCITT facade, whose only
# p256 references are inside its `#[cfg(test)] mod fixtures` (a test service has to be able
# to sign an ES256 receipt for the negative controls to mean anything).
#
# The gate's proposition is unchanged and is stated the same way: nothing on the serving
# path can reach the P-256 verifier without editing this list.
ALLOWED_CRATE = "mcp-re-http-profile"
ALLOWED_MODULES = {
    "src/scitt/cose_key/mod.rs",
    "src/scitt/cose_key/verify.rs",
    "src/scitt/mod.rs",
}

# Core is on every signing path; it must not gain an ECDSA verifier.
SIGNING_CORE = "mcp-re-core"

# The owner that decides which algorithm MCP-RE's own signatures may use.
REGISTRY_FILE = Path("mcp-re-http-profile") / "src" / "policy.rs"
REGISTRY_ENUM = "enum ProfileAlgorithm"
REGISTRY_VARIANT = "Ed25519"
# The RFC 9421 registry token and its two common spellings in code.
P256_TOKENS = ("ecdsa-p256-sha256", "ES256", "es256")

P256_USE = re.compile(r"\bp256\s*::|\buse\s+p256\b")
P256_DEP = re.compile(r"^\s*p256\s*(=|\.)", re.MULTILINE)


def crate_dirs(root: Path) -> list[Path]:
    return sorted(p.parent for p in root.glob("*/Cargo.toml"))


def check(root: Path) -> list[str]:
    problems: list[str] = []

    for crate in crate_dirs(root):
        name = crate.name
        manifest = (crate / "Cargo.toml").read_text(encoding="utf-8")
        declares = bool(P256_DEP.search(manifest))

        if declares and name != ALLOWED_CRATE:
            problems.append(
                f"{name}/Cargo.toml declares a p256 dependency; only {ALLOWED_CRATE} may. "
                "ES256 is verified for RECEIPTS, not adopted as a signing algorithm."
            )
        if name == SIGNING_CORE and declares:
            problems.append(
                f"{SIGNING_CORE} must never depend on p256: every request/response "
                "signing path goes through it, and it refuses ES256 by name."
            )

        for src in sorted((crate / "src").rglob("*.rs")):
            rel = src.relative_to(crate).as_posix()
            if not P256_USE.search(src.read_text(encoding="utf-8")):
                continue
            if name != ALLOWED_CRATE or rel not in ALLOWED_MODULES:
                problems.append(
                    f"{name}/{rel} references p256; permitted only in "
                    f"{ALLOWED_CRATE}/{{{', '.join(sorted(ALLOWED_MODULES))}}}."
                )

    problems.extend(check_registry(root))
    return problems


def _enum_body(prod: str) -> str | None:
    """The brace-delimited body of `REGISTRY_ENUM`, comments blanked, or `None`."""
    at = prod.find(REGISTRY_ENUM)
    if at < 0:
        return None
    open_at = prod.find("{", at)
    if open_at < 0:
        return None
    depth, i, n = 0, open_at, len(prod)
    body: list[str] = []
    while i < n:
        if prod.startswith("//", i):
            j = prod.find("\n", i)
            i = n if j < 0 else j
            continue
        ch = prod[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return "".join(body)
        elif depth >= 1:
            body.append(ch)
        i += 1
    return None


def check_registry(root: Path) -> list[str]:
    """Clause 4: the HTTP profile's algorithm registry admits no ECDSA P-256.

    Production region only — `mcp-re-http-profile/src/scitt/mod.rs` legitimately signs
    ES256 receipts inside a `#[cfg(test)] mod fixtures`, and a region-blind check would
    have to allowlist files instead of reading where the test region ends.

    A vanished or renamed target is a FAIL, not a pass: a check that silently measures
    nothing when its subject moves is the defect this clause exists to correct.
    """
    path = root / REGISTRY_FILE
    if not path.exists():
        return [
            f"{REGISTRY_FILE.as_posix()} is absent; the algorithm registry this gate "
            "measures has moved or gone, so the gate is measuring nothing."
        ]

    prod = "\n".join(production_source(path.read_text(encoding="utf-8")))
    problems: list[str] = []

    body = _enum_body(prod)
    if body is None:
        problems.append(
            f"`{REGISTRY_ENUM}` was not found in {REGISTRY_FILE.as_posix()}'s production "
            "region; the algorithm registry has moved or been renamed."
        )
    else:
        extra = sorted(
            set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", body)) - {REGISTRY_VARIANT}
        )
        if extra:
            problems.append(
                f"`{REGISTRY_ENUM}` names {', '.join(extra)} besides {REGISTRY_VARIANT}; "
                "a variant is a commitment that MCP-RE's own signatures may use that "
                "algorithm. ES256 is verified for RECEIPTS, not adopted for signing."
            )

    for token in P256_TOKENS:
        if token in prod:
            problems.append(
                f"{REGISTRY_FILE.as_posix()} names {token!r} in its production region; "
                "an ECDSA P-256 token in the algorithm registry widens the signing "
                "policy. Receipt verification is not a signing policy."
            )

    return problems


PERMITTED_POLICY = """\
use crate::ids::ALG_ED25519;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileAlgorithm {
    /// RFC 9421 `ed25519`.
    Ed25519,
}

impl ProfileAlgorithm {
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            ALG_ED25519 => Some(ProfileAlgorithm::Ed25519),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn an_algorithm_without_a_verifier_cannot_be_allowlisted() {
        for t in ["ecdsa-p256-sha256"] {
            assert!(super::ProfileAlgorithm::from_token(t).is_none());
        }
        assert_eq!("ES256", "ES256");
    }
}
"""

MUTATION_A = PERMITTED_POLICY.replace("    Ed25519,\n", "    Ed25519,\n    EcdsaP256,\n")
MUTATION_B = PERMITTED_POLICY.replace(
    "            _ => None,\n",
    '            "ecdsa-p256-sha256" => Some(ProfileAlgorithm::EcdsaP256),\n            _ => None,\n',
)


def selftest() -> int:
    """Every clause must be shown to catch the edit it exists to catch.

    A clause whose self-test never constructs the shape the real tree has proves only
    that `check()` opened a file. Case C is the one that matters most here: the two
    ECDSA P-256 strings appear in the real `policy.rs` ONLY inside its test region, so
    a region-blind check would be satisfied by the tests and say nothing about
    production.
    """
    cases = 0
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name in (ALLOWED_CRATE, SIGNING_CORE, "mcp-re-proxy"):
            (root / name / "src").mkdir(parents=True)
            (root / name / "Cargo.toml").write_text(f'[package]\nname = "{name}"\n')
        (root / ALLOWED_CRATE / "Cargo.toml").write_text(
            f'[package]\nname = "{ALLOWED_CRATE}"\n\n[dependencies]\np256 = "0.13"\n'
        )
        (root / ALLOWED_CRATE / "src" / "scitt" / "cose_key").mkdir(parents=True)
        (root / ALLOWED_CRATE / "src" / "scitt" / "cose_key" / "verify.rs").write_text(
            "use p256::ecdsa;\n"
        )
        policy_rs = root / REGISTRY_FILE
        policy_rs.parent.mkdir(parents=True, exist_ok=True)
        policy_rs.write_text(PERMITTED_POLICY)

        # Permitted: a one-variant production enum, both ES256 spellings test-region only.
        cases += 1
        if check(root):
            print("selftest FAIL: the permitted arrangement was rejected")
            return 1

        # A signing path pulling in the verifier.
        cases += 1
        (root / "mcp-re-proxy" / "src" / "serve.rs").write_text("let k = p256::foo();\n")
        if not check(root):
            print("selftest FAIL: p256 on a serving path was not caught")
            return 1
        (root / "mcp-re-proxy" / "src" / "serve.rs").unlink()

        # Core gaining the dependency.
        cases += 1
        (root / SIGNING_CORE / "Cargo.toml").write_text(
            f'[package]\nname = "{SIGNING_CORE}"\n\n[dependencies]\np256 = "0.13"\n'
        )
        if not check(root):
            print("selftest FAIL: p256 in the signing core was not caught")
            return 1
        (root / SIGNING_CORE / "Cargo.toml").write_text(f'[package]\nname = "{SIGNING_CORE}"\n')

        # A — a second variant in the production enum.
        cases += 1
        policy_rs.write_text(MUTATION_A)
        if not check(root):
            print("selftest FAIL: an ECDSA P-256 algorithm variant was not caught")
            return 1

        # B — a production `from_token` arm for the P-256 token.
        cases += 1
        policy_rs.write_text(MUTATION_B)
        if not check(root):
            print("selftest FAIL: an ECDSA P-256 token arm was not caught")
            return 1

        # C — production restored; both literals live only in the test region.
        cases += 1
        policy_rs.write_text(PERMITTED_POLICY)
        if check(root):
            print("selftest FAIL: a test-region ES256 string changed the verdict")
            return 1

        # D — the target vanishes. Absence must not pass vacuously.
        cases += 1
        policy_rs.unlink()
        if not check(root):
            print("selftest FAIL: a vanished target passed vacuously")
            return 1

    print(f"es256 containment gate selftest: PASS — {cases} cases, all caught")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    problems = check(REPO)
    if problems:
        print("es256 containment gate: FAIL")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(
        f"es256 containment gate: OK — {SIGNING_CORE} does not depend on p256; p256 is "
        f"confined to {len(ALLOWED_MODULES)} module(s) in {ALLOWED_CRATE} "
        f"({', '.join(sorted(ALLOWED_MODULES))}); and {REGISTRY_FILE.as_posix()}'s "
        f"production algorithm registry carries no ECDSA P-256 variant or token."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
