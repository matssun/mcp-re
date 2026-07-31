#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ES256 containment gate — receipt verification must not become a signing policy.

MCPRE-501 needs ECDSA P-256 for ONE reason: a SCITT transparency service is not ours
and signs its receipts with `ES256` (RFC 9942's own examples do). Verifying a receipt
therefore requires P-256.

MCP-RE's own request and response signatures are Ed25519, and `mcp-re-core` refuses
`ES256` for them by name (`ensure_ed25519_alg`). Those two facts must stay separate.
The failure this gate exists to prevent is quiet: someone reaches for the P-256
verifier already sitting in the workspace to "support ES256 clients", and MCP-RE's
message-signing policy widens without any decision being recorded. An algorithm
accepted for a countersignature by a third party is not thereby accepted for the
signatures MCP-RE's own authorization decisions rest on.

So P-256 is confined by construction:

1. `p256` is a dependency of exactly one crate — the HTTP profile.
2. Inside it, `p256` is referenced from exactly one module — the SCITT receipt
   verifier. Nothing on the serving path can reach it without editing this list.
3. `mcp-re-core` — which every signing path uses — must not depend on `p256` at all,
   and must keep refusing `ES256` explicitly.

Run:  python3 scripts/es256_containment_gate.py
      python3 scripts/es256_containment_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# The one crate permitted to depend on p256, and the one module permitted to use it.
ALLOWED_CRATE = "mcp-re-http-profile"
ALLOWED_MODULES = {"src/scitt.rs"}

# Core is on every signing path; it must not gain an ECDSA verifier.
SIGNING_CORE = "mcp-re-core"

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

    # The refusal itself must still be there, by name.
    core_crypto = root / SIGNING_CORE / "src" / "crypto.rs"
    if core_crypto.exists() and '"ES256"' not in core_crypto.read_text(encoding="utf-8"):
        problems.append(
            f"{SIGNING_CORE}/src/crypto.rs no longer names ES256 as refused for message "
            "signatures — the separation this gate protects is gone."
        )

    return problems


def selftest() -> int:
    """A crate that reaches for the receipt verifier from a signing path must fail."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name in (ALLOWED_CRATE, SIGNING_CORE, "mcp-re-proxy"):
            (root / name / "src").mkdir(parents=True)
            (root / name / "Cargo.toml").write_text(f'[package]\nname = "{name}"\n')
        (root / ALLOWED_CRATE / "Cargo.toml").write_text(
            f'[package]\nname = "{ALLOWED_CRATE}"\n\n[dependencies]\np256 = "0.13"\n'
        )
        (root / ALLOWED_CRATE / "src" / "scitt.rs").write_text("use p256::ecdsa;\n")
        (root / SIGNING_CORE / "src" / "crypto.rs").write_text('ensure("ES256");\n')

        if check(root):
            print("selftest FAIL: the permitted arrangement was rejected")
            return 1

        # A signing path pulling in the verifier.
        (root / "mcp-re-proxy" / "src" / "serve.rs").write_text("let k = p256::foo();\n")
        if not check(root):
            print("selftest FAIL: p256 on a serving path was not caught")
            return 1
        (root / "mcp-re-proxy" / "src" / "serve.rs").unlink()

        # Core gaining the dependency.
        (root / SIGNING_CORE / "Cargo.toml").write_text(
            f'[package]\nname = "{SIGNING_CORE}"\n\n[dependencies]\np256 = "0.13"\n'
        )
        if not check(root):
            print("selftest FAIL: p256 in the signing core was not caught")
            return 1
        (root / SIGNING_CORE / "Cargo.toml").write_text(f'[package]\nname = "{SIGNING_CORE}"\n')

        # The refusal being dropped.
        (root / SIGNING_CORE / "src" / "crypto.rs").write_text("// anything goes\n")
        if not check(root):
            print("selftest FAIL: dropping the ES256 refusal was not caught")
            return 1

    print("es256 containment gate selftest: PASS")
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
        f"es256 containment gate: OK — p256 confined to {ALLOWED_CRATE}/"
        f"{sorted(ALLOWED_MODULES)[0]}, and {SIGNING_CORE} still refuses ES256."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
