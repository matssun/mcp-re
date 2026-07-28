#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Deploy image-tag gate — every image reference must name the version in VERSION.

The deploy surface names container images in several places that must agree:
`deploy/cloudbuild/*.yaml` BUILDS and PUSHES the tags, `deploy/k8s/*.yaml` and the
Helm chart REFERENCE them, and the runbooks + live-validation harnesses under
`docs/security/` and `tools/` DEPLOY them. Nothing tied those together, so they
drifted: the multi-replica harness pinned `0.12.1` while Cloud Build had moved to
`0.13.0`, and the SLO Job runner pinned `0.12.1` against a `0.13.0` bench image.

That failure mode is expensive and late. Every pin is syntactically fine and every
file reads correctly on its own; the mismatch only surfaces as ImagePullBackOff on a
cluster that is already billing, after `gcloud builds submit` has run. It also has a
silent variant: a `sed` that rewrites `image: <name>:<tag>` stops matching when the
manifest's tag moves, leaving the un-rewritten bare local name in the applied YAML.

So: any `mcp-re-*:<literal semver>` in the deploy surface must equal VERSION. The fix
when this gate fires is usually NOT to retype the number — it is to read the tag from
VERSION at run time, which is what the harnesses now do.

Run:  python3 scripts/deploy_image_tag_gate.py
      python3 scripts/deploy_image_tag_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Files whose image references are DEPLOYED or PUSHED. Docs that merely narrate a past
# run are excluded — a historical "the v0.12.1 run" is a fact, not a pin.
SCAN_GLOBS = (
    "deploy/**/*.yaml",
    "deploy/**/*.yml",
    "deploy/**/*.tpl",
    "docs/security/*.sh",
    "docs/security/gke-slo-baseline-runbook.md",
    "tools/**/*.sh",
    ".github/workflows/*.yml",
)

# `mcp-re-proxy:0.13.0`, `.../mcp-re-slo-bench:0.13.0` — a LITERAL semver tag on one of
# this project's images. A tag that is a shell/Helm expansion (`$TAG`, `${_TAG}`,
# `{{ .Values… }}`) is exactly the fix this gate wants and must not match.
IMAGE_TAG = re.compile(r"\b(mcp-re-[a-z0-9-]+):(\d+\.\d+\.\d+)\b")


def expected_version() -> str:
    return (REPO / "VERSION").read_text().strip()


def scan(root: Path, version: str) -> list[str]:
    """Return one finding per image reference whose literal tag != version."""
    findings: list[str] = []
    for glob in SCAN_GLOBS:
        for path in sorted(root.glob(glob)):
            if not path.is_file():
                continue
            for lineno, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
                for image, tag in IMAGE_TAG.findall(line):
                    if tag != version:
                        findings.append(
                            f"{path.relative_to(root)}:{lineno}: {image}:{tag} "
                            f"!= VERSION {version} — read the tag from VERSION "
                            f"rather than restating it"
                        )
    return findings


def selftest() -> int:
    """The gate must FAIL on a drifted pin. A gate that only ever passes proves nothing."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "VERSION").write_text("9.9.9\n")
        (root / "deploy").mkdir()
        good = root / "deploy" / "good.yaml"
        bad = root / "deploy" / "bad.yaml"
        good.write_text("image: mcp-re-proxy:9.9.9\nimage: mcp-re-inner-fastmcp:${TAG}\n")
        bad.write_text("image: mcp-re-proxy:0.12.1\n")

        findings = scan(root, "9.9.9")
        if len(findings) != 1 or "bad.yaml" not in findings[0]:
            print(f"SELFTEST FAILED: expected exactly one finding in bad.yaml, got {findings}")
            return 1
        bad.write_text("image: mcp-re-proxy:9.9.9\n")
        if scan(root, "9.9.9"):
            print("SELFTEST FAILED: a correctly-pinned tree still reported findings")
            return 1
    print("deploy image-tag gate selftest: PASS")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    version = expected_version()
    findings = scan(REPO, version)
    if findings:
        print(f"deploy image-tag gate: FAIL ({len(findings)} drifted pin(s), VERSION={version})")
        for f in findings:
            print(f"  {f}")
        return 1
    print(f"deploy image-tag gate: PASS (every deployed image tag == VERSION {version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
