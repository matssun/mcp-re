#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The self-hosted runner's Docker contract — two defects that only a real run could show.

The extraction lane is gated on a V2/V3 unit existing, so until one was declared it had
never executed. Its first two executions each failed on a property of the runner rather
than of the code, and each was hidden behind the previous one:

1. **`docker login` cannot persist a credential here.**

       error saving credentials - err: exit status 1,
       out: `User interaction is not allowed. (-25308)`

   `-25308` is `errSecInteractionNotAllowed` — the macOS keychain refusing a background
   service. Note *saving*: the registry ACCEPTED the token, so this is neither a bad
   credential nor a package-permissions problem. Pointing `DOCKER_CONFIG` at an empty
   directory does not avoid it either: the CLI detects `osxkeychain` as the platform
   default whenever the helper is on `PATH`, so a fresh config detects the same store.
   Measured on the runner, and then again in CI with `DOCKER_CONFIG` demonstrably set.

2. **An isolated config loses the docker CONTEXT as well as the store.**

       failed to connect to the docker API at unix:///var/run/docker.sock

   A config directory carries `currentContext` and the definitions under `contexts/`, not
   just `auths`. This runner's Docker is colima on `colima-gh-runner`, so a fresh directory
   sends the CLI to a socket that does not exist. The step that had passed two steps
   earlier passed *because* it ran before the switch.

Both are now fixed by writing the credential and naming `DOCKER_HOST`. This gate exists
because nothing else can see either property: the lane runs only on a self-hosted macOS
runner, only when a unit asks it for evidence, and both failures look like ordinary Docker
errors rather than like a contract being broken.

Run:  python3 scripts/self_hosted_docker_gate.py
      python3 scripts/self_hosted_docker_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: Workflows whose jobs may target the self-hosted runner. Read from the tree rather than
#: listed, so a new workflow is covered the day it is added.
WORKFLOW_DIR = Path(".github") / "workflows"

#: The runner label set that identifies the machine this contract is about. A GitHub-hosted
#: Linux runner has no keychain and a working default socket, so `docker login` there is
#: correct and must not be flagged — `extraction-image.yml` publishes from one.
SELF_HOSTED = re.compile(r"runs-on:\s*\[\s*self-hosted[^\]]*\]")

_JOB = re.compile(r"^  (?P<name>[A-Za-z0-9_-]+):\s*$")
_DOCKER_LOGIN = re.compile(r"^\s*(?:\||.*\|\s*)?docker\s+login\b")
_DOCKER_DAEMON = re.compile(r"\bdocker\s+(pull|run|manifest|image|save|load)\b")
_SETS_HOST = re.compile(r'echo\s+"DOCKER_HOST=')
_SETS_CONFIG = re.compile(r'echo\s+"DOCKER_CONFIG=')


def jobs(text: str) -> dict[str, list[str]]:
    """Each top-level job's body, by name. Two-space indent is the workflow's own shape."""
    out: dict[str, list[str]] = {}
    current = ""
    for line in text.splitlines():
        match = _JOB.match(line)
        if match and not line.startswith("    "):
            current = match.group("name")
            out[current] = []
        elif current:
            out[current].append(line)
    return out


def findings(root: Path) -> list[str]:
    """Every self-hosted job that breaks the contract, with the reason."""
    out: list[str] = []
    for path in sorted((root / WORKFLOW_DIR).glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        for name, body_lines in jobs(text).items():
            body = "\n".join(body_lines)
            if not SELF_HOSTED.search(body):
                continue

            # Comments explain WHY the contract exists and must not trip it. Only an
            # executable line counts — the same distinction `slo_invocation_gate` draws
            # between an invocation and a paragraph warning about one.
            code = [
                line
                for line in body_lines
                if not line.lstrip().startswith("#") and line.strip()
            ]
            code_text = "\n".join(code)

            if any(_DOCKER_LOGIN.search(line) for line in code):
                out.append(
                    f"{path.relative_to(root)}: job `{name}` runs on a self-hosted runner "
                    f"and calls `docker login`. It cannot persist a credential there — the "
                    f"macOS keychain refuses a background service (-25308) — and an "
                    f"isolated DOCKER_CONFIG does not avoid it. Write the credential into "
                    f"the config instead."
                )

            if _DOCKER_DAEMON.search(code_text):
                if not _SETS_CONFIG.search(code_text):
                    out.append(
                        f"{path.relative_to(root)}: job `{name}` talks to the Docker daemon "
                        f"on a self-hosted runner without setting DOCKER_CONFIG. The "
                        f"credential has nowhere to live that the keychain will not claim."
                    )
                if not _SETS_HOST.search(code_text):
                    out.append(
                        f"{path.relative_to(root)}: job `{name}` sets DOCKER_CONFIG but not "
                        f"DOCKER_HOST. An isolated config carries no `currentContext`, so "
                        f"the CLI falls back to unix:///var/run/docker.sock, which this "
                        f"runner does not have."
                    )
    return out


def _workflow(*, login: bool, config: bool, host: bool, self_hosted: bool = True) -> str:
    runs_on = "[self-hosted, macOS, ARM64]" if self_hosted else "ubuntu-24.04-arm"
    steps = ["      - name: creds", "        run: |"]
    if config:
        steps.append('          echo "DOCKER_CONFIG=$x" >> "$GITHUB_ENV"')
    if host:
        steps.append('          echo "DOCKER_HOST=$y" >> "$GITHUB_ENV"')
    if login:
        steps.append("          docker login ghcr.io -u u --password-stdin")
    steps += ["      - name: use", "        run: |", "          docker pull x@sha256:y"]
    return "jobs:\n  extraction:\n    runs-on: " + runs_on + "\n    steps:\n" + "\n".join(steps) + "\n"


def selftest() -> int:
    """Both shipped defects, as mutations the gate must catch.

    A gate that only ever passes proves nothing, and these two are the exact forms that
    reached the runner — not hypotheticals.
    """
    cases: list[tuple[str, str, int]] = [
        # The form that shipped first: a plain `docker login`, no isolation at all.
        ("the original docker login", _workflow(login=True, config=False, host=False), 3),
        # The form that shipped second: DOCKER_CONFIG set, login still present, no HOST.
        ("DOCKER_CONFIG plus a login", _workflow(login=True, config=True, host=False), 2),
        # The third form: login gone, but the context lost with it.
        ("a written credential with no DOCKER_HOST", _workflow(login=False, config=True, host=False), 1),
        # The contract satisfied.
        ("the current form", _workflow(login=False, config=True, host=True), 0),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / WORKFLOW_DIR).mkdir(parents=True)
        target = root / WORKFLOW_DIR / "probe.yml"
        for label, text, expected in cases:
            target.write_text(text, encoding="utf-8")
            got = findings(root)
            if len(got) != expected:
                print(f"SELFTEST FAILED: {label} — expected {expected} finding(s), got {got}")
                return 1

        # A GitHub-hosted runner has no keychain and a working default socket, so the same
        # `docker login` there is correct. `extraction-image.yml` publishes from one, and a
        # gate that flagged it would be telling the truth about the wrong machine.
        target.write_text(
            _workflow(login=True, config=False, host=False, self_hosted=False), encoding="utf-8"
        )
        if findings(root):
            print("SELFTEST FAILED: a GitHub-hosted runner's docker login was flagged")
            return 1

        # A comment explaining the contract is not a breach of it.
        target.write_text(
            "jobs:\n  extraction:\n    runs-on: [self-hosted, macOS, ARM64]\n    steps:\n"
            "      - name: creds\n        run: |\n"
            "          # NOT `docker login`: it cannot persist here.\n"
            '          echo "DOCKER_CONFIG=$x" >> "$GITHUB_ENV"\n'
            '          echo "DOCKER_HOST=$y" >> "$GITHUB_ENV"\n'
            "      - name: use\n        run: |\n          docker pull x\n",
            encoding="utf-8",
        )
        if findings(root):
            print("SELFTEST FAILED: a comment naming docker login was read as a call")
            return 1

    print("self-hosted docker gate selftest: OK")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    found = findings(REPO)
    if found:
        print("self-hosted docker gate: FAIL", file=sys.stderr)
        for entry in found:
            print(f"  {entry}", file=sys.stderr)
        return 1
    print(
        "self-hosted docker gate: OK — no self-hosted job logs in to a registry, and every "
        "one that reaches the daemon names both its config and its endpoint"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
