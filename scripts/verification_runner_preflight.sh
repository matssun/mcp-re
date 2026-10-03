#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Refuse to start a verification lane on a host that cannot run it.
#
# The self-hosted runner is persistent, and the job PATH it uses is NOT the
# operator's login PATH — it comes from the runner service's own `.env`. So the
# same box that verifies by hand can fail the lane, and the failure surfaces
# deep inside a step as `ModuleNotFoundError: tomllib` or
# `bazel: command not found`. Both name a symptom in a tool nobody was thinking
# about; neither names the runner environment that actually decided it.
#
# This runs first and states the requirement it is checking, so a rebuilt or
# re-registered runner reports what is missing instead of what broke.
#
# Usage:  scripts/verification_runner_preflight.sh
set -uo pipefail

failed=0

fail() {
  echo "PREFLIGHT FAIL: $1" >&2
  failed=1
}

# --- Python must be new enough for tomllib -----------------------------------
# The lock file is TOML and both lanes parse it with the standard library.
# tomllib is 3.11+; macOS ships a 3.9 under /usr/bin that satisfies `python3`
# and fails only once it imports.
python_path="$(command -v python3 || true)"
if [[ -z "$python_path" ]]; then
  fail "no python3 on the lane PATH."
else
  python_version="$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null || true)"
  if python3 -c 'import tomllib' 2>/dev/null; then
    echo "python3 ${python_version} at ${python_path} (tomllib present)"
  else
    fail "python3 ${python_version} at ${python_path} has no tomllib (needs 3.11+)."
  fi
fi

# --- every Rust lane runs through Bazel --------------------------------------
# The test, mutation, structural, measured and Verus lanes build and run with Bazel, on the
# Rust toolchain MODULE.bazel pins — the prover included, which runs on that toolchain's
# own compiler driver. So what this box needs is a Bazel that starts, asked rather than
# looked for on PATH: a launcher that cannot fetch or start the pinned release fails here,
# naming itself, instead of inside a lane step.
if ! command -v bazel >/dev/null 2>&1; then
  fail "no bazel on the lane PATH — every Rust lane runs through it."
elif version="$(bazel --version 2>&1)"; then
  echo "bazel at $(command -v bazel): ${version}"
else
  fail "bazel on the lane PATH does not start: ${version}"
fi

# --- the ecosystems the REGISTRY actually uses ---------------------------------
# ADR-MCPRE-059 §2 / issue #745: a review unit is not a Cargo package, so the lane may have
# a battery to run under pytest or vitest. Which toolchains this box needs is therefore a
# fact about the registry rather than a list kept here — a hardcoded requirement would
# either demand tools no unit uses, or stay silent when the first non-Rust unit lands and
# let the lane report a battery it could not run.
#
# Derived, and each requirement names its remedy. A missing toolchain is a FAIL rather than
# a skip for the reason the rest of this script exists: a lane that cannot run its battery
# must not report the claim above it as measured.
ecosystems="$(python3 - <<'PYEOF' 2>/dev/null || true
import sys
from pathlib import Path

sys.path.insert(0, str(Path("tools/verification").resolve()))
from _ecosystems import unit_ecosystem  # noqa: E402
from _manifest import claims_test_evidence, load_verification  # noqa: E402

doc = load_verification()
names = set()
for unit in doc.get("unit", []):
    if not claims_test_evidence(unit):
        continue
    eco = unit_ecosystem(unit)
    if eco is not None:
        names.add(eco.name)
print(" ".join(sorted(names)))
PYEOF
)"
echo "registry ecosystems: ${ecosystems:-<none>}"

for eco in $ecosystems; do
  case "$eco" in
    rust) ;;  # covered by the bazel check above
    python)
      if command -v uv >/dev/null 2>&1; then
        echo "uv at $(command -v uv) (a python unit's battery runs through it)"
      else
        fail "a registered unit's battery is a python one and there is no uv on the lane PATH. Install it (brew install uv) and put it on the runner's PATH."
      fi
      ;;
    typescript)
      if command -v npx >/dev/null 2>&1; then
        echo "npx at $(command -v npx) (a typescript unit's battery runs through it)"
      else
        fail "a registered unit's battery is a typescript one and there is no npx on the lane PATH. Install node (brew install node) and put it on the runner's PATH."
      fi
      # THE RUNTIMES, not just the tool that launches them.
      #
      # `npx` being on PATH says nothing about the thing the lane actually measures
      # through: one prepared environment per PINNED Node version, under
      # `sdk/typescript/.node-v<major>`. Those are build products on a persistent box, and
      # the nightly disk reclaim removes them — after which the lane finds no runtime,
      # measures nothing, and the gate fails naming a directory rather than the missing
      # prerequisite. That happened, and "remember to re-run the preparation script" is not
      # a control.
      #
      # Present -> use them. Absent -> PREPARE them, here, because preparation is a
      # different job from measurement: `prepare_node_matrix.sh` is already the canonical
      # pinned mechanism (npm install of exact versions, integrity-checked like any other
      # dependency), so provisioning introduces no network or trust decision the lane does
      # not already rest on. If preparation itself fails, that is an explicit, reproducible
      # prerequisite failure and the lane does not start.
      #
      # Preparation stays OUT of the lane for the reason its own header gives: a lane that
      # builds what it measures can report a battery it has just made pass.
      if ! missing="$(python3 scripts/node_matrix_state.py --print-missing)"; then
        fail "cannot determine which pinned Node runtimes are prepared: $missing"
      elif [[ -n "$missing" ]]; then
        echo "pinned Node runtime(s) not prepared: ${missing}"
        echo "preparing them with scripts/prepare_node_matrix.sh (the canonical pinned mechanism)"
        if scripts/prepare_node_matrix.sh >/dev/null 2>&1; then
          if still_missing="$(python3 scripts/node_matrix_state.py --print-missing)" \
             && [[ -z "$still_missing" ]]; then
            echo "pinned Node runtimes prepared"
          else
            fail "preparation ran but these pinned Node runtimes are still absent: ${still_missing:-<unknown>}. Run scripts/prepare_node_matrix.sh and read its output."
          fi
        else
          fail "scripts/prepare_node_matrix.sh failed, so the TypeScript battery has no runtime to be measured on. Run it directly and read its output; the lane must not start without the pinned runtimes."
        fi
      else
        echo "pinned Node runtimes prepared (all $(python3 scripts/node_matrix_state.py --count))"
      fi
      ;;
    *)
      fail "a registered unit names ecosystem '${eco}', which this preflight does not know how to check. Teach it here rather than letting the lane discover it."
      ;;
  esac
done

if [[ $failed -ne 0 ]]; then
  cat >&2 <<'REMEDY'

The lane PATH is set by the runner service, not by the login shell. Fix it in
the runner's own `.env` (next to `svc.sh`), then restart the service:

  PATH=/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin

  ./svc.sh stop && ./svc.sh start

See docs/dev/verification-runner.md.
REMEDY
  exit 1
fi

echo "PREFLIGHT PASS: the runner environment can run this lane."
