#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Prepare one environment per PINNED CPython interpreter for the Python SDK batteries —
# ADR-MCPRE-059 §28 / issue #746.
#
# WHY THIS IS A PREPARATION STEP AND NOT PART OF THE LANE. `tools/verification/verify-tests`
# measures whatever environment it finds and refuses to build one: a lane that builds what
# it measures can report a battery it has just made pass, and a lane that resolves its own
# interpreter picks whatever the machine offers — which is precisely the gap the `[python]`
# runtime pin closes. So this script prepares, the lane measures, and a preparation failure
# stops the job before the lane can report anything at all.
#
# WHAT IT GUARANTEES. For every version in `[python].interpreters`:
#
#   * that exact patch version is installed (`uv python install <exact>`);
#   * `sdk/python/.venv-cp<major><minor>` exists and holds it;
#   * the abi3 wheel built from THIS tree is installed into it, together with the test
#     dependencies the batteries import.
#
# The wheel is built ONCE. The PyO3 layer is `abi3-py39`, so one artifact serves every
# supported minor — and installing the same bytes everywhere is what makes the matrix a
# measurement of the interpreter rather than of five separate builds.
#
# THE DEPENDENCIES COME FROM THE COMMITTED LOCK, not from loose specifiers written here.
# `sdk/python/uv.lock` is tracked (it was `.gitignore`d as a maturin by-product, which kept
# the resolution out of every fingerprint), so `uv export` gives the one resolution the tree
# describes and the environments differ from each other in the interpreter and nothing else.
# `uv lock --check` refuses a lock that no longer matches `pyproject.toml`, because a stale
# lock would pin a resolution the manifest has moved away from.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
PROJECT="sdk/python"

command -v uv >/dev/null || { echo "prepare_python_matrix: uv is not on PATH." >&2; exit 1; }

readarray -t RUNTIMES < <(python3 - <<'PY'
import sys, tomllib
doc = tomllib.load(open("verification/policy/toolchains.lock.toml", "rb"))
entry = doc.get("python")
if not isinstance(entry, dict) or entry.get("state") != "resolved":
    sys.exit("prepare_python_matrix: [python] is not a resolved pin.")
versions = [str(v) for v in entry.get("interpreters", [])]
if not versions:
    sys.exit("prepare_python_matrix: [python] names no interpreter.")
print("\n".join(sorted(versions)))
PY
)

echo "prepare_python_matrix: ${#RUNTIMES[@]} pinned interpreter(s): ${RUNTIMES[*]}"

# Exact versions, never a minor: `uv python install 3.12` would resolve to whatever patch
# the index offers today, and the lane refuses an environment whose interpreter is not
# exactly the pin — so a loose install here surfaces as a confusing lane failure rather
# than as the unpinned install it is.
uv python install "${RUNTIMES[@]}"

cd "$ROOT/$PROJECT"

echo "prepare_python_matrix: checking the committed lock against pyproject.toml"
uv lock --check

# One resolution for every environment, exported from that lock. `--no-emit-project`
# because the project itself arrives as the built wheel below — installing it from source
# as well would put the tree on `sys.path` beside the artifact and measure the wrong one.
REQS="$(mktemp -t mcp-re-python-matrix)"
trap 'rm -f "$REQS"' EXIT
uv export --quiet --extra dev --no-emit-project --no-hashes -o "$REQS"

# Built with the same pinned Rust toolchain as every other lane: rustup walks up to the
# repository's rust-toolchain.toml from here.
echo "prepare_python_matrix: building the abi3 wheel once"
rm -rf dist
uv run --quiet --extra dev maturin build --release --out dist >/dev/null
WHEEL="$(ls dist/*.whl | head -1)"
[ -n "$WHEEL" ] || { echo "prepare_python_matrix: maturin produced no wheel." >&2; exit 1; }
echo "prepare_python_matrix: wheel $WHEEL"

for version in "${RUNTIMES[@]}"; do
  minor="${version%.*}"
  venv=".venv-cp${minor/./}"
  echo "prepare_python_matrix: $venv <- cpython-$version"
  rm -rf "$venv"
  uv venv --quiet --python "$version" "$venv"
  # The locked resolution first, then the wheel — one `mcp`, one `cryptography`, one
  # `pytest`, identical in all five environments. The wheel is installed WITHOUT its extras
  # here because the export already carries them; naming a dependency again on this line is
  # how a cap pyproject declares gets bypassed, which is what once let a major bump of the
  # upstream SDK break 33 tests on a branch that had not touched the SDK.
  VIRTUAL_ENV="$venv" uv pip install --quiet -r "$REQS"
  VIRTUAL_ENV="$venv" uv pip install --quiet --no-deps "$WHEEL"
  reported="$("$venv/bin/python" -c 'import sys;print("%d.%d.%d" % sys.version_info[:3])')"
  [ "$reported" = "$version" ] || {
    echo "prepare_python_matrix: $venv reports $reported, expected $version." >&2
    exit 1
  }
  # The INSTALLED extension must be importable, and it must be the one just built. A venv
  # that resolves `mcp_re_sdk` from the source tree would measure the tree instead of the
  # artifact, and the batteries would pass with no native core at all.
  "$venv/bin/python" -c 'import mcp_re_sdk._core' >/dev/null
done

echo "prepare_python_matrix: ${#RUNTIMES[@]} environment(s) ready"
