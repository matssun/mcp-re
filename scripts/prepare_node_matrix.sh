#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Prepare one Node runtime per PINNED version for the TypeScript SDK battery —
# ADR-MCPRE-059 §28 / issue #747, the sibling of `prepare_python_matrix.sh`.
#
# WHY THIS IS A PREPARATION STEP AND NOT PART OF THE LANE. `tools/verification/verify-tests`
# measures whatever environment it finds and refuses to build one: a lane that builds what it
# measures can report a battery it has just made pass, and a lane that resolves its own
# runtime picks whatever the machine offers — which is the gap `[typescript].interpreters`
# closes. So this prepares, the lane measures, and a preparation failure stops the job before
# the lane can report anything.
#
# WHERE THE BINARIES COME FROM. `npm install node@<exact>`: the official distribution,
# published to the registry, fetched by exact version and integrity-checked by npm like any
# other dependency. No external version manager is assumed on the runner — one more
# unpinned tool deciding which runtime the evidence describes is precisely what this exists
# to remove.
#
# ONE BUILD, MANY RUNTIMES. The native addon is N-API, whose ABI is stable across Node
# versions by construction, so `npm run build` runs once and every runtime loads the same
# artifact. That is what makes the matrix a measurement of the runtime rather than of four
# separate builds.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
PROJECT="sdk/typescript"

command -v npm >/dev/null || { echo "prepare_node_matrix: npm is not on PATH." >&2; exit 1; }

readarray -t RUNTIMES < <(python3 - <<'PY'
import sys, tomllib
doc = tomllib.load(open("verification/policy/toolchains.lock.toml", "rb"))
entry = doc.get("typescript")
if not isinstance(entry, dict) or entry.get("state") != "resolved":
    sys.exit("prepare_node_matrix: [typescript] is not a resolved pin.")
versions = [str(v) for v in entry.get("interpreters", [])]
if not versions:
    sys.exit("prepare_node_matrix: [typescript] names no runtime.")
print("\n".join(sorted(versions)))
PY
)

echo "prepare_node_matrix: ${#RUNTIMES[@]} pinned runtime(s): ${RUNTIMES[*]}"

cd "$ROOT/$PROJECT"

# The project's own dependencies and build, once. `npm ci` rather than `npm install`: the
# lockfile is the resolution the fingerprint carries, and `ci` is the command that refuses
# to drift from it.
echo "prepare_node_matrix: installing the locked dependencies and building once"
npm ci --silent
npm run --silent build

for version in "${RUNTIMES[@]}"; do
  major="${version%%.*}"
  dir=".node-v${major}"
  echo "prepare_node_matrix: $dir <- node@$version"
  rm -rf "$dir"
  mkdir -p "$dir"
  # ITS OWN package.json, and it is load-bearing rather than tidiness: `npm install` run in
  # a directory without one walks UP to the nearest ancestor package and installs there. The
  # first version of this script did exactly that, putting the Node runtime into the SDK's
  # own `node_modules` — the tool that runs the tests inside the tree that ships. A manifest
  # here makes this directory the project root for that install.
  printf '{"name":"mcp-re-node-runtime","private":true,"version":"0.0.0"}\n' > "$dir/package.json"
  # `--no-save` on top: nothing about this runtime belongs in a dependency graph.
  npm install --silent --prefix "$dir" --no-save --no-package-lock "node@${version}"
  binary="$dir/node_modules/node/bin/node"
  [ -x "$binary" ] || { echo "prepare_node_matrix: $binary is missing." >&2; exit 1; }
  reported="$("$binary" -p 'process.versions.node')"
  [ "$reported" = "$version" ] || {
    echo "prepare_node_matrix: $dir reports $reported, expected $version." >&2
    exit 1
  }
  # The battery imports the BUILT package; a runtime that cannot load the native addon
  # would fail every control for a reason that is not the property under test.
  "$binary" -e 'require("./native/binding.js")' >/dev/null
done

echo "prepare_node_matrix: ${#RUNTIMES[@]} runtime(s) ready"
