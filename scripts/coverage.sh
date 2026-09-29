#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Deterministic code-coverage runner + gate. ONE command, no freelancing:
#   scripts/coverage.sh                      # summary + enforce the region floor
#   scripts/coverage.sh --html               # also write an HTML report under .coverage-report/html
#   scripts/coverage.sh --targets '//a:t …'  # measure only these test targets (no gate)
#
# `bazel coverage` runs the tests instrumented and keeps each test's raw profiles
# (`--experimental_fetch_all_coverage_outputs`). The floor is on REGION coverage — the finer,
# per-branch metric — which Bazel's LCOV report does not carry, so the profiles are merged
# and read with the `llvm-profdata`/`llvm-cov` of the registered Rust toolchain
# (`//bazel/coverage:llvm_tools`), the one that instrumented them. Lines and functions are
# printed alongside for transparency; the residue is feature-gated adapter code
# (KMS/pkcs11/etcd/OCSP), the delegated-TLS path, and Redis-fault branches.
set -euo pipefail
cd "$(dirname "$0")/.."

# The floor the suite must hold. Raising it is a deliberate ratchet.
GATE="${COVERAGE_MIN_REGIONS:-90}"

HTML=0
TARGETS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --html) HTML=1; shift ;;
    --targets) TARGETS="${2:?--targets needs a space-separated label list}"; shift 2 ;;
    -h|--help) sed -n '3,15p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# Instrumented: every first-party package except the test-only runfiles helper.
FILTER='^//,-^//mcp-re-test-paths[/:]'
# Excluded from the report:
#   * mcp-re-proxy/src/main.rs — the irreducible binary shim (argv + signal handlers)
#     AFTER its serve orchestration was moved into the covered `app::run`.
#   * test, example and bench sources — they are the measurement, not the measured.
#   * third-party and standard-library sources.
IGNORE='(^|/)external/|^/rustc/|(^|/)(tests|examples|benches)/|mcp-re-proxy/src/main\.rs'
FLAGS=(--instrumentation_filter="$FILTER")

GATED=1
if [[ -z "$TARGETS" ]]; then
  # The deployed serving path (app::run / async_serve / async_fleet / http_profile_serve)
  # is exercised in-process only by the `manual` tls_load_harness_bench, which stands up a
  # Redis fleet — so the gated run adds it to every non-manual test, and needs Docker.
  # The load is capped low: coverage cares about lines hit, not throughput.
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 \
    || { echo "docker daemon required (the serve-path coverage stands up a Redis fleet)" >&2; exit 1; }
  export MCP_RE_LOADGEN_REQUESTS="${MCP_RE_LOADGEN_REQUESTS:-200}"
  export MCP_RE_LOADGEN_CONCURRENCY="${MCP_RE_LOADGEN_CONCURRENCY:-16}"
  TARGETS="$(bazel query --output=label \
    'kind("rust_test rule", //...) except attr(tags, "\bmanual\b", //...)' 2>/dev/null | tr '\n' ' ')"
  TARGETS+=" //mcp-re-proxy:tls_load_harness_bench"
else
  GATED=0
fi
read -r -a LABELS <<<"$TARGETS"
[[ ${#LABELS[@]} -gt 0 ]] || { echo "coverage: no test target selected — nothing to measure" >&2; exit 1; }

echo "coverage: ${#LABELS[@]} test target(s), gate=${GATE}% regions"
bazel coverage "${FLAGS[@]}" \
  --experimental_fetch_all_coverage_outputs --experimental_split_coverage_postprocessing \
  --test_output=errors "${LABELS[@]}"

EXEC_ROOT="$(bazel info execution_root 2>/dev/null)"
TESTLOGS="$(bazel info bazel-testlogs 2>/dev/null)"
tools="$(bazel cquery --output=files //bazel/coverage:llvm_tools 2>/dev/null)"
LLVM_COV="$EXEC_ROOT/$(grep '/llvm-cov$' <<<"$tools")"
LLVM_PROFDATA="$EXEC_ROOT/$(grep '/llvm-profdata$' <<<"$tools")"
[[ -x "$LLVM_COV" && -x "$LLVM_PROFDATA" ]] \
  || { echo "coverage: //bazel/coverage:llvm_tools resolved no llvm-cov/llvm-profdata" >&2; exit 1; }

# The instrumented test binaries, in the configuration `bazel coverage` built them in.
OBJECTS=()
while IFS= read -r f; do
  [[ -f "$EXEC_ROOT/$f" ]] && OBJECTS+=(-object "$EXEC_ROOT/$f")
done < <(bazel cquery --collect_code_coverage "${FLAGS[@]}" --output=files "set(${LABELS[*]})" 2>/dev/null)

PROFILES=()
for label in "${LABELS[@]}"; do
  pkg="${label#//}"; pkg="${pkg%%:*}"; name="${label##*:}"
  while IFS= read -r p; do PROFILES+=("$p"); done \
    < <(find -L "$TESTLOGS/$pkg/$name" -path '*/_coverage/*.profraw' 2>/dev/null)
done
[[ ${#PROFILES[@]} -gt 0 && ${#OBJECTS[@]} -gt 0 ]] \
  || { echo "coverage: no raw profile or no instrumented binary — this run measured nothing" >&2; exit 1; }

OUT=.coverage-report
mkdir -p "$OUT"
"$LLVM_PROFDATA" merge -sparse "${PROFILES[@]}" -o "$OUT/merged.profdata"
COV=("-instr-profile=$OUT/merged.profdata" "-ignore-filename-regex=$IGNORE")
"$LLVM_COV" report "${COV[@]}" "${OBJECTS[@]}" | tail -1
if [[ $HTML -eq 1 ]]; then
  "$LLVM_COV" show -format=html -output-dir="$OUT/html" "${COV[@]}" "${OBJECTS[@]}"
  echo "coverage: HTML report in $OUT/html/index.html"
fi

"$LLVM_COV" export -summary-only "${COV[@]}" "${OBJECTS[@]}" >"$OUT/summary.json"
python3 - "$OUT/summary.json" "$GATE" "$GATED" <<'PY'
import json, sys
totals = json.load(open(sys.argv[1]))["data"][0]["totals"]
gate, gated = float(sys.argv[2]), sys.argv[3] == "1"
for k in ("regions", "functions", "lines"):
    t = totals[k]
    print(f"coverage: {k:<9} {t['covered']}/{t['count']}  {t['percent']:.2f}%")
if totals["regions"]["count"] == 0:
    sys.exit("coverage: FAIL — zero regions measured; a report over nothing is not a pass")
if not gated:
    print("coverage: targeted run — the region floor is enforced on the full selection only")
    sys.exit(0)
pct = totals["regions"]["percent"]
if pct < gate:
    sys.exit(f"coverage: FAIL — regions {pct:.2f}% is under the {gate:g}% floor")
print(f"coverage: PASS — regions {pct:.2f}% >= {gate:g}%")
PY
