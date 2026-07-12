#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Deterministic code-coverage runner + gate. ONE command, no freelancing:
#   scripts/coverage.sh              # summary + enforce the ≥90% line gate
#   scripts/coverage.sh --html       # also write an HTML report under target/llvm-cov
#   scripts/coverage.sh --open       # open the HTML report
#
# It resolves the LLVM tools from the repo's PINNED toolchain (rust-toolchain.toml),
# not the ambient one — the 1.94.x toolchain ships the tools under the `llvm-tools`
# component but names the binaries `llvm-cov`/`llvm-profdata` in
# lib/rustlib/<host>/bin, which cargo-llvm-cov does not find on its own. We point it
# there explicitly so the run is reproducible on any machine with the pinned
# toolchain + `rustup component add llvm-tools`.
set -euo pipefail
cd "$(dirname "$0")/.."

# The floor the suite must hold, on REGION coverage — the finer, per-branch metric
# (every conditional region, not just whole lines). Line coverage is ALSO printed in
# the summary for transparency; its small residual is feature-gated adapter code
# (KMS/pkcs11/etcd/OCSP), the delegated-TLS path, and Redis-fault branches — compiled
# but off/unreachable in this build. Raising this floor is a deliberate ratchet.
GATE="${COVERAGE_MIN_REGIONS:-90}"

cargo llvm-cov --version >/dev/null 2>&1 \
  || { echo "cargo-llvm-cov not installed — run: cargo install cargo-llvm-cov" >&2; exit 1; }

# Resolve the pinned toolchain's LLVM tools (host-triple bin dir under its sysroot).
TC="$(rustup show active-toolchain 2>/dev/null | awk '{print $1}')"
[[ -n "$TC" ]] || { echo "no active rustup toolchain" >&2; exit 1; }
rustup component add llvm-tools --toolchain "$TC" >/dev/null 2>&1 || true
TC_SYSROOT="$(rustc +"$TC" --print sysroot 2>/dev/null || echo "$HOME/.rustup/toolchains/$TC")"
LLVM_BIN="$(dirname "$(find "$TC_SYSROOT" -name llvm-cov -type f 2>/dev/null | head -1)")"
[[ -n "$LLVM_BIN" && -x "$LLVM_BIN/llvm-cov" ]] \
  || { echo "llvm-cov not found in $TC_SYSROOT (run: rustup component add llvm-tools --toolchain $TC)" >&2; exit 1; }
export LLVM_COV="$LLVM_BIN/llvm-cov"
export LLVM_PROFDATA="$LLVM_BIN/llvm-profdata"

# The deployed serving path (app::run / async_serve / async_fleet / http_profile_serve)
# is exercised ONLY by the IN-PROCESS integration test in tls_load_harness_bench,
# which stands up a Redis fleet — so coverage MUST enable `redis_replay` (and needs
# Docker). A spawned-binary subprocess does NOT contribute coverage (verified), which
# is why the harness drives `app::run` in-process. The heavy load bench is capped low
# here: coverage cares about lines hit, not throughput.
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 \
  || { echo "docker daemon required (the serve-path coverage stands up a Redis fleet)" >&2; exit 1; }
export MCP_RE_LOADGEN_REQUESTS="${MCP_RE_LOADGEN_REQUESTS:-200}"
export MCP_RE_LOADGEN_CONCURRENCY="${MCP_RE_LOADGEN_CONCURRENCY:-16}"

EXTRA=()
case "${1:-}" in
  --html) EXTRA=(--html) ;;
  --open) EXTRA=(--html --open) ;;
esac

# Excluded from the gate:
#   * mcp-re-proxy/src/main.rs — the irreducible binary shim (argv + signal handlers)
#     AFTER its serve orchestration was moved into the covered `app::run`.
#   * mcp-re-test-paths — a test-only runfiles helper, not product code.
IGNORE='(mcp-re-proxy/src/main\.rs|mcp-re-test-paths/)'

echo "coverage: toolchain=$TC  llvm=$LLVM_BIN  gate=${GATE}% regions  (features: redis_replay)"
cargo llvm-cov --workspace --features redis_replay --summary-only \
  --ignore-filename-regex "$IGNORE" \
  --fail-under-regions "$GATE" "${EXTRA[@]}"
