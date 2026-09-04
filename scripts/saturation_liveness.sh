#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# LIVENESS of the standardized capacity instrument. Not a measurement, and it prints no
# throughput number.
#
#   scripts/saturation_liveness.sh
#
# WHAT IT PROVES: the saturation rig can still construct a production-equivalent request
# that this proxy ADMITS, and that a positive request reaches the inner backend. It
# stands up the same three tiers, the same fixtures, the same admission posture
# (transport binding `exact` over the URI SAN, delegated-required response signing) and
# the same replay tier the measurement lane uses, sends a tiny fixed load, and asserts
# zero failures, a non-zero rate and a backend CPU clock that moved.
#
# WHY IT EXISTS: the rig is not on the merge path, so when ADR-MCPRE-064 Slice 4 moved
# the channel-binding operand to the request SUBJECT, the rig kept minting a leaf naming
# the composed actor id. Every request it sent was refused `mcp-re.transport_binding_failed`
# before backend dispatch. It measured nothing for eleven days while every ordinary gate
# stayed green, because nothing anywhere asked the instrument to send one request.
#
# WHAT IT IS NOT: the sweep. It runs one core, one generator and 2000 requests, and it
# reports no capacity figure — the full sweep needs a quiet box and stays out of CI.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null 2>&1 && [[ -z "${MCP_RE_SAT_REDIS_URL:-}" ]]; then
  echo "saturation liveness: no Docker and no MCP_RE_SAT_REDIS_URL — SKIPPING (CI still enforces it)."
  exit 0
fi

. scripts/lib/sat_replay_fleet.sh
trap sat_fleet_down EXIT
sat_fleet_up || exit 2

# Debug binaries: this lane asserts admission, never speed, and an optimized build would
# add minutes to every pull request to prove the same thing.
echo "saturation liveness: building the rig (debug)"
cargo build -p mcp-re-proxy --features async_serve,redis_replay --bins --examples

export MCP_RE_PROXY_CLI="target/debug/mcp-re-proxy"
export CARGO_BIN_EXE_DIR="target/debug/examples"

target/debug/examples/saturation_rig --smoke
