#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Refuse to start a verification lane on a host that cannot run it.
#
# The self-hosted runner is persistent, and the job PATH it uses is NOT the
# operator's login PATH — it comes from the runner service's own `.env`. So the
# same box that verifies by hand can fail the lane, and the failure surfaces
# deep inside a step as `ModuleNotFoundError: tomllib` or
# `verus: rustup not found`. Both name a symptom in a tool nobody was thinking
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

# --- Verus resolves its toolchain through rustup ------------------------------
# The Verus release archive ships its own Z3 but NOT a compiler: it shells out to
# rustup to find the pinned channel. rustup lives in ~/.cargo/bin, which a
# service PATH assembled from /usr/bin and Homebrew alone does not contain.
rustup_path="$(command -v rustup || true)"
if [[ -z "$rustup_path" ]]; then
  fail "no rustup on the lane PATH — Verus cannot resolve the pinned channel."
else
  echo "rustup at ${rustup_path}"
fi

# --- rustup must actually resolve the pinned channel ---------------------------
# Checked by resolving it, not by inspecting PATH. A directory-prefix heuristic
# would call this box healthy: its `cargo` is Homebrew's `rust` formula rather
# than a rustup shim, and it sits in the same directory as rustup. What Verus
# needs is not a well-arranged PATH but a rustup that hands back the pinned
# compiler, so ask for that.
if [[ -n "$rustup_path" ]]; then
  channel="$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' rust-toolchain.toml | head -n 1)"
  if [[ -z "$channel" ]]; then
    fail "no channel found in rust-toolchain.toml."
  elif resolved="$(rustup run "$channel" rustc --version 2>&1)"; then
    echo "rustup resolves ${channel}: ${resolved}"
  else
    fail "rustup cannot resolve the pinned channel ${channel}: ${resolved}"
  fi
fi

if [[ $failed -ne 0 ]]; then
  cat >&2 <<'REMEDY'

The lane PATH is set by the runner service, not by the login shell. Fix it in
the runner's own `.env` (next to `svc.sh`), then restart the service:

  PATH=/Users/mats/.cargo/bin:/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin

  ./svc.sh stop && ./svc.sh start

~/.cargo/bin FIRST is not cosmetic: Homebrew's cargo would otherwise shadow the
rustup shim. See docs/dev/verification-runner.md.
REMEDY
  exit 1
fi

echo "PREFLIGHT PASS: the runner environment can run this lane."
