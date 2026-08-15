#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run a cargo test lane and REFUSE a run that selected no tests.
#
# Naming a test binary that does not exist is loud — cargo exits 101. Naming a
# module filter that matches nothing is silent: libtest prints
# `test result: ok. 0 passed` and exits 0. Since the proxy's suites were
# consolidated into shared binaries, every named lane selects by filter, so
# every named lane can now pass having measured nothing. That is the one failure
# mode a release gate must not have.
#
# Usage:  scripts/run_test_lane.sh cargo test -p pkg --test bin -- module::
#
# Runs the command verbatim, then sums the `N passed` across every test binary
# it reported and fails if the total is zero. `--ignored` lanes are the reason
# this is not optional: a wrong filter plus `--ignored` selects nothing twice
# over, and those are the live-endpoint lanes nobody re-runs casually.
set -uo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: $0 cargo test -p <pkg> --test <bin> -- <module>::" >&2
  exit 2
fi

output="$("$@" 2>&1)"
status=$?
printf '%s\n' "$output"

if [[ $status -ne 0 ]]; then
  exit "$status"
fi

passed="$(
  printf '%s\n' "$output" \
    | sed -n 's/^test result: ok\. \([0-9]*\) passed.*/\1/p' \
    | awk '{ total += $1 } END { print total + 0 }'
)"

if [[ "$passed" -eq 0 ]]; then
  echo "" >&2
  echo "FAIL: this lane exited 0 having run ZERO tests." >&2
  echo "  command: $*" >&2
  echo "  A filter that matches no test is not a pass. Check the module filter" >&2
  echo "  against the modules declared in the binary's main.rs." >&2
  exit 1
fi

echo "lane ran ${passed} test(s)"
