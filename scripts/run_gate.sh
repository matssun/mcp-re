#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run a gate so that its VERDICT and its EXIT STATUS are the same fact.
#
# THE FAILURE CLASS, which is why this exists rather than a rule in a document.
#
# A gate's result is read two ways: the line it prints, and the status it exits with. Both
# are correct at the source — `scripts/local_gate.sh` prints exactly one `LOCAL GATE:` line
# and exits non-zero on failure. They come apart in the INVOCATION, and every way of
# reading the output is a way of losing the status:
#
#     scripts/local_gate.sh --fast | tail            # tail's status, always 0
#     scripts/local_gate.sh --fast > log; grep X log # grep's status, 0 when it matched
#
# Both have happened in this repository. The second is the subtler one, because it looks
# like the careful form: the output is kept, the verdict line is even printed — and the
# caller still reads 0 for a run that failed at stage 1. CLAUDE.md's "never read a gate's
# result through a pipe" is the rule; this is the mechanism, and a rule whose only
# enforcement is remembering it is the class this whole gate suite exists to remove.
#
# THE INVARIANT, in both directions:
#
#     any required stage FAILS   =>  this wrapper exits non-zero
#     all required stages PASS   =>  this wrapper exits zero
#
# and one more, which is the same rule applied to a green that measured nothing:
#
#     the command exits 0 but prints no verdict line, or prints a FAIL one,
#     or prints more than one                          =>  exits non-zero
#
# A run that ended without stating a verdict did not finish, whatever it exited with.
#
# Usage:
#   scripts/run_gate.sh [--log PATH] [--verdict-prefix P] [--no-require-verdict] -- CMD...
#   scripts/run_gate.sh --selftest
#
# The command's output goes to the terminal AND to the log. The status this exits with is
# the COMMAND's, never the tee's, never the grep's.
set -uo pipefail

VERDICT_PREFIX="LOCAL GATE:"
REQUIRE_VERDICT=1
LOG=""

usage() {
  sed -n '3,40p' "$0" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --log) LOG="${2:?--log needs a path}"; shift 2 ;;
    --verdict-prefix) VERDICT_PREFIX="${2:?--verdict-prefix needs a string}"; shift 2 ;;
    --no-require-verdict) REQUIRE_VERDICT=0; shift ;;
    --selftest) exec "$(dirname "$0")/run_gate_selftest.sh" ;;
    --) shift; break ;;
    -h|--help) usage ;;
    *) echo "run_gate: unknown option '$1'" >&2; usage ;;
  esac
done

if [[ $# -eq 0 ]]; then
  echo "run_gate: no command given" >&2
  usage
fi

if [[ -z "$LOG" ]]; then
  LOG="$(mktemp -t run_gate.XXXXXX)"
fi

# `tee` is in the pipeline, so `$?` here is TEE's status. PIPESTATUS[0] is the command's,
# and reading it is the entire point of this file.
"$@" 2>&1 | tee "$LOG"
status="${PIPESTATUS[0]}"

# The verdict, read from what the run actually printed.
verdicts="$(grep -c -- "^${VERDICT_PREFIX}" "$LOG" 2>/dev/null || true)"
verdicts="${verdicts//[^0-9]/}"
: "${verdicts:=0}"

printf '\n---------------------------------------------------------------------\n'
printf 'run_gate: command exited %s\n' "$status"

if (( verdicts == 1 )); then
  printf 'run_gate: verdict  %s\n' "$(grep -- "^${VERDICT_PREFIX}" "$LOG" | head -n 1)"
else
  printf 'run_gate: verdict  <%s line(s) matching "%s">\n' "$verdicts" "$VERDICT_PREFIX"
fi
printf 'run_gate: log      %s\n' "$LOG"

# 1. A non-zero command is a failure, whatever it printed. Reported first because it is
#    the case the broken invocation forms lose.
if (( status != 0 )); then
  printf 'run_gate: FAIL — the gate exited %s\n' "$status"
  printf -- '---------------------------------------------------------------------\n'
  exit "$status"
fi

# 2. A zero exit still has to have STATED something, and exactly once. Two verdict lines
#    means two runs' output in one log, and neither is this run's answer.
if (( REQUIRE_VERDICT )); then
  if (( verdicts == 0 )); then
    printf 'run_gate: FAIL — exited 0 but printed no "%s" line, so the run did not finish\n' \
      "$VERDICT_PREFIX"
    printf -- '---------------------------------------------------------------------\n'
    exit 1
  fi
  if (( verdicts > 1 )); then
    printf 'run_gate: FAIL — %s "%s" lines; a run states its verdict exactly once\n' \
      "$verdicts" "$VERDICT_PREFIX"
    printf -- '---------------------------------------------------------------------\n'
    exit 1
  fi
  if grep -q -- "^${VERDICT_PREFIX}.*FAIL" "$LOG"; then
    printf 'run_gate: FAIL — exited 0 while stating FAIL; the two must be one fact\n'
    printf -- '---------------------------------------------------------------------\n'
    exit 1
  fi
fi

printf 'run_gate: PASS\n'
printf -- '---------------------------------------------------------------------\n'
exit 0
