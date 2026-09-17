#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Mutation probe for `scripts/run_gate.sh`: prove the wrapper reports a FAILED stage as a
# non-zero exit even when a successful reporting step follows it.
#
# A control that is only ever exercised by passing gates establishes nothing — the defect
# it exists for is invisible until something fails. So every case below INJECTS a
# synthetic gate with a known verdict and a known status, and asserts the wrapper's own
# exit status. Case 1 is the measured instance: a gate that fails at stage 1, followed by a
# grep that matches and exits 0.
#
# Run:  scripts/run_gate.sh --selftest
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
RUN_GATE="$HERE/run_gate.sh"
TMP="$(mktemp -d -t run_gate_selftest.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

ok=1

# A synthetic gate: prints the lines it is given, exits with the status it is given.
#
# The lines go in a DATA file the gate `cat`s, rather than being quoted into generated
# shell. The first version of this helper built `printf` calls and lost the trailing
# newlines, so two verdict lines arrived as one and case 5 passed against a wrapper that
# had not been exercised — a fixture defect that reads exactly like a working control.
make_gate() { # make_gate <name> <exit-status> <line>...
  local name="$1" code="$2"; shift 2
  local path="$TMP/$name" data="$TMP/$name.out"
  : > "$data"
  local line
  for line in "$@"; do printf '%s\n' "$line" >> "$data"; done
  {
    echo '#!/usr/bin/env bash'
    printf 'cat %s\n' "'$data'"
    echo "exit $code"
  } > "$path"
  chmod +x "$path"
  echo "$path"
}

check() { # check <name> <expected-nonzero|expected-zero> <actual-status>
  local name="$1" want="$2" got="$3"
  if [[ "$want" == "zero" && "$got" -eq 0 ]] || [[ "$want" == "nonzero" && "$got" -ne 0 ]]; then
    printf '  ok    %s (exit %s)\n' "$name" "$got"
  else
    printf '  FAIL  %s: wanted %s, got exit %s\n' "$name" "$want" "$got"
    ok=0
  fi
}

# --- 1. THE MEASURED DEFECT -------------------------------------------------------
# A gate that fails, then a successful reporting step. The bare redirect-then-grep shell
# form exits 0 here; the wrapper must not.
gate="$(make_gate failing_gate 1 \
  '[stage 1] FAILED: static gates' \
  'LOCAL GATE: FAIL (stage 1 — static gates)')"
"$RUN_GATE" --log "$TMP/log1" -- "$gate" >/dev/null 2>&1
check "a failed stage followed by a successful report exits non-zero" nonzero "$?"

# And the control is not vacuous: show the broken form really does read as success, so
# this case is measuring the difference rather than restating that 1 != 0.
( "$gate" > "$TMP/log1b" 2>&1; grep -q 'LOCAL GATE' "$TMP/log1b" ) >/dev/null 2>&1
broken_status=$?
if [[ "$broken_status" -eq 0 ]]; then
  printf '  ok    the bare redirect-then-grep form does read 0 (the defect is real)\n'
else
  printf '  FAIL  the bare form exited %s; this probe no longer reproduces the defect\n' \
    "$broken_status"
  ok=0
fi

# --- 2. THE PASSING DIRECTION -----------------------------------------------------
# The invariant has two halves and a wrapper that always failed would satisfy case 1.
gate="$(make_gate passing_gate 0 'LOCAL GATE: PASS (stages 1-2)')"
"$RUN_GATE" --log "$TMP/log2" -- "$gate" >/dev/null 2>&1
check "a clean run stating PASS exits zero" zero "$?"

# --- 3. A GREEN THAT MEASURED NOTHING ---------------------------------------------
# Exit 0 with no verdict line: the run did not finish.
gate="$(make_gate silent_gate 0 'some output' 'more output')"
"$RUN_GATE" --log "$TMP/log3" -- "$gate" >/dev/null 2>&1
check "exit 0 with no verdict line exits non-zero" nonzero "$?"

# ...unless the caller declared the command has no verdict line to state.
"$RUN_GATE" --log "$TMP/log3b" --no-require-verdict -- "$gate" >/dev/null 2>&1
check "the same run passes when no verdict is required" zero "$?"

# --- 4. A VERDICT AND A STATUS THAT DISAGREE --------------------------------------
# The exact shape the invariant is about, from the other side: a gate that states FAIL
# and exits 0 anyway.
gate="$(make_gate lying_gate 0 'LOCAL GATE: FAIL (stage 3 — bazel parity)')"
"$RUN_GATE" --log "$TMP/log4" -- "$gate" >/dev/null 2>&1
check "exit 0 while stating FAIL exits non-zero" nonzero "$?"

# --- 5. TWO VERDICTS ---------------------------------------------------------------
# One log holding two runs' output states no single answer for this run.
gate="$(make_gate double_gate 0 \
  'LOCAL GATE: PASS (stages 1-2)' \
  'LOCAL GATE: PASS (stages 1-2)')"
"$RUN_GATE" --log "$TMP/log5" -- "$gate" >/dev/null 2>&1
check "two verdict lines exit non-zero" nonzero "$?"

# --- 6. A STATUS OTHER THAN 1 SURVIVES ---------------------------------------------
# The command's own status is propagated, not flattened to 1 — a killed gate (137/143)
# and a failed one are different facts.
gate="$(make_gate killed_gate 143 'LOCAL GATE: FAIL (stage 2 — cargo suites)')"
"$RUN_GATE" --log "$TMP/log6" -- "$gate" >/dev/null 2>&1
status=$?
if [[ "$status" -eq 143 ]]; then
  printf '  ok    the command'\''s own exit status is propagated (143)\n'
else
  printf '  FAIL  expected the command status 143 to propagate, got %s\n' "$status"
  ok=0
fi

# --- 7. A COMMAND THAT DOES NOT EXIST ----------------------------------------------
"$RUN_GATE" --log "$TMP/log7" -- "$TMP/no-such-gate" >/dev/null 2>&1
check "an unrunnable command exits non-zero" nonzero "$?"

if [[ "$ok" -eq 1 ]]; then
  echo "run_gate: selftest passed"
  exit 0
fi
echo "run_gate: selftest FAILED" >&2
exit 1
