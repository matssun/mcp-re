# The test lane could not read a coloured report — 2026-09-06

A platform defect found while establishing the THM-0104 correction, and fixed here. It
belongs to the class **#739** owns: *the false-green classes that gate trusting ESTABLISHED*.
This instance is a false RED rather than a false green, which is the safe direction — but it
states something false about the tests, and a reader acting on it goes to the wrong file.

## 1. What happened

`verify --gate` reported `VERIFICATION: FAIL — test`. `verify-tests` reproduced it:

```
FAIL: cpython-3.14.7 pytest: 39 of 39 declared test(s) did not pass:
  tests/test_correlation.py::TestFailsClosed::test_a_late_response_is_rejected (never ran), …
```

Every one of those thirty-nine controls had just passed. Running the lane's own argv, in the
lane's own working directory, in the pinned `.venv-cp314`, gave `39 passed in 3.05s`; each
symbol re-run alone passed as well. The unit's whole declared battery was green and the lane
said it never ran.

## 2. The cause

`pytest` honours `FORCE_COLOR` **even when its stdout is a pipe**, and the invoking
environment had `FORCE_COLOR=3`. So the status line arrived as

```
tests/test_x.py::test_one ESC[32mPASSED ESC[0m ESC[32m [ 50%] ESC[0m
```

`_PYTEST_RESULT` matches a WORD at a known position — `^(?P<name>\S+::\S+)\s+(?P<status>PASSED|…)`
— and an escape sequence in front of that word makes the line unmatchable while leaving it
perfectly legible to a human reading the log. Nothing parsed, so `observed` was empty, so
every declared symbol fell into the `missing` branch and was reported as `never ran`.

The re-run path did not save it: re-running an unreadable report produces another unreadable
report.

**An environment variable set by whatever invoked the lane decided whether the lane could
read its own evidence.** That is the defect. The tests, the runner and the pin were all fine.

## 3. The fix, in three parts

1. **`--color=no` in the pytest argv.** The runner is told what to emit rather than the lane
   guessing what it meant — the same reasoning that already put `-p no:randomly` there.
2. **ANSI stripped before any line is matched, for every line-scraping runner.** So the lane
   does not depend on one runner honouring one flag. Cargo was not affected today (libtest
   does not read `FORCE_COLOR`), and this makes that a property of the reader rather than a
   fact about libtest.
3. **A collected run this reader cannot read is a READING failure.** pytest states how many
   cases it collected; a run that collected some and yielded no status the lane understands
   now raises `ReportUnreadable` instead of reporting absent tests.

Part 3 is the one that matters beyond this bug. The project already holds the rule — *an
unread report is not a battery of absent tests; a lane that cannot parse a runner fails as
its own reading failure* — and the vitest reader enforces it. The pytest reader did not:
it degraded silently to an empty result set, which is indistinguishable from a suite in which
no declared control ran. **The two verdicts call for opposite next actions.** `never ran`
sends a reader to the test files; unreadable sends them to the lane.

## 4. Controls

| control | asserts |
|---|---|
| `test_the_python_command_runs_the_prepared_environment_for_that_runtime` (extended) | `--color=no` reaches the runner |
| `test_a_coloured_pytest_report_is_still_read` | a report that arrives coloured anyway is read, both PASSED and FAILED |
| `test_a_collected_run_this_lane_cannot_read_is_a_reading_failure_not_absent_tests` | collected > 0 with nothing parsed raises `ReportUnreadable`, naming the count |
| `test_a_run_that_collected_nothing_is_not_called_unreadable` | an EMPTY selection stays `never ran` — otherwise the `--exact` selection stops catching a declared symbol that does not exist |

Red-verified 2026-09-06: with the ANSI strip removed the suite goes red; restored, green.
All fourteen `tools/verification/test_*.py` suites re-run, 0 failures — a change to any of
them means running all of them, because they hand-load each other.

## 5. Consequence for the graph

None to any claim. No theorem's statement, scope or dependency moved, and no unit's declared
battery changed. What changed is that the lane can read a report it was already being given.
`sdk_python.exchange_path` measures `39 passed` again.

## 6. The general rule this is the third instance of

> A lane's result is only as good as its ability to say what it measured.

The first two are recorded: `tls_load_harness_bench` selecting zero tests and exiting 0, and
`verify-mutations` building its battery without `--features` so a feature-gated control
compiled to nothing (#822). This is the third, and it is the mirror image — the battery ran
and the lane could not read the answer. All three have the same repair: make the measurement
name its own conditions rather than inherit them from the machine that happened to run it.
