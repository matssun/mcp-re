# dev1 quiescence policy — measured, not chosen

Measured 2026-09-10 on dev1: 151 samples at 10 s intervals over 25.0 minutes, 14 CPUs. Raw samples: `quiescence-samples.jsonl`.

## Why load1 alone was insufficient

The previous rule read the 1-minute load average once and admitted the measurement. The
failed SLO run shows the gap that leaves, as fractions of CPU count:

```
                  load1   load5   load15
  dev1 at rest     0.10    0.12    0.11   <- floor: 3 runner listeners + 2 colima VMs
  dev1 at-rest max 1.20    0.42    0.27
  THE FAILED RUN   0.25    0.41    0.40
  threshold        0.20    0.25    0.30
```

Read the load1 column. The failed run's load1 was 0.25 against an idle floor of
0.10 and an ordinary at-rest peak of 1.20 — load1 BARELY separates a
contended host from an idle one, which is precisely how a one-sample load1 rule declared
that box quiet while it was still working through another runner's job.

**load5 and load15 carry the discrimination**, exceeding their thresholds by 64% and 33%.
load1 is retained only as a fast-moving corroborator.

## Why consecutive samples

dev1's load1 touches 1.20 at rest under ordinary background activity, so any
single sample is noisy. Six consecutive quiet observations at 10 s means ~60 s of SUSTAINED
quiet, which no transient satisfies.

## Reachability is a requirement, not an afterthought

A threshold below the measured floor would make the lane permanently INCONCLUSIVE. The
controls in `tools/slo/test_host_gate.py` therefore assert BOTH directions: the failed
run's reading is refused, and dev1's measured idle floor is admitted.
