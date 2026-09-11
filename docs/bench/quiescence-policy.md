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


## Re-measured 2026-09-11, after a THIRD VM was added

The dedicated `colima-slo` profile is persistent infrastructure, so it raises dev1's idle
floor and the policy had to be re-checked against it. 120 samples over
19.9 minutes:

```
                     load1   load5   load15
  2-VM floor (was)    0.099   0.125   0.113
  3-VM clean floor    0.110   0.151   0.178
  3-VM clean max      0.256   0.238   0.240
  threshold           0.200   0.250   0.300
```

95 of 120 samples satisfy the policy and the longest consecutive quiet streak is 45,
against a requirement of 6. **The policy is unchanged.**

### The measurement that was thrown away, and why

A first re-measurement reported 0/46 satisfying samples and an unreachable policy. It was
taken over 7.6 minutes immediately after booting the VM, pulling an image, deleting 40 image
layers and running two `fstrim`s — and `load15` has a 15-minute time constant, so it could
not possibly have decayed. Its 0.861 load1 peak was the setup work itself.

Retuning against it would have permanently loosened the thresholds to accommodate a
transient, and would have been indistinguishable from tuning until the gate goes green.
The discarded samples are NOT kept, because a contaminated series invites exactly the
comparison that should not be made; this note is the record that it happened.
