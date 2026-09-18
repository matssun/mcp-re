# ADR-MCPRE-068 Phase 2, slice 1 — the mutation lane reaches the two SDK roots

Phase-1 closure derived the Phase-2 order from the graph rather than from the N1 table, and
this is what it put first. The reasoning is worth restating because it inverts the obvious
answer:

| lane | N1 rows | critical | roots unblocked | mechanism existed? |
|---|---|---|---|---|
| `python-falsifier-lane` | 13 | 10 | THM-0094 (whole root) | **no** |
| `node-falsifier-lane` | 14 | 11 | THM-0095 (whole root) | **no** |
| `cargo-mutation-lane` | 60 | 34 | 9 roots | yes — 199 probes |

The cargo lane holds the most Critical obligations and is not first. Its mechanism exists,
so each of its 60 rows is an individual falsifier against a working lane. The two SDK lanes
had no mechanism at all: 27 obligations and two entire system roots were blocked on
building each one once.

## 1. What actually blocked it, which was not what it looked like

`test_package_for` is ecosystem-aware and answers `sdk/python` for an `sdk_python.*` unit,
so resolution was never the problem — a first draft of this work "fixed" a refusal that
does not exist, and the comment asserting it was removed. `run_battery` was the blocker: it
spoke cargo and nothing else, so a probe naming a `pytest#` or `vitest#` control could not
be executed at all. The only probes those units could carry were the gate-only ones Phase 1
added.

The dispatch now goes through `_ecosystems`, the same seam `verify-tests` resolves through.
That is deliberate: a control green in the test lane and unrunnable in the mutation lane
would be two answers about one declared symbol.

## 2. The scratch tree could not run either SDK, and that is three separate facts

`copy_tracked_tree` copies TRACKED files, which is exactly right for cargo — it builds from
source — and insufficient for both SDKs:

* `sdk/python`'s package imports a compiled `_core.abi3.so` that `.gitignore` excludes;
* `sdk/typescript` cannot run vitest without `node_modules`;
* and it also loads `native/mcp-re-sdk-core.<triple>.node`, likewise ignored. That one was
  found only by running the lane and reading why zero tests collected.

`prepare_scratch` carries each across — linking the third-party trees, copying the compiled
artefacts — and carries **only what the weakening does not change**. A probe whose path is
Rust compiled into `_core.abi3.so` is REFUSED rather than measured, because the carried
binary would be stale by construction: the battery would run the old native code against
the new declaration and report a green describing neither tree.

## 3. The false green this lane would otherwise have had

`prepare_python_matrix.sh` installs the SDK as a **built wheel**. `site-packages/mcp_re_sdk/`
is a real copied directory, not a link to the tree, so `python -m pytest` in that
environment imports the wheel's `mtls.py` whatever the scratch tree says. Without
`PYTHONPATH` pointing at the weakened package root, every control would pass under every
weakening and each probe would report a control that refused to go red — not a false green,
but permanently unmeasurable, which is the same lane saying nothing.

Proved rather than assumed, both directions, at this tree:

```
weakened   (read1 -> read)   test_the_aggregate_read_deadline_holds_...  FAILED
unweakened (same shadowing)  test_the_aggregate_read_deadline_holds_...  PASSED
```

The second line is the one that matters. It shows the redness measures the property and not
the shadowing, and it shows the shadowing takes effect — had it not, the weakened run would
have imported the wheel and passed too.

## 4. A finding: post-close emission is defended in depth, and no single-site probe can
falsify it

The first TypeScript candidate attacked `sdk_typescript.post_close_emission`'s conjunct —
*a request still waiting for a concurrency slot is not signed and sent after `close()`
lands*. Deleting the post-queue `this.#refuseIfClosed()` left every declared control GREEN.
Retargeting at `#exchange`'s per-leg `if (this.#abort.signal.aborted) throw ...` left them
green too.

They are mutually redundant. With the guard removed, `Promise.race` rejects from the
already-aborted signal while `#exchange` throws at its own check; with the in-exchange check
removed, the guard throws first. Either way no POST happens and `posted.length` stays 1.

**This is recorded, not forced.** The weakening that would falsify the conjunct removes BOTH
sites, and the probe schema carries one `path`/`anchor`/`weakening` — so expressing it would
mean either contorting the schema or softening the claim, and the lane's own refusal message
says which of those is correct: *write a control, do not soften the statement*.

Worth noting for whoever takes it: the two checks read DIFFERENT sources. `#refuseIfClosed()`
reads `#state`, an ordinary field this class owns — which is the repair that let ASM-0043 be
withdrawn. `#exchange` reads `#abort.signal.aborted`, which is the runtime semantic ASM-0043
was withdrawn to stop trusting. So the backstop rests on the premise the repair removed.
Phase-2 obligation, on `sdk_typescript.post_close_emission`, unchanged and still open.

## 5. What this slice discharged

Two, by measurement rather than by registration:

| probe | unit | control turned red |
|---|---|---|
| `M178-python-aggregate-read-fills` | `sdk_python.bounded_read` | the aggregate deadline against a real trickling peer |
| `M179-typescript-sign-time-nonce-floor` | `sdk_typescript.nonce_floor` | a sub-floor override, and a non-string override |

N1 moves 87 -> 85. The remaining 25 SDK obligations now have a lane that can carry their
falsifiers; they are not discharged here, and registering probes in bulk against them is
exactly what the campaign forbids.

M178's weakening is the HISTORICAL defect rather than an invented one: `read1` returns what
one underlying read produced so the deadline is consulted between reads, while `read` fills
to `n` and a trickling peer keeps one call outstanding forever. That is what R9-C010
recorded and what ASM-0042 registered as a foreign-runtime premise before the bound was made
local. The probe is what makes that discharge falsifiable instead of remembered.
