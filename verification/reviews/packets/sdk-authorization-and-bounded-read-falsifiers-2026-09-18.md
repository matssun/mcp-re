# ADR-MCPRE-068 Phase 2, slice 10 — the canonical bytes, and the last aggregate bound

Four probes, `M211`–`M214`, and with them the SDK falsifier lane reaches **one remaining
obligation**: `sdk_typescript.post_close_emission`, which is blocked on a mechanism this
campaign has deliberately not built yet.

## 1. The default is the defect

`authorization_binding` requires the spec serialization to be byte-identical across SDKs,
because SDK-1/SDK-4 reconcile the same digest from a Python client's record and a TypeScript
client's. Two probes attack the two halves, and each weakening is **the library default**:

| probe | weakening | what drifts |
|---|---|---|
| `M212` | `ensure_ascii=False` → `True` | Python escapes non-ASCII as `\uXXXX`; `JSON.stringify` emits raw UTF-8 |
| `M214` | `Object.keys(spec).sort()` → `Object.keys(spec)` | JS key order is insertion order; Python's `sort_keys` is a keyword |

That is what makes them worth falsifiers rather than review: once the keyword or the `.sort()`
is gone, **nothing about the code looks wrong**. A tenant name or grant handle carrying one
non-ASCII character then digests to two different values, and an audit pipeline reconciling
the two clients reads a difference in SERIALIZER as *the artifact binding changed*.

One probe suffices per SDK because the control names the cross-SDK digest directly: a
serialization that stops being canonical stops matching the pinned digest whichever way it
drifts.

## 2. The bound that is not the socket timeout

`M213` is the TypeScript twin of `M178`. The weakening keeps the timer and moves the bound to
24 hours rather than deleting it — deleting it would also delete the `settled()` bookkeeping
and measure a different change.

The per-socket `timeout` is **not** a second carrier. It is re-armed by every byte that
arrives, so a peer trickling just under it holds the exchange — and the transport semaphore
slot it occupies — open for as long as it cares to, and `maxConcurrentExchanges` such
responses wedge the session with no error and no timeout. Python recorded the same defect
from the `read1` / `read` direction.

## 3. What remains

| unit | state |
|---|---|
| `sdk_typescript.post_close_emission` | **open**, and deliberately so |

Two independent sites each enforce the WHOLE proposition — `#refuseIfClosed()` reading
`#state`, and `#exchange`'s per-leg `if (this.#abort.signal.aborted)` — so removing either
alone leaves every declared control green, and the one-anchor schema cannot express the
weakening that would falsify it. The standing ruling is: **one** measured defence-in-depth
instance records the requirement and builds nothing; **two** justify a narrowly typed
multi-anchor weakening; three or more, a general mechanism. The count is still one, and the
cargo lane is where a second would most likely appear.

The ASM-0043 note stays attached: the backstop reads `#abort.signal.aborted`, the runtime
semantic ASM-0043 was withdrawn to stop trusting, so the eventual remediation should stop
crediting that carrier rather than merely noting it.

## 4. What this slice discharged

| unit | probes | severity |
|---|---|---|
| `sdk_python.authorization_binding` | `M211`, `M212` | medium |
| `sdk_typescript.authorization_binding` | `M214` | medium |
| `sdk_typescript.bounded_read` | `M213` | medium |

N1 moves 64 -> 61; the probe registry 232 -> 236. **SDK N1: 27 -> 1.**
