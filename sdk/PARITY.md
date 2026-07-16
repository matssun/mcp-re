<!-- SPDX-License-Identifier: Apache-2.0 -->

# The SDK parity contract

The Python and TypeScript SDKs bind the **same** audited `mcp-re-client-core`, so the
canonical signed preimage is byte-identical across them by construction. That guarantee is
real, and it is narrower than it looks.

**Byte parity and behavioural parity are separate gates.** The fixtures pin what the SDKs
*emit*. They cannot see what the SDKs *do*.

## Why this document exists

In July 2026 both SDKs passed every byte-level test — the frozen oracle, the recorded
transport fixture, the cross-language replay — while disagreeing on how many requests may
be in flight at once:

| SDK | Peak concurrent posts (4 issued) |
| --- | --- |
| Python | **1** — the pump awaited each exchange before reading the next |
| TypeScript | **4** — concurrent and unbounded |

Neither was a chosen behaviour, and no test could have caught it, because both emitted
identical bytes for every request. The divergence was found by reading the code.

The lesson generalises: *identical wire bytes do not imply identical behaviour, and
behaviour is where the interesting failures live.*

## Gate 1 — byte parity

**Asked:** do both SDKs emit the same bytes for the same inputs?

| Oracle | Pins |
| --- | --- |
| `sdk/fixtures/parity_vectors.json` | signed request evidence for fixed inputs (`tools/gen_sdk_parity_fixture.py`) |
| `sdk/fixtures/delegated_response_replay.json` | a recorded delegated session — accepted call, elicitation open leg, rejection receipt (`tools/gen_sdk_transport_fixture.py`) |

The transport fixture is recorded by the **Python** adapter and replayed by the
**TypeScript** one, asserting request bytes match before serving each recorded reply. That
extends byte parity from the primitives to the transport.

Ed25519 is deterministic and every input is fixed, so freezing bytes is honest.

## Gate 2 — behavioural parity

**Asked:** given identical bytes, do both SDKs *behave* the same?

Nothing in Gate 1 can answer this. Each dimension below needs a test that **measures the
behaviour**, in both languages, mirrored:

| Dimension | What to measure | Covered by |
| --- | --- | --- |
| **Concurrency** | peak in-flight exchanges; that a bound is honoured; that bounding delays rather than drops | `test_transport.py` / `transport.test.ts` — `concurrency` |
| **Resource bounds** | invalid bounds refused, not silently deadlocking | same — invalid-bound cases |
| **Error propagation** | which exception type/shape a caller sees; wire code vs local condition | `failure delivery` groups |
| **Lifecycle** | double-start, close, restart; what is checked at open vs per-request | `lifecycle` groups |
| **Notification handling** | fail-closed default, unsafe opt-in, hardened refusal | `notification handling` groups |
| **Shutdown** | in-flight work on close; whether a reply can still be delivered | *partially covered* — see below |

### The rule

> When adding cross-SDK surface, ask what the fixture **cannot** see. Then write a test
> that measures it, in both languages.

A behavioural test usually cannot assert bytes. It asserts a *count*, an *ordering*, a
*type*, or a *timing* — e.g. a `poster` that counts peak in-flight posts, or an assertion
that a slot is not leaked after a re-thrown error.

### Known asymmetries — deliberate, not drift

Some behaviour cannot be identical, because the two upstream SDKs expose different seams.
Where that is true it is recorded here rather than papered over:

| Behaviour | Python | TypeScript | Why |
| --- | --- | --- | --- |
| Bound validation point | `McpReConfig.__post_init__` | `McpReHttpTransport` constructor | Each validates where the value first enters SDK-owned code. Python's config is an SDK dataclass; TypeScript's is a caller-owned object literal, so the transport constructor is the earliest point the SDK controls. |
| Notification refusal surfaces as | the pump raises, tearing down the session | `send()` rejects | Python's transport is a stream pair with no per-message reply channel; TypeScript's `Transport.send` is a method call that can reject. Both fail closed; both are visible. |
| Unexpected-exception shape | `ExceptionGroup` (task group) | the thrown value | anyio task groups always wrap. Callers already saw this — `mcp_re_http_transport` runs the pump in a task group. |

### Not covered — public shutdown is UNTESTED and UNDECIDED

**Shutdown is release-critical and unresolved ([#421](https://github.com/matssun/mcp-re/issues/421)).**
Neither SDK has a specified shutdown contract; what each does today is an accident of its
seam, not a decision, and the two differ. Measured, not inferred:

| Observed | Python | TypeScript |
| --- | --- | --- |
| In-flight exchange when the caller shuts down | **cancelled, not drained** — `mcp_re_http_transport` calls `tg.cancel_scope.cancel()` on exit, so a poster that has started never completes | the in-flight `send()` **runs to completion** and still calls `onmessage` |
| Callback ordering | n/a (stream pair, no `onclose`) | **`onmessage` fires *after* `onclose`** — observed: `poster-hit \| onclose \| onmessage` |
| Work submitted after close | n/a | **still reaches the `poster`** — `close()` sets `#started = false`, but `send()` never reads it |

Do not read the inner `_pump` as evidence of draining: its task group does close inside
the streams, so an exchange can deliver its reply *when the write stream ends normally* —
but the public context manager cancels that scope on exit, which is the path callers
actually take. (An earlier revision of this document made exactly that mistake:
generalising the inner nesting into a claim about the public API.)

The intended contract, to be ratified in #421:

- explicit `NEW → OPEN → CLOSING → CLOSED` state;
- send before start or after close **fails**;
- close is **idempotent** and refuses new work immediately;
- queued and in-flight local requests fail with a **connection-closed** condition;
- poster work is cancelled where possible;
- **no message callback after the close callback**;
- abandoned correlation state is cleared;
- **no claim that already-dispatched remote work has stopped.**

Normal `close()` is **abortive**, matching upstream client behaviour of rejecting pending
requests. A separately named bounded drain may be considered later.

## Running both gates

```sh
# Python
cd sdk/python && maturin develop && pytest --cov      # 90% gate in pyproject.toml

# TypeScript
cd sdk/typescript && npm test                          # 90% gate in vitest.config.ts
```

The live proxy e2e tests self-skip without their harness (a built
`http_profile_proxy` + `fastmcp`), including in CI: **live interoperability is exercised;
the offline replay is what is continuously CI-gated.**
