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
| **Notification handling** | that the notification reaches the wire signed and id-less; that an unverifiable 202 fails closed; that the nonce floor governs it too | `notification handling` groups |
| **Result classification** | that a verified reply which cannot be classified is refused rather than read as a completed call — a withheld `requestState`, and a `resultType` outside the recognized set | `malformed_elicitation` / `unrecognized_result_type` fixtures, replayed in both |
| **Continuation** | that a chain is driven to a TERMINAL result; that the answer leg's bytes carry the continuation binding; that an unanswerable pause is refused; that the round ceiling is enforced before the caller is asked; that no correlation entry outlives the chain | `transport_replay` — `elicitation.answer`, replayed in both |
| **mTLS channel** | that an untrusted root and a wrong-identity certificate are both refused; that response headers keep wire order and repeats | `test_mtls.py` / `mtls.test.ts` — same generated X.509 |
| **Shutdown** | in-flight work on close, for a request AND a notification; whether a reply can still be delivered | *partially covered* — see below |

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
| A client->server response | `ClientResponseUnsupported` from the pump | `ClientResponseUnsupported` from `send()` | Same refusal, same reason: MCP-RE profiles a signed request and a signed notification, and a response is neither. Delivery differs only where every other failure's does. |
| An unverified notification acknowledgement surfaces as | `on_notification_failure` (stderr by default); the session continues | `send()` rejects | Python's transport is a stream pair with no per-message reply channel; TypeScript's `Transport.send` is a method call that can reject. Both fail closed; both are visible; neither treats the message as delivered. Python used to let it escape the pump's task group, which cancelled every unrelated in-flight exchange and tore the session down — on a trigger the PEER controls (one unverifiable 202 for a routine `notifications/initialized` from a proxy whose delegated key is past `exp`). That is the remotely-triggerable session kill round 5 fixed on the request path, so round 6 contained it here too. |
| Correlation state observable as | a `CorrelationStore` the caller may pass in | `transport.pendingCorrelations` / `pendingRequests()` | Python's transport is a context-manager function with no object to hang a getter on. Both own **one store per transport**; see below. |
| Non-`Error` thrown value | n/a — Python has no analogue | re-thrown | Throwing a non-`Error` is a JavaScript defect with no Python counterpart. |
| `authz_binding_digest` serialization | `json.dumps(..., separators=(",", ":"), sort_keys=True)` | `JSON.stringify` over key-sorted objects | Byte-identical, and pinned by a LITERAL in both test suites. Each SDK used to recompute the expectation with its own serializer, which hid a real divergence: Python's default `", "`/`": "` separators produced a different digest from `JSON.stringify` for byte-identical bindings, so cross-SDK audit reconciliation reported a false "artifact binding changed". |
| The mTLS leg is built on | `http.client` + `ssl`, on a worker thread | `node:https` | Each uses its platform's own audited HTTP/1.1 implementation rather than hand-rolling framing in two languages. Python's is blocking, so it runs under `to_thread` and is abandoned on cancellation — the same claim `ConnectionClosed` already makes. The security posture is identical and identically tested: configured CA only, name proven, client certificate presented, TLS 1.2 floor, one connection per exchange, bounded response. |
| Client certificate material | file paths | PEM paths **or** bytes | `ssl.SSLContext.load_cert_chain` reads from disk only; Node accepts either. The CA bundle takes bytes in both. |
| A continuation answer that is not an object | `ContinuationNotAnswered` naming the type | same, naming `typeof` / "an array" | Same refusal; only the type name the message can offer differs. |

### Failure delivery — one contract, decided (round 5)

Both SDKs now deliver **every** failed exchange as a JSON-RPC error correlated to its
request id. Nothing escapes to end the session.

Python previously let anything that was not `McpReError` / `McpReSdkError` / `ValueError`
escape `_one`. Exchanges share one anyio task group, so a `ConnectionResetError` on one
request cancelled every other in-flight exchange and tore down the session — remotely
triggerable, and a contradiction of the module's own documented contract. TypeScript
already delivered it per request.

The message format is the shared half of the contract: **a bare `mcp-re.*` token means the
peer said it; anything else is prefixed `mcp-re-sdk:` and named.** Python distinguishes by
type (the core raises `ValueError` carrying the token); TypeScript cannot — the napi
binding and `fetch` both throw plain `Error` — so it matches the message against
`/^mcp-re\.[a-z0-9_]+$/` instead. Same guarantee, different discriminator.

| Thrown | Python delivers | TypeScript delivers |
| --- | --- | --- |
| core fail-closed error | `mcp-re.response_sig_invalid` | `mcp-re.response_sig_invalid` |
| wire rejection (`McpReError`) | its `wire_code` | its `wireCode` |
| local SDK/device failure | `mcp-re-sdk: <detail>` | `mcp-re-sdk: <detail>` |
| network / unexpected | `mcp-re-sdk: ConnectionResetError: …` | `mcp-re-sdk: Error: …` |

Cancellation is deliberately **not** caught in either: Python re-raises `BaseException`,
TypeScript re-throws `ConnectionClosed`. `close()` could not abort an in-flight exchange
otherwise.

### Correlation state — owned by the transport, and bounded

Both stores hold **two** halves, and both are bounded:

| Half | Bounded by |
| --- | --- |
| outstanding requests | consumed on answer, retired on failure (`abandon` / `abandon`), reaped by `expire_before` / `expireBefore` |
| consumed ids (the "already answered" memory) | dropped at `expires + 300s`, scanned amortised every 1024 records |

Retention outlasts the request window because the consumed set only ever matters for a
*late* response. Past the grace an evicted id fails a duplicate as
`mcp-re.request_binding_mismatch` rather than `mcp-re.replay_detected` — less precise,
never an acceptance.

The store belongs to the transport in both, not to the config. Python's used to hang off
`McpReConfig`, which a caller may reasonably reuse for a second session; closing either
transport then reaped the other's outstanding requests.

### Shutdown — decided and covered (#421)

`close()` is **abortive**, matching the upstream client's rejection of pending requests. It
makes **no claim that already-dispatched remote work has stopped**: the server may have
received the request and acted on it. Only that this client will not process an answer.

| Contract | Python | TypeScript |
| --- | --- | --- |
| Explicit lifecycle | structural — the `async with` block **is** the state | `TransportState` `NEW → OPEN → CLOSING → CLOSED`, one-way |
| Send before start / after close fails | streams do not exist / are closed → `ClosedResourceError` \| `BrokenResourceError` | `ConnectionClosed` |
| Close idempotent, refuses new work at once | structural (the block exits once) | `close()` returns early when already CLOSING/CLOSED |
| In-flight local requests fail connection-closed | cancelled scope | in-flight `send()` rejects `ConnectionClosed` |
| An in-flight NOTIFICATION is aborted too | cancelled scope (the pump's task group) | the notification `send()` races `#aborted()`, as a request does |
| Poster work cancelled where possible | anyio cancel scope | `AbortController` raced against the exchange |
| No message callback after the close callback | streams closed — nothing can be delivered | `onmessage` suppressed unless state is OPEN |
| Abandoned correlation cleared | `expire_before(_FAR_FUTURE)` on exit | `expireBefore(MAX_SAFE_INTEGER)` in `close()` |

The lifecycle asymmetry is seam-forced and deliberate: Python's public surface is a context
manager, so the state is the block — an enum nobody can observe would be theatre.
TypeScript's `Transport` is a long-lived object the caller holds across `start`/`close`, so
it needs the explicit state.

### Continuation — the adapter drives it, decided (#419)

An ADR-MCPS-047 `InputRequiredResult` **pauses** a call; it does not finish it. The
adapter therefore owns the whole chain: it signs each answer leg over the verified handles
of the leg before it, and only a terminal result reaches the application.

The surface is one handler, at parity: `answer_input_required` / `answerInputRequired`
returns the `inputResponses` to continue with, or nothing to decline. It may be async in
both. `on_input_required` / `onInputRequired` stays what it was — an observer that fires
once per round and decides nothing.

| Contract | Both SDKs |
| --- | --- |
| An answered chain | driven to a terminal result; the caller's single `await` resolves to it |
| The answer leg's id | a NEW id (`<caller-id>/mrt-<n>`), per SEP-2322 §retry; the reply is relabelled to the caller's before delivery |
| No handler installed | `ContinuationNotAnswered` — the pause is **never** delivered as a result |
| Handler declines / returns a non-object | `ContinuationNotAnswered` |
| Round ceiling | `max_continuation_rounds` / `maxContinuationRounds`, default 4, checked **before** the handler runs |
| Correlation | the open leg stays outstanding while its answer leg runs, then is retired — a chain leaks nothing, answered or not |

The fail-closed default is the load-bearing part. An elicitation delivered up as the reply
to `call_tool` presents a call still waiting for input as one that finished — the §5.2 /
§9.3 misrepresentation the protected non-terminal classification exists to make detectable,
and the same failure `unrecognized_result_type` covers from the other direction.

Relabelling the id is honest here for one reason only: every hop was verified *in this
adapter* before the terminal result was handed up, so what the application receives is a
complete record (§9.3), not a spliced one.

## Running both gates

```sh
# Python
cd sdk/python && maturin develop && pytest --cov      # 90% gate in pyproject.toml

# TypeScript
cd sdk/typescript && npm test                          # 90% gate in vitest.config.ts
```

The live proxy e2e tests self-skip without their harness (a built
`http_profile_proxy` + the MCP SDK inner backend), including in CI: **live interoperability is exercised;
the offline replay is what is continuously CI-gated.**
