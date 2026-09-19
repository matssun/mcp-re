# ADR-MCPRE-068 Phase 2, slice 6 — what the receipt said, and who said it

Four probes, `M197`–`M200`. Both propositions are about the SDK not speaking for the peer,
and measuring them found one control that could not fail for the reason it existed for.

## 1. An explicit null is an invented member

`execution_report` says the application is told exactly the members the verified receipt
carried. The weakening emits every key whatever the receipt said, so `executionStatus: null`
reaches an application that branches on the member's PRESENCE.

ADR-MCPRE-058 SL-10 is what makes that a security conjunct rather than a tidiness one. An
absent `executionStatus` means the server stated nothing; a caller reading the key as stated
collapses *unknown whether it ran* into an answer, at the one place that decides whether a
retry re-executes a tool call that already executed.

## 2. The control that could not fail — `toEqual` and the undefined key

`M198` first turned only ONE of its two controls red. The other is the one that names the
shape directly — *invents no disposition for a receipt that stated none* — and it stayed
green, because:

> `toEqual` **ignores an undefined-valued key**, so it cannot tell `{ requestBound }` from
> `{ requestBound, executionStatus: undefined }`.

An emitted-but-undefined member is exactly what that control exists to refuse. This is
R9-C094's shape one level over, and the same shape the `FORCED_VERDICT_MEMBERS` control in
that file was written against. It now asserts the KEY SET first and compares with
`toStrictEqual`, and it goes red under the weakening.

The Python twin was never affected: dict equality distinguishes `{"a": None}` from `{}`.

## 3. Provenance has two carriers, and they compose by exception class

`local_failure_provenance` says a condition this SDK originated is reported under the SDK's
own prefix. The first `expect_red` list assumed one carrier and was wrong — two of three
named controls stayed green, and the reason is structural rather than a probe defect:

| origin | carrier | consults the predicate? |
|---|---|---|
| `McpReSdkError` (the signing device, the aggregate read deadline) | its own `except` branch, prefix unconditional | **no** |
| `ValueError` from the caller's `poster`, and anything else | `_peer_wire_code(...) or "mcp-re-sdk: …"` | **yes** |

So the typed branch and the predicate each cover a disjoint set of origins — **composition**,
the shape slice 2 first recorded, not defence in depth. `M199` is scoped to the predicate's
half and names the control that measures it; the typed branch's controls stay green under
this weakening because the weakening cannot reach them.

The `None` return is the carrier there, not a null-guard: every caller spells the delivery as
`_peer_wire_code(...) or "mcp-re-sdk: …"`, so the only thing separating a local condition from
a peer verdict is the predicate refusing to call a reset connection, a TLS error or a
caller-raised timeout a token. Under the weakening a caller branching on the frozen taxonomy
(REQ-14/POL-6) acts on a verdict no peer issued.

`M200`'s sibling control — *delivers a core failure as its frozen token* — is deliberately
not expected red. It stays green because the weakening only WIDENS what counts as a token; a
probe expecting it would be measuring the wrong direction.

## 4. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `sdk_python.execution_report` | `M197` | critical, root-reachable |
| `sdk_typescript.execution_report` | `M198` | critical, root-reachable |
| `sdk_python.local_failure_provenance` | `M199` | critical, root-reachable |
| `sdk_typescript.local_failure_provenance` | `M200` | critical, root-reachable |

N1 moves 74 -> 70; the probe registry 218 -> 222. One control repaired, found by a probe
rather than by reading it.
