# Preserved authorization vector corpus — NOT conformance

`phase5_vectors.json` is a preserved vector corpus. **No harness executes it, and
it is not a conformance category.** Nothing in this repository reads the file.

## Why it is not executed

The vectors specify a signed-authorization profile whose evaluator was bound to
the retired object carrier. MCP-RE is HTTP-profile only (RFC 9421 + RFC 9530),
and the proxy refuses to start with the profile selected:

```
--authz reference selects the reference/conformance signed-authorization
profile ... must be rebuilt on the HTTP-profile request evidence first.
Run --authz off.
```

So `authz` is `Off` in every configuration the proxy accepts, and there is no
implementation for these vectors to run against. A harness written today would
have nothing to exercise.

## Why it is retained anyway

The generator that produced these vectors no longer exists, so this file is the
only remaining copy of the corpus. It is design input for a future authorization
profile — a worked set of allow/deny cases with their bindings, windows, and
scopes — not evidence about the current release.

## What would change this

If an authorization profile is rebuilt on HTTP-profile request evidence, these
vectors become a candidate corpus for it. At that point the corpus moves under
`mcp-re-conformance/tests/vectors/`, gains per-fixture hashes and a
`corpus_digest`, and is advertised as a row in the category table in
[`docs/conformance-guide.md`](../../../docs/conformance-guide.md) — which
`scripts/conformance_claims_gate.py` will then hold to having a real harness.

Until then: preserved, not proven.
