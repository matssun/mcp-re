# ADR-MCPRE-068 Phase 2, slice 29 — one verdict, two vocabularies

Three probes, `M270`–`M272`, opening the Medium band. Every one of them substitutes a string
that is already in the codebase for another string that is already in the codebase — and each
substitution changes what a deployment tells the world.

## 1. Both refuse the call, which is why one token for both looks harmless

`mcp-re.authorization_revoked` says an authority made a decision about this credential.
`mcp-re.authorization_revocation_unavailable` says **nobody could ask**.

Serving the first for the second tells an operator their credential was revoked when what
actually happened is that their revocation backend is down — and the two have **opposite
remediations**: rotate the credential, or restore the service.

The variant survives `M270`, so nothing internal collapses. Only the frozen vocabulary the
caller branches on does, which is the whole of what this unit owns.

## 2. A label that IS a token

A security record carries two things about one verdict: the frozen `mcp-re.*` token a caller
branches on, and a human sentence for an operator reading the trail. `M271` makes one label a
token.

That makes the record self-describing in the wrong direction — a reader cannot tell which field
they are looking at, and a pipeline keyed on the prose field starts matching wire vocabulary
that was never promised to be stable there.

The control quantifies over every variant rather than checking one, which is why a single
substituted arm takes it red: the rule is about the shape of the whole mapping.

## 3. The projection is lossy on purpose, and this is where it must not be

Five shape refusals all mean *the spec is not a legal authorization binding* and share one
verdict. The narrowing means something else: the artifact type is not supported **in this
form**, and an opaque provider asked to mint a `pdp-decision` binding is half of a Mode-2 pair,
not a malformed document. `M272` folds it into the shape bucket, so a caller is told their spec
is broken when what is broken is the pairing they asked for.

**Why there is no table of strings beside it.** `wire_code` asks this projection which verdict
a refusal IS and takes that verdict's token, because two statements of one mapping is how a
renamed Core token leaves a carrier emitting the old spelling (ADR-MCPRE-066 Slice 2). So this
match is the sole carrier of both facts, and the weakening reaches the wire token without
touching any string.

## 4. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `policy.authorization_taxonomy` | `M270` | medium |
| `core.audit_vocabulary` | `M271` | medium |
| `client.binding_spec_refusal` | `M272` | medium |

N1 moves 13 -> 10; the probe registry 291 -> 294.
