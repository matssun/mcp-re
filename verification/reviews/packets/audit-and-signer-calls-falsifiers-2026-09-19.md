# ADR-MCPRE-068 Phase 2, slice 30 — a space is a separator

Two probes, `M273` and `M274`.

## 1. One logical record must be one physical record

A space is a separator in the audit record grammar. A scalar that renders a bare space **splits
its own line**: a field value becomes two fields, or the record becomes two records, and a
pipeline reading them gets a well-formed record that says something nobody wrote. Nothing later
can undo it, because by then the bytes are the same bytes a legitimate two-field record would
have produced.

**The injectivity is the property, not the escaping** — which is why the round-trip control is
what goes red. The inverse must recover exactly the value, and a scalar that passes a separator
through has an image the inverse cannot tell from a different value's.

`escape_scalar` is the ONE authority over this; the module states it as an invariant rather than
a convention. The verbatim control stays green under `M273`, correctly: a separator-free string
still renders verbatim, and that sibling conjunct cannot see a separator being let through.

## 2. The status is the only fact a shed-load answer carries

A 429 minted by a gateway **in front of** the service has no AWS `__type` and no Cloud KMS
`error.status` — there is no body to classify, because the service never saw the request.
Reading the status first is what lets the classifier answer at all; reading the body first would
answer *states no quota* and arm nothing.

The stated-name path is not a second carrier: it distinguishes one provider's exhaustion
vocabulary from the other's, on answers the service itself produced. Two disjoint populations,
one verdict — composition, and `M274` drops half of the status half.

## 3. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `proxy.audit_text_rendering` | `M273` | medium |
| `proxy.remote_signer_call_aws` | `M274` | medium |

N1 moves 10 -> 8; the probe registry 294 -> 296.
