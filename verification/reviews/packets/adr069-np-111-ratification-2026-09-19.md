<!-- SPDX-License-Identifier: Apache-2.0 -->

# NP-111 — R6 ratification packet: a rebuilt plain reply is a JSON-RPC response or it is nothing

**Disposition:** referred, in part. Six controls, six `[[disposition]]` rows, one record kept
and rewritten. Of the record's original fifteen, six landed under THM-0061 in the same change
and three moved to records of their own (NP-181, NP-182, NP-183).

## Provenance

Filed by the ADR-MCPRE-069 census over `mcp-re-client-proxy/src/proxy.rs` and
`mcp-re-client-core/src/response.rs` as ONE record of fifteen controls. Split under RR-002 C5
during the S-05/CL-CLIENT slice, which measured four independently describable propositions
inside it.

## What the six are, and what they share

All six drive `plain_response_from_verified`, one `pub(crate)` function in `proxy.rs`, and
all six ask the same question of it: *is what comes back a JSON-RPC response?*

| control | what it refuses or preserves |
|---|---|
| `a_json_rpc_error_reply_is_carried_through_not_flattened_to_a_null_result` | an `error` reply is not rebuilt from `result` alone |
| `a_reply_that_is_not_a_json_rpc_response_fails_closed` | empty envelope, batch array, bare scalar, both members, a legal result beside a top-level `method` |
| `an_ordinary_result_still_rebuilds` | the guard refuses malformed evidence, not an empty result |
| `an_unparseable_verified_reply_is_a_verification_failure_not_a_bad_request` | non-JSON bytes are a RESPONSE failure; a 400 implies nothing ran |
| `the_proxy_owned_meta_is_stripped_from_the_plain_reply` | the RFC 9421 evidence block leaves both positions |
| `the_reply_carries_the_id_the_proxy_signed_not_the_one_the_server_echoed` | the id addresses the local client's outstanding call |

## Why no client theorem contains it

Three were checked in terms, and each one's own scope is what rules it out.

**THM-0084** — *"the `SignedRequest` handed to the transport and the `ResponseExpectation`
handed to response verification come from ONE owner"*. The work package proposed
`the_reply_carries_the_id_the_proxy_signed_not_the_one_the_server_echoed` as an R1 into
`client.proxy_request_correspondence` under this clause, and the measurement refuses it. The
control never calls `handle`. It calls `plain_response_from_verified(body, &json!("req-7"))`
with a literal, so it witnesses nothing about a single owner, and no weakening of `handle`'s
composition can turn it red. What it does witness is that the REBUILD takes the id from its
caller rather than from the body — which is this record's sixth clause and sits in the same
function as the other five. THM-0084's four existing controls are a source-text scan over
`handle`; this is a different function measured a different way.

**THM-0126** — *"COMPOSITION, not classification and not trust"*, over `read_outcome` in
`verified_outcome.rs`. It takes a plain reply as given and decides what the caller may
conclude. The bytes-to-reply step is upstream of it, in another file, and its scope says
nothing about what a well-formed reply IS.

**THM-0061** — *"What the receipt SAYS, and what a client may conclude from it."* Six of the
record's original fifteen decomposed into that clause and landed. These six do not: a body
that is a bare scalar has no receipt to say anything, and stripping `_meta` is not a statement
the server made.

## The asymmetry, which is the finding

The Python and TypeScript SDKs each have an `sdk_*.reply_envelope` unit stating this
proposition for their implementation of the same profile. The Rust client proxy — the shipped
one — has none. Three implementations, one profile, two propositions. That is not evidence
that the Rust half is weaker; the six controls above are careful and they pass. It is evidence
that the graph's coverage of one profile depends on which language the census reached first,
which is exactly the blindness ADR-MCPRE-069 exists to report.

## Why it is R6 and not a widening

The tempting registration is a unit over `proxy.rs` under THM-0126, since the file is the
proxy's and the question is about a reply. The operational test refuses it: `read_outcome`
can be correct in every clause THM-0126 states while `plain_response_from_verified` flattens
an error reply to a null result, because `read_outcome` is handed the flattened reply and
classifies it faithfully. A proposition that can be false while every clause of the candidate
theorem stays true is not a decomposition of it.

## Proposed shape for ratification

A theorem over the client proxy's plain-MCP boundary, owned by a unit over
`mcp-re-client-proxy/src/proxy.rs`, and stated as the sibling of the two SDK reply-envelope
units rather than as a new idea:

> The bytes a verified reply is rebuilt into are a JSON-RPC response carrying exactly one of
> `result`/`error`, addressed to the id this proxy signed, with the proxy-owned evidence block
> removed — or they are a refusal. There is no third outcome, and in particular no
> `result: null` standing in for a body that could not be read.

Its dependents are the local agent's own error handling and the ambassador's status mapping.
Its natural falsifier is the one the record's "if false" already names: make the
`(None, None)` arm return `Ok(json!({"result": null}))` and watch a signed envelope with
neither member arrive as a completed tool call.

## N1

Nothing registered from this half, so no obligation moves. The two units this slice DID
register each carry demonstrated-red falsifiers — `M332` and `M333` for
`client.proxy_reply_disposition`, `M334` for `client.receipt_contract_carriage` — and
`scripts/assurance_obligation_gate.py` reports 0 open N1 after the change.
