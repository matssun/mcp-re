# The client mTLS transport — 2026-09-06

Item 5 of the ranked remainder listed `mcp-re-transport` as a wholly unowned crate: **0 of 9
files**.

Baseline: main `5ff19aad` (#826).

## 1. A measurement correction, first

The first reading of this crate counted inline `#[cfg(test)]` blocks, found five of nine
source files with none, and concluded it was an **evidence** gap. **That was wrong.**

The evidence lives in `tests/`:

* `mtls_client_test.rs` — five guards;
* `dos_hardening_test.rs` — four bounds;
* the lib — twenty framing and header controls;
* `fault_injection_test.rs` — two catch demonstrations, whose Bazel targets are explicitly
  **not** `manual` and therefore run on every `bazel test //...`.

It is an **ownership** gap over evidence that already exists, like the keysources. The
corrected measurement is what this registration rests on, and it is recorded here rather than
quietly replaced — "an architecture gap needs a measurement" cuts both ways, and a gap
asserted from the wrong count is the same defect as a claim asserted from prose.

## 2. Two units, because the crate holds two authorities

Whom this client trusts to be the proxy is not the same question as what it is willing to read
off the wire. One unit answering both would need an "and" in its answer to ADR-MCPRE-061 §8
question 1, which is the project's own evidence of a shallow authority boundary.

## 3. THM-0109 — and the asymmetry that makes it worth stating

`ClientTlsConfig` builds rustls' standard `WebPkiServerVerifier` over **only** the configured
server CA. An untrusted, wrong-identity, or expired server certificate aborts the handshake, so
the request body is never sent — there is no session to send it over. An empty CA bundle is
refused at construction.

The module states the reason itself, and it is the whole point:

> Presenting a client certificate is visible when it is missing — the handshake fails.
> VERIFYING the server is not: an accept-any verifier completes every handshake, so nothing
> about a working deployment tells you the check is absent.

The excluded outcome is a client that signs and sends MCP-RE requests, carrying its own
authenticated identity, to an endpoint that merely answered on the right address.

### Where the load-bearing demonstration lives, and why it is cited nowhere

`fault_injection_test.rs` compiles the crate with `fault_accept_any_server`, which **discards**
the `WebPkiServerVerifier` and installs an accept-any one, then asserts that the very scenarios
the guards reject are **accepted**. That is a genuine catch demonstration and it already runs.

It **cannot** be a `tested_symbol` of this unit, because it runs in a lane where the property
this theorem states is deliberately false — a unit citing both would be naming controls that
cannot pass together. So the scope names it, and cites it nowhere.

The probe this unit carries reaches the one conjunct a weakening can reach in the default lane:
the empty-bundle refusal (M130). The other three rest on rustls enforcing what
`WebPkiServerVerifier` is documented to enforce — a property of that library, not of this code
— and the scope says so rather than implying the probe covers them.

## 4. THM-0110 — refusal, not repair

Every excluded outcome is a **disagreement** that would otherwise be resolved silently and
differently at each end. A stripped CR in a header value is request splitting: the caller
described one request, the peer reads two, no error anywhere. A `transfer-encoding` alongside a
`content-length`, or a duplicated `content-length`, is the classic desync. A truncated body
silently shortened is a response the caller believes is complete.

The bounds exclude the other shape — a peer that never finishes. Catching the stall but not the
trickle would leave the slower attack unbounded, which is why both are asserted and why the
aggregate deadline exists alongside the per-read timeout rather than instead of it.

| conjunct | probe |
|---|---|
| a CR/LF in a header value is REFUSED, never sanitised | M131 |
| a body shorter than its declared length is an ERROR, not a shorter body | M132 |

## 5. A probe the lane refused, and why that is the system working

M131's anchor carries Rust byte escapes (`b'\r'`). A TOML **basic** multi-line string processes
those escapes, so the lane received the control characters themselves and the anchor matched
zero sites. It reported:

```
STALE — the anchor matches 0 site(s), expected exactly 1. Re-adjudicate this probe against the
current implementation; do NOT restore the old code to make it match.
```

and refused to run. Rewritten with TOML **literal** strings (`'''`), which do not escape-process.
A lane that refuses a probe it cannot locate — rather than reporting something about the code —
is what makes a probe evidence rather than a ritual.

## 6. What is not claimed

Nothing about what the proxy does once the handshake succeeds, and nothing about the signing
above this layer: the crate is transport-only and does no signing. Nothing about the configured
server CA being the **right** one — that is the operator's trust decision, and this theorem is
about honouring it rather than choosing it. Nothing about a well-framed response being true or
correctly signed. Nothing about the proxy's own framing, whose symmetry is by construction
rather than by a shared owner. And no number is asserted as sufficient: what is claimed is that
a ceiling and a deadline are applied, not that a deployment's values are large or small enough.

Both are outside every root's closure: no §2 root is stated about the client transport.
