# MCP-RE Python SDK (`mcp-re-sdk`)

Runtime-evidence security for the [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk):
signed requests and verified responses, added without changing application code.

> **Status (ADR-MCPS-044) — the client obligation is shipped whole.** This SDK binds the
> audited `mcp-re-client-core` over PyO3 and gives you the two cryptographic halves of the
> client obligation, custody, a verifying mTLS connection, and a transport that drives all
> of it underneath a standard `mcp.ClientSession`:
>
> | Capability | State |
> | --- | --- |
> | Request signing (`sign_request`) — RFC 9421 + RFC 9530 | **done** |
> | Delegated response verification (`verify_response`) — ADR-MCPRE-052 credential chain, revocation, trust epoch, audience | **done** |
> | Custody classes (`Signer` / `SignerPolicy` / `SigningDevice`) incl. non-exporting | **done** |
> | ADR-MCPS-047 continuation (answer leg) — `sign_request(..., cont_*)` / `verify_response().request_state` | **done** |
> | Cross-language parity gate vs the frozen oracle | **done** |
> | In-flight correlation (`CorrelationStore`) — fail-closed on unbound / late / duplicate responses | **done** |
> | Authorization-binding providers (`opaque-bytes` / `authz-system-reference`) — core digests real artifacts | **done** |
> | Transport adapter (`mcp_re_http_transport`) — a real `ClientSession` signs/verifies by construction | **done** |
> | Nonce/freshness generation | **done** (adapter-generated) |
> | Concurrent exchanges, bounded (`max_concurrent_exchanges`, default 8) | **done** |
> | One-way notifications (`notifications/*`) — signed POST + verified signed `202` | **done** ([#418](https://github.com/matssun/mcp-re/issues/418)) |
> | ADR-MCPS-047 answer-leg orchestration — the adapter drives the chain to a terminal result | **done** ([#419](https://github.com/matssun/mcp-re/issues/419)) |
> | Transport shutdown contract — abortive close, `NEW → OPEN → CLOSING → CLOSED` | **done** ([#421](https://github.com/matssun/mcp-re/issues/421)) |
> | mTLS connection helper (`connect_mtls_http`) — configured CA only, server identity proven, client certificate presented | **done** ([#413](https://github.com/matssun/mcp-re/issues/413)) |
>
> **Not released.** The one-way notification + acknowledgement profile
> ([#418](https://github.com/matssun/mcp-re/issues/418)) has landed: a notification is its
> own signed POST and the `202` it earns is signed, bodyless, and bound to that exact
> transmission, so a standard client no longer needs an unsafe opt-in to complete its
> lifecycle.
>
> `mcp.ClientSession` speaks MCP-RE by construction: open it on the adapter's streams and
> application code calls `session.call_tool(...)` with no sign/verify of its own — including
> for a multi-round-trip tool, whose elicitation the adapter answers and continues to a
> terminal result. `connect_mtls_http` supplies the HTTP leg as a verifying mTLS connection;
> the injected `poster` remains available for a caller who wants a different one.
>
> Using `sign_request` / `verify_response` directly remains supported for callers who want
> to drive the exchange themselves; it is no longer the only option.
>
> MCP-RE is **HTTP-profile only** — one signed mTLS POST per request against the production
> `mcp-re-proxy`; a stdio-only MCP server is fronted by an external plain-MCP adapter (e.g.
> FastMCP) that speaks HTTP to the proxy.
>
> **Delegated-required.** `verify_response` implements the ADR-MCPRE-052 credential chain and
> is the only response-verification mode: a direct-root-signed response is **rejected**. A
> verified *rejection receipt* is genuine evidence but is NOT an acceptance — read
> `.outcome` (`"success"` / `"rejection"`) and `.wire_code`, never `.ok` alone.
>
> **Non-exporting custody.** `Signer.non_exporting(signer_id, key_id, sign_callback)` holds
> only a `preimage -> signature` callback (a KMS/HSM client call in production); the private
> key never enters the SDK. Custody is `NON_EXPORTING`, the only class
> `SignerPolicy.hardened()` accepts. `SigningDevice.from_seed(...)` is the HSM/KMS stand-in:
> it encapsulates the key and exposes ONLY `.sign(preimage)` (no getter). The delegation is
> byte-identical to the software path — the frozen parity oracle asserts exactly that — and a
> device that cannot sign fails closed as `mcp-re.invalid_signature`.

## Why this exists, and why it's an *adapter*

MCP-RE is a two-sided protocol: the client must sign the **exact** canonical
outbound bytes before they leave the process and verify the **exact** inbound
response bytes before the app parses them. The `mcp-re-client-proxy` already does
this as a sidecar; this SDK does it **in-process**.

The wrap-or-fork spike found that the MCP Python SDK serializes JSON-RPC *inside*
each transport — the anyio stream between `ClientSession` and the transport
carries already-parsed pydantic objects, not bytes. So the only seam with
exact-byte control is the transport itself. Per ADR-MCPS-044 this is the
**transport-adapter** path (not a transparent wrapper): we ship our own
implementation of the SDK's public `Transport` protocol.

That adapter is `mcp_re_http_transport`:

```
application code
  -> mcp.ClientSession            plain MCP; unaware of MCP-RE
  -> mcp_re_http_transport        signs outbound bytes / verifies inbound bytes
  -> mcp_re_sdk._core (PyO3)      the AUDITED mcp-re-client-core logic, in Rust
  -> mcp-re-proxy (HTTP profile)  one signed POST per request (your poster)
```

```python
from mcp import ClientSession
from mcp_re_sdk import mcp_re_http_transport

async with mcp_re_http_transport(config, poster) as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()
        # Signed, verified, and correlated — with nothing MCP-RE-shaped in sight.
        await session.call_tool("add", {"a": 2, "b": 40})
```

The upstream MCP SDK is an **extra** (`pip install mcp-re-sdk[mcp]`), not a hard
dependency: it is needed only to open a session, so a caller who wants just the
signing/verification bindings installs nothing else.

**Every failure is delivered, correlated to its request, as a JSON-RPC error.** A
transport that dropped a failed exchange would leave `ClientSession` awaiting a reply that
never comes, and a hang is a worse failure mode than a raise.

**Exchanges run concurrently, bounded.** MCP is not lock-step, and each MCP-RE exchange is
an independent signed POST with its own nonce and correlation entry, so nothing requires
serializing them — awaiting each before starting the next would make one slow tool call
block the whole session. The bound (`max_concurrent_exchanges`, default 8) exists because
each in-flight exchange holds a connection in your `poster` and a signing operation (a KMS
round trip under non-exporting custody).

**One-way notifications are carried and acknowledged.** A `notifications/*` message is its
own signed POST — same RFC 9421 request signature, same RFC 9530 `Content-Digest`, same
evidence block as any request — and the enforcement boundary answers it with a signed,
bodyless `202`. The adapter verifies that acknowledgement before treating the message as
delivered; `on_notification_acknowledged` observes the ones that verified.

The acknowledgement is bound to the **transmission**, not merely to the content: it covers
`mcp-re-request-evidence`, the digest of the request's own signature base, which includes
its nonce. A `202` captured from an earlier send of a byte-identical notification therefore
does not verify for a later one.

**What a verified acknowledgement claims, exactly: the enforcement boundary authenticated
and accepted the message.** Not that the action completed — a verified ack for
`notifications/cancelled` does not mean anything was cancelled.

If it does not verify, the adapter raises `NotificationNotAcknowledged` and the transport
fails closed. A notification has no reply for an error to ride back on, so there is no
request id to correlate a failure to and no application call awaiting an answer; continuing
a session in which an unverifiable claim of acceptance was accepted would be exactly the
take-it-on-faith posture this SDK exists to remove.

**A multi-round-trip call is driven to a terminal result.** An ADR-MCPS-047
`InputRequiredResult` pauses a call rather than finishing it. Supply
`answer_input_required` and the adapter signs the answer leg over the *verified* handles of
the leg before it, posts it, verifies the reply, and repeats until the server returns a
terminal result — which is what your single `await` resolves to:

```python
config = McpReConfig(
    ...,
    # Return the `inputResponses` to continue with, or None to decline. May be async.
    answer_input_required=lambda prompt: ask_the_user(prompt.result["elicitation"]),
)
# One call, whatever the server needs in between.
await session.call_tool("confirm_action", {})
```

Without a handler an elicitation **fails closed** (`ContinuationNotAnswered`); it is never
delivered up as the result. A pause handed to the application as the reply to `call_tool`
would present a call still waiting for input as one that finished. `max_continuation_rounds`
(default 4) bounds how long a server may keep one call in that cycle, and is checked before
you are asked for an answer that could not be sent.

**The connection itself is verified.** `connect_mtls_http` builds the HTTP leg as a mutual
TLS connection to the proxy:

```python
from mcp_re_sdk import MtlsOptions, connect_mtls_http

options = MtlsOptions(
    server_ca="ca.pem",          # the ONLY root trusted to authenticate the proxy
    client_cert="client.pem",    # presented for the proxy's own binding check
    client_key="client.key",
    # Optional: dial a load balancer while still requiring the proxy's own identity.
    connect_address=("10.0.0.7", 8601),
)

async with connect_mtls_http(config, options) as (read, write):
    async with ClientSession(read, write) as session:
        ...
```

The system trust store is never consulted, the certificate must be valid for the name in
your `target_uri` (or `server_name`), and there is no way to turn either check off. A
helper with a `verify=False` knob is how mTLS deployments quietly become TLS-shaped
plaintext — and nothing above this layer could notice, because a response signature
verifies identically whether or not the channel proved who produced it.

## Why PyO3, not pure Python

The signing/verification/enforcement logic lives **once**, in the audited Rust
`mcp-re-client-core` crate — the same code the proxy uses. Binding to it (rather
than reimplementing it in Python) guarantees the canonical signed preimage is
byte-identical across SDK and proxy, by construction, and means a draft-spec
change is edited in one place. The Python you actually touch — the transport
adapter, custody, policy, tests — stays plain Python. End users `pip install`
a prebuilt `abi3` wheel and need no Rust toolchain.

## Layout

```
sdk/python/
  Cargo.toml             # PyO3 cdylib -> mcp_re_sdk._core; OWN workspace (separate from root)
  src/lib.rs             # the binding: sign_request / sign_request_with_signer /
                         #   verify_response (delegated) / sign_preimage
  pyproject.toml         # maturin backend, mixed Rust/Python layout, coverage gate
  python/mcp_re_sdk/
    __init__.py          # public surface
    custody.py           # CustodyClass / Signer / SignerPolicy / SigningDevice / McpReError
    correlation.py       # CorrelationStore / PendingRequest / ContinuationHandles
    authorization.py     # OpaqueBytesProvider / AuthzSystemReferenceProvider / policy
    transport.py         # McpReConfig / mcp_re_http_transport — the adapter
  tests/
    test_smoke.py        # the installed wheel stands alone (native _core loads, signing works)
    test_custody.py      # the two custody classes + the hardening policy, fail-closed
    test_correlation.py  # in-flight correlation, fail-closed on unbound/late/duplicate
    test_authorization.py # binding providers, digests checked vs an independent oracle
    test_parity.py       # the frozen cross-language oracle (../fixtures/parity_vectors.json)
    test_transport.py    # the adapter, offline, with an injected poster
    test_transport_replay.py  # a RECORDED delegated session (../fixtures/delegated_response_replay.json)
    test_transport_e2e.py     # the LIVE proxy + a real MCP SDK backend; self-skips without them
```

## Develop

```sh
cd sdk/python
python -m venv .venv && . .venv/bin/activate
pip install -U maturin 'pytest>=8' 'pytest-cov>=5'
maturin develop            # builds mcp_re_sdk._core against the in-repo Rust crates
pytest --cov               # the suite + the 90% coverage gate (fail_under in pyproject)
```

Both SDKs are pinned to one frozen oracle, `sdk/fixtures/parity_vectors.json`. Regenerate
it with `tools/gen_sdk_parity_fixture.py` (against an installed wheel); CI fails if the
regenerated bytes differ from the committed ones, which is what catches either binding
drifting from the core or from the other language.

**Byte parity is only one of two gates.** The fixtures pin what the SDKs *emit*; they
cannot see what the SDKs *do*. Concurrency, error propagation, lifecycle, notification
handling and shutdown must be measured separately, in both languages — see
[the SDK parity contract](../PARITY.md), written after the two adapters were found to
disagree on concurrency with every byte-level test green.

The transport adapter is proved three ways, because each covers what the others cannot.
**Live interoperability is exercised; the offline replay is what is continuously
CI-gated** — the live test self-skips wherever its harness is absent, which includes
the downloader lane, so it is a development-time proof rather than a standing gate:

| Test | Counterparty | Runs in CI |
| --- | --- | --- |
| `test_transport.py` | injected `poster`, no network | always |
| `test_transport_replay.py` | a **recorded** delegated session, a full elicitation chain (open leg + answer leg), and a rejection receipt (`sdk/fixtures/delegated_response_replay.json`) | always |
| `test_mtls.py` | a real TLS server holding real certificates, client-auth required | always (material minted by `tools/gen_mtls_test_material.py`) |
| `test_transport_e2e.py` | the **live** `http_profile_proxy` + a real MCP SDK backend | **no** — self-skips without the harness (incl. in CI) |

The replay fixture exists because the live test self-skips in the downloader lane — the
one place the shipped artifact is gated — which would leave the verification path
unproven exactly where it matters. Its bytes are a recording of the real proxy signing
with a real delegated key, not a hand-built imitation, so a wire-format change fails the
test instead of passing a lookalike. It also asserts the adapter reproduces the recorded
**request** byte-for-byte before serving a reply, which is what makes replaying one
legitimate — and, since the same fixture is replayed by the TypeScript SDK, extends the
parity oracle from the primitives to the transport itself. Re-record with
`tools/gen_sdk_transport_fixture.py` against a running harness.

## Known open work

- **Transport-as-dispatcher rework** upstream may move the integration seam.

  (An earlier note here claimed the package was "mid-refactor — the v1 session layer was
  removed; message types moved to `mcp_types`". That is stale: at 1.28.1 `mcp.types` and
  `mcp.ClientSession` both exist and `mcp_types` does not.)

See ADR-MCPS-044 §SDK wrap-or-fork rule and issue #199.
