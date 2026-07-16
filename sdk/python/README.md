# MCP-RE Python SDK (`mcp-re-sdk`)

Runtime-evidence security for the [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk):
signed requests and verified responses, added without changing application code.

> **Status (ADR-MCPS-044) — the transport adapter is shipped; the mTLS connection helper
> is not.** This SDK binds the audited `mcp-re-client-core` over PyO3 and gives you the two
> cryptographic halves of the client obligation, custody, and a transport that drives both
> underneath a standard `mcp.ClientSession`:
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
> | mTLS connection helper (`connect_mtls_http`) | **not implemented** |
>
> `mcp.ClientSession` now speaks MCP-RE by construction: open it on the adapter's streams
> and application code calls `session.call_tool(...)` with no sign/verify of its own. **You
> still supply the HTTP leg** — the adapter takes an injected `poster` that performs the
> POST, so establishing and hardening the connection (mTLS, pooling, timeouts) is yours
> until `connect_mtls_http` lands.
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
never comes, and a hang is a worse failure mode than a raise. A client→server
*notification* has no reply, so it carries no evidence and cannot be verified: the adapter
drops it and reports it through `on_dropped_notification` rather than silently.

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
    test_transport_e2e.py     # the LIVE proxy + a real FastMCP backend; self-skips without them
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

The transport adapter is proved three ways, because each covers what the others cannot:

| Test | Counterparty | Runs in CI |
| --- | --- | --- |
| `test_transport.py` | injected `poster`, no network | always |
| `test_transport_replay.py` | a **recorded** delegated session, elicitation open leg, and rejection receipt (`sdk/fixtures/delegated_response_replay.json`) | always |
| `test_transport_e2e.py` | the **live** `http_profile_proxy` + a real FastMCP backend | only where the harness is available; self-skips otherwise |

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

- **The mTLS connection helper** (`connect_mtls_http`) — the adapter takes an injected
  `poster`, so establishing and hardening the connection is still the caller's job. See
  the status table above.
- **The ADR-MCPS-047 answer leg is not driven end-to-end by the adapter.** The open leg is
  covered — `on_input_required` hands up the two evidence handles and the opaque
  `requestState`, against a recorded elicitation from the real backend's `confirm_action`
  tool. Signing the answer leg with those handles is still the caller's move
  (`sign_request(..., cont_*)`); the adapter does not yet re-drive it for you.
- **Transport-as-dispatcher rework** upstream may move the integration seam.

  (An earlier note here claimed the package was "mid-refactor — the v1 session layer was
  removed; message types moved to `mcp_types`". That is stale: at 1.28.1 `mcp.types` and
  `mcp.ClientSession` both exist and `mcp_types` does not.)

See ADR-MCPS-044 §SDK wrap-or-fork rule and issue #199.
