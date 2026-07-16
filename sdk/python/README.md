# MCP-RE Python SDK (`mcp-re-sdk`)

Runtime-evidence security for the [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk):
signed requests and verified responses, added without changing application code.

> **Status — partial (ADR-MCPS-044).** This SDK is **not yet a drop-in transport
> adapter**. It binds the audited `mcp-re-client-core` over PyO3 and gives you the two
> cryptographic halves of the client obligation, plus custody:
>
> | Capability | State |
> | --- | --- |
> | Request signing (`sign_request`) — RFC 9421 + RFC 9530 | **done** |
> | Delegated response verification (`verify_response`) — ADR-MCPRE-052 credential chain, revocation, trust epoch, audience | **done** |
> | Custody classes (`Signer` / `SignerPolicy` / `SigningDevice`) incl. non-exporting | **done** |
> | ADR-MCPS-047 continuation (answer leg) — `sign_request(..., cont_*)` / `verify_response().request_state` | **done** |
> | Cross-language parity gate vs the frozen oracle | **done** |
> | In-flight correlation (`CorrelationStore`) | **not implemented** |
> | Authorization-binding providers (`opaque-bytes` / `authz-system-reference`) | **not implemented** — the DPoP token is currently the only binding |
> | Transport adapter (`McpReHttpTransport` / `connect_mtls_http`) | **not implemented** |
> | Nonce/freshness generation | **caller-supplied** |
>
> Until the transport adapter lands you must drive the two calls yourself: sign, POST the
> returned `.method` / `.target_uri` / `.headers` / `.body()` over your own mTLS client,
> then verify the reply. `mcp.ClientSession` does **not** yet speak MCP-RE by construction
> here — that is the ADR-MCPS-044 wrap-or-fork endpoint, and it is still open work.
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

That adapter is the **target**, and is not built yet — the `McpReHttpTransport` row below
is the design, not shipped code:

```
application code
  -> mcp.ClientSession            plain MCP; unaware of MCP-RE
  -> McpReHttpTransport             TARGET — not implemented; today you call
                                    sign_request / verify_response yourself
  -> mcp_re_sdk._core (PyO3)         the AUDITED mcp-re-client-core logic, in Rust
  -> mcp-re-proxy (HTTP profile)     one signed mTLS POST per request
```

## Why PyO3, not pure Python

The signing/verification/enforcement logic lives **once**, in the audited Rust
`mcp-re-client-core` crate — the same code the proxy uses. Binding to it (rather
than reimplementing it in Python) guarantees the canonical signed preimage is
byte-identical across SDK and proxy, by construction, and means a draft-spec
change is edited in one place. The Python you actually touch — the transport
adapter, `connect_mtls_http()`, policy, tests — stays plain Python. End users `pip install`
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
  tests/
    test_smoke.py        # the installed wheel stands alone (native _core loads, signing works)
    test_custody.py      # the two custody classes + the hardening policy, fail-closed
    test_parity.py       # the frozen cross-language oracle (../fixtures/parity_vectors.json)
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

## Known open work

- **The transport adapter** (`McpReHttpTransport` / `connect_mtls_http`), in-flight
  correlation, and the authorization-binding providers — see the status table above.
  These are the remainder of the ADR-MCPS-044 client obligation.
- **Pin upstream `mcp`.** The package is mid-refactor (the v1 session layer was
  removed; message types moved to `mcp_types`). Pin to an exact version once the
  transport seam stabilizes.
- **Transport-as-dispatcher rework** upstream may move the integration seam.

See ADR-MCPS-044 §SDK wrap-or-fork rule and issue #199.
