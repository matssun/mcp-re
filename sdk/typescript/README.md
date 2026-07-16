# MCP-RE TypeScript SDK (`@mcp-re/sdk`)

Runtime-evidence security for the [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk):
signed requests and verified responses, added without changing application code.

> **Status — partial.** This SDK is **not yet a drop-in transport adapter**. It binds
> the audited `mcp-re-client-core` over a **napi-rs** native addon and gives you the two
> cryptographic halves of the client obligation, plus custody:
>
> | Capability | State |
> | --- | --- |
> | Request signing (`signRequest`) — RFC 9421 + RFC 9530 | **done** |
> | Delegated response verification (`verifyResponse`) — ADR-MCPRE-052 credential chain, revocation, trust epoch, audience | **done** |
> | Custody classes (`Signer` / `SignerPolicy` / `SigningDevice`) incl. non-exporting | **done** |
> | ADR-MCPS-047 continuation (answer leg) — `signRequest(..., cont*)` / `verifyResponse().requestState` | **done** |
> | Cross-language parity gate vs the frozen oracle | **done** |
> | In-flight correlation (`CorrelationStore`) — fail-closed on unbound / late / duplicate responses | **done** |
> | Authorization-binding providers (`opaque-bytes` / `authz-system-reference`) | **not implemented** — the DPoP token is currently the only binding |
> | Transport adapter (`McpReHttpTransport` / `connectMtlsHttp`) | **not implemented** |
> | Nonce/freshness generation | **caller-supplied** |
>
> Until the transport adapter lands you must drive the two calls yourself: sign, POST the
> returned `{method, targetUri, headers, body}` over your own mTLS client, then verify the
> reply. An `mcp` `Client` does **not** yet speak MCP-RE by construction here — that is the
> ADR-MCPS-044 wrap-or-fork endpoint, and it is still open work.
>
> MCP-RE is **HTTP-profile only** — one signed mTLS POST per request against the production
> `mcp-re-proxy`; a stdio-only MCP server is fronted by an external plain-MCP adapter (e.g.
> FastMCP) that speaks HTTP to the proxy.
>
> **Delegated-required.** `verifyResponse` implements the ADR-MCPRE-052 credential chain and
> is the only response-verification mode: a direct-root-signed response is **rejected**. A
> verified *rejection receipt* is genuine evidence but is NOT an acceptance — read
> `.outcome` (`"success"` / `"rejection"`) and `.wireCode`, never `.ok` alone.
>
> **Non-exporting custody.** `Signer.nonExporting(signerId, keyId, signCallback)` holds only
> a `(preimage: Buffer) => Buffer` callback (a KMS/HSM client call in production), invoked
> **synchronously** on the Node main thread; the private key never enters the SDK. Custody is
> `NonExporting`, the only class `SignerPolicy.hardened()` accepts. `SigningDevice.fromSeed(...)`
> is the HSM/KMS stand-in exposing ONLY `.sign(preimage)`. The delegation is byte-identical to
> the software path — the frozen parity oracle asserts exactly that — and a device that cannot
> sign fails closed as `mcp-re.invalid_signature`.

## Why this exists, and why it's an *adapter*

MCP-RE is a two-sided protocol: the client must sign the **exact** canonical outbound
bytes before they leave the process and verify the **exact** inbound response bytes
before the app parses them. The `mcp-re-client-proxy` already does this as a sidecar; this
SDK does it **in-process**.

The MCP TypeScript SDK serializes JSON-RPC *inside* each transport — the `Protocol`
layer hands the transport parsed `JSONRPCMessage` objects, and each transport does its
own `JSON.stringify`/framing. So the only seam with exact-byte control is the transport
itself. Per ADR-MCPS-044 this is the **transport-adapter** path (not a transparent
wrapper): we ship our own implementation of the SDK's public `Transport` interface.

That adapter is the **target**, and is not built yet — the `McpReHttpTransport` row below
is the design, not shipped code:

```
application code
  -> new Client(...).connect(transport)   plain MCP; unaware of MCP-RE
  -> McpReHttpTransport                     TARGET — not implemented; today you call
                                            signRequest / verifyResponse yourself
  -> mcp-re-sdk-core (napi-rs)               the AUDITED mcp-re-client-core logic, in Rust
  -> mcp-re-proxy (HTTP profile)             one signed mTLS POST per request
```

## Why napi-rs, not pure TypeScript

The signing/verification/enforcement logic lives **once**, in the audited Rust
`mcp-re-client-core` crate — the same code the proxy and the Python SDK use. Binding to it
(rather than reimplementing it in TypeScript) guarantees the canonical signed preimage is
byte-identical across every SDK and the proxy, **by construction**, and means a
draft-spec change is edited in one place. The frozen parity oracle
(`sdk/fixtures/parity_vectors.json`) turns "by construction" into a gate: this SDK and the
Python SDK must reproduce the same frozen bytes or their tests fail. The TypeScript you
actually touch — custody, policy, tests, and the transport adapter once it lands — stays
plain TypeScript. napi-rs
(vs WASM) was chosen because an MCP-RE client needs real crypto, filesystem key custody,
and mTLS sockets, and has no browser requirement; the native addon is the direct analog
of the Python SDK's PyO3 wheel.

## Usage

Sign, send, verify. You own the HTTP leg until the transport adapter lands.

```ts
import { Signer, SignerPolicy, SigningDevice, verifyResponse } from "@mcp-re/sdk";

// Non-exporting custody: the key stays behind the device; the SDK gets a callback.
// In production `sign` is a KMS/HSM call rather than a local SigningDevice.
const signer = Signer.fromDevice("did:example:client", "client-key-1", SigningDevice.fromSeed(seed));

// The hardening profile accepts non-exporting custody only, and refuses a software
// key before anything is signed (mcp-re.actor_binding_failed).
SignerPolicy.hardened("did:example:client").check(signer);

const req = signer.signRequest({
  idJson: "1",
  method: "tools/list",
  paramsJson: "{}",
  targetUri: "https://proxy.internal:8600/mcp",
  audienceId: "did:example:server-1",
  dpopToken: accessToken,
  nonce: freshNonce(),          // you generate this; it must not repeat in-window
  created: now,
  expires: now + 300,
});

// One signed mTLS POST to mcp-re-proxy, using your own HTTPS client.
const res = await postOverMtls(req.method, req.targetUri, req.headers, req.body);

const v = verifyResponse(
  res.status, res.headers, res.body,
  req.method, req.targetUri, req.headers, req.body,
  req.evidenceDigestAlg, req.evidenceDigestValue,
  rootKeyId, rootPubKeyB64Url, "server", "example.com", "did:example:server-1",
  ["verifier-1"], audienceScopeHash, ["epoch-1"], 60, revokedKids, now,
);

// A verified rejection receipt is genuine evidence, NOT an acceptance.
if (v.outcome !== "success") throw new Error(`rejected: ${v.wireCode}`);
```

## Layout

```
sdk/typescript/
  Cargo.toml             # napi cdylib -> mcp-re-sdk-core; OWN workspace (separate from root)
  build.rs               # napi-build hook
  package.json           # @napi-rs/cli build config, mixed Rust/TS layout
  native/                # generated: binding.js + binding.d.ts + *.node
  src/
    lib.rs               # the napi binding (the exact analog of sdk/python/src/lib.rs)
    index.ts             # public surface (re-exports the native core + the modules)
    custody.ts           # CustodyClass / Signer / SignerPolicy / SigningDevice / McpReError
    correlation.ts       # CorrelationStore / PendingRequest / ContinuationHandles
  test/
    smoke.test.ts        # the built package stands alone (native addon loads, signing works)
    custody.test.ts      # the two custody classes + the hardening policy, fail-closed
    correlation.test.ts  # in-flight correlation, fail-closed on unbound/late/duplicate
    parity.test.ts       # the frozen cross-language oracle (../../fixtures/parity_vectors.json)
```

## Develop

```sh
cd sdk/typescript
npm install
npm run build      # napi build (native addon) + tsc (dist)
npm test           # build + vitest run
```

The test suite reuses the oracle fixtures under `../python/tests/fixtures` — the single
source of truth generated by `cargo run --example gen_vector` (etc.) in
`mcp-re-client-core`. A drift in either the TypeScript or the Python binding is caught
against the same vectors.
