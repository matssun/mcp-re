# MCP-RE TypeScript SDK (`@mcp-re/sdk`)

Runtime-evidence security for the [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk):
signed requests and verified responses, added without changing application code.

> **Status.** The full client obligation is bound and tested over the audited
> `mcp-re-client-core` via a **napi-rs** native addon — the exact analog of the Python
> SDK's PyO3 binding: request signing (`signRequest`), custody/signer policy (`Signer` /
> `SignerPolicy`), response verification (`verifyResponse` / `TrustResolver`), in-flight
> correlation (`CorrelationStore`), authorization-binding providers, ADR-MCPS-047
> stateless multi-round-trip continuation, and the **transport adapters**
> (`McpReTransport` / `McpReHttpTransport`) that sign/verify at the byte boundary so an
> `mcp` `Client` speaks plain MCP. **104 tests pass**, all parity against the SAME
> independent `mcp-re-client-core` oracle vectors the Python SDK and the proxy are checked
> against (`sign_request_vector.json`, `verify_response_vectors.json`,
> `correlation_wire_codes.json`).
>
> **Server-initiated policy.** Server-initiated messages (a server→client
> request/notification) carry no `request_hash`, so the core cannot verify them and
> draft-02 defines no evidence for this direction (ADR-MCPS-047). **Strict MCP-RE is the
> client-initiated request/response subset:** the inbound policy **fails closed** by
> default (`mcp-re.missing_envelope` / `mcp-re.notification_forbidden`).
> `allowUnverifiedServerInitiated` is a **degraded/migration opt-out only** (delivered,
> audited as no-evidence) — never strict MCP-RE. ADR-MCPS-047 folds request-associated
> elicitation (`InputRequiredResult` → signed continuation) back into the strict
> request/response profile; **arbitrary** server push stays out of scope and fails closed.
>
> **ADR-MCPS-047 continuation (done).** `verifyResponse` classifies a verified
> `InputRequiredResult` (`inputRequired`, `responseHash`); `CorrelationStore.recordInputRequired`
> associates-without-consuming and returns the `(previousRequestHash,
> inputRequiredResponseHash)` binding; `signRequest(..., continuation*)` embeds the signed
> `continuation`. `McpReTransport` drives the elicitation → continuation round trip
> transparently, keyed by the opaque `requestState`, with every fail-closed boundary
> (tampered/absent/replayed state, first-round splice, arbitrary push) tested.
>
> **Non-exporting custody (done).** `Signer.nonExporting(signerId, keyId, signCallback)`
> is a signer whose private key NEVER enters the SDK — it holds only a
> `(preimage: Buffer) => signature` callback (a KMS/HSM client call in production),
> invoked **synchronously** on the Node main thread via napi-rs's `FunctionRef` seam.
> Custody is `NonExporting`, the only class `SignerPolicy.requireNonExporting()` accepts.
> `SigningDevice.fromSeed(...)` is the HSM/KMS stand-in exposing ONLY `.sign(preimage)`.
> The delegation is byte-identical to the direct software path (same evidence, key just
> moved behind the device); a device that can't sign fails closed.
>
> **Remaining (clearly scoped):** live cross-process e2es against the real Rust binaries
> (stdio proxy + mTLS `mcp-re-proxy`/`mcp-re-demo-fileserver`) and wiring `driver.ts` into the
> `mcp-re-walkthrough` `sdk_driver_matrix` as the TypeScript client leg. The pieces those
> need — `connectStdio`, `connectMtlsHttp`, `McpReHttpTransport`, `driver.ts` — are all
> implemented; what is pending is the harness integration + minting the demo mTLS
> material, mirroring the Python `test_e2e_*`.

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

```
application code
  -> new Client(...).connect(transport)   plain MCP; unaware of MCP-RE
  -> McpReTransport (this SDK)              signs outbound bytes / verifies inbound bytes
  -> mcp-re-sdk-core (napi-rs)               the AUDITED mcp-re-client-core logic, in Rust
  -> remote MCP-RE server / proxy
```

## Why napi-rs, not pure TypeScript

The signing/verification/enforcement logic lives **once**, in the audited Rust
`mcp-re-client-core` crate — the same code the proxy and the Python SDK use. Binding to it
(rather than reimplementing it in TypeScript) guarantees the canonical signed preimage is
byte-identical across every SDK and the proxy, **by construction**, and means a
draft-spec change is edited in one place. The TypeScript you actually touch — the
transport adapter, `connect*` helpers, policy, tests — stays plain TypeScript. napi-rs
(vs WASM) was chosen because an MCP-RE client needs real crypto, filesystem key custody,
and mTLS sockets, and has no browser requirement; the native addon is the direct analog
of the Python SDK's PyO3 wheel.

## Usage

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { Signer, SignerPolicy, TrustResolver, connectStdio, OpaqueBytesProvider } from "@mcp-re/sdk";

const transport = connectStdio("mcp-re-stdio-server", ["--mode", "proxy"], {
  signer: Signer.software(seed, "did:example:client", "client-key-1"),
  policy: new SignerPolicy("did:example:client", "production", true),
  resolver: (() => { const r = new TrustResolver(); r.insertPublicKey(serverId, serverKeyId, serverPubKey); return r; })(),
  audience: "did:example:server",
  onBehalfOf: "user:alice",
  authorization: new OpaqueBytesProvider(capabilityBytes),
  expectedServerSigner: serverId,
});

const client = new Client({ name: "app", version: "1.0.0" });
await client.connect(transport); // every request signed, every response verified
```

## Layout

```
sdk/typescript/
  Cargo.toml             # napi cdylib -> mcp-re-sdk-core; OWN workspace (separate from root)
  build.rs               # napi-build hook
  src/lib.rs             # the napi binding (the exact analog of sdk/python/src/lib.rs)
  package.json           # @napi-rs/cli build config, mixed Rust/TS layout
  native/                # generated: binding.js + binding.d.ts + *.node
  src/
    index.ts             # public surface (re-exports the native core + the modules)
    transport.ts         # McpReTransport — the pipeline mirroring proxy.rs::handle
    httpTransport.ts     # McpReHttpTransport — one signed POST per request
    streamable.ts        # multi-path inbound decode (direct JSON / POST-SSE / GET-SSE)
    authorization.ts     # authorization-binding providers
    client.ts            # connectStdio / connectMtlsHttp transport factories
    driver.ts            # the SDK as an interchangeable conformance client leg
  test/                  # vitest suite; reuses the shared oracle fixtures from sdk/python
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
