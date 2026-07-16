# MCP-RE TypeScript SDK (`@mcp-re/sdk`)

Runtime-evidence security for the [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk):
signed requests and verified responses, added without changing application code.

> **Status — the transport adapter is shipped; the mTLS connection helper is not.** This
> SDK binds the audited `mcp-re-client-core` over a **napi-rs** native addon and gives you
> the two cryptographic halves of the client obligation, custody, and an MCP `Transport`
> that drives both underneath a standard `Client`:
>
> | Capability | State |
> | --- | --- |
> | Request signing (`signRequest`) — RFC 9421 + RFC 9530 | **done** |
> | Delegated response verification (`verifyResponse`) — ADR-MCPRE-052 credential chain, revocation, trust epoch, audience | **done** |
> | Custody classes (`Signer` / `SignerPolicy` / `SigningDevice`) incl. non-exporting | **done** |
> | ADR-MCPS-047 continuation (answer leg) — `signRequest(..., cont*)` / `verifyResponse().requestState` | **done** |
> | Cross-language parity gate vs the frozen oracle | **done** |
> | In-flight correlation (`CorrelationStore`) — fail-closed on unbound / late / duplicate responses | **done** |
> | Authorization-binding providers (`opaque-bytes` / `authz-system-reference`) — core digests real artifacts | **done** |
> | Transport adapter (`McpReHttpTransport`) — a real `Client` signs/verifies by construction | **done** |
> | Nonce/freshness generation | **done** (adapter-generated) |
> | mTLS connection helper (`connectMtlsHttp`) | **not implemented** |
>
> A standard `Client` now speaks MCP-RE by construction: hand it an `McpReHttpTransport`
> and application code calls `client.callTool(...)` with no sign/verify of its own. **You
> still supply the HTTP leg** — the adapter takes an injected `poster` that performs the
> POST, so establishing and hardening the connection (mTLS, pooling, timeouts) is yours
> until `connectMtlsHttp` lands.
>
> Using `signRequest` / `verifyResponse` directly remains supported for callers who want
> to drive the exchange themselves; it is no longer the only option.
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

That adapter is `McpReHttpTransport`:

```
application code
  -> new Client(...).connect(transport)   plain MCP; unaware of MCP-RE
  -> McpReHttpTransport                   signs outbound bytes / verifies inbound bytes
  -> mcp-re-sdk-core (napi-rs)            the AUDITED mcp-re-client-core logic, in Rust
  -> mcp-re-proxy (HTTP profile)          one signed POST per request (your poster)
```

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { McpReHttpTransport } from "@mcp-re/sdk/transport";

const client = new Client({ name: "app", version: "1.0.0" });
await client.connect(new McpReHttpTransport(config, poster));

// Signed, verified, and correlated — with nothing MCP-RE-shaped in sight.
await client.callTool({ name: "add", arguments: { a: 2, b: 40 } });
```

The adapter ships from the subpath `@mcp-re/sdk/transport` because it is the only part of
this package that needs the upstream MCP SDK, which is an **optional peer**: a caller who
wants just the signing/verification bindings imports `@mcp-re/sdk` and installs nothing
else.

**Every failure is delivered, correlated to its request, as a JSON-RPC error.** A
transport that dropped a failed exchange would leave `Client` awaiting a reply that never
comes, and a hang is a worse failure mode than a raise. A client→server *notification* has
no reply, so it carries no evidence and cannot be verified: the adapter drops it and
reports it through `onDroppedNotification` rather than silently.

## Why napi-rs, not pure TypeScript

The signing/verification/enforcement logic lives **once**, in the audited Rust
`mcp-re-client-core` crate — the same code the proxy and the Python SDK use. Binding to it
(rather than reimplementing it in TypeScript) guarantees the canonical signed preimage is
byte-identical across every SDK and the proxy, **by construction**, and means a
draft-spec change is edited in one place. The frozen parity oracle
(`sdk/fixtures/parity_vectors.json`) turns "by construction" into a gate: this SDK and the
Python SDK must reproduce the same frozen bytes or their tests fail. The TypeScript you
actually touch — custody, policy, the transport adapter, and tests — stays plain
TypeScript. napi-rs
(vs WASM) was chosen because an MCP-RE client needs real crypto, filesystem key custody,
and mTLS sockets, and has no browser requirement; the native addon is the direct analog
of the Python SDK's PyO3 wheel.

## Usage

Point a standard `Client` at `McpReHttpTransport` and application code is done (see
above). To drive the exchange yourself instead — sign, send, verify — the two halves stay
public:

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
    authorization.ts     # OpaqueBytesProvider / AuthzSystemReferenceProvider / policy
  test/
    smoke.test.ts        # the built package stands alone (native addon loads, signing works)
    custody.test.ts      # the two custody classes + the hardening policy, fail-closed
    correlation.test.ts  # in-flight correlation, fail-closed on unbound/late/duplicate
    authorization.test.ts # binding providers, digests checked vs an independent oracle
    parity.test.ts       # the frozen cross-language oracle (../../fixtures/parity_vectors.json)
    transport.test.ts    # the adapter, offline, with an injected poster
    transport_replay.test.ts  # a RECORDED delegated session (../../fixtures/delegated_response_replay.json)
    transport_e2e.test.ts     # the LIVE proxy + a real FastMCP backend; self-skips without them
```

## Develop

```sh
cd sdk/typescript
npm install
npm run build      # napi build (native addon) + tsc (dist)
npm test           # build + vitest run
```

The test suite reads the frozen oracle at `../fixtures/parity_vectors.json` — the single
source of truth, regenerated by `tools/gen_sdk_parity_fixture.py`. A drift in either the
TypeScript or the Python binding is caught against the same vectors.

The transport adapter is proved three ways, because each covers what the others cannot:

| Test | Counterparty | Runs in CI |
| --- | --- | --- |
| `transport.test.ts` | injected `poster`, no network | always |
| `transport_replay.test.ts` | a **recorded** delegated session, elicitation open leg, and rejection receipt (`../fixtures/delegated_response_replay.json`) | always |
| `transport_e2e.test.ts` | the **live** `http_profile_proxy` + a real FastMCP backend | only where the harness is available; self-skips otherwise |

The replay fixture exists because the live test self-skips in the npm downloader lane —
the one place the shipped artifact is gated — which would leave the verification path
unproven exactly where it matters. Its bytes are a recording of the real proxy signing
with a real delegated key, not a hand-built imitation, so a wire-format change fails the
test instead of passing a lookalike. It also asserts the adapter reproduces the recorded
**request** byte-for-byte before serving a reply, which is what makes replaying one
legitimate — and since that recording was made by the **Python** adapter, this SDK
matching it extends the parity oracle from the primitives to the transport itself.
Re-record with `tools/gen_sdk_transport_fixture.py` against a running harness.
