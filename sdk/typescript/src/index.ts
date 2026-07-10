/**
 * MCP-RE TypeScript SDK — runtime-evidence security for the MCP TypeScript SDK.
 *
 * Architecture (ADR-MCPS-044 §SDK wrap-or-fork rule; ADR-MCPS-047 v0.8)::
 *
 *     application code
 *       -> new Client(...).connect(transport)   (plain MCP; unaware of MCP-RE)
 *       -> McpReHttpTransport                       (signs outbound bytes, verifies inbound)
 *       -> native mcp-re-sdk-core (napi-rs)         (the AUDITED mcp-re-client-core logic, in Rust)
 *       -> mcp-re-proxy (HTTP profile)              (one signed mTLS POST per request)
 *
 * The spike verdict (Python, #199) was **transport adapter**, not a transparent
 * wrapper: the MCP SDK serializes JSON-RPC *inside* each transport, so the only place
 * with exact-byte control is the transport itself. We ship our own implementation of
 * the SDK's public `Transport` interface and delegate every security decision to the
 * Rust core — one implementation of the signed preimage, shared with `mcp-re-client-proxy`
 * and the Python SDK. See `README.md`.
 */

// --- the audited native core (napi-rs binding to mcp-re-client-core) ---------
export {
  coreVersion,
  canonicalizationId,
  responseMetaKey,
  signRequest,
  signRequestWithSigner,
  verifyResponse,
  Signer,
  SigningDevice,
  SignerPolicy,
  TrustResolver,
  CorrelationStore,
  AuthorizationBinding,
  AuthorizationBindingPolicy,
} from "../native/binding.js";
export type {
  SignedRequest,
  VerifyResult,
  PendingRequest,
  ContinuationBinding,
  SignRequestOptions,
  SignWithSignerOptions,
  VerifyResponseOptions,
  RegisterOptions,
} from "../native/binding.js";

// --- the transport adapter + policy (plain TypeScript) ---------------------
export {
  McpReVerificationError,
  signOutbound,
  verifyInbound,
} from "./transport.js";
export type {
  McpReConfig,
  InboundOutcome,
  AuthorizationBindingProvider,
  BindingRequestContext,
  MrtStore,
  SignOutboundOptions,
  VerifyInboundOptions,
  TransportHooks,
} from "./transport.js";

export { McpReHttpTransport, MCP_RE_REJECTED_CODE } from "./httpTransport.js";
export type { PostFn } from "./httpTransport.js";

export { decodeInbound, sseDataEvents, verifyInboundMessages } from "./streamable.js";

export {
  OpaqueBytesProvider,
  AuthzSystemReferenceProvider,
  StaticAuthorizationProvider,
} from "./authorization.js";
export type { AuthzReference, ArtifactSource } from "./authorization.js";

export { connectMtlsHttp } from "./client.js";
