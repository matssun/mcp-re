// SPDX-License-Identifier: Apache-2.0
/**
 * MCP-RE TypeScript SDK — RFC 9421 runtime-evidence security for MCP (ADR-MCPRE-050).
 *
 *     application code
 *       -> signRequest(...)        -> RFC 9421 signed request (method, targetUri, headers, body)
 *       -> one signed HTTPS POST to mcp-re-proxy
 *       -> verifyResponse(...)     -> the response, verified + request-bound
 *
 * The sole carrier is RFC 9421 HTTP Message Signatures + RFC 9530 Content-Digest;
 * the signature rides in the HTTP headers, not a JSON-RPC `_meta` block, on any
 * wire. The signing/verification logic is the audited `mcp-re-client-core` Rust core
 * (napi-rs binding).
 */

export {
  coreVersion,
  profileTag,
  signPreimage,
  signRequest,
  signRequestWithSigner,
  verifyResponse,
} from "../native/binding.js";
export type {
  HttpHeader,
  SignedRequestJs,
  VerifyResultJs,
} from "../native/binding.js";
export {
  CustodyClass,
  McpReError,
  McpReSdkError,
  Signer,
  SignerPolicy,
  SignerUnavailable,
  SigningDevice,
} from "./custody.js";
export type { SignRequestArgs } from "./custody.js";
export { ContinuationHandles, CorrelationStore } from "./correlation.js";
export type { PendingRequest, RecordArgs } from "./correlation.js";
export {
  ARTIFACT_TYPES,
  AuthorizationBindingPolicy,
  AuthzSystemReferenceProvider,
  OpaqueBytesProvider,
  bindingsJson,
} from "./authorization.js";
export type {
  ArtifactType,
  AuthorizationBindingProvider,
  BindingRequestContext,
  BindingSpec,
} from "./authorization.js";
// The transport adapter (`McpReHttpTransport`) is deliberately NOT exported here. It is
// the only part of this SDK that needs the upstream MCP SDK — a third-party package, not
// MCP-RE — because it binds to that package's JSON-RPC seam. A caller who only wants the
// signing/verification bindings must not be made to install it, so it ships as the
// optional-peer subpath `@mcp-re/sdk/transport` and this entry point keeps no hard
// runtime dependency. The Python package draws the same line with its `mcp` extra.
//
//     import { McpReHttpTransport } from "@mcp-re/sdk/transport";
