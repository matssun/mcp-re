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
 * there is NO object/JCS `_meta` signature and NO canonicalization preimage on any
 * wire. The signing/verification logic is the audited `mcp-re-client-core` Rust core
 * (napi-rs binding).
 */

export {
  coreVersion,
  profileTag,
  signRequest,
  verifyResponse,
} from "../native/binding.js";
export type {
  HttpHeader,
  SignedRequestJs,
  VerifyResultJs,
} from "../native/binding.js";
