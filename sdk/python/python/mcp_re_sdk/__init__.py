"""MCP-RE Python SDK — RFC 9421 runtime-evidence security for MCP (ADR-MCPRE-050).

The SDK signs an outbound MCP request as an **RFC 9421 HTTP Message Signature +
RFC 9530 Content-Digest** message and verifies the signed response bound to that
request. The sole carrier is the RFC 9421 HTTP evidence profile — the signature
rides in the HTTP ``Signature``/``Signature-Input``/``Content-Digest`` headers, not
a JSON-RPC ``_meta`` block.

    application code
      -> mcp_re_sdk.sign_request(...)     -> RFC 9421 signed request (method, uri, headers, body)
      -> one signed HTTPS POST to mcp-re-proxy
      -> mcp_re_sdk.verify_response(...)  -> the response, verified + request-bound

The signing/verification logic is the audited ``mcp-re-client-core`` Rust core,
exposed through the ``_core`` PyO3 extension (built by maturin).
"""

from . import _core  # native extension (mcp_re_sdk._core)
from .authorization import (
    AuthorizationBindingPolicy,
    AuthorizationBindingProvider,
    AuthzSystemReferenceProvider,
    BindingRequestContext,
    OpaqueBytesProvider,
)
from .correlation import ContinuationHandles, CorrelationStore, PendingRequest
from .custody import (
    CustodyClass,
    McpReError,
    McpReSdkError,
    Signer,
    SignerPolicy,
    SignerUnavailable,
    SigningDevice,
)

__version__ = "0.12.1"
__all__ = [
    "core_version",
    "profile_tag",
    "sign_preimage",
    "sign_request",
    "sign_request_with_signer",
    "verify_response",
    "SignedRequest",
    "VerifyResult",
    "CustodyClass",
    "McpReError",
    "McpReSdkError",
    "SignerUnavailable",
    "Signer",
    "SignerPolicy",
    "SigningDevice",
    "ContinuationHandles",
    "CorrelationStore",
    "PendingRequest",
    "AuthorizationBindingPolicy",
    "AuthorizationBindingProvider",
    "AuthzSystemReferenceProvider",
    "BindingRequestContext",
    "OpaqueBytesProvider",
    # Lazy — these need the upstream `mcp` extra (see __getattr__ below).
    "HttpReply",
    "McpReConfig",
    "NotificationsUnsupported",
    "UnsafeConfigurationRefused",
    "mcp_re_http_transport",
]

#: The transport adapter's names, resolved lazily. `transport` imports the upstream MCP
#: SDK, which is an optional extra: a caller who wants only the signing/verification
#: bindings must be able to `import mcp_re_sdk` without installing `mcp`.
_TRANSPORT_EXPORTS = frozenset(
    {
        "HttpReply",
        "McpReConfig",
        "NotificationsUnsupported",
        "UnsafeConfigurationRefused",
        "mcp_re_http_transport",
    }
)


def __getattr__(name: str):
    if name in _TRANSPORT_EXPORTS:
        try:
            from . import transport
        except ImportError as exc:  # pragma: no cover - depends on the install extras
            raise ImportError(
                f"mcp_re_sdk.{name} needs the upstream MCP SDK: pip install 'mcp-re-sdk[mcp]'"
            ) from exc
        return getattr(transport, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

#: The audited SDK core version string.
core_version = _core.core_version
#: The RFC 9421 profile tag the signature is emitted/verified under.
profile_tag = _core.profile_tag
#: Sign exact preimage bytes with a raw seed (the primitive behind SigningDevice).
sign_preimage = _core.sign_preimage
#: Sign an MCP request as an RFC 9421 + RFC 9530 message (returns a SignedRequest).
sign_request = _core.sign_request
#: Sign an MCP request under non-exporting custody: the SDK holds only a sign callback.
sign_request_with_signer = _core.sign_request_with_signer
#: Verify a signed RFC 9421 response bound to the request the client sent.
verify_response = _core.verify_response
#: A signed RFC 9421 request: ``.method`` / ``.target_uri`` / ``.headers`` /
#: ``.body()`` (bytes) / ``.evidence_digest_alg`` / ``.evidence_digest_value``.
SignedRequest = _core.PySignedRequest
#: The verification outcome: ``.ok`` / ``.server_keyid``.
VerifyResult = _core.PyVerifyResult
