"""Authorization-binding providers — bind real evidence, never a magic constant.

MCP-RE **binds, never interprets** authorization evidence (bind-not-interpret): the
client includes a typed ``authorization_binding`` in the signed request preimage so
a later verifier can tie the request to the authorization artifact, without MCP-RE
ever reading the artifact's meaning. The cryptographic digest MUST be computed over
the *actual* artifact — handing in a precomputed ``digest_value`` defeats the point.

These providers mirror ``mcp-re-client-core::authz`` and delegate digest computation
to the audited core (``mcp_re_sdk.AuthorizationBinding``), so the binding is produced
in one place, identically to the proxy:

* :class:`OpaqueBytesProvider` — binds the EXACT decoded artifact bytes (e.g. a
  bearer token already base64url-decoded off the transport):
  ``digest_value = base64url-no-pad(SHA-256(bytes))``, computed in Rust.
* :class:`AuthzSystemReferenceProvider` — binds an external authorization system's
  self-contained digest plus its cross-audit reference, via a resolver.
* :class:`StaticAuthorizationProvider` — wraps one prebuilt binding (e.g. a single
  long-lived capability reused across requests).

Wire one into ``McpReConfig.authorization``; the transport calls ``provide(ctx)`` per
request with a real :class:`BindingRequestContext`, then enforces the optional
``McpReConfig.authorization_policy`` (fails closed on a disallowed binding type).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional, Union

import mcp_re_sdk


@dataclass(frozen=True)
class BindingRequestContext:
    """What a provider may use to LOCATE/produce the right artifact for a request.

    Bind-not-interpret: a provider uses these to select/fetch the artifact; the core
    never reads the artifact's meaning out of them. Mirrors the Rust
    ``BindingRequestContext``.
    """

    audience: str
    route_id: str
    method: Optional[str]
    tool_id: Optional[str]
    deadline_unix: int


@dataclass(frozen=True)
class AuthzReference:
    """An external authorization system's reference + its self-contained digest.

    The digest (not the reference) is the cryptographic binding, so the record stays
    verifiable independent of the external system.
    """

    authorization_system_id: str
    reference_scheme_id: str
    reference_value: str
    digest_value: str


# Artifact source: fixed decoded bytes, or a callable producing them per request
# (e.g. to fetch a fresh grant within the deadline). The callable receives the
# BindingRequestContext.
ArtifactSource = Union[bytes, Callable[[BindingRequestContext], bytes]]


class OpaqueBytesProvider:
    """Bind the EXACT decoded authorization-artifact bytes as ``opaque-bytes``.

    ``artifact`` is the decoded bytes, or a callable ``ctx -> bytes`` that yields
    them per request. The SHA-256 digest is computed by the audited core
    (``mcp_re_sdk.AuthorizationBinding.opaque_bytes``), never by this layer.
    """

    def __init__(self, artifact: ArtifactSource) -> None:
        self._artifact = artifact

    def provide(self, ctx: BindingRequestContext) -> Any:
        data = self._artifact(ctx) if callable(self._artifact) else self._artifact
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("OpaqueBytesProvider artifact must be bytes (the decoded artifact)")
        return mcp_re_sdk.AuthorizationBinding.opaque_bytes(bytes(data))


class AuthzSystemReferenceProvider:
    """Bind an external authz system's digest + reference (``authz-system-reference``).

    ``resolver`` is a callable ``ctx -> AuthzReference``. With no resolver this fails
    closed (the mandatory binding cannot be produced), mirroring the Rust
    ``AuthzSystemReferenceProvider::without_resolver``.
    """

    def __init__(
        self, resolver: Optional[Callable[[BindingRequestContext], AuthzReference]] = None
    ) -> None:
        self._resolver = resolver

    def provide(self, ctx: BindingRequestContext) -> Any:
        if self._resolver is None:
            # No resolver: the mandatory binding is missing — fail closed with the
            # frozen taxonomy reason (matches the Rust provider's posture).
            raise ValueError("mcp-re.authorization_binding_missing")
        ref = self._resolver(ctx)
        return mcp_re_sdk.AuthorizationBinding.authz_system_reference(
            ref.authorization_system_id,
            ref.reference_scheme_id,
            ref.reference_value,
            ref.digest_value,
        )


class StaticAuthorizationProvider:
    """Wrap one prebuilt ``mcp_re_sdk.AuthorizationBinding`` (reused across requests)."""

    def __init__(self, binding: Any) -> None:
        self._binding = binding

    def provide(self, ctx: BindingRequestContext) -> Any:
        return self._binding
