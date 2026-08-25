# SPDX-License-Identifier: Apache-2.0
"""Authorization-binding providers (ADR-MCPS-044 §Authorization-binding hook).

**Bind, do not interpret.** A provider hands the SDK the *artifact itself*; the audited
core digests it and puts the digest — never the bytes — into the signed evidence. MCP-RE
never dereferences a reference, evaluates a permission, or parses authorization
semantics. It proves *which* artifact authorized a request, and nothing about what the
artifact means.

Two base forms:

``OpaqueBytesProvider``
    The client holds the artifact bytes (a capability token, a consent record). The
    binding digest is ``base64url-no-pad(SHA-256(bytes))``, computed in Rust.

``AuthzSystemReferenceProvider``
    Same digest over the same real bytes, plus the external system's identity and grant
    handle for cross-audit. The record stays verifiable independently of that system's
    live state.

``AuthorizationDecisionProvider``
    An authorization authority's signed decision document (ADR-MCPRE-065). This one is
    not merely a binding: the document travels inside the signed evidence block AND the
    core mints the ``pdp-decision``/``opaque-digest`` binding over those exact bytes, so
    the carried decision and the digest committing to it cannot disagree.

    ``pdp-decision`` is therefore not available through ``OpaqueBytesProvider``. That
    would build the binding half alone — a request a Mode-2 verifier necessarily refuses,
    and half of a pair ADR-MCPRE-065 says must exist together. The *reference* form is
    untouched: ``AuthzSystemReferenceProvider("pdp-decision", ...)`` still expresses
    external decision linkage, which is a different claim.

Neither accepts a precomputed digest: the digest is always derived from material the
caller actually presents, so a caller cannot assert a binding to an artifact it does not
have.

Providers here are **synchronous and supply already-acquired material.** Fetching a
decision from a PDP belongs in the application or transport layer, above this one.
"""
from __future__ import annotations

import abc
import base64
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

from .custody import McpReError

__all__ = [
    "ArtifactType",
    "AuthorizationBindingPolicy",
    "AuthorizationDecisionProvider",
    "AuthorizationBindingProvider",
    "AuthzSystemReferenceProvider",
    "BindingRequestContext",
    "OpaqueBytesProvider",
]

#: The seven artifact-type registry tokens the RFC 9421 profile defines
#: (ADR-MCPRE-050 §Resolved Q5). `oauth-dpop` is the SDK's built-in header-derived
#: binding and is not provider-supplied.
ArtifactType = str

_REGISTRY: frozenset = frozenset(
    {
        "oauth-dpop",
        "oauth-mtls",
        "oauth-rar",
        "pdp-decision",
        "dtr-approval",
        "classifier-result",
        "human-approval",
    }
)


#: The artifact type an authorization decision is, and the one type whose opaque form is
#: reachable only through :class:`AuthorizationDecisionProvider`.
_DECISION_TYPE = "pdp-decision"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


@dataclass(frozen=True)
class BindingRequestContext:
    """What a provider may branch on when choosing a binding.

    The route/method/audience a request is about — never the request bytes, so a
    provider cannot make the binding depend on content the core has not yet signed.
    """

    audience_id: str
    target_uri: str
    method: str
    route: Optional[str] = None
    deadline: Optional[int] = None


class AuthorizationBindingProvider(abc.ABC):
    """Given a request context, produce one artifact binding spec.

    Implementations return the artifact MATERIAL; the core digests it.
    """

    @abc.abstractmethod
    def binding_type(self) -> str:
        """The `artifact_type` registry token this provider binds."""

    @abc.abstractmethod
    def spec(self, context: BindingRequestContext) -> dict:
        """The binding spec the native core consumes."""


class OpaqueBytesProvider(AuthorizationBindingProvider):
    """Bind the exact artifact bytes the client holds.

    The digest is computed by the core from ``material``; the bytes themselves never
    enter the evidence block.
    """

    def __init__(self, artifact_type: str, material: bytes) -> None:
        if artifact_type not in _REGISTRY:
            raise McpReError(
                "mcp-re.authorization_binding_type_unsupported",
                f"{artifact_type!r} is not an artifact-type registry token",
            )
        if artifact_type == _DECISION_TYPE:
            # Ergonomics only — the native seam refuses this pair independently, because
            # a caller composing the spec JSON never passes through this class.
            raise McpReError(
                "mcp-re.authorization_binding_type_unsupported",
                f"{_DECISION_TYPE!r} has no generic opaque form: an opaque binding "
                "without its decision document is half of a pair the verifier refuses. "
                "Use AuthorizationDecisionProvider, or AuthzSystemReferenceProvider for "
                "external decision linkage.",
            )
        if not isinstance(material, (bytes, bytearray)) or not material:
            raise McpReError(
                "mcp-re.authorization_binding_missing",
                "opaque binding requires non-empty artifact material",
            )
        self._artifact_type = artifact_type
        self._material = bytes(material)

    def binding_type(self) -> str:
        return self._artifact_type

    def spec(self, context: BindingRequestContext) -> dict:
        return {
            "artifact_type": self._artifact_type,
            "form": "opaque-bytes",
            "material_b64url": _b64url(self._material),
        }


class AuthzSystemReferenceProvider(AuthorizationBindingProvider):
    """Bind real artifact bytes AND name the external system that issued them.

    The digest still comes from ``material`` — the reference fields identify the
    decision for cross-audit, they do not replace the binding. Nothing secret belongs in
    them: they are emitted verbatim into the evidence block.
    """

    def __init__(
        self,
        artifact_type: str,
        material: bytes,
        *,
        authorization_system_id: str,
        reference_scheme_id: str,
        reference_value: str,
    ) -> None:
        if artifact_type not in _REGISTRY:
            raise McpReError(
                "mcp-re.authorization_binding_type_unsupported",
                f"{artifact_type!r} is not an artifact-type registry token",
            )
        if not isinstance(material, (bytes, bytearray)) or not material:
            raise McpReError(
                "mcp-re.authorization_binding_missing",
                "reference binding requires non-empty artifact material",
            )
        if not (authorization_system_id and reference_scheme_id and reference_value):
            # The core rejects a partial reference form; catch it here with a message
            # that names the hook rather than the wire shape.
            raise McpReError(
                "mcp-re.authorization_binding_malformed",
                "reference binding requires authorization_system_id, reference_scheme_id, "
                "and reference_value",
            )
        self._artifact_type = artifact_type
        self._material = bytes(material)
        self._authorization_system_id = authorization_system_id
        self._reference_scheme_id = reference_scheme_id
        self._reference_value = reference_value

    def binding_type(self) -> str:
        return self._artifact_type

    def spec(self, context: BindingRequestContext) -> dict:
        return {
            "artifact_type": self._artifact_type,
            "form": "authz-system-reference",
            "material_b64url": _b64url(self._material),
            "authorization_system_id": self._authorization_system_id,
            "reference_scheme_id": self._reference_scheme_id,
            "reference_value": self._reference_value,
        }


class AuthorizationDecisionProvider(AuthorizationBindingProvider):
    """Present the authorization decision this call acts under (ADR-MCPRE-065).

    ``decision`` is the compact JWS an authorization authority issued. Unlike the other
    providers this contributes TWO things — the document, carried inside the signed
    evidence block, and the ``pdp-decision``/``opaque-digest`` binding over it — and the
    binding is minted by the audited core from the document's exact bytes.

    There is deliberately no parameter for the digest. A caller able to supply both could
    commit to one document and carry another, and the digest is the only thing tying the
    two together.
    """

    def __init__(self, decision: bytes | str) -> None:
        material = decision.encode() if isinstance(decision, str) else decision
        if not isinstance(material, (bytes, bytearray)) or not material:
            raise McpReError(
                "mcp-re.authorization_binding_missing",
                "an authorization decision requires the compact decision document",
            )
        self._material = bytes(material)

    def binding_type(self) -> str:
        return _DECISION_TYPE

    def spec(self, context: BindingRequestContext) -> dict:
        return {
            "artifact_type": _DECISION_TYPE,
            "form": "authorization-decision",
            "material_b64url": _b64url(self._material),
        }


@dataclass(frozen=True)
class AuthorizationBindingPolicy:
    """Which artifact types a route will carry, and whether one is required.

    Enforced before signing: a provider whose type is not permitted fails the route
    closed rather than emitting evidence the verifier would reject.
    """

    permitted_types: frozenset
    require_binding: bool = False

    @classmethod
    def permitting(cls, types: Iterable[str], *, require_binding: bool = False):
        return cls(permitted_types=frozenset(types), require_binding=require_binding)

    def check(self, providers: Sequence[AuthorizationBindingProvider]) -> None:
        """Fail closed unless every provider is permitted (and one exists if required)."""
        if self.require_binding and not providers:
            raise McpReError(
                "mcp-re.authorization_binding_missing",
                "this route requires an authorization binding",
            )
        for p in providers:
            if p.binding_type() not in self.permitted_types:
                raise McpReError(
                    "mcp-re.authorization_binding_type_unsupported",
                    f"{p.binding_type()!r} is not permitted on this route "
                    f"(permitted: {sorted(self.permitted_types)})",
                )
