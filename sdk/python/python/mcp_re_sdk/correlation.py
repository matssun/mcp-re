# SPDX-License-Identifier: Apache-2.0
"""In-flight request correlation (ADR-MCPS-044 §In-flight correlation state).

Stateless means no discovery-session state — it does not mean no in-flight state. A
conforming client MUST track every outstanding request and bind each response back to
the exact request it answers, failing closed when it cannot.

This store keeps, per outstanding request, the fields the ADR enumerates: correlation
id, request evidence handle, nonce / JSON-RPC id, issued-at, expiry, route, audience,
expected signer, and the authorization-binding digest for audit.

The correlation id is the request's evidence digest value: it is unique per request and
is the very handle a signed response binds to, so correlation and cryptographic binding
cannot drift apart.

Fail-closed, using the frozen `mcp-re.*` taxonomy — no code is invented here:

===============================  ==========================================
A response that...               fails as
===============================  ==========================================
matches no outstanding request    ``mcp-re.request_binding_mismatch``
arrives after its request expired ``mcp-re.expired_request``
answers an already-answered one   ``mcp-re.replay_detected``
===============================  ==========================================
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional

from .custody import McpReError

__all__ = [
    "ContinuationHandles",
    "CorrelationStore",
    "PendingRequest",
]


@dataclass(frozen=True)
class PendingRequest:
    """One outstanding request, as ADR-MCPS-044 §In-flight correlation state requires."""

    correlation_id: str
    request_id: str
    nonce: str
    evidence_digest_alg: str
    evidence_digest_value: str
    audience_id: str
    expected_signer_id: str
    created: int
    expires: int
    route: Optional[str] = None
    #: Retained for audit only — never re-interpreted (bind-not-interpret).
    authz_binding_digest: Optional[str] = None

    def is_expired(self, now: int) -> bool:
        return now > self.expires


@dataclass(frozen=True)
class ContinuationHandles:
    """The two evidence handles + opaque state an ADR-MCPS-047 answer leg signs over.

    Feed these straight into ``sign_request(..., cont_prev_alg=..., ...)``.
    """

    prev_alg: str
    prev_value: str
    irr_alg: str
    irr_value: str
    request_state: str

    def as_sign_kwargs(self) -> dict:
        """The continuation kwargs for :func:`mcp_re_sdk.sign_request`."""
        return {
            "cont_prev_alg": self.prev_alg,
            "cont_prev_value": self.prev_value,
            "cont_irr_alg": self.irr_alg,
            "cont_irr_value": self.irr_value,
            "cont_request_state": self.request_state,
        }


class CorrelationStore:
    """Tracks outstanding requests and binds responses back to them, fail-closed.

    Not thread-safe: hold one store per client session, as the request/response cycle
    that drives it is already serialized per connection.
    """

    def __init__(self) -> None:
        self._pending: Dict[str, PendingRequest] = {}
        # Consumed correlation ids, so a second response for the same request is a
        # replay rather than an unknown-request mismatch. The distinction matters: one
        # is a duplicate, the other is an unrelated message.
        self._consumed: set[str] = set()

    def __len__(self) -> int:
        return len(self._pending)

    def __iter__(self) -> Iterator[PendingRequest]:
        return iter(self._pending.values())

    def record(
        self,
        signed,
        *,
        request_id: str,
        nonce: str,
        audience_id: str,
        expected_signer_id: str,
        created: int,
        expires: int,
        route: Optional[str] = None,
        authz_binding_digest: Optional[str] = None,
    ) -> str:
        """Register a signed request as outstanding; returns its correlation id.

        ``signed`` is the :class:`SignedRequest` returned by ``sign_request``.
        """
        correlation_id = signed.evidence_digest_value
        if correlation_id in self._pending:
            # The evidence digest is unique per request; a collision means the same
            # request was recorded twice, which would let one response consume the
            # wrong entry.
            raise McpReError(
                "mcp-re.replay_detected",
                f"request {correlation_id!r} is already outstanding",
            )
        self._pending[correlation_id] = PendingRequest(
            correlation_id=correlation_id,
            request_id=request_id,
            nonce=nonce,
            evidence_digest_alg=signed.evidence_digest_alg,
            evidence_digest_value=signed.evidence_digest_value,
            audience_id=audience_id,
            expected_signer_id=expected_signer_id,
            created=created,
            expires=expires,
            route=route,
            authz_binding_digest=authz_binding_digest,
        )
        return correlation_id

    def peek(self, correlation_id: str) -> Optional[PendingRequest]:
        """The outstanding request, or None. Does not consume."""
        return self._pending.get(correlation_id)

    def take(self, correlation_id: str, *, now: int) -> PendingRequest:
        """Consume the outstanding request a response answers.

        Fails closed if the response matches nothing outstanding, answers a request
        that already expired, or duplicates one already answered.
        """
        pending = self._pending.get(correlation_id)
        if pending is None:
            if correlation_id in self._consumed:
                raise McpReError(
                    "mcp-re.replay_detected",
                    f"request {correlation_id!r} was already answered",
                )
            raise McpReError(
                "mcp-re.request_binding_mismatch",
                f"response does not bind to any outstanding request ({correlation_id!r})",
            )
        if pending.is_expired(now):
            # A late response is dropped AND the entry consumed: it must not stay
            # outstanding for a later, even later, answer.
            del self._pending[correlation_id]
            self._consumed.add(correlation_id)
            raise McpReError(
                "mcp-re.expired_request",
                f"response arrived at {now} for a request that expired at {pending.expires}",
            )
        del self._pending[correlation_id]
        self._consumed.add(correlation_id)
        return pending

    def record_input_required(
        self,
        correlation_id: str,
        *,
        response_digest_alg: str,
        response_digest_value: str,
        request_state: str,
        now: int,
    ) -> ContinuationHandles:
        """Associate a verified `InputRequiredResult` WITHOUT consuming its request.

        An ADR-MCPS-047 elicitation is not the end of the exchange: the open leg stays
        outstanding until the answer leg terminates it, so this associates rather than
        consumes. The returned handles are what the answer leg signs over.
        """
        pending = self._pending.get(correlation_id)
        if pending is None:
            if correlation_id in self._consumed:
                raise McpReError(
                    "mcp-re.replay_detected",
                    f"request {correlation_id!r} was already answered",
                )
            raise McpReError(
                "mcp-re.request_binding_mismatch",
                f"input-required response does not bind to any outstanding request "
                f"({correlation_id!r})",
            )
        if pending.is_expired(now):
            del self._pending[correlation_id]
            self._consumed.add(correlation_id)
            raise McpReError(
                "mcp-re.expired_request",
                f"input-required response arrived at {now} for a request that expired "
                f"at {pending.expires}",
            )
        return ContinuationHandles(
            prev_alg=pending.evidence_digest_alg,
            prev_value=pending.evidence_digest_value,
            irr_alg=response_digest_alg,
            irr_value=response_digest_value,
            request_state=request_state,
        )

    def expire_before(self, now: int) -> List[PendingRequest]:
        """Drop every outstanding request past its deadline; returns those dropped.

        Reaping bounds the store: without it, requests that never get an answer
        accumulate for the life of the session.
        """
        dead = [p for p in self._pending.values() if p.is_expired(now)]
        for p in dead:
            del self._pending[p.correlation_id]
            self._consumed.add(p.correlation_id)
        return dead
