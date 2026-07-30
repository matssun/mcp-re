# SPDX-License-Identifier: Apache-2.0
"""The MCP-RE transport adapter (ADR-MCPS-044 §wrap-or-fork rule).

``mcp.ClientSession`` speaks plain MCP; this adapter signs the outgoing bytes and
verifies the incoming bytes underneath it, so application code never calls
``sign_request`` / ``verify_response`` itself.

Why a transport and not a wrapper: the MCP Python SDK serializes JSON-RPC *inside* each
transport — the anyio stream between ``ClientSession`` and the transport carries parsed
pydantic objects, not bytes. The transport is therefore the only seam with exact-byte
control, which is what a byte-exact signature requires.

    application code
      -> mcp.ClientSession            plain MCP; unaware of MCP-RE
      -> mcp_re_http_transport        signs outbound bytes / verifies inbound bytes
      -> mcp_re_sdk._core (PyO3)      the audited mcp-re-client-core, in Rust
      -> mcp-re-proxy (HTTP profile)  one signed mTLS POST per request

**Every failure is delivered, correlated to the request id, as a JSON-RPC error.** A
transport that dropped a failed exchange would leave ``ClientSession`` awaiting a reply
that never comes; a hang is a worse failure mode than a raise, and an unverifiable
response must never reach the application as a result.

**One-way notifications are carried, not dropped.** A notification is its own signed
POST, and the acknowledgement it earns — a signed bodyless 202 bound to that exact
transmission — is verified before the adapter treats it as delivered. See
:class:`NotificationNotAcknowledged` for what happens when it is not.

MCP-RE is HTTP-profile only: one signed POST per request. The POST itself is injected as
a ``poster`` so this layer stays transport-agnostic and testable; ``connect_mtls_http``
(the mTLS construction helper) builds on top of it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional, Sequence

import anyio
from mcp.shared.message import SessionMessage
from mcp.types import (
    ErrorData,
    JSONRPCError,
    JSONRPCNotification,
    JSONRPCRequest,
    jsonrpc_message_adapter,
)

from . import _core
from .authorization import AuthorizationBindingPolicy, AuthorizationBindingProvider, BindingRequestContext
from .correlation import ContinuationHandles, CorrelationStore
from .custody import McpReError, McpReSdkError, Signer, SignerPolicy

__all__ = [
    "ClientResponseUnsupported",
    "ConnectionClosed",
    "HttpReply",
    "McpReConfig",
    "NotificationNotAcknowledged",
    "mcp_re_http_transport",
]


class ClientResponseUnsupported(McpReSdkError):
    """The session tried to send a client->server RESPONSE, which has no MCP-RE carrier.

    A server-initiated request (sampling, elicitation over the same session) would be
    answered by a JSON-RPC response travelling client->server. MCP-RE profiles two client
    message shapes — a request that earns a signed reply, and a notification that earns a
    signed bodyless 202 — and a response is neither.

    Failing closed here is the narrow choice on purpose. The alternative the notification
    path makes available is worse: a response has no `method`, so carrying it as a
    notification would mean signing a fabricated message and reporting the acknowledgement
    of THAT as if the response had been delivered.
    """


class NotificationNotAcknowledged(McpReSdkError):
    """A notification was transmitted and its acknowledgement did not verify.

    The message left this process. What could not be established is that the enforcement
    boundary authenticated and accepted it: the 202 was absent, unsigned, signed by an
    untrusted key, or bound to a different transmission.

    **This tears the transport down**, because a notification has no reply for an error
    to ride back on. There is no request id to correlate a failure to and no application
    call awaiting an answer, so the only alternatives are to continue a session in which
    an unverifiable claim of acceptance was accepted, or to say nothing at all. Both
    reduce to taking the peer's word for it, which is the posture this protocol exists to
    remove. ``wire_code`` carries the frozen reason when the failure has one.
    """

    def __init__(self, method: str, wire_code: str) -> None:
        super().__init__(
            f"'{method}' was sent but its acknowledgement did not verify ({wire_code}); "
            f"the transport is failing closed rather than treating it as delivered"
        )
        self.method = method
        self.wire_code = wire_code


class ConnectionClosed(McpReSdkError):
    """The transport is not open for work: not started, or closing/closed.

    Also what queued and in-flight local requests fail with when ``close`` aborts them.

    **This says nothing about the server.** Cancelling a local ``poster`` call does not
    mean the request never arrived or that already-dispatched remote work has stopped —
    only that this client will not process an answer to it.
    """


#: The response-side body evidence block. Stripped before the result reaches the app:
#: MCP-RE's own evidence is not part of the MCP result.
_RESPONSE_BLOCK_KEY = "se.syncom/mcp-re.http.response"

#: JSON-RPC application error code for a delivered MCP-RE failure. The precise cause is
#: always the frozen `mcp-re.*` token in `.message`.
_MCP_RE_ERROR_CODE = -32001

#: Past every possible deadline: close reaps ALL outstanding correlation entries, not the
#: merely-expired ones.
_FAR_FUTURE = 2**63 - 1

#: Widest delegation clock skew a caller may configure, in seconds.
#:
#: Mirrors the RFC 9421 verifier's own ceiling (`VerifierPolicy::MAX_CLOCK_SKEW_BOUND`)
#: so one deployment does not run two different notions of "close enough" — beyond this
#: the credential's nbf/exp window stops bounding anything.
MAX_CLOCK_SKEW_BOUND = 300


@dataclass(frozen=True)
class HttpReply:
    """What a ``poster`` returns: the raw HTTP response, unparsed and unverified."""

    status: int
    headers: list
    body: bytes


#: Send one signed POST. ``(method, target_uri, headers, body) -> HttpReply``.
Poster = Callable[[str, str, list, bytes], Awaitable[HttpReply]]


#: Minimum characters in an anti-replay nonce. 128 bits base64url-encodes to 22
#: characters, which is what both SDKs' default generators produce — so this floor
#: never constrains the default path. It constrains an OVERRIDE: ``nonce_factory`` is
#: caller-supplied and was accepted unchecked, so a factory returning a counter, a
#: timestamp, or a truncated value silently weakened replay protection for every
#: request while every signature still verified.
MIN_NONCE_CHARS = 22


def _default_nonce() -> str:
    # 128 bits from the OS CSPRNG: the freshness window rejects a repeat, so the only
    # requirement here is that a collision is not reachable in practice.
    return secrets.token_urlsafe(16)


def _checked_nonce(factory: Callable[[], str]) -> str:
    """Draw a nonce and refuse a sub-floor one, at SIGN time.

    Fails closed rather than signing: a request signed under a guessable nonce is
    accepted by the verifier and is exactly what the replay window cannot save you
    from. Enforced only where a nonce is EMITTED — the accepted wire language is
    unchanged, so this needs no cross-implementation coordination and no fixture
    regeneration.
    """
    nonce = factory()
    if not isinstance(nonce, str) or len(nonce) < MIN_NONCE_CHARS:
        raise McpReError(
            f"mcp-re-sdk: nonce_factory returned {len(nonce) if isinstance(nonce, str) else type(nonce).__name__} "
            f"characters; a nonce must be at least {MIN_NONCE_CHARS} (128 bits base64url)"
        )
    return nonce


def _default_clock() -> int:
    return int(time.time())


@dataclass
class McpReConfig:
    """Everything the adapter needs to sign one request and verify one response.

    Freshness is generated here, not by the caller: a nonce that repeats inside the
    window is a defect, not a policy knob.
    """

    # --- signing ---
    signer: Signer
    audience_id: str
    target_uri: str
    dpop_token: str
    route: Optional[str] = None
    policy: Optional[SignerPolicy] = None

    # --- delegated verification (ADR-MCPRE-052): the trusted ROOT ISSUER anchor ---
    issuer_key_id: str = ""
    issuer_pubkey_b64url: str = ""
    issuer_role: str = "server"
    issuer_trust_domain: str = ""
    issuer_subject: str = ""
    verifier_audiences: Sequence[str] = ()
    expected_audience_hash: str = ""
    accepted_epochs: Sequence[str] = ()
    max_clock_skew: int = 60

    #: This client's static denylist of delegated key ids, issuer key ids, and credential
    #: `jti` values. Any hit fails the response closed.
    #:
    #: **Empty is the TTL-only posture, and it is the default.** With no denylist the
    #: client relies entirely on short delegated-key lifetimes and on the accepted-epoch
    #: set to retire a compromised key: a credential stays acceptable until it expires or
    #: its epoch leaves `accepted_epochs`. That is a legitimate deployment choice — it is
    #: what the audited core calls the explicit TTL-only posture — but stating it here
    #: makes it a choice rather than something that happened by omission.
    revoked_identifiers: Sequence[str] = ()

    # --- authorization bindings (bind-not-interpret) ---
    authorization: Sequence[AuthorizationBindingProvider] = ()
    authorization_policy: Optional[AuthorizationBindingPolicy] = None

    # --- freshness ---
    request_ttl: int = 300
    clock: Callable[[], int] = _default_clock
    nonce_factory: Callable[[], str] = _default_nonce

    #: How many signed exchanges may be in flight at once.
    #:
    #: MCP is not lock-step — a client may have several requests outstanding, and each
    #: MCP-RE exchange is an independent signed POST with its own nonce and its own
    #: correlation entry, so nothing about the protocol requires serializing them. Running
    #: them one at a time would make one slow tool call block every other, which is
    #: head-of-line blocking the transport has no reason to impose.
    #:
    #: It is bounded rather than unlimited because each in-flight exchange holds a
    #: connection in the caller's `poster` and a signing operation (a KMS round trip under
    #: non-exporting custody); an unbounded fan-out would let a burst of calls exhaust
    #: either. Raise it for a client that genuinely wants more parallelism.
    max_concurrent_exchanges: int = 8

    #: Called with `(method, server_keyid)` for each client->server notification whose
    #: signed 202 verified. Observability only — the acceptance claim has already been
    #: checked by the time this runs, and declining to observe it changes nothing.
    #:
    #: What a verified acknowledgement means is exactly: the enforcement boundary
    #: authenticated and accepted the message. NOT that the action completed — a verified
    #: ack for `notifications/cancelled` does not mean anything was cancelled.
    on_notification_acknowledged: Optional[Callable[[str, str], None]] = None

    #: Called when a verified response is an ADR-MCPS-047 `InputRequiredResult`, with the
    #: handles its answer leg must sign over. The open leg stays outstanding.
    on_input_required: Optional[Callable[[ContinuationHandles], None]] = None

    def __post_init__(self) -> None:
        # Validated where the value first enters SDK-owned code. A bound of 0 is not a
        # degenerate case that merely throttles: every sender waits for a slot that can
        # never be released, so the session deadlocks in silence.
        n = self.max_concurrent_exchanges
        if isinstance(n, bool) or not isinstance(n, int) or n < 1:
            raise McpReSdkError(
                f"max_concurrent_exchanges must be a positive integer, got {n!r}"
            )
        # The delegation credential's nbf/exp window is only as strong as the skew
        # allowed around it: `now + skew < nbf` and `now - skew > exp` are how it is
        # applied, so a large value accepts a credential arbitrarily far outside its
        # validity window and a negative one distorts the comparison rather than
        # tightening it. Nothing downstream bounds this — DelegationPolicy stores it
        # verbatim — so it is checked where it enters SDK-owned code, mirroring the
        # RFC 9421 skew, which is capped at 300s by VerifierPolicy.
        s = self.max_clock_skew
        if isinstance(s, bool) or not isinstance(s, int) or not 0 <= s <= MAX_CLOCK_SKEW_BOUND:
            raise McpReSdkError(
                f"max_clock_skew must be an integer in 0..={MAX_CLOCK_SKEW_BOUND} "
                f"seconds, got {s!r}"
            )
        # The delegated-verification anchor. Every field below is compared against the
        # credential the server presents, and an empty value cannot match anything: an
        # empty `accepted_epochs` fails every response as a stale trust epoch, an empty
        # `verifier_audiences` as an audience mismatch, an empty issuer key as an invalid
        # key. The client is therefore not *unsafe* with them unset — it is unusable —
        # but it does not discover that until the first response comes back looking like
        # a server fault. TypeScript makes these required interface fields; this is where
        # Python states the same requirement, at construction, naming what is missing.
        missing = [
            name
            for name in (
                "issuer_key_id",
                "issuer_pubkey_b64url",
                "issuer_trust_domain",
                "issuer_subject",
                "expected_audience_hash",
            )
            if not getattr(self, name)
        ] + [
            name
            for name in ("verifier_audiences", "accepted_epochs")
            if not list(getattr(self, name))
        ]
        if missing:
            raise McpReSdkError(
                "the delegated-verification trust anchor is incomplete: "
                f"{', '.join(sorted(missing))} must be set. Every response is verified "
                "against these, so an empty value rejects every response the server "
                "sends rather than relaxing the check."
            )


def _binding_context(config: McpReConfig, method: str) -> BindingRequestContext:
    return BindingRequestContext(
        audience_id=config.audience_id,
        target_uri=config.target_uri,
        method=method,
        route=config.route,
    )


def _bindings_json(config: McpReConfig, method: str) -> Optional[str]:
    if not config.authorization:
        return None
    ctx = _binding_context(config, method)
    return json.dumps([p.spec(ctx) for p in config.authorization])


def _authz_binding_digest(bindings_json: Optional[str]) -> Optional[str]:
    """``sha-256:<b64url>`` over the exact authorization-binding bytes that were signed.

    ADR-MCPS-044 enumerates this among the fields a conforming client keeps per
    outstanding request. It is retained for audit only and never re-interpreted
    (bind-not-interpret): it records WHICH authorization artefacts this request was bound
    to, so an audit trail can be reconciled against the signed bytes without the
    transport ever parsing them. ``None`` when the request carried no bindings.
    """
    if bindings_json is None:
        return None
    digest = hashlib.sha256(bindings_json.encode()).digest()
    return "sha-256:" + base64.urlsafe_b64encode(digest).decode().rstrip("=")


def _strip_response_evidence(body: bytes) -> bytes:
    """Remove MCP-RE's response evidence block; the app sees plain MCP.

    Read only AFTER verification: the content-digest covered these bytes.
    """
    doc = json.loads(body)
    meta = doc.get("_meta")
    if isinstance(meta, dict) and _RESPONSE_BLOCK_KEY in meta:
        meta.pop(_RESPONSE_BLOCK_KEY)
        if not meta:
            doc.pop("_meta")
    return json.dumps(doc).encode()


def _error_message(request_id, wire_code: str) -> SessionMessage:
    """A JSON-RPC error correlated to the request, so the awaiting call raises."""
    return SessionMessage(
        JSONRPCError(
            jsonrpc="2.0",
            id=request_id,
            error=ErrorData(code=_MCP_RE_ERROR_CODE, message=wire_code),
        )
    )


async def _exchange(
    config: McpReConfig,
    poster: Poster,
    request: JSONRPCRequest,
    correlation: CorrelationStore,
) -> SessionMessage:
    """Sign one request, POST it, verify the reply, and correlate it back.

    Returns the plain-MCP message to hand the session — a result on success, or a
    JSON-RPC error carrying the frozen wire code on any failure.
    """
    params = request.params if request.params is not None else {}
    created = config.clock()
    expires = created + config.request_ttl
    bindings_json = _bindings_json(config, request.method)

    signed = config.signer.sign_request(
        id_json=json.dumps(request.id),
        method=request.method,
        params_json=json.dumps(params),
        target_uri=config.target_uri,
        audience_id=config.audience_id,
        route=config.route,
        dpop_token=config.dpop_token,
        nonce=_checked_nonce(config.nonce_factory),
        created=created,
        expires=expires,
        bindings_json=bindings_json,
    )
    correlation_id = correlation.record(
        signed,
        request_id=str(request.id),
        nonce="",  # the nonce rode into the signature; the handle is the evidence digest
        audience_id=config.audience_id,
        expected_signer_id=config.issuer_key_id,
        created=created,
        expires=expires,
        route=config.route,
        authz_binding_digest=_authz_binding_digest(bindings_json),
    )

    try:
        reply = await poster(signed.method, signed.target_uri, signed.headers, signed.body())

        verified = _core.verify_response(
            reply.status,
            list(reply.headers),
            reply.body,
            signed.method,
            signed.target_uri,
            list(signed.headers),
            signed.body(),
            signed.evidence_digest_alg,
            signed.evidence_digest_value,
            config.issuer_key_id,
            config.issuer_pubkey_b64url,
            config.issuer_role,
            config.issuer_trust_domain,
            config.issuer_subject,
            list(config.verifier_audiences),
            config.expected_audience_hash,
            list(config.accepted_epochs),
            config.max_clock_skew,
            list(config.revoked_identifiers),
            config.clock(),
        )

        # A verified rejection receipt is genuine evidence, but it is NOT an acceptance:
        # it must reach the app as an error, never as a result.
        if verified.outcome != "success":
            correlation.take(correlation_id, now=config.clock())
            return _error_message(request.id, verified.wire_code or "mcp-re.response_sig_invalid")

        if verified.request_state is not None:
            # ADR-MCPS-047: an elicitation does not end the exchange, so the open leg
            # stays outstanding (associate, do not consume) until its answer leg
            # terminates it.
            handles = correlation.record_input_required(
                correlation_id,
                response_digest_alg=verified.resp_evidence_digest_alg,
                response_digest_value=verified.resp_evidence_digest_value,
                request_state=verified.request_state,
                now=config.clock(),
            )
            if config.on_input_required is not None:
                config.on_input_required(handles)
        else:
            correlation.take(correlation_id, now=config.clock())
    except BaseException:
        # This exchange produced no answer, so nothing will ever bind this entry.
        # Everything that lands here is remotely triggerable — a reset connection, a
        # reply that fails verification, a rejection whose own bookkeeping raised — so
        # leaving the entry outstanding would let a peer grow the store one failed
        # request at a time, for the life of the session. Retiring it is not a security
        # decision: a response that arrives for it afterwards is refused either way.
        correlation.abandon(correlation_id)
        raise

    return SessionMessage(jsonrpc_message_adapter.validate_json(_strip_response_evidence(reply.body)))


async def _notify(config: McpReConfig, poster: Poster, method: str, params) -> None:
    """Sign one notification, POST it, and verify the acknowledgement it earns.

    A notification is signed by the ordinary request rules — same evidence block, same
    covered components, same freshness triple. What it gets back is a signed bodyless
    202 whose `;req` components plus `mcp-re-request-evidence` bind it to THIS
    transmission (owner ruling C019b), so a 202 captured from an earlier send of the
    same notification does not verify here.

    Raises :class:`NotificationNotAcknowledged` on any failure. There is deliberately no
    "sent it anyway" path: an unverified acknowledgement establishes nothing, and
    treating it as delivery is the take-it-on-faith posture the profile removes.
    """
    created = config.clock()
    expires = created + config.request_ttl
    bindings_json = _bindings_json(config, method)

    signed = config.signer.sign_notification(
        method=method,
        params_json=json.dumps(params if params is not None else {}),
        target_uri=config.target_uri,
        audience_id=config.audience_id,
        route=config.route,
        dpop_token=config.dpop_token,
        nonce=_checked_nonce(config.nonce_factory),
        created=created,
        expires=expires,
        bindings_json=bindings_json,
    )

    reply = await poster(signed.method, signed.target_uri, signed.headers, signed.body())
    try:
        accepted = _core.verify_accepted_202(
            reply.status,
            list(reply.headers),
            reply.body,
            signed.method,
            signed.target_uri,
            list(signed.headers),
            signed.body(),
            config.issuer_key_id,
            config.issuer_pubkey_b64url,
            config.issuer_role,
            config.issuer_trust_domain,
            config.issuer_subject,
            list(config.verifier_audiences),
            config.expected_audience_hash,
            list(config.accepted_epochs),
            config.max_clock_skew,
            list(config.revoked_identifiers),
            config.clock(),
        )
    except McpReError as e:
        raise NotificationNotAcknowledged(method, e.wire_code) from e
    except ValueError as e:
        # The core's fail-closed errors arrive as ValueError carrying the frozen token.
        raise NotificationNotAcknowledged(method, str(e)) from e

    if config.on_notification_acknowledged is not None:
        config.on_notification_acknowledged(method, accepted.server_keyid)


async def _one(config: McpReConfig, poster: Poster, request: JSONRPCRequest, read_writer,
               limiter, correlation: CorrelationStore) -> None:
    """Run one exchange to completion and deliver its outcome to the session.

    Every failure becomes a message. The session is awaiting this id, so returning
    without sending would hang it forever.
    """
    async with limiter:
        try:
            message = await _exchange(config, poster, request, correlation)
        except McpReError as e:
            message = _error_message(request.id, e.wire_code)
        except McpReSdkError as e:
            # A local failure (e.g. the signing device). No wire code describes it.
            message = _error_message(request.id, f"mcp-re-sdk: {e}")
        except ValueError as e:
            # The core's own fail-closed errors arrive as ValueError carrying the
            # frozen token; deliver it rather than letting the caller hang.
            message = _error_message(request.id, str(e))
        except Exception as e:
            # Anything else — and in practice that is dominated by the caller's `poster`
            # doing real I/O: a reset connection, a TLS error, a timeout. Exchanges run
            # concurrently in one task group, so letting these escape would cancel every
            # OTHER in-flight exchange and tear down the session; one flaky connection
            # would take out seven unrelated requests, and a peer that can cause a reset
            # could end the session at will.
            #
            # It is delivered under the `mcp-re-sdk:` prefix and tagged with its type,
            # never as a bare `mcp-re.*` token, so it can never be read as something the
            # peer said. A genuine defect stays fully visible — it arrives named, as
            # `mcp-re-sdk: TypeError: ...`, correlated to the request that hit it —
            # rather than as an ExceptionGroup with the session gone.
            #
            # BaseException is deliberately NOT caught: cancellation must propagate, or
            # `close()` could not abort an in-flight exchange.
            message = _error_message(request.id, f"mcp-re-sdk: {type(e).__name__}: {e}")
    await read_writer.send(message)


async def _one_notification(config: McpReConfig, poster: Poster, method: str, params,
                            limiter) -> None:
    """Run one notification to completion under the concurrency bound.

    Unlike :func:`_one`, a failure here is NOT converted into a delivered message: there
    is no request id to correlate it to and no caller awaiting a reply, so it propagates
    out of the pump's task group and closes the transport. That asymmetry is the shape of
    a one-way message, not a difference in how strictly the two are checked.
    """
    async with limiter:
        await _notify(config, poster, method, params)


async def _pump(config: McpReConfig, poster: Poster, write_reader, read_writer,
                correlation: Optional[CorrelationStore] = None) -> None:
    """Drive every outbound session message through the MCP-RE obligation.

    Exchanges run concurrently, up to ``max_concurrent_exchanges``: awaiting each one
    before reading the next request would make a single slow tool call block every other
    request on the session.
    """
    limiter = anyio.CapacityLimiter(config.max_concurrent_exchanges)
    if correlation is None:
        correlation = CorrelationStore()
    async with write_reader, read_writer:
        # The task group closes INSIDE the streams: it waits for every in-flight exchange
        # before the streams are closed, so a slow exchange can still deliver its reply
        # rather than failing to send on a closed stream.
        async with anyio.create_task_group() as tg:
            async for outgoing in write_reader:
                message = outgoing.message
                if isinstance(message, JSONRPCNotification):
                    # A one-way notification: its own signed POST, answered by a signed
                    # bodyless 202 rather than a JSON-RPC reply. It runs under the same
                    # concurrency bound as an exchange because it costs the same
                    # resources — a connection and a signing operation.
                    tg.start_soon(
                        _one_notification, config, poster, message.method, message.params, limiter
                    )
                    continue
                if not isinstance(message, JSONRPCRequest):
                    # A client->server RESPONSE or error. It has no `method`, so the
                    # notification path above could only carry it by signing a fabricated
                    # message; refuse it instead of inventing one.
                    raise ClientResponseUnsupported(
                        f"{type(message).__name__} is a client->server response; MCP-RE "
                        f"profiles a signed request and a signed notification, and a "
                        f"response is neither"
                    )
                tg.start_soon(_one, config, poster, message, read_writer, limiter, correlation)


@asynccontextmanager
async def mcp_re_http_transport(
    config: McpReConfig,
    poster: Poster,
    *,
    correlation: Optional[CorrelationStore] = None,
):
    """An MCP client transport that signs requests and verifies responses.

    Yields the ``(read_stream, write_stream)`` pair ``mcp.ClientSession`` expects::

        async with mcp_re_http_transport(config, poster) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                await session.call_tool("read_file", {"path": "/etc/hosts"})

    The signer is checked against the route's policy before anything is signed, so a
    custody violation fails the connection rather than a request.

    In-flight correlation state belongs to ONE transport, not to the config: the config
    is a value object a caller may reasonably reuse, and two transports sharing a store
    would let either one clear the other's outstanding requests on close. A store is
    created per invocation; pass ``correlation`` only to observe it (the TypeScript
    transport exposes the same state as ``pendingCorrelations``).
    """
    if correlation is None:
        correlation = CorrelationStore()
    if config.policy is not None:
        config.policy.check(config.signer)
    if config.authorization_policy is not None:
        config.authorization_policy.check(list(config.authorization))

    read_writer, read_stream = anyio.create_memory_object_stream(0)
    write_stream, write_reader = anyio.create_memory_object_stream(0)

    async with anyio.create_task_group() as tg:
        tg.start_soon(_pump, config, poster, write_reader, read_writer, correlation)
        try:
            yield read_stream, write_stream
        finally:
            # Abortive close (#421), matching the upstream client's rejection of pending
            # requests: in-flight exchanges are cancelled rather than drained, and the
            # streams close, so a later send fails and no reply can be delivered to a
            # caller that has left the block.
            #
            # This makes NO claim that already-dispatched remote work has stopped: the
            # server may have received the request and acted on it. Only that this client
            # will not process an answer.
            tg.cancel_scope.cancel()
            # Abandoned entries would otherwise outlive the transport that owns them.
            correlation.expire_before(_FAR_FUTURE)
