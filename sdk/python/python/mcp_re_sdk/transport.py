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

**This is a request/response adapter.** One-way notifications fail closed by default —
see :class:`NotificationsUnsupported` for why that is a missing profile rather than an
inherent limit, and ``unsafe_drop_notifications`` for the interim escape hatch.

MCP-RE is HTTP-profile only: one signed POST per request. The POST itself is injected as
a ``poster`` so this layer stays transport-agnostic and testable; ``connect_mtls_http``
(the mTLS construction helper) builds on top of it.
"""
from __future__ import annotations

import json
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional, Sequence

import anyio
from mcp.shared.message import SessionMessage
from mcp.types import ErrorData, JSONRPCError, JSONRPCMessage, JSONRPCRequest

from . import _core
from .authorization import AuthorizationBindingPolicy, AuthorizationBindingProvider, BindingRequestContext
from .correlation import ContinuationHandles, CorrelationStore
from .custody import McpReError, McpReSdkError, Signer, SignerPolicy

__all__ = [
    "ConnectionClosed",
    "HttpReply",
    "McpReConfig",
    "NotificationsUnsupported",
    "UnsafeConfigurationRefused",
    "mcp_re_http_transport",
]


class NotificationsUnsupported(McpReSdkError):
    """A one-way MCP notification was sent, and MCP-RE has no ratified profile for one.

    **Not** an inherent limitation: a notification is its own POST under MCP Streamable
    HTTP, so its request signature and ``Content-Digest`` authenticate it exactly like any
    other request. What is missing is the ratified one-way notification + acknowledgement
    profile (MCP-RE issue #418) — what a verifier returns for a message with no JSON-RPC
    response, and how that acknowledgement binds to the request evidence.

    Until that lands the adapter fails closed here rather than passing the message
    unprotected or discarding it silently. ``unsafe_drop_notifications=True`` opts into
    dropping instead; a hardened policy refuses that opt-in outright.

    A local condition — nothing was transmitted, so no wire code describes it.
    """


class ConnectionClosed(McpReSdkError):
    """The transport is not open for work: not started, or closing/closed.

    Also what queued and in-flight local requests fail with when ``close`` aborts them.

    **This says nothing about the server.** Cancelling a local ``poster`` call does not
    mean the request never arrived or that already-dispatched remote work has stopped —
    only that this client will not process an answer to it.
    """


class UnsafeConfigurationRefused(McpReSdkError):
    """A hardening profile refused an explicitly unsafe option.

    The hardened profile exists to make "this deployment does not accept known-unsafe
    behaviour" enforceable rather than advisory, so an unsafe opt-in must fail the
    connection there instead of being honoured.
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


@dataclass(frozen=True)
class HttpReply:
    """What a ``poster`` returns: the raw HTTP response, unparsed and unverified."""

    status: int
    headers: list
    body: bytes


#: Send one signed POST. ``(method, target_uri, headers, body) -> HttpReply``.
Poster = Callable[[str, str, list, bytes], Awaitable[HttpReply]]


def _default_nonce() -> str:
    # 128 bits from the OS CSPRNG: the freshness window rejects a repeat, so the only
    # requirement here is that a collision is not reachable in practice.
    return secrets.token_urlsafe(16)


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

    #: Drop client->server notifications instead of failing closed on them. **Unsafe.**
    #:
    #: A standard MCP client cannot complete its lifecycle without
    #: `notifications/initialized`, so this exists to keep the adapter usable at all until
    #: the one-way notification + acknowledgement profile is ratified (#418). It is named
    #: for what it is: the notification leaves the process unprotected in the sense that
    #: it never leaves the process at all — `notifications/cancelled` silently becomes
    #: "keep going", which is a safety hole, not a compatibility quirk.
    #:
    #: A hardened `SignerPolicy` refuses this outright.
    unsafe_drop_notifications: bool = False

    #: Called with each client->server notification the adapter drops, when
    #: `unsafe_drop_notifications` is on. Dropping is never silent by default — the
    #: default is to fail closed — but a caller who opts in should still be able to see it.
    on_dropped_notification: Optional[Callable[[str], None]] = None

    #: Called when a verified response is an ADR-MCPS-047 `InputRequiredResult`, with the
    #: handles its answer leg must sign over. The open leg stays outstanding.
    on_input_required: Optional[Callable[[ContinuationHandles], None]] = None

    _correlation: CorrelationStore = field(default_factory=CorrelationStore, init=False)

    def __post_init__(self) -> None:
        # Validated where the value first enters SDK-owned code. A bound of 0 is not a
        # degenerate case that merely throttles: every sender waits for a slot that can
        # never be released, so the session deadlocks in silence.
        n = self.max_concurrent_exchanges
        if isinstance(n, bool) or not isinstance(n, int) or n < 1:
            raise McpReSdkError(
                f"max_concurrent_exchanges must be a positive integer, got {n!r}"
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
        JSONRPCMessage(
            JSONRPCError(
                jsonrpc="2.0",
                id=request_id,
                error=ErrorData(code=_MCP_RE_ERROR_CODE, message=wire_code),
            )
        )
    )


async def _exchange(config: McpReConfig, poster: Poster, request: JSONRPCRequest) -> SessionMessage:
    """Sign one request, POST it, verify the reply, and correlate it back.

    Returns the plain-MCP message to hand the session — a result on success, or a
    JSON-RPC error carrying the frozen wire code on any failure.
    """
    params = request.params if request.params is not None else {}
    created = config.clock()
    expires = created + config.request_ttl

    signed = config.signer.sign_request(
        id_json=json.dumps(request.id),
        method=request.method,
        params_json=json.dumps(params),
        target_uri=config.target_uri,
        audience_id=config.audience_id,
        route=config.route,
        dpop_token=config.dpop_token,
        nonce=config.nonce_factory(),
        created=created,
        expires=expires,
        bindings_json=_bindings_json(config, request.method),
    )
    correlation_id = config._correlation.record(
        signed,
        request_id=str(request.id),
        nonce="",  # the nonce rode into the signature; the handle is the evidence digest
        audience_id=config.audience_id,
        expected_signer_id=config.issuer_key_id,
        created=created,
        expires=expires,
        route=config.route,
    )

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

    # A verified rejection receipt is genuine evidence, but it is NOT an acceptance: it
    # must reach the app as an error, never as a result.
    if verified.outcome != "success":
        config._correlation.take(correlation_id, now=config.clock())
        return _error_message(request.id, verified.wire_code or "mcp-re.response_sig_invalid")

    if verified.request_state is not None:
        # ADR-MCPS-047: an elicitation does not end the exchange, so the open leg stays
        # outstanding (associate, do not consume) until its answer leg terminates it.
        handles = config._correlation.record_input_required(
            correlation_id,
            response_digest_alg=verified.resp_evidence_digest_alg,
            response_digest_value=verified.resp_evidence_digest_value,
            request_state=verified.request_state,
            now=config.clock(),
        )
        if config.on_input_required is not None:
            config.on_input_required(handles)
    else:
        config._correlation.take(correlation_id, now=config.clock())

    return SessionMessage(JSONRPCMessage.model_validate_json(_strip_response_evidence(reply.body)))


async def _one(config: McpReConfig, poster: Poster, request: JSONRPCRequest, read_writer,
               limiter) -> None:
    """Run one exchange to completion and deliver its outcome to the session.

    Every failure becomes a message. The session is awaiting this id, so returning
    without sending would hang it forever.
    """
    async with limiter:
        try:
            message = await _exchange(config, poster, request)
        except McpReError as e:
            message = _error_message(request.id, e.wire_code)
        except McpReSdkError as e:
            # A local failure (e.g. the signing device). No wire code describes it.
            message = _error_message(request.id, f"mcp-re-sdk: {e}")
        except ValueError as e:
            # The core's own fail-closed errors arrive as ValueError carrying the
            # frozen token; deliver it rather than letting the caller hang.
            message = _error_message(request.id, str(e))
    await read_writer.send(message)


async def _pump(config: McpReConfig, poster: Poster, write_reader, read_writer) -> None:
    """Drive every outbound session message through the MCP-RE obligation.

    Exchanges run concurrently, up to ``max_concurrent_exchanges``: awaiting each one
    before reading the next request would make a single slow tool call block every other
    request on the session.
    """
    limiter = anyio.CapacityLimiter(config.max_concurrent_exchanges)
    async with write_reader, read_writer:
        # The task group closes INSIDE the streams: it waits for every in-flight exchange
        # before the streams are closed, so a slow exchange can still deliver its reply
        # rather than failing to send on a closed stream.
        async with anyio.create_task_group() as tg:
            async for outgoing in write_reader:
                root = outgoing.message.root
                if not isinstance(root, JSONRPCRequest):
                    method = getattr(root, "method", "<unknown>")
                    if not config.unsafe_drop_notifications:
                        # Fail closed. MCP-RE has no ratified profile for a one-way
                        # message (#418), and the two ways to proceed without one are
                        # both worse than stopping: pass it unprotected, or discard a
                        # `notifications/cancelled` and let the peer keep going.
                        raise NotificationsUnsupported(
                            f"'{method}' is a one-way notification; MCP-RE has no ratified "
                            f"one-way notification profile yet (#418). Set "
                            f"unsafe_drop_notifications=True to drop notifications instead."
                        )
                    if config.on_dropped_notification is not None:
                        config.on_dropped_notification(method)
                    continue
                tg.start_soon(_one, config, poster, root, read_writer, limiter)


@asynccontextmanager
async def mcp_re_http_transport(config: McpReConfig, poster: Poster):
    """An MCP client transport that signs requests and verifies responses.

    Yields the ``(read_stream, write_stream)`` pair ``mcp.ClientSession`` expects::

        async with mcp_re_http_transport(config, poster) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                await session.call_tool("read_file", {"path": "/etc/hosts"})

    The signer is checked against the route's policy before anything is signed, so a
    custody violation fails the connection rather than a request.
    """
    if config.policy is not None:
        config.policy.check(config.signer)
        if config.policy.require_non_exporting and config.unsafe_drop_notifications:
            # The hardening profile is what makes "this deployment does not accept
            # known-unsafe behaviour" enforceable rather than advisory.
            raise UnsafeConfigurationRefused(
                f"profile '{config.policy.profile}' requires non-exporting custody and so "
                f"refuses unsafe_drop_notifications: silently discarding "
                f"'notifications/cancelled' is not acceptable under a hardened policy (#418)"
            )
    if config.authorization_policy is not None:
        config.authorization_policy.check(list(config.authorization))

    read_writer, read_stream = anyio.create_memory_object_stream(0)
    write_stream, write_reader = anyio.create_memory_object_stream(0)

    async with anyio.create_task_group() as tg:
        tg.start_soon(_pump, config, poster, write_reader, read_writer)
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
            config._correlation.expire_before(_FAR_FUTURE)
