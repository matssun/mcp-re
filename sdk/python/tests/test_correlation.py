# SPDX-License-Identifier: Apache-2.0
"""In-flight correlation (ADR-MCPS-044 §In-flight correlation state).

The obligation: every outstanding request is tracked, and every response binds back to
the exact request it answers or fails closed. These tests pin the three fail-closed
boundaries onto the frozen `mcp-re.*` taxonomy — an unbound response, a late response,
and a duplicate — plus the ADR-MCPS-047 rule that an elicitation *associates without
consuming*.
"""
import pytest

import mcp_re_sdk
from mcp_re_sdk import CorrelationStore, McpReError

SEED = bytes(range(32))
SIGNER_ID = "did:example:client"
CREATED, EXPIRES = 1000, 2000
IN_WINDOW, LATE = 1500, 2001


def _sign(nonce: str = "nonce-corr-0001", request_id: str = "1"):
    return mcp_re_sdk.sign_request(
        SEED,
        "key-1",
        id_json=request_id,
        method="tools/list",
        params_json="{}",
        target_uri="https://proxy.internal:8600/mcp",
        audience_id="did:example:server-1",
        route=None,
        dpop_token="dpop-token",
        nonce=nonce,
        created=CREATED,
        expires=EXPIRES,
    )


def _record(store: CorrelationStore, signed, **over) -> str:
    args = dict(
        request_id="1",
        nonce="nonce-corr-0001",
        audience_id="did:example:server-1",
        expected_signer_id="did:example:server-1",
        created=CREATED,
        expires=EXPIRES,
    )
    args.update(over)
    return store.record(signed, **args)


class TestRecordAndTake:
    def test_the_correlation_id_is_the_request_evidence_handle(self):
        store, signed = CorrelationStore(), _sign()
        cid = _record(store, signed)
        # Correlation and cryptographic binding must be the same handle, or they drift.
        assert cid == signed.evidence_digest_value
        assert len(store) == 1

    def test_take_consumes_the_outstanding_request(self):
        store, signed = CorrelationStore(), _sign()
        cid = _record(store, signed)
        pending = store.take(cid, now=IN_WINDOW)
        assert pending.correlation_id == cid
        assert pending.request_id == "1"
        assert pending.nonce == "nonce-corr-0001"
        assert pending.evidence_digest_value == signed.evidence_digest_value
        assert pending.audience_id == "did:example:server-1"
        assert len(store) == 0

    def test_peek_does_not_consume(self):
        store, signed = CorrelationStore(), _sign()
        cid = _record(store, signed)
        assert store.peek(cid) is not None
        assert store.peek(cid) is not None
        assert len(store) == 1
        assert store.peek("no-such-id") is None

    def test_the_store_carries_the_audit_fields_the_adr_enumerates(self):
        store, signed = CorrelationStore(), _sign()
        cid = _record(store, signed, route="route-a", authz_binding_digest="abc123")
        p = store.take(cid, now=IN_WINDOW)
        assert p.route == "route-a"
        assert p.authz_binding_digest == "abc123"
        assert p.created == CREATED and p.expires == EXPIRES
        assert p.expected_signer_id == "did:example:server-1"

    def test_iterating_yields_the_outstanding_requests(self):
        store = CorrelationStore()
        _record(store, _sign("n-1"), nonce="n-1")
        _record(store, _sign("n-2"), nonce="n-2")
        assert len(store) == 2
        assert {p.nonce for p in store} == {"n-1", "n-2"}


class TestFailsClosed:
    def test_a_response_binding_to_nothing_outstanding_is_rejected(self):
        store = CorrelationStore()
        with pytest.raises(McpReError) as ei:
            store.take("not-an-outstanding-handle", now=IN_WINDOW)
        assert ei.value.wire_code == "mcp-re.request_binding_mismatch"

    def test_a_late_response_is_rejected(self):
        store, signed = CorrelationStore(), _sign()
        cid = _record(store, signed)
        with pytest.raises(McpReError) as ei:
            store.take(cid, now=LATE)
        assert ei.value.wire_code == "mcp-re.expired_request"

    def test_a_late_response_also_retires_the_entry(self):
        """A dropped-late request must not linger for an even later answer."""
        store, signed = CorrelationStore(), _sign()
        cid = _record(store, signed)
        with pytest.raises(McpReError):
            store.take(cid, now=LATE)
        assert len(store) == 0
        with pytest.raises(McpReError) as ei:
            store.take(cid, now=LATE)
        assert ei.value.wire_code == "mcp-re.replay_detected"

    def test_a_duplicate_response_is_a_replay_not_a_mismatch(self):
        store, signed = CorrelationStore(), _sign()
        cid = _record(store, signed)
        store.take(cid, now=IN_WINDOW)
        with pytest.raises(McpReError) as ei:
            store.take(cid, now=IN_WINDOW)
        assert ei.value.wire_code == "mcp-re.replay_detected"

    def test_recording_the_same_request_twice_is_rejected(self):
        store, signed = CorrelationStore(), _sign()
        _record(store, signed)
        with pytest.raises(McpReError) as ei:
            _record(store, signed)
        assert ei.value.wire_code == "mcp-re.replay_detected"

    def test_a_response_at_exactly_the_deadline_is_still_in_window(self):
        store, signed = CorrelationStore(), _sign()
        cid = _record(store, signed)
        store.take(cid, now=EXPIRES)  # must not raise — expiry is inclusive


class TestReaping:
    def test_expire_before_drops_only_the_dead(self):
        store = CorrelationStore()
        live = _sign("n-live")
        dead = _sign("n-dead")
        _record(store, live, nonce="n-live", expires=9000)
        cid_dead = _record(store, dead, nonce="n-dead", expires=1200)
        dropped = store.expire_before(1500)
        assert [p.correlation_id for p in dropped] == [cid_dead]
        assert len(store) == 1

    def test_a_reaped_request_cannot_later_be_answered(self):
        store, signed = CorrelationStore(), _sign()
        cid = _record(store, signed)
        store.expire_before(LATE)
        with pytest.raises(McpReError) as ei:
            store.take(cid, now=LATE)
        assert ei.value.wire_code == "mcp-re.replay_detected"

    def test_reaping_an_empty_store_is_a_no_op(self):
        assert CorrelationStore().expire_before(LATE) == []


class TestInputRequiredAssociatesWithoutConsuming:
    def test_an_elicitation_leaves_the_open_leg_outstanding(self):
        store, signed = CorrelationStore(), _sign()
        cid = _record(store, signed)
        handles = store.record_input_required(
            cid,
            response_digest_alg="sha-256",
            response_digest_value="aXJyLWhhbmRsZQ",
            request_state="opaque-state-xyz",
            now=IN_WINDOW,
        )
        # ADR-MCPS-047: the exchange is not over, so the request must NOT be consumed.
        assert len(store) == 1
        assert store.peek(cid) is not None
        assert handles.prev_alg == signed.evidence_digest_alg
        assert handles.prev_value == signed.evidence_digest_value
        assert handles.irr_value == "aXJyLWhhbmRsZQ"
        assert handles.request_state == "opaque-state-xyz"

    def test_the_handles_feed_straight_into_the_answer_leg(self):
        store, signed = CorrelationStore(), _sign()
        cid = _record(store, signed)
        handles = store.record_input_required(
            cid,
            response_digest_alg="sha-256",
            response_digest_value="aXJyLWhhbmRsZQ",
            request_state="opaque-state-xyz",
            now=IN_WINDOW,
        )
        answer = mcp_re_sdk.sign_request(
            SEED,
            "key-1",
            id_json="2",
            method="tools/call",
            params_json="{}",
            target_uri="https://proxy.internal:8600/mcp",
            audience_id="did:example:server-1",
            route=None,
            dpop_token="dpop-token",
            nonce="nonce-corr-answer",
            created=CREATED,
            expires=EXPIRES,
            **handles.as_sign_kwargs(),
        )
        # The signed continuation must actually change the evidence.
        assert answer.evidence_digest_value != signed.evidence_digest_value
        assert b"tools/call" in answer.body()

    def test_the_open_leg_can_still_be_taken_by_the_terminal_answer(self):
        store, signed = CorrelationStore(), _sign()
        cid = _record(store, signed)
        store.record_input_required(
            cid,
            response_digest_alg="sha-256",
            response_digest_value="aXJyLWhhbmRsZQ",
            request_state="s",
            now=IN_WINDOW,
        )
        assert store.take(cid, now=IN_WINDOW).correlation_id == cid

    def test_an_unbound_elicitation_is_rejected(self):
        store = CorrelationStore()
        with pytest.raises(McpReError) as ei:
            store.record_input_required(
                "not-outstanding",
                response_digest_alg="sha-256",
                response_digest_value="x",
                request_state="s",
                now=IN_WINDOW,
            )
        assert ei.value.wire_code == "mcp-re.request_binding_mismatch"

    def test_a_late_elicitation_is_rejected(self):
        store, signed = CorrelationStore(), _sign()
        cid = _record(store, signed)
        with pytest.raises(McpReError) as ei:
            store.record_input_required(
                cid,
                response_digest_alg="sha-256",
                response_digest_value="x",
                request_state="s",
                now=LATE,
            )
        assert ei.value.wire_code == "mcp-re.expired_request"

    def test_an_elicitation_for_an_answered_request_is_a_replay(self):
        store, signed = CorrelationStore(), _sign()
        cid = _record(store, signed)
        store.take(cid, now=IN_WINDOW)
        with pytest.raises(McpReError) as ei:
            store.record_input_required(
                cid,
                response_digest_alg="sha-256",
                response_digest_value="x",
                request_state="s",
                now=IN_WINDOW,
            )
        assert ei.value.wire_code == "mcp-re.replay_detected"
