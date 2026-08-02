# SPDX-License-Identifier: Apache-2.0
"""C080/C088 — a caller-supplied nonce_factory is checked at SIGN time.

The default generator already produces 22 characters, so this floor never constrains
the default path. What it constrains is the OVERRIDE, which was accepted unchecked: a
factory returning a counter or a truncated value silently weakened replay protection
for every request while every signature still verified.
"""
import pytest

from mcp_re_sdk.custody import McpReSdkError
from mcp_re_sdk.transport import MIN_NONCE_CHARS, _checked_nonce, _default_nonce


def test_the_default_generator_clears_the_floor():
    assert len(_default_nonce()) >= MIN_NONCE_CHARS


def test_the_default_generator_is_accepted():
    assert _checked_nonce(_default_nonce)


@pytest.mark.parametrize("bad", ["", "1", "counter-1", "nonce-parity-0001"])
def test_a_sub_floor_override_is_refused_at_sign_time(bad):
    # `McpReSdkError`, not `McpReError`: a local misconfiguration is not a protocol
    # verdict, and raising `McpReError` here put an English sentence in `.wire_code`,
    # which the taxonomy documents as a frozen token a caller branches on.
    with pytest.raises(McpReSdkError) as excinfo:
        _checked_nonce(lambda: bad)
    assert "at least 22" in str(excinfo.value)


def test_a_non_string_override_is_refused_without_raising_typeerror():
    with pytest.raises(McpReSdkError):
        _checked_nonce(lambda: 12345)


def test_a_factory_at_exactly_the_floor_is_accepted():
    assert _checked_nonce(lambda: "a" * MIN_NONCE_CHARS)
