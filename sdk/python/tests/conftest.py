# SPDX-License-Identifier: Apache-2.0
"""Shared pytest configuration for the SDK suite."""
import pytest


@pytest.fixture(scope="session")
def anyio_backend():
    """Run the async transport tests on asyncio only.

    The adapter is backend-agnostic (it uses anyio), but pinning one backend keeps the
    live-harness tests from standing the proxy up twice for no added coverage.
    """
    return "asyncio"
