"""The single refusal type raised by the host admission gate."""

from __future__ import annotations


class ArbiterError(RuntimeError):
    """An admission refusal.

    Every raise site is fail-closed: the caller must NOT execute workload. The message is
    written for an operator reading a runner log at 03:00 who has no context, so it says
    what was refused and why, never merely that something went wrong.
    """
