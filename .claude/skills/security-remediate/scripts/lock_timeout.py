"""The one exception type raised by the harness persistence layer.

Its own file per the repo's one-class-per-file rule. `_persist` is a module of
functions; this is the only class it needs, so it lives here rather than
distorting that module's name.
"""


class LockTimeout(RuntimeError):
    """Raised when a persistence critical section could not be entered in time.

    Deliberately an ERROR, and never a silent fall-through to an unlocked write:
    proceeding without the lock is exactly the defect the locking exists to stop.
    A caller that swallows this and writes anyway has reintroduced the 2026-09-22
    ledger loss.
    """
