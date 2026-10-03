"""The one exception type raised by the journal auditor.

Its own file per the repo's one-class-per-file rule, as `lock_timeout.py` is for
the persistence layer. `reduce` is a module of functions; this is the only class
it needs.
"""


class JournalInputError(Exception):
    """The input cannot be read as a journal at all — exit 2, not a finding.

    Deliberately distinct from ValueError: a defect inside the reducer must crash
    loudly, never be mistaken for a malformed input and reported as exit 2.
    """
