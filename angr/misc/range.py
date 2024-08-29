from __future__ import annotations


class IRange:
    """
    A simple range object for testing inclusion. Like range but works for huge numbers.
    """

    __slots__ = ("start", "end")

    def __init__(self, start, end):
        self.start = start
        self.end = end

    def __contains__(self, k):
        if type(k) is int:
            return k >= self.start and k < self.end
        return False

    def __getstate__(self):
        return self.start, self.end

    def __setstate__(self, state):
        self.start, self.end = state
