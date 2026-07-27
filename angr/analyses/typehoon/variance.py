from __future__ import annotations

import enum


class Variance(enum.Enum):
    """
    Enum class describing the variance of type constraints.
    """

    def __init__(self, n):
        self._hash = hash(("Variance", n))

    def __hash__(self):
        return self._hash

    COVARIANT = 0
    CONTRAVARIANT = 1
