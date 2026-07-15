from __future__ import annotations

import enum

from ._typehash import type_tag


class Variance(enum.Enum):
    """
    Enum class describing the variance of type constraints.
    """

    COVARIANT = 0
    CONTRAVARIANT = 1

    def __hash__(self):
        return hash((type_tag(Variance), self.value))
