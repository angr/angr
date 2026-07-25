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
        return self._cached_hash


# Variance members are singletons that never change, so their (process-independent) hash can be computed once
# here instead of on every lookup. Note that we cannot do this inside __init__: enum member instances are
# created by EnumType before the class object -- and therefore Variance itself -- exists.
for _member in Variance:
    _member._cached_hash = hash((type_tag(Variance), _member.value))
del _member
