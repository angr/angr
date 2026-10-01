from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Self


class VVarSet:
    """
    A set of non-negative integers (virtual variable IDs) stored as one Python int bitmask.

    Liveness sets are wide (thousands of ids) and numerous (two per block), so a hash set costs tens of bytes per
    element while a bitmask costs one bit. It supports the subset of the set protocol that liveness and its consumers
    use; mixed operations with real sets are accepted and return the type of the left operand.
    """

    __slots__ = ("_bits",)

    def __init__(self, iterable: Iterable[int] = ()):
        bits = 0
        for v in iterable:
            bits |= 1 << v
        self._bits = bits

    @classmethod
    def from_bits(cls, bits: int) -> VVarSet:
        s = cls.__new__(cls)
        s._bits = bits
        return s

    @property
    def bits(self) -> int:
        return self._bits

    @staticmethod
    def _to_bits(other: object) -> int:
        if isinstance(other, VVarSet):
            return other._bits
        if isinstance(other, Iterable):
            bits = 0
            for v in other:
                bits |= 1 << v
            return bits
        return NotImplemented  # type: ignore[return-value]

    # mutation

    def add(self, v: int) -> None:
        self._bits |= 1 << v

    def discard(self, v: int) -> None:
        self._bits &= ~(1 << v)

    def remove(self, v: int) -> None:
        if not (self._bits >> v) & 1:
            raise KeyError(v)
        self._bits &= ~(1 << v)

    def update(self, other: Iterable[int]) -> None:
        self._bits |= self._to_bits(other)

    def difference_update(self, other: Iterable[int]) -> None:
        self._bits &= ~self._to_bits(other)

    def intersection_update(self, other: Iterable[int]) -> None:
        self._bits &= self._to_bits(other)

    def clear(self) -> None:
        self._bits = 0

    # queries

    def __contains__(self, v: object) -> bool:
        return isinstance(v, int) and v >= 0 and bool((self._bits >> v) & 1)

    def __iter__(self) -> Iterator[int]:
        b = self._bits
        while b:
            low = b & -b
            yield low.bit_length() - 1
            b ^= low

    def __len__(self) -> int:
        return self._bits.bit_count()

    def __bool__(self) -> bool:
        return self._bits != 0

    def copy(self) -> VVarSet:
        return VVarSet.from_bits(self._bits)

    def isdisjoint(self, other: Iterable[int]) -> bool:
        return self._bits & self._to_bits(other) == 0

    def issubset(self, other: Iterable[int]) -> bool:
        return self._bits & ~self._to_bits(other) == 0

    def issuperset(self, other: Iterable[int]) -> bool:
        return self._to_bits(other) & ~self._bits == 0

    # operators; a plain set on the left keeps producing a plain set

    def __or__(self, other: Iterable[int]) -> VVarSet:
        bits = self._to_bits(other)
        return NotImplemented if bits is NotImplemented else VVarSet.from_bits(self._bits | bits)

    def __ror__(self, other: Iterable[int]):
        return set(other) | set(self)

    def __ior__(self, other: Iterable[int]) -> Self:
        self._bits |= self._to_bits(other)
        return self

    def __and__(self, other: Iterable[int]) -> VVarSet:
        bits = self._to_bits(other)
        return NotImplemented if bits is NotImplemented else VVarSet.from_bits(self._bits & bits)

    def __rand__(self, other: Iterable[int]):
        return {v for v in other if v in self}

    def __iand__(self, other: Iterable[int]) -> Self:
        self._bits &= self._to_bits(other)
        return self

    def __sub__(self, other: Iterable[int]) -> VVarSet:
        bits = self._to_bits(other)
        return NotImplemented if bits is NotImplemented else VVarSet.from_bits(self._bits & ~bits)

    def __rsub__(self, other: Iterable[int]):
        return {v for v in other if v not in self}

    def __isub__(self, other: Iterable[int]) -> Self:
        self._bits &= ~self._to_bits(other)
        return self

    def __xor__(self, other: Iterable[int]) -> VVarSet:
        bits = self._to_bits(other)
        return NotImplemented if bits is NotImplemented else VVarSet.from_bits(self._bits ^ bits)

    union = __or__
    intersection = __and__
    difference = __sub__

    # comparisons

    def __eq__(self, other: object) -> bool:
        bits = self._to_bits(other) if isinstance(other, (VVarSet, set, frozenset)) else NotImplemented
        return NotImplemented if bits is NotImplemented else self._bits == bits

    def __ne__(self, other: object) -> bool:
        eq = self.__eq__(other)
        return NotImplemented if eq is NotImplemented else not eq

    def __le__(self, other: Iterable[int]) -> bool:
        return self.issubset(other)

    def __lt__(self, other: Iterable[int]) -> bool:
        bits = self._to_bits(other)
        return self._bits != bits and self._bits & ~bits == 0

    def __ge__(self, other: Iterable[int]) -> bool:
        return self.issuperset(other)

    def __gt__(self, other: Iterable[int]) -> bool:
        bits = self._to_bits(other)
        return self._bits != bits and bits & ~self._bits == 0

    __hash__ = None  # type: ignore[assignment]

    def __repr__(self) -> str:
        return f"VVarSet({sorted(self)})"
