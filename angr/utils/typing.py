from __future__ import annotations
from typing import TypeVar
from collections.abc import Iterable

_T = TypeVar("_T")


def unwrap(thing: _T | None) -> _T:
    assert thing is not None, "Tried to unwrap a `None` value"
    return thing


def one(thing: Iterable[_T]) -> _T:
    try:
        (result,) = thing
    except ValueError as e:
        raise AssertionError("Tried to get only value of an iterable with some other number of items") from e
    return result
