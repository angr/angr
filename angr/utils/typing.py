from typing import TypeVar, Optional, Iterable

_T = TypeVar("_T")


def unwrap(thing: Optional[_T]) -> _T:
    assert thing is not None, "Tried to unwrap a `None` value"
    return thing


def one(thing: Iterable[_T]) -> _T:
    try:
        (result,) = thing
    except ValueError as e:
        raise AssertionError("Tried to get only value of an iterable with some other number of items") from e
    return result
