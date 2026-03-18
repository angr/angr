from __future__ import annotations
from typing import Any, TYPE_CHECKING
from collections.abc import Callable

if TYPE_CHECKING:
    from collections import deque


def binary_insert(lst: list | deque, elem: Any, key: Callable, lo: int = 0, hi: int | None = None) -> None:
    """
    Insert an element into a sorted list, and keep the list sorted.

    The major difference from bisect.bisect_left is that this function supports a key method, so user doesn't have
    to create the key array for each insertion.

    :param lst:     The list. Must be pre-ordered.
    :param element: An element to insert into the list.
    :param key:     A method to get the key for each element in the list.
    :param lo:      Lower bound of the search.
    :param hi:      Upper bound of the search.
    :return:        None
    """

    if lo < 0:
        raise ValueError("lo must be a non-negative number")

    if hi is None:
        hi = len(lst)

    while lo < hi:
        mid = (lo + hi) // 2
        if key(lst[mid]) < key(elem):
            lo = mid + 1
        else:
            hi = mid

    lst.insert(lo, elem)
