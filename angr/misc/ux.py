from __future__ import annotations

import warnings
from collections.abc import Callable
from functools import wraps
from typing import ParamSpec, TypeVar

once_set: set[str] = set()


def once(key: str) -> bool:
    if key in once_set:
        return False
    once_set.add(key)
    return True


already_complained: set[object] = set()

P = ParamSpec("P")
R = TypeVar("R")


def deprecated(replacement: str | None = None) -> Callable[[Callable[P, R]], Callable[P, R]]:
    def outer(func: Callable[P, R]) -> Callable[P, R]:
        @wraps(func)
        def inner(*args: P.args, **kwargs: P.kwargs) -> R:
            if func not in already_complained:
                if replacement is None:
                    warnings.warn(f"Don't use {func.__name__}", DeprecationWarning, stacklevel=2)
                else:
                    warnings.warn(f"Use {replacement} instead of {func.__name__}", DeprecationWarning, stacklevel=2)
                already_complained.add(func)
            return func(*args, **kwargs)

        return inner

    return outer
