from __future__ import annotations
from typing import NamedTuple, Any
from collections.abc import Callable
import multiprocessing
import platform
from ..errors import AngrRuntimeError


class Closure(NamedTuple):
    """
    A pickle-able lambda; note that f, args, and kwargs must be pickleable
    """

    f: Callable[..., None]
    args: list[Any]
    kwargs: dict[str, Any]


class Initializer:
    """
    A singleton class with global state used to initialize a multiprocessing.Process
    """

    _single: Initializer | None = None

    @classmethod
    def get(cls) -> Initializer:
        """
        A wrapper around init since this class is a singleton
        """
        if cls._single is None:
            cls._single = cls(_manual=False)
        return cls._single

    def __init__(self, *, _manual: bool = True):
        if _manual:
            raise AngrRuntimeError("This is a singleton; call .get() instead")
        self.initializers: list[Closure] = []

    def register(self, f: Callable[..., None], *args: Any, **kwargs: Any) -> None:
        """
        A shortcut for adding Closures as initializers
        """
        self.initializers.append(Closure(f, args, kwargs))

    def initialize(self) -> None:
        """
        Initialize a multiprocessing.Process
        Set the current global initializer to the same state as this initializer, then calls each initializer
        """
        self._single = self
        for i in self.initializers:
            i.f(*i.args, **i.kwargs)


def mp_context():
    system = platform.system()
    spawn_methods = {
        "Windows": "spawn",
        "Linux": "fork",
        # Python<3.8 defaults to fork
        # https://bugs.python.org/issue33725
        "Darwin": "spawn",
    }
    spawn_method = spawn_methods.get(system, "fork")  # default to fork on other platforms
    return multiprocessing.get_context(spawn_method)
