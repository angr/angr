from __future__ import annotations

import contextlib
import io
import multiprocessing
import os
import platform
import sys
from collections.abc import Callable
from typing import Any, NamedTuple

from angr.errors import AngrRuntimeError


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


_stdio_fork_hook_installed = False


def _detach_child_stdio() -> None:
    """
    Give a freshly forked child its own, harmless stdin and stdout.
    """
    try:
        devnull = os.open(os.devnull, os.O_RDONLY)
        try:
            os.dup2(devnull, 0)
        finally:
            os.close(devnull)
    except OSError:
        pass

    # anything the child prints goes to stderr
    with contextlib.suppress(OSError):
        os.dup2(2, 1)

    try:
        sys.stdin = io.TextIOWrapper(
            io.BufferedReader(io.FileIO(0, "rb", closefd=False)), encoding="utf-8", errors="replace"
        )
    except OSError:
        sys.stdin = None  # type: ignore[assignment]

    try:
        sys.stdout = io.TextIOWrapper(
            io.BufferedWriter(io.FileIO(1, "wb", closefd=False)),
            encoding="utf-8",
            errors="replace",
            line_buffering=True,
        )
    except OSError:
        sys.stdout = None  # type: ignore[assignment]


def protect_stdio_from_forked_children() -> None:
    """
    Make forked worker processes safe to use from a process whose stdin/stdout are a protocol channel.
    """
    global _stdio_fork_hook_installed  # pylint:disable=global-statement

    if _stdio_fork_hook_installed:
        return
    if not hasattr(os, "register_at_fork"):
        # Windows; the fork start method is not used there anyway
        _stdio_fork_hook_installed = True
        return

    os.register_at_fork(after_in_child=_detach_child_stdio)
    _stdio_fork_hook_installed = True
