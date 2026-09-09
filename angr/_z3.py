"""Load the libz3 that angr.rustylib links against, without importing the z3 python bindings.

Nothing puts the z3-solver wheel's lib directory on the dynamic loader's search path, and a running
process cannot add one, so angr opens the file itself before importing the extension. setup.py
loads this module out of the source tree to link against the same directory, so keep it stdlib-only
and free of side effects.
"""

from __future__ import annotations

import ctypes
import functools
import importlib.util
import sys
from pathlib import Path

if sys.platform == "darwin":
    LIBRARY_NAME = "libz3.dylib"
elif sys.platform in {"win32", "cygwin"}:
    LIBRARY_NAME = "libz3.dll"
else:
    LIBRARY_NAME = "libz3.so"


def library_dir() -> Path:
    """The lib directory of the installed z3-solver wheel. find_spec does not import the package."""
    spec = importlib.util.find_spec("z3")
    if spec is None or spec.origin is None:
        raise ImportError("angr requires the z3-solver package, which does not appear to be installed")
    return Path(spec.origin).parent / "lib"


@functools.cache
def load() -> ctypes.CDLL:
    return ctypes.CDLL(library_dir() / LIBRARY_NAME)
