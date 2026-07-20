from __future__ import annotations

import sys
from typing import Any

if sys.platform != "emscripten":
    try:
        import lmdb as lmdb
    except ImportError:
        lmdb = None
else:
    lmdb = None

if lmdb is None:

    class _LmdbError(Exception):
        pass

    class _LmdbUnavailable:
        Error = _LmdbError
        MapFullError = _LmdbError
        Environment = Any

        @staticmethod
        def open(*_args, **_kwargs):
            raise _LmdbError("LMDB is not available on this platform")

    lmdb = _LmdbUnavailable()  # type: ignore[assignment]
    lmdb_available = False
else:
    lmdb_available = True

__all__ = ("lmdb", "lmdb_available")
