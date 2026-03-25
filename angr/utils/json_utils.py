"""
JSON encode/decode wrappers that use msgspec when available (CPython only),
falling back to the standard library json module otherwise.
"""

from __future__ import annotations
import platform
import json
from typing import Any


if platform.python_implementation() == "CPython":
    try:
        import msgspec as _msgspec
    except ImportError:
        _msgspec = None


def json_encode(obj: Any) -> bytes:
    if _msgspec is not None:
        return _msgspec.json.encode(obj)
    return json.dumps(obj).encode("utf-8")


def json_decode(data: bytes) -> Any:
    if _msgspec is not None:
        return _msgspec.json.decode(data)

    data_s = data.decode("utf-8")
    return json.loads(data_s)


__all__ = ["json_decode", "json_encode"]
