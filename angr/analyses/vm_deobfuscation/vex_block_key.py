"""
Structural keys of VEX blocks, so per-block analyses can reuse the result of an identical block.
"""

from __future__ import annotations

import hashlib

import archinfo
from pyvex.block import IRSB
from pyvex.enums import VEXObject

_SCALARS = (int, str, bytes, bool, float, type(None))
# per-class token emitters, built on first sight of a class
_EMITTERS: dict[type, object] = {}


def _slots(cls: type) -> tuple[str, ...]:
    names: list[str] = []
    for klass in cls.__mro__:
        for name in getattr(klass, "__slots__", ()):
            if name not in ("__dict__", "__weakref__") and name not in names:
                names.append(name)
    return tuple(names)


def _emitter(t: type, obj):
    if isinstance(obj, VEXObject):
        slots = _slots(t)
        name = t.__name__

        def emit(o, out):
            out.append(name)
            for n in slots:
                _emit(getattr(o, n, None), out)
            attrs = getattr(o, "__dict__", None)
            if attrs:
                # the block ids of the data-sensitive consts and tmps name successors and do not
                # change what the statements compute
                for k in sorted(attrs):
                    if k != "block_id":
                        out.append(k)
                        _emit(attrs[k], out)
            out.append(";")

        return emit
    if isinstance(obj, archinfo.Arch):
        return lambda o, out: out.append(o.name)
    raise TypeError(f"no block key for {t.__name__}")


def _emit(obj, out: list):
    t = type(obj)
    if t in _SCALARS:
        out.append(repr(obj))
        return
    if t is list or t is tuple:
        out.append("(")
        for x in obj:
            _emit(x, out)
        out.append(")")
        return
    emit = _EMITTERS.get(t)
    if emit is None:
        emit = _EMITTERS[t] = _emitter(t, obj)
    emit(obj, out)


def block_content_key(irsb: IRSB) -> bytes:
    """
    A digest of everything a per-block analysis of `irsb` reads: address, size, statements, types,
    default exit. Raises TypeError for IR that contains objects the key does not know.
    """
    out = [repr((irsb.addr, irsb.size, irsb.arch.name, irsb.jumpkind, tuple(irsb.tyenv.types)))]
    _emit(irsb.next, out)
    for stmt in irsb.statements:
        _emit(stmt, out)
    return hashlib.blake2b("\x00".join(out).encode(), digest_size=20).digest()
