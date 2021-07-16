from typing import Union, Tuple, Optional, TYPE_CHECKING
import struct

import claripy

try:
    import _md5 as md5lib
except ImportError:
    import hashlib as md5lib

if TYPE_CHECKING:
    from .expression import Expression


def get_bits(expr: Union[claripy.ast.Bits,'Expression',int]) -> Optional[int]:
    # delayed import
    from .expression import Expression

    if isinstance(expr, Expression):
        return expr.bits
    elif isinstance(expr, claripy.ast.Bits):
        return expr.size()
    elif hasattr(expr, 'bits'):
        return expr.bits
    else:
        return None


md5_unpacker = struct.Struct('4I')


def stable_hash(t: Tuple) -> int:
    cnt = _dump_tuple(t)
    hd = md5lib.md5(cnt).digest()
    v = md5_unpacker.unpack(hd)[0]
    return md5_unpacker.unpack(hd)[0]  # 32 bits


def _dump_tuple(t: Tuple) -> bytes:
    cnt = b""
    for item in t:
        if item is not None:
            type_ = type(item)
            if type_ in _DUMP_BY_TYPE:
                cnt += _DUMP_BY_TYPE[type_](item)
            else:
                # for TaggedObjects, hash(item) is stable
                # other types of items may show up, such as pyvex.expr.CCall and Dirty. they will be removed some day.
                cnt += struct.pack("<Q", hash(item) & 0xffff_ffff_ffff_ffff)
        cnt += b"\xf0"
    return cnt


def _dump_str(t: str) -> bytes:
    return t.encode('ascii')


def _dump_int(t: int) -> bytes:
    prefix = b"" if t >= 0 else b"-"
    t = abs(t)
    if t <= 0xffff:
        return prefix + struct.pack("<H", t)
    elif t <= 0xffff_ffff:
        return prefix + struct.pack("<I", t)
    elif t <= 0xffff_ffff_ffff_ffff:
        return prefix + struct.pack("<Q", t)
    else:
        cnt = b""
        while t > 0:
            cnt += _dump_int(t & 0xffff_ffff_ffff_ffff)
            t >>= 64
        return prefix + cnt


def _dump_type(t: type) -> bytes:
    return t.__name__.encode("ascii")


_DUMP_BY_TYPE = {
    tuple: _dump_tuple,
    str: _dump_str,
    int: _dump_int,
    type: _dump_type,
}
