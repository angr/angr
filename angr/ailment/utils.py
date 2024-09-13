from typing import Union, TYPE_CHECKING
import struct

try:
    import claripy
except ImportError:
    claripy = None

try:
    import _md5 as md5lib
except ImportError:
    import hashlib as md5lib

if TYPE_CHECKING:
    from .expression import Expression


get_bits_type_params = Union[int, "Expression"]
if claripy:
    get_bits_type_params = Union[int, claripy.ast.Bits, "Expression"]


def get_bits(expr: get_bits_type_params) -> int | None:
    # delayed import
    from .expression import Expression  # pylint:disable=import-outside-toplevel

    if isinstance(expr, Expression):
        return expr.bits
    elif isinstance(expr, claripy.ast.Bits):
        return expr.size()
    elif hasattr(expr, "bits"):
        return expr.bits
    else:
        return None


md5_unpacker = struct.Struct("4I")


def stable_hash(t: tuple) -> int:
    cnt = _dump_tuple(t)
    hd = md5lib.md5(cnt).digest()
    return md5_unpacker.unpack(hd)[0]  # 32 bits


def _dump_tuple(t: tuple) -> bytes:
    cnt = b""
    for item in t:
        if item is not None:
            type_ = type(item)
            if type_ in _DUMP_BY_TYPE:
                cnt += _DUMP_BY_TYPE[type_](item)
            else:
                # for TaggedObjects, hash(item) is stable
                # other types of items may show up, such as pyvex.expr.CCall and Dirty. they will be removed some day.
                cnt += struct.pack("<Q", hash(item) & 0xFFFF_FFFF_FFFF_FFFF)
        cnt += b"\xf0"
    return cnt


def _dump_str(t: str) -> bytes:
    return t.encode("ascii")


def _dump_int(t: int) -> bytes:
    prefix = b"" if t >= 0 else b"-"
    t = abs(t)
    if t <= 0xFFFF:
        return prefix + struct.pack("<H", t)
    elif t <= 0xFFFF_FFFF:
        return prefix + struct.pack("<I", t)
    elif t <= 0xFFFF_FFFF_FFFF_FFFF:
        return prefix + struct.pack("<Q", t)
    else:
        cnt = b""
        while t > 0:
            cnt += _dump_int(t & 0xFFFF_FFFF_FFFF_FFFF)
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


def is_none_or_likeable(arg1, arg2, is_list=False):
    """
    Returns whether two things are both None or can like each other
    """
    from .expression import Expression  # pylint:disable=import-outside-toplevel

    if arg1 is None or arg2 is None:
        if arg1 == arg2:
            return True
        return False

    if is_list:
        return len(arg1) == len(arg2) and all(is_none_or_likeable(a1, a2) for a1, a2 in zip(arg1, arg2))

    if isinstance(arg1, Expression):
        return arg1.likes(arg2)
    return arg1 == arg2


def is_none_or_matchable(arg1, arg2, is_list=False):
    """
    Returns whether two things are both None or can match each other
    """
    from .expression import Expression  # pylint:disable=import-outside-toplevel

    if arg1 is None or arg2 is None:
        if arg1 == arg2:
            return True
        return False

    if is_list:
        return len(arg1) == len(arg2) and all(is_none_or_matchable(a1, a2) for a1, a2 in zip(arg1, arg2))

    if isinstance(arg1, Expression):
        return arg1.matches(arg2)
    return arg1 == arg2
