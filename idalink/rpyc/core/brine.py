"""
**Brine** is a simple, fast and secure object serializer for **immutable** objects.
The following types are supported: ``int``, ``long``, ``bool``, ``str``, ``float``,
``unicode``, ``bytes``, ``slice``, ``complex``, ``tuple`` (of simple types), 
``forzenset`` (of simple types) as well as the following singletons: ``None``, 
``NotImplemented``, and ``Ellipsis``.

Example::

    >>> x = ("he", 7, u"llo", 8, (), 900, None, True, Ellipsis, 18.2, 18.2j + 13,
    ... slice(1,2,3), frozenset([5,6,7]), NotImplemented)
    >>> dumpable(x)
    True
    >>> y = dump(x)
    >>> y.encode("hex")
    '140e0b686557080c6c6c6f580216033930300003061840323333333333331b402a000000000000403233333333333319125152531a1255565705'
    >>> z = load(y)
    >>> x == z
    True
"""
from rpyc.lib.compat import Struct, BytesIO, all, is_py3k, BYTES_LITERAL


# singletons
TAG_NONE = BYTES_LITERAL("\x00")
TAG_EMPTY_STR = BYTES_LITERAL("\x01")
TAG_EMPTY_TUPLE = BYTES_LITERAL("\x02")
TAG_TRUE = BYTES_LITERAL("\x03")
TAG_FALSE = BYTES_LITERAL("\x04")
TAG_NOT_IMPLEMENTED = BYTES_LITERAL("\x05")
TAG_ELLIPSIS = BYTES_LITERAL("\x06")
# types
TAG_UNICODE = BYTES_LITERAL("\x08")
TAG_LONG = BYTES_LITERAL("\x09")
TAG_STR1 = BYTES_LITERAL("\x0a")
TAG_STR2 = BYTES_LITERAL("\x0b")
TAG_STR3 = BYTES_LITERAL("\x0c")
TAG_STR4 = BYTES_LITERAL("\x0d")
TAG_STR_L1 = BYTES_LITERAL("\x0e")
TAG_STR_L4 = BYTES_LITERAL("\x0f")
TAG_TUP1 = BYTES_LITERAL("\x10")
TAG_TUP2 = BYTES_LITERAL("\x11")
TAG_TUP3 = BYTES_LITERAL("\x12")
TAG_TUP4 = BYTES_LITERAL("\x13")
TAG_TUP_L1 = BYTES_LITERAL("\x14")
TAG_TUP_L4 = BYTES_LITERAL("\x15")
TAG_INT_L1 = BYTES_LITERAL("\x16")
TAG_INT_L4 = BYTES_LITERAL("\x17")
TAG_FLOAT = BYTES_LITERAL("\x18")
TAG_SLICE = BYTES_LITERAL("\x19")
TAG_FSET = BYTES_LITERAL("\x1a")
TAG_COMPLEX = BYTES_LITERAL("\x1b")
if is_py3k:
    IMM_INTS = dict((i, bytes([i + 0x50])) for i in range(-0x30, 0xa0))
else:
    IMM_INTS = dict((i, chr(i + 0x50)) for i in range(-0x30, 0xa0))

I1 = Struct("!B")
I4 = Struct("!L")
F8 = Struct("!d")
C16 = Struct("!dd")

_dump_registry = {}
_load_registry = {}
IMM_INTS_LOADER = dict((v, k) for k, v in IMM_INTS.items())

def register(coll, key):
    def deco(func):
        coll[key] = func
        return func
    return deco

#===============================================================================
# dumping
#===============================================================================
@register(_dump_registry, type(None))
def _dump_none(obj, stream):
    stream.append(TAG_NONE)

@register(_dump_registry, type(NotImplemented))
def _dump_notimplemeted(obj, stream):
    stream.append(TAG_NOT_IMPLEMENTED)

@register(_dump_registry, type(Ellipsis))
def _dump_ellipsis(obj, stream):
    stream.append(TAG_ELLIPSIS)

@register(_dump_registry, bool)
def _dump_bool(obj, stream):
    if obj:
        stream.append(TAG_TRUE)
    else:
        stream.append(TAG_FALSE)

@register(_dump_registry, slice)
def _dump_slice(obj, stream):
    stream.append(TAG_SLICE)
    _dump((obj.start, obj.stop, obj.step), stream)

@register(_dump_registry, frozenset)
def _dump_frozenset(obj, stream):
    stream.append(TAG_FSET)
    _dump(tuple(obj), stream)

@register(_dump_registry, int)
def _dump_int(obj, stream):
    if obj in IMM_INTS:
        stream.append(IMM_INTS[obj])
    else:
        obj = BYTES_LITERAL(str(obj))
        l = len(obj)
        if l < 256:
            stream.append(TAG_INT_L1 + I1.pack(l) + obj)
        else:
            stream.append(TAG_INT_L4 + I4.pack(l) + obj)

@register(_dump_registry, float)
def _dump_float(obj, stream):
    stream.append(TAG_FLOAT + F8.pack(obj))

@register(_dump_registry, complex)
def _dump_complex(obj, stream):
    stream.append(TAG_COMPLEX + C16.pack(obj.real, obj.imag))

if is_py3k:
    @register(_dump_registry, bytes)
    def _dump_bytes(obj, stream):
        l = len(obj)
        if l == 0:
            stream.append(TAG_EMPTY_STR)
        elif l == 1:
            stream.append(TAG_STR1 + obj)
        elif l == 2:
            stream.append(TAG_STR2 + obj)
        elif l == 3:
            stream.append(TAG_STR3 + obj)
        elif l == 4:
            stream.append(TAG_STR4 + obj)
        elif l < 256:
            stream.append(TAG_STR_L1 + I1.pack(l) + obj)
        else:
            stream.append(TAG_STR_L4 + I4.pack(l) + obj)

    @register(_dump_registry, str)
    def _dump_str(obj, stream):
        stream.append(TAG_UNICODE)
        _dump_bytes(obj.encode("utf8"), stream)
else:
    @register(_dump_registry, str)
    def _dump_str(obj, stream):
        l = len(obj)
        if l == 0:
            stream.append(TAG_EMPTY_STR)
        elif l == 1:
            stream.append(TAG_STR1 + obj)
        elif l == 2:
            stream.append(TAG_STR2 + obj)
        elif l == 3:
            stream.append(TAG_STR3 + obj)
        elif l == 4:
            stream.append(TAG_STR4 + obj)
        elif l < 256:
            stream.append(TAG_STR_L1 + I1.pack(l) + obj)
        else:
            stream.append(TAG_STR_L4 + I4.pack(l) + obj)

    @register(_dump_registry, unicode)
    def _dump_unicode(obj, stream):
        stream.append(TAG_UNICODE)
        _dump_str(obj.encode("utf8"), stream)

    @register(_dump_registry, long)
    def _dump_long(obj, stream):
        stream.append(TAG_LONG)
        _dump_int(obj, stream)


@register(_dump_registry, tuple)
def _dump_tuple(obj, stream):
    l = len(obj)
    if l == 0:
        stream.append(TAG_EMPTY_TUPLE)
    elif l == 1:
        stream.append(TAG_TUP1)
    elif l == 2:
        stream.append(TAG_TUP2)
    elif l == 3:
        stream.append(TAG_TUP3)
    elif l == 4:
        stream.append(TAG_TUP4)
    elif l < 256:
        stream.append(TAG_TUP_L1 + I1.pack(l))
    else:
        stream.append(TAG_TUP_L4 + I4.pack(l))
    for item in obj:
        _dump(item, stream)

def _undumpable(obj, stream):
    raise TypeError("cannot dump %r" % (obj,))

def _dump(obj, stream):
    _dump_registry.get(type(obj), _undumpable)(obj, stream)

#===============================================================================
# loading
#===============================================================================
@register(_load_registry, TAG_NONE)
def _load_none(stream):
    return None
@register(_load_registry, TAG_NOT_IMPLEMENTED)
def _load_nonimp(stream):
    return NotImplemented
@register(_load_registry, TAG_ELLIPSIS)
def _load_elipsis(stream):
    return Ellipsis
@register(_load_registry, TAG_TRUE)
def _load_true(stream):
    return True
@register(_load_registry, TAG_FALSE)
def _load_false(stream):
    return False
@register(_load_registry, TAG_EMPTY_TUPLE)
def _load_empty_tuple(stream):
    return ()

if is_py3k:
    @register(_load_registry, TAG_EMPTY_STR)
    def _load_empty_str(stream):
        return BYTES_LITERAL("")
else:
    @register(_load_registry, TAG_EMPTY_STR)
    def _load_empty_str(stream):
        return ""

if is_py3k:
    @register(_load_registry, TAG_LONG)
    def _load_long(stream):
        obj = _load(stream)
        return int(obj)
else:
    @register(_load_registry, TAG_LONG)
    def _load_long(stream):
        obj = _load(stream)
        return long(obj)

@register(_load_registry, TAG_FLOAT)
def _load_float(stream):
    return F8.unpack(stream.read(8))[0]
@register(_load_registry, TAG_COMPLEX)
def _load_complex(stream):
    real, imag = C16.unpack(stream.read(16))
    return complex(real, imag)

@register(_load_registry, TAG_STR1)
def _load_str1(stream):
    return stream.read(1)
@register(_load_registry, TAG_STR2)
def _load_str2(stream):
    return stream.read(2)
@register(_load_registry, TAG_STR3)
def _load_str3(stream):
    return stream.read(3)
@register(_load_registry, TAG_STR4)
def _load_str4(stream):
    return stream.read(4)
@register(_load_registry, TAG_STR_L1)
def _load_str_l1(stream):
    l, = I1.unpack(stream.read(1))
    return stream.read(l)
@register(_load_registry, TAG_STR_L4)
def _load_str_l4(stream):
    l, = I4.unpack(stream.read(4))
    return stream.read(l)

@register(_load_registry, TAG_UNICODE)
def _load_unicode(stream):
    obj = _load(stream)
    return obj.decode("utf-8")

@register(_load_registry, TAG_TUP1)
def _load_tup1(stream):
    return (_load(stream),)
@register(_load_registry, TAG_TUP2)
def _load_tup2(stream):
    return (_load(stream), _load(stream))
@register(_load_registry, TAG_TUP3)
def _load_tup3(stream):
    return (_load(stream), _load(stream), _load(stream))
@register(_load_registry, TAG_TUP4)
def _load_tup4(stream):
    return (_load(stream), _load(stream), _load(stream), _load(stream))
@register(_load_registry, TAG_TUP_L1)
def _load_tup_l1(stream):
    l, = I1.unpack(stream.read(1))
    return tuple(_load(stream) for i in range(l))

if is_py3k:
    @register(_load_registry, TAG_TUP_L4)
    def _load_tup_l4(stream):
        l, = I4.unpack(stream.read(4))
        return tuple(_load(stream) for i in range(l))
else:
    @register(_load_registry, TAG_TUP_L4)
    def _load_tup_l4(stream):
        l, = I4.unpack(stream.read(4))
        return tuple(_load(stream) for i in xrange(l))

@register(_load_registry, TAG_SLICE)
def _load_slice(stream):
    start, stop, step = _load(stream)
    return slice(start, stop, step)
@register(_load_registry, TAG_FSET)
def _load_frozenset(stream):
    return frozenset(_load(stream))

@register(_load_registry, TAG_INT_L1)
def _load_int_l1(stream):
    l, = I1.unpack(stream.read(1))
    return int(stream.read(l))
@register(_load_registry, TAG_INT_L4)
def _load_int_l4(stream):
    l, = I4.unpack(stream.read(4))
    return int(stream.read(l))

def _load(stream):
    tag = stream.read(1)
    if tag in IMM_INTS_LOADER:
        return IMM_INTS_LOADER[tag]
    return _load_registry.get(tag)(stream)

#===============================================================================
# API
#===============================================================================
def dump(obj):
    """Converts (dumps) the given object to a byte-string representation
    
    :param obj: any :func:`dumpable` object
    
    :returns: a byte-string representation of the object
    """
    stream = []
    _dump(obj, stream)
    return BYTES_LITERAL("").join(stream)

def load(data):
    """Recreates (loads) an object from its byte-string representation
    
    :param data: the byte-string representation of an object
    
    :returns: the dumped object
    """
    stream = BytesIO(data)
    return _load(stream)

if is_py3k:
    simple_types = frozenset([type(None), int, bool, float, bytes, str, complex, 
        type(NotImplemented), type(Ellipsis)])
else:
    simple_types = frozenset([type(None), int, long, bool, float, str, unicode, complex, 
        type(NotImplemented), type(Ellipsis)])

def dumpable(obj):
    """Indicates whether the given object is *dumpable* by brine
    
    :returns: ``True`` if the object is dumpable (e.g., :func:`dump` would succeed),
              ``False`` otherwise
    """
    if type(obj) in simple_types:
        return True
    if type(obj) in (tuple, frozenset):
        return all(dumpable(item) for item in obj)
    if type(obj) is slice:
        return dumpable(obj.start) and dumpable(obj.stop) and dumpable(obj.step)
    return False


if __name__ == "__main__":
    import doctest
    doctest.testmod()

