# pylint:disable=line-too-long
from __future__ import annotations

from collections import OrderedDict

from angr.procedures.definitions import SimTypeCollection
from angr.sim_type import (
    SimCppClass,
    SimStruct,
    SimTypeArray,
    SimTypeChar,
    SimTypeInt,
    SimTypeLongLong,
    SimTypePointer,
    SimTypeShort,
)

typelib = SimTypeCollection()
typelib.set_names("cpp::std")
typelib.types = {
    "class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>": SimCppClass(
        unique_name="class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>",
        name="std::string",
        members=OrderedDict(
            [
                ("m_data", SimTypePointer(SimTypeChar())),
                ("m_size", SimTypeInt(signed=False)),
                ("m_capacity", SimTypeInt(signed=False)),
            ]
        ),
    ),
    "class std::vector<int, class std::allocator<int>>": SimCppClass(
        unique_name="class std::vector<int, class std::allocator<int>>",
        name="std::vector<int>",
        members=OrderedDict(
            [
                ("m_start", SimTypePointer(SimTypeInt())),
                ("m_finish", SimTypePointer(SimTypeInt())),
                ("m_end_of_storage", SimTypePointer(SimTypeInt())),
            ]
        ),
    ),
    "class std::vector<short, class std::allocator<short>>": SimCppClass(
        unique_name="class std::vector<short, class std::allocator<short>>",
        name="std::vector<short>",
        members=OrderedDict(
            [
                ("m_start", SimTypePointer(SimTypeShort())),
                ("m_finish", SimTypePointer(SimTypeShort())),
                ("m_end_of_storage", SimTypePointer(SimTypeShort())),
            ]
        ),
    ),
    "class std::vector<long long, class std::allocator<long long>>": SimCppClass(
        unique_name="class std::vector<long long, class std::allocator<long long>>",
        name="std::vector<long long>",
        members=OrderedDict(
            [
                ("m_start", SimTypePointer(SimTypeLongLong())),
                ("m_finish", SimTypePointer(SimTypeLongLong())),
                ("m_end_of_storage", SimTypePointer(SimTypeLongLong())),
            ]
        ),
    ),
}

#: Element sizes for which an opaque ``std::vector<T<N>>`` class exists.
#:
#: The std::vector<T>::size() exact-division patterns (see
#: analyses/decompiler/known_patterns/std_vector_size.py) recover sizeof(T) from
#: the compiler's magic constant but not the element type, so each supported size
#: gets an opaque N-byte element class named ``T<N>``. Only non-power-of-two
#: sizes are listed: a power-of-two sizeof(T) divides with a bare shift and needs
#: no magic constant (those are the named std::vector<short/int/long long>
#: templates). The upper bound is empirical -- real containers of large records
#: exist (CryptoPP::ECPPoint is 112 bytes, and vectors of 100+ byte structs are
#: common in C++ code), and covering only a handful of small sizes leaves the
#: pattern silent on exactly the code where the raw magic multiply is least
#: readable.
EXACTDIV_ELEMENT_SIZES = tuple(n for n in range(3, 513) if n & (n - 1))

for _n in EXACTDIV_ELEMENT_SIZES:
    _elt_name = f"T{_n}"
    _elt = SimStruct(OrderedDict([("data", SimTypeArray(SimTypeChar(), _n))]), name=_elt_name)
    _uniq = f"class std::vector<{_elt_name}, class std::allocator<{_elt_name}>>"
    typelib.types[_uniq] = SimCppClass(
        unique_name=_uniq,
        name=f"std::vector<{_elt_name}>",
        members=OrderedDict(
            [
                ("m_start", SimTypePointer(_elt)),
                ("m_finish", SimTypePointer(_elt)),
                ("m_end_of_storage", SimTypePointer(_elt)),
            ]
        ),
    )
