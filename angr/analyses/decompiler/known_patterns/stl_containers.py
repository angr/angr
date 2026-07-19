"""C++ STL container accessors (libstdc++), beyond size()/length().

Calibrated against tests/x86_64/decompiler/known_patterns_stl (g++ 12.2.0 -O2).
All are guarded by C++ evidence (``is_cpp_binary``), AMD64, Linux. The
distinctive accessors (empty/capacity) are enabled by default; the indexing
accessors and the genericish string ``empty`` are opt-in (their shapes overlap
plain pointer/array code).
"""

from __future__ import annotations

from .dsl import PBinOp, PConst, PLoad, PVVar
from .pattern import CppRef, KnownPattern, PatternParam, is_cpp_binary, is_msvc_cpp_binary
from .std_string_length import STD_BASIC_STRING
from .std_vector_size import STD_VECTOR_INT

_AMD64 = ("AMD64",)
_LINUX = ("linux",)
# std::vector uses the same three-pointer layout in libstdc++ and the MSVC STL,
# so the vector accessors apply on both platforms.
_LINUX_WIN = ("linux", "win32", "windows")
_WIN = ("win32", "windows")


def _add(cap: str, off: int) -> PBinOp:
    return PBinOp("Add", (PVVar(cap), PConst(off)))


# std::vector<int>::empty(): _M_start == _M_finish  ==  Load(v+8) CmpEQ Load(v)
# (wrapped in Insert(...); the finder matches the inner comparison).
STD_VECTOR_INT_EMPTY = KnownPattern(
    name="std_vector_int_empty",
    display_name="std::vector<int>::empty",
    call_name="std::vector<int>::empty",
    pattern=PBinOp("CmpEQ", (PLoad(_add("v", 8), size=8), PLoad(PVVar("v"), size=8))),
    params=(PatternParam("v", type=CppRef(STD_VECTOR_INT)),),
    returnty="int",
    arches=_AMD64,
    platforms=_LINUX_WIN,
    binary_guard=is_cpp_binary,
)


# std::vector<int>::capacity(): (_M_end_of_storage - _M_start) / sizeof(int)
#   = (Load(v+16) - Load(v)) >>s 2
STD_VECTOR_INT_CAPACITY = KnownPattern(
    name="std_vector_int_capacity",
    display_name="std::vector<int>::capacity",
    call_name="std::vector<int>::capacity",
    pattern=PBinOp(
        frozenset({"Sar", "Shr"}),
        (
            PBinOp("Sub", (PLoad(_add("v", 16), size=8), PLoad(PVVar("v"), size=8))),
            PConst(2),
        ),
    ),
    params=(PatternParam("v", type=CppRef(STD_VECTOR_INT)),),
    returnty="unsigned long long",
    arches=_AMD64,
    platforms=_LINUX_WIN,
    binary_guard=is_cpp_binary,
)


# std::vector<int>::operator[](i): *(_M_start + i*sizeof(int))
#   = Load(Load(v) + i*4, size=4)     (opt-in: overlaps plain int-array indexing)
STD_VECTOR_INT_INDEX = KnownPattern(
    name="std_vector_int_index",
    display_name="std::vector<int>::operator[]",
    call_name="std::vector<int>::operator[]",
    pattern=PLoad(
        PBinOp("Add", (PLoad(PVVar("v"), size=8), PBinOp("Mul", (PVVar("i"), PConst(4))))),
        size=4,
    ),
    params=(PatternParam("v", type=CppRef(STD_VECTOR_INT)), PatternParam("i")),
    returnty="int",
    arches=_AMD64,
    platforms=_LINUX_WIN,
    binary_guard=is_cpp_binary,
    enabled_by_default=False,
)


# std::string::empty(): _M_string_length == 0  ==  Load(s+8) CmpEQ 0
#   (opt-in: "field at +8 == 0" is generic)
STD_STRING_EMPTY = KnownPattern(
    name="std_string_empty",
    display_name="std::string::empty",
    call_name="std::string::empty",
    pattern=PBinOp("CmpEQ", (PLoad(_add("s", 8), size=8), PConst(0))),
    params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)),),
    returnty="int",
    arches=_AMD64,
    platforms=_LINUX,
    binary_guard=is_cpp_binary,
    enabled_by_default=False,
)


# std::string::empty(), MSVC layout: _Mysize at +16  ==  Load(s+16) CmpEQ 0
# Calibrated against tests/x86_64/windows/known_patterns_stl_msvc_17_x64.exe.
STD_STRING_EMPTY_MSVC = KnownPattern(
    name="std_string_empty_msvc",
    display_name="std::string::empty",
    call_name="std::string::empty",
    pattern=PBinOp("CmpEQ", (PLoad(_add("s", 16), size=8), PConst(0))),
    params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)),),
    returnty="int",
    arches=_AMD64,
    platforms=_WIN,
    binary_guard=is_msvc_cpp_binary,
    enabled_by_default=False,
)


# std::string::operator[](i): *(_M_p + i)  =  Load(Load(s) + i, size=1)
#   (opt-in: overlaps plain char* indexing)
# Note: the MSVC std::string::operator[] has an SSO branch (inline buffer vs
# heap pointer), so it does not reduce to a clean load and has no MSVC variant.
STD_STRING_INDEX = KnownPattern(
    name="std_string_index",
    display_name="std::string::operator[]",
    call_name="std::string::operator[]",
    pattern=PLoad(PBinOp("Add", (PLoad(PVVar("s"), size=8), PVVar("i"))), size=1),
    params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)), PatternParam("i")),
    returnty="char",
    arches=_AMD64,
    platforms=_LINUX,
    binary_guard=is_cpp_binary,
    enabled_by_default=False,
)


ALL_STL_CONTAINER_PATTERNS = [
    STD_VECTOR_INT_EMPTY,
    STD_VECTOR_INT_CAPACITY,
    STD_VECTOR_INT_INDEX,
    STD_STRING_EMPTY,
    STD_STRING_EMPTY_MSVC,
    STD_STRING_INDEX,
]
