"""32-bit (X86) STL container-accessor patterns.

In 32-bit builds pointers and size_t are 4 bytes, so the field loads are
``size=4`` and the std::vector member offsets are 4/8 (not 8/16). The MSVC
std::string still keeps ``_Mysize`` at +16 (behind the 16-byte SSO buffer
union).

Calibrated against tests/i386/windows/known_patterns_stl_msvc_17_x86.exe
(VS 2022 /O2). The vector layout (three 4-byte pointers) is shared by 32-bit
libstdc++, so the vector patterns are not MSVC-specific; the string
length/empty offsets (+16) are MSVC-specific.
"""

from __future__ import annotations

from .dsl import PBinOp, PConst, PLoad, PVVar
from .pattern import CppRef, KnownPattern, PatternParam, is_cpp_binary, is_msvc_cpp_binary
from .std_string_length import STD_BASIC_STRING
from .std_vector_size import STD_VECTOR_INT

_X86 = ("X86",)
_WIN = ("win32", "windows")
_LINUX_WIN = ("linux", "win32", "windows")


def _add(cap: str, off: int) -> PBinOp:
    return PBinOp("Add", (PVVar(cap), PConst(off)))


# std::string::length(), MSVC x86: _Mysize at +16, 4-byte load
STD_STRING_LENGTH_X86_MSVC = KnownPattern(
    name="std_string_length_x86_msvc",
    display_name="std::string::length",
    call_name="std::string::length",
    pattern=PLoad(_add("s", 16), size=4),
    params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)),),
    returnty="unsigned long long",  # size_t; kept 64-bit-wide to share the call-name prototype
    arches=_X86,
    platforms=_WIN,
    binary_guard=is_msvc_cpp_binary,
)


# std::string::empty(), MSVC x86: _Mysize == 0
STD_STRING_EMPTY_X86_MSVC = KnownPattern(
    name="std_string_empty_x86_msvc",
    display_name="std::string::empty",
    call_name="std::string::empty",
    pattern=PBinOp("CmpEQ", (PLoad(_add("s", 16), size=4), PConst(0))),
    params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)),),
    returnty="int",
    arches=_X86,
    platforms=_WIN,
    binary_guard=is_msvc_cpp_binary,
    enabled_by_default=False,
)


# std::vector<int>::size(): (_M_finish - _M_start) / 4 ; 32-bit offsets 4/0
STD_VECTOR_INT_SIZE_X86 = KnownPattern(
    name="std_vector_int_size_x86",
    display_name="std::vector<int>::size",
    call_name="std::vector<int>::size",
    pattern=PBinOp(
        frozenset({"Sar", "Shr"}),
        (PBinOp("Sub", (PLoad(_add("v", 4), size=4), PLoad(PVVar("v"), size=4))), PConst(2)),
    ),
    params=(PatternParam("v", type=CppRef(STD_VECTOR_INT)),),
    returnty="unsigned long long",
    arches=_X86,
    platforms=_LINUX_WIN,
    binary_guard=is_cpp_binary,
)


# std::vector<int>::empty(): _M_start == _M_finish ; 32-bit offsets 0/4
STD_VECTOR_INT_EMPTY_X86 = KnownPattern(
    name="std_vector_int_empty_x86",
    display_name="std::vector<int>::empty",
    call_name="std::vector<int>::empty",
    pattern=PBinOp("CmpEQ", (PLoad(_add("v", 4), size=4), PLoad(PVVar("v"), size=4))),
    params=(PatternParam("v", type=CppRef(STD_VECTOR_INT)),),
    returnty="int",
    arches=_X86,
    platforms=_LINUX_WIN,
    binary_guard=is_cpp_binary,
)


# std::vector<int>::capacity(): (_M_end_of_storage - _M_start) / 4 ; offsets 8/0
STD_VECTOR_INT_CAPACITY_X86 = KnownPattern(
    name="std_vector_int_capacity_x86",
    display_name="std::vector<int>::capacity",
    call_name="std::vector<int>::capacity",
    pattern=PBinOp(
        frozenset({"Sar", "Shr"}),
        (PBinOp("Sub", (PLoad(_add("v", 8), size=4), PLoad(PVVar("v"), size=4))), PConst(2)),
    ),
    params=(PatternParam("v", type=CppRef(STD_VECTOR_INT)),),
    returnty="unsigned long long",
    arches=_X86,
    platforms=_LINUX_WIN,
    binary_guard=is_cpp_binary,
)


# std::vector<int>::operator[](i): *(_M_start + i*4) ; 4-byte pointer load
STD_VECTOR_INT_INDEX_X86 = KnownPattern(
    name="std_vector_int_index_x86",
    display_name="std::vector<int>::operator[]",
    call_name="std::vector<int>::operator[]",
    pattern=PLoad(
        PBinOp("Add", (PLoad(PVVar("v"), size=4), PBinOp("Mul", (PVVar("i"), PConst(4))))),
        size=4,
    ),
    params=(PatternParam("v", type=CppRef(STD_VECTOR_INT)), PatternParam("i")),
    returnty="int",
    arches=_X86,
    platforms=_LINUX_WIN,
    binary_guard=is_cpp_binary,
    enabled_by_default=False,
)


ALL_STL_X86_PATTERNS = [
    STD_STRING_LENGTH_X86_MSVC,
    STD_STRING_EMPTY_X86_MSVC,
    STD_VECTOR_INT_SIZE_X86,
    STD_VECTOR_INT_EMPTY_X86,
    STD_VECTOR_INT_CAPACITY_X86,
    STD_VECTOR_INT_INDEX_X86,
]
