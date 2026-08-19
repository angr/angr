"""Inlined std::string::length() / size() and empty().

The length field is an 8- or 4-byte load of the string's size member. libstdc++
keeps ``_M_string_length`` one word past the data pointer; the MSVC STL keeps
``_Mysize`` behind a fixed 16-byte SSO buffer union (see :mod:`.layouts`). One
template covers all of {libstdc++, MSVC} x {32, 64}-bit.

Calibrated against tests/x86_64/decompiler/known_patterns_stl (g++ 12.2.0 -O2),
tests/x86_64/windows/known_patterns_stl_msvc_17_x64.exe and
tests/i386/windows/known_patterns_stl_msvc_17_x86.exe (VS 2022 /O2).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .context import CPP, INTEL, LIBSTDCXX, size_t_typename
from .dsl import PBinOp, PConst, PLoad, PVVar
from .gating import corroborated_by
from .layouts import string_data_offset, string_size_offset
from .pattern import CppRef, KnownPattern, PatternParam
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext

STD_BASIC_STRING = "class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>"

# The generic std::string accessors are shapes that occur all over any binary — a field-equals-zero test, an indexed
# byte load, a double dereference. What makes them safe is knowing that the pointer really is a std::string, and the
# cheapest proof of that is another, self-guarding string idiom in the same function: ``capacity`` is the SSO select
# that tests the data pointer against the object's own local-buffer address, and the destructor is that same test
# guarding a call to ``operator delete`` on the object's own buffer. Where either matched, this object is a
# std::string and its other accessors can be named.
#
# ``length`` is also a witness, and is the weakest of the three: it is a bare one-word load at the layout's size
# offset, which std::vector's _M_finish shares, so it measures 59.9% precision on the benchmark corpus against 98%+
# for the self-guarding shapes. It stays in the set because dropping it costs recall on functions that touch a string
# only through its length; narrowing it is its own piece of work.
STRING_WITNESSED = corroborated_by(
    "std::string::length", "std::string::capacity", "std::string::~string", "std_string_dtor"
)


def _string_field(cap: str, off: int, size: int) -> PLoad:
    addr = PVVar(cap) if off == 0 else PBinOp("Add", (PVVar(cap), PConst(off)))
    return PLoad(addr, size=size)


def _build_string_length(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="std_string_length",
        display_name="std::string::length",
        call_name="std::string::length",
        pattern=_string_field("s", string_size_offset(ctx), ctx.word_size),
        params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)),),
        returnty=size_t_typename(ctx.bits),
    )


def _build_string_empty(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="std_string_empty",
        display_name="std::string::empty",
        call_name="std::string::empty",
        pattern=PBinOp("CmpEQ", (_string_field("s", string_size_offset(ctx), ctx.word_size), PConst(0))),
        params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)),),
        returnty="int",
    )


def _build_string_index(ctx: PatternContext) -> KnownPattern:
    # *(_M_p + i) = Load(Load(s) + i, size=1); MSVC has an SSO branch, hence
    # libstdc++-only.
    data = _string_field("s", string_data_offset(ctx), ctx.word_size)
    return KnownPattern(
        name="std_string_index",
        display_name="std::string::operator[]",
        call_name="std::string::operator[]",
        pattern=PLoad(PBinOp("Add", (data, PVVar("i"))), size=1),
        params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)), PatternParam("i")),
        returnty="char",
    )


STD_STRING_LENGTH = make_template("std::string::length", _build_string_length, arches=INTEL, languages=(CPP,))

# opt-in: "field == 0" is generic — unless an unambiguous string idiom already identified the object
STD_STRING_EMPTY = make_template(
    "std::string::empty",
    _build_string_empty,
    arches=INTEL,
    languages=(CPP,),
    enabled_by_default=False,
    gate=STRING_WITNESSED,
)

# opt-in: overlaps plain char* indexing; libstdc++ only (MSVC has an SSO branch)
STD_STRING_INDEX = make_template(
    "std::string::operator[]",
    _build_string_index,
    arches=INTEL,
    languages=(CPP,),
    runtimes=(LIBSTDCXX,),
    enabled_by_default=False,
    gate=STRING_WITNESSED,
)
