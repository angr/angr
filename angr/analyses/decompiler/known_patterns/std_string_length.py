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
from .layouts import string_data_offset, string_size_offset
from .pattern import CppRef, KnownPattern, PatternParam
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext

STD_BASIC_STRING = "class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>"


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

# opt-in: "field == 0" is generic
STD_STRING_EMPTY = make_template(
    "std::string::empty", _build_string_empty, arches=INTEL, languages=(CPP,), enabled_by_default=False
)

# opt-in: overlaps plain char* indexing; libstdc++ only (MSVC has an SSO branch)
STD_STRING_INDEX = make_template(
    "std::string::operator[]",
    _build_string_index,
    arches=INTEL,
    languages=(CPP,),
    runtimes=(LIBSTDCXX,),
    enabled_by_default=False,
)
