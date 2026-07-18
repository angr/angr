"""Inlined std::string::length() / size().

libstdc++ (new ABI) lays out std::basic_string as ``{_M_p at +0,
_M_string_length at +8, union at +16}``; the inlined accessor is a single
8-byte load at offset 8 off the string pointer:

    Load(addr=(s Add 8<64>), size=8)

Calibrated against tests/x86_64/decompiler/known_patterns_stl (g++ 12.2.0 -O2).
"""

from __future__ import annotations

from .dsl import PBinOp, PConst, PLoad, PVVar
from .pattern import CppRef, KnownPattern, PatternParam, is_cpp_binary

STD_BASIC_STRING = "class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>"

STD_STRING_LENGTH = KnownPattern(
    name="std_string_length",
    display_name="std::string::length",
    call_name="std::string::length",
    pattern=PLoad(addr=PBinOp("Add", (PVVar("s"), PConst(8))), size=8),
    params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)),),
    returnty="unsigned long long",
    arches=("AMD64",),
    platforms=("linux",),
    # a bare Load(s + 8) is common in plain C code; require C++ evidence
    binary_guard=is_cpp_binary,
)
