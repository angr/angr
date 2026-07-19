"""Inlined std::string::length() / size().

libstdc++ (new ABI) lays out std::basic_string as ``{_M_p at +0,
_M_string_length at +8, union at +16}``; the inlined accessor is a single
8-byte load at offset 8 off the string pointer:

    Load(addr=(s Add 8<64>), size=8)

The MSVC STL instead stores the string in ``_Mypair._Myval2`` as ``{_Bx
(16-byte buf/pointer union) at +0, _Mysize at +16, _Myres at +24}``, so the
inlined accessor on x64 Windows is an 8-byte load at offset 16.

The libstdc++ variant is calibrated against
tests/x86_64/decompiler/known_patterns_stl (g++ 12.2.0 -O2); the MSVC variant
against tests/x86_64/windows/known_patterns_stl_msvc_17_x64.exe (VS 2022 /O2).
"""

from __future__ import annotations

from .dsl import PBinOp, PConst, PLoad, PVVar
from .pattern import CppRef, KnownPattern, PatternParam, is_cpp_binary, is_msvc_cpp_binary

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

STD_STRING_LENGTH_MSVC = KnownPattern(
    name="std_string_length_msvc",
    display_name="std::string::length",
    call_name="std::string::length",
    pattern=PLoad(addr=PBinOp("Add", (PVVar("s"), PConst(16))), size=8),
    params=(PatternParam("s", type=CppRef(STD_BASIC_STRING)),),
    returnty="unsigned long long",
    arches=("AMD64",),
    platforms=("win32", "windows"),
    # mingw PEs use libstdc++ layouts; require MSVC-STL evidence specifically
    binary_guard=is_msvc_cpp_binary,
)
