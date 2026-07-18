"""Inlined std::vector<T>::size().

libstdc++ lays out std::vector as ``{_M_start at +0, _M_finish at +8,
_M_end_of_storage at +16}``, and the MSVC STL uses the same three-pointer
layout (``_Myfirst``/``_Mylast``/``_Myend``); the inlined size() is
``(_M_finish - _M_start) / sizeof(T)``:

    ((Load(addr=(v Add 8<64>), size=8) Sub Load(addr=v, size=8)) Sar log2(sizeof(T)))

Note the shift amount is an 8-bit constant. One pattern is registered per
common element size (short/int/long long); ``sizeof(T) == 1`` (vector<char>)
is deliberately not covered — without the shift, the shape degenerates to a
bare pointer difference, which is far too generic.

Calibrated against tests/x86_64/decompiler/known_patterns_stl (g++ 12.2.0 -O2).
"""

from __future__ import annotations

from .dsl import PBinOp, PConst, PLoad, PVVar
from .pattern import CppRef, KnownPattern, PatternParam, is_cpp_binary

STD_VECTOR_UNIQUE_NAME_TMPL = "class std::vector<{elt}, class std::allocator<{elt}>>"


def make_std_vector_size_pattern(elt_name: str, log2_elt_size: int) -> KnownPattern:
    """Build the inlined-size() pattern for ``std::vector<elt_name>`` with
    ``sizeof(elt) == 1 << log2_elt_size``. The element type must be registered
    in the cpp::std type collection under the standard vector unique name."""
    assert log2_elt_size > 0, "sizeof(T) == 1 has no shift and is too generic to match"
    slug = elt_name.replace(" ", "_")
    return KnownPattern(
        name=f"std_vector_{slug}_size",
        display_name=f"std::vector<{elt_name}>::size",
        call_name=f"std::vector<{elt_name}>::size",
        pattern=PBinOp(
            frozenset({"Sar", "Shr"}),
            (
                PBinOp(
                    "Sub",
                    (
                        PLoad(addr=PBinOp("Add", (PVVar("v"), PConst(8))), size=8),  # _M_finish
                        PLoad(addr=PVVar("v"), size=8),  # _M_start
                    ),
                ),
                PConst(log2_elt_size),
            ),
        ),
        params=(PatternParam("v", type=CppRef(STD_VECTOR_UNIQUE_NAME_TMPL.format(elt=elt_name))),),
        returnty="unsigned long long",
        arches=("AMD64",),
        # the MSVC STL uses the same three-pointer layout (_Myfirst/_Mylast/_Myend),
        # so the pattern applies to Windows binaries as-is
        platforms=("linux", "win32", "windows"),
        # pointer-difference-and-shift also appears in plain C code; require C++ evidence
        binary_guard=is_cpp_binary,
    )


STD_VECTOR_SHORT_SIZE = make_std_vector_size_pattern("short", 1)
STD_VECTOR_INT_SIZE = make_std_vector_size_pattern("int", 2)
STD_VECTOR_LONG_LONG_SIZE = make_std_vector_size_pattern("long long", 3)

STD_VECTOR_INT = STD_VECTOR_UNIQUE_NAME_TMPL.format(elt="int")
