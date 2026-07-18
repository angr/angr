"""Inlined std::vector<int>::size().

libstdc++ lays out std::vector as ``{_M_start at +0, _M_finish at +8,
_M_end_of_storage at +16}``; the inlined size() is
``(_M_finish - _M_start) / sizeof(int)``:

    ((Load(addr=(v Add 8<64>), size=8) Sub Load(addr=v, size=8)) Sar 2<8>)

Note the shift amount is an 8-bit constant. Calibrated against
tests/x86_64/decompiler/known_patterns_stl (g++ 12.2.0 -O2).
"""

from __future__ import annotations

from .dsl import PBinOp, PConst, PLoad, PVVar
from .pattern import CppRef, KnownPattern, PatternParam, is_cpp_binary

STD_VECTOR_INT = "class std::vector<int, class std::allocator<int>>"

STD_VECTOR_INT_SIZE = KnownPattern(
    name="std_vector_int_size",
    display_name="std::vector<int>::size",
    call_name="std::vector<int>::size",
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
            PConst(2),  # log2(sizeof(int))
        ),
    ),
    params=(PatternParam("v", type=CppRef(STD_VECTOR_INT)),),
    returnty="unsigned long long",
    arches=("AMD64",),
    platforms=("linux",),
    # pointer-difference-and-shift also appears in plain C code; require C++ evidence
    binary_guard=is_cpp_binary,
)
