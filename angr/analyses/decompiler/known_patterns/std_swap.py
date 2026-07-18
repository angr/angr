"""Inlined std::swap on 8-byte values through pointers/references:

    t = *a; *a = *b; *b = t

which appears in AIL as a three-statement sequence:

    vT = Load(a, 8)
    Store(a, Load(b, 8))
    Store(b, vT)

The synthesized call is void: the temporary must die inside the region (a
region with a live-out value does not match the void declaration and is
rejected at outline time).

Calibrated against tests/x86_64/decompiler/known_patterns_multiblock
(g++ 12.2.0 -O2).
"""

from __future__ import annotations

from .dsl import PAssign, PLoad, PStmtSeq, PStore, PVVar
from .pattern import KnownPattern, PatternParam, is_cpp_binary

STD_SWAP_8 = KnownPattern(
    name="std_swap_8",
    display_name="std::swap",
    call_name="std::swap",
    pattern=PStmtSeq(
        (
            PAssign(PVVar("t"), PLoad(PVVar("a"), size=8)),
            PStore(PVVar("a"), PLoad(PVVar("b"), size=8), size=8),
            PStore(PVVar("b"), PVVar("t"), size=8),
        )
    ),
    params=(
        PatternParam("a", type="unsigned long long *"),
        PatternParam("b", type="unsigned long long *"),
    ),
    returnty=None,  # void
    arches=("AMD64",),
    platforms=("linux",),
    # load/store/store sequences appear in plain C code too; require C++ evidence
    binary_guard=is_cpp_binary,
)
