"""Inlined std::swap on pointer-word values:

    t = *a; *a = *b; *b = t

as a three-statement sequence. The load/store width is the target word size, so
one template covers 32- and 64-bit. Void (the temporary dies inside the region).

Calibrated against tests/x86_64/decompiler/known_patterns_multiblock (g++ -O2).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .context import CPP, INTEL
from .dsl import PAssign, PLoad, PStmtSeq, PStore, PVVar
from .pattern import KnownPattern, PatternParam
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext


def _build_std_swap(ctx: PatternContext) -> KnownPattern:
    ws = ctx.word_size
    ptr = "unsigned long long *" if ctx.bits >= 64 else "unsigned int *"
    return KnownPattern(
        name="std_swap",
        display_name="std::swap",
        call_name="std::swap",
        pattern=PStmtSeq(
            (
                PAssign(PVVar("t"), PLoad(PVVar("a"), size=ws)),
                PStore(PVVar("a"), PLoad(PVVar("b"), size=ws), size=ws),
                PStore(PVVar("b"), PVVar("t"), size=ws),
            )
        ),
        params=(PatternParam("a", type=ptr), PatternParam("b", type=ptr)),
        returnty=None,
    )


STD_SWAP = make_template("std::swap", _build_std_swap, arches=INTEL, languages=(CPP,))
