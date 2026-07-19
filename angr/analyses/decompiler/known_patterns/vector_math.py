"""3-component float vector math (glm / DirectXMath / game-graphics code).

Scalar float arithmetic compiles to SSE MulV/AddV on 128-bit registers with
Conv(32->128, Load(..., 4)) operands under Extract(..., 64@0). Intel-SSE
specific (float width is 4 bytes regardless of pointer size), so these are not
word-scaled. Opt-in; calibrated against
tests/x86_64/decompiler/known_patterns_vecmath (g++ -O2 -fno-tree-vectorize).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .context import INTEL
from .dsl import PBinOp, PConst, PLoad, PVVar
from .pattern import KnownPattern, PatternParam
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext


def _f(cap: str, off: int) -> PLoad:
    addr = PVVar(cap) if off == 0 else PBinOp("Add", (PVVar(cap), PConst(off)))
    return PLoad(addr, size=4)


def _mul(x: PLoad, y: PLoad) -> PBinOp:
    return PBinOp("MulV", (x, y), commutative=True)


def _add(x: PBinOp, y: PBinOp) -> PBinOp:
    return PBinOp("AddV", (x, y), commutative=True)


def _build_dot3(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="vec_dot3",
        display_name="dot3",
        call_name="dot3",
        pattern=_add(
            _add(_mul(_f("a", 0), _f("b", 0)), _mul(_f("a", 4), _f("b", 4))),
            _mul(_f("a", 8), _f("b", 8)),
        ),
        params=(PatternParam("a"), PatternParam("b")),
        returnty="float",
    )


def _build_length_sq(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="vec_length_sq",
        display_name="length_sq",
        call_name="length_sq",
        pattern=_add(
            _add(_mul(_f("a", 0), _f("a", 0)), _mul(_f("a", 4), _f("a", 4))),
            _mul(_f("a", 8), _f("a", 8)),
        ),
        params=(PatternParam("a"),),
        returnty="float",
    )


# length_sq registered before dot3 so it wins on a dot-with-itself. Not
# language-gated: scalar vector math appears in C as well as C++.
VEC_LENGTH_SQ = make_template("length_sq", _build_length_sq, arches=INTEL, enabled_by_default=False)
VEC_DOT3 = make_template("dot3", _build_dot3, arches=INTEL, enabled_by_default=False)

ALL_VECTOR_MATH_TEMPLATES = [VEC_LENGTH_SQ, VEC_DOT3]
