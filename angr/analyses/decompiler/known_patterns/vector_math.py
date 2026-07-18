"""3-component float vector math (glm / DirectXMath / game-graphics code).

Scalar float arithmetic compiles to SSE scalar-in-vector ops, which angr models
as ``MulV``/``AddV`` on 128-bit registers with ``Conv(32->128, Load(..., 4))``
operands, the result taken with ``Extract(..., 64@0)``:

    dot3(a,b) = a.x*b.x + a.y*b.y + a.z*b.z
      = Extract( AddV(AddV(MulV(*a,*b), MulV(*(a+4),*(b+4))), MulV(*(a+8),*(b+8))), 64@0 )

Calibrated against tests/x86_64/decompiler/known_patterns_vecmath
(g++ 12.2.0 -O2 -fno-tree-vectorize). The Conv wrappers are skipped by the
matcher; MulV/AddV are marked commutative. These are opt-in
(``enabled_by_default=False``): FP arithmetic shapes are sensitive to compiler
and vectorization, and the association captured here is the left-associative
form gcc emits.
"""

from __future__ import annotations

from .dsl import PBinOp, PConst, PLoad, PVVar
from .pattern import KnownPattern, PatternParam


def _f(cap: str, off: int) -> PLoad:
    addr = PVVar(cap) if off == 0 else PBinOp("Add", (PVVar(cap), PConst(off)))
    return PLoad(addr, size=4)


def _mul(x: PLoad, y: PLoad) -> PBinOp:
    return PBinOp("MulV", (x, y), commutative=True)


def _add(x: PBinOp, y: PBinOp) -> PBinOp:
    return PBinOp("AddV", (x, y), commutative=True)


# dot(a,b) = a.x*b.x + a.y*b.y + a.z*b.z
VEC_DOT3 = KnownPattern(
    name="vec_dot3",
    display_name="dot3",
    call_name="dot3",
    pattern=_add(
        _add(_mul(_f("a", 0), _f("b", 0)), _mul(_f("a", 4), _f("b", 4))),
        _mul(_f("a", 8), _f("b", 8)),
    ),
    params=(PatternParam("a"), PatternParam("b")),
    returnty="float",
    arches=("AMD64",),
    enabled_by_default=False,
)


# length_sq(a) = a.x*a.x + a.y*a.y + a.z*a.z  (dot with itself)
VEC_LENGTH_SQ = KnownPattern(
    name="vec_length_sq",
    display_name="length_sq",
    call_name="length_sq",
    pattern=_add(
        _add(_mul(_f("a", 0), _f("a", 0)), _mul(_f("a", 4), _f("a", 4))),
        _mul(_f("a", 8), _f("a", 8)),
    ),
    params=(PatternParam("a"),),
    returnty="float",
    arches=("AMD64",),
    enabled_by_default=False,
)


# length_sq is registered first so it wins over dot3 on a dot-with-itself.
ALL_VECTOR_MATH_PATTERNS = [
    VEC_LENGTH_SQ,
    VEC_DOT3,
]
