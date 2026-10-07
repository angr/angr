"""3-component float vector math (glm / DirectXMath / game-graphics code).

Scalar float arithmetic compiles to SSE mulss/addss, which the lifter lowers
from their 128-bit vector form to 32-bit floating-point Mul/Add over
Load(..., 4) operands. The ops must be floating point: the same shape over
integer Mul/Add is an integer dot product. Intel-SSE specific (float width is
4 bytes regardless of pointer size), so these are not word-scaled. Opt-in;
calibrated against tests/x86_64/decompiler/known_patterns_vecmath
(g++ -O2 -fno-tree-vectorize).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from angr.ailment.expression import BinaryOp

from .context import INTEL
from .dsl import PBinOp, PConst, PLoad, PVVar
from .pattern import KnownPattern, PatternParam
from .templates import make_template

if TYPE_CHECKING:
    from angr.ailment.expression import Expression

    from .context import PatternContext

_OPS = ("m0", "m1", "m2", "s0", "s1")


def _f(cap: str, off: int) -> PLoad:
    addr = PVVar(cap) if off == 0 else PBinOp("Add", (PVVar(cap), PConst(off)))
    return PLoad(addr, size=4)


def _mul(name: str, x: PLoad, y: PLoad) -> PBinOp:
    return PBinOp("Mul", (x, y), commutative=True, name=name)


def _add(name: str, x: PBinOp, y: PBinOp) -> PBinOp:
    return PBinOp("Add", (x, y), commutative=True, name=name)


def _all_fp(bindings: dict[str, Expression]) -> bool:
    for n in _OPS:
        op = bindings[n]
        assert isinstance(op, BinaryOp)
        if not op.floating_point:
            return False
    return True


def _build_dot3(_ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="vec_dot3",
        display_name="dot3",
        call_name="dot3",
        pattern=_add(
            "s1",
            _add("s0", _mul("m0", _f("a", 0), _f("b", 0)), _mul("m1", _f("a", 4), _f("b", 4))),
            _mul("m2", _f("a", 8), _f("b", 8)),
        ),
        params=(PatternParam("a"), PatternParam("b")),
        returnty="float",
        where=_all_fp,
    )


def _build_length_sq(_ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="vec_length_sq",
        display_name="length_sq",
        call_name="length_sq",
        pattern=_add(
            "s1",
            _add("s0", _mul("m0", _f("a", 0), _f("a", 0)), _mul("m1", _f("a", 4), _f("a", 4))),
            _mul("m2", _f("a", 8), _f("a", 8)),
        ),
        params=(PatternParam("a"),),
        returnty="float",
        where=_all_fp,
    )


# length_sq registered before dot3 so it wins on a dot-with-itself. Not
# language-gated: scalar vector math appears in C as well as C++.
VEC_LENGTH_SQ = make_template("length_sq", _build_length_sq, arches=INTEL, default_enabled=False)
VEC_DOT3 = make_template("dot3", _build_dot3, arches=INTEL, default_enabled=False)

ALL_VECTOR_MATH_TEMPLATES = [VEC_LENGTH_SQ, VEC_DOT3]
