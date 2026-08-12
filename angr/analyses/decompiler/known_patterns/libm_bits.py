"""libm floating-point bit-twiddling idioms (fabs / -x / copysign / isnan / isinf).

Every one of these "functions" is a compiler intrinsic: on x86-64 with SSE they
become a single ``andpd`` / ``xorpd`` / ``andnpd`` / ``ucomisd`` against a
sign-mask constant kept in ``.rodata``. angr's ``constant_derefs`` peephole
folds the rip-relative mask load into a ``Const``, so what reaches the AIL is a
plain integer bit operation on the raw float bits -- e.g. ``fabs(x)`` is
``x & 0x7fffffffffffffff``, unreadable unless it is named again.

Two AIL spellings show up for the SSE operand, depending on whether the
128-bit vector op survived narrowing:

* narrowed:  ``BinaryOp(And, vvar_0, 0x7fffffffffffffff<64>)``
* unnarrowed: ``BinaryOp(Xor, Conv(64->128, vvar_0), 0x8000000000000000<128>)``
  under an ``Extract(..., 64bits@0)``

``_sse_operand`` accepts both and always captures the underlying vvar, which
the Outliner requires (call parameters must bind VirtualVariables).

Intel-SSE specific (the mask widths are fixed by the FP format, not by the
pointer size), so these are not word-scaled. Calibrated against
tests/x86_64/decompiler/known_patterns_libm_bits (gcc -O2 -fno-tree-vectorize).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .context import INTEL
from .dsl import PBinOp, PChoice, PConst, PConv, PExtract, PUnaryOp, PVVar
from .pattern import KnownPattern, PatternParam
from .templates import make_template

if TYPE_CHECKING:
    from .context import PatternContext

# IEEE-754 field masks
SIGN64 = 0x8000000000000000
ABS64 = 0x7FFFFFFFFFFFFFFF
INF64 = 0x7FF0000000000000
SIGN32 = 0x80000000
ABS32 = 0x7FFFFFFF


def _sse_operand(cap: str) -> PChoice:
    """An SSE scalar operand: a bare vvar (the 128-bit vector op was narrowed
    away), a vvar widened into the vector register, or the low half extracted
    back out of one.

    The width of the widening is not pinned: it follows the *recovered
    prototype*, so a float argument appears as Conv(32->128) when the prototype
    is known and as Conv(64->128) when it was guessed from the xmm register. The
    mask constant already discriminates float from double.

    The Extract arm is what a *computed* operand looks like -- ``isinf(a * b)``
    rather than ``isinf(x)``. The product stays in a vector vvar and ``movq
    %xmm2,%rax`` lifts to ``Extract(vvar_128, 64bits@0)``; without this arm every
    such site is silent, which is why isinf scored 4%."""
    return PChoice(PVVar(cap), PConv(PVVar(cap), to_bits=128), PExtract(PVVar(cap), offset=0))


def _scalar_mask(value: int) -> PChoice:
    """A scalar IEEE-754 field mask. The constant's width likewise follows the
    recovered prototype (a float mask shows up 32- or 64-bit wide), but 128-bit
    vector constants are excluded so a genuine vector op is not mistaken for a
    scalar one."""
    return PChoice(PConst(value, bits=32), PConst(value, bits=64))


def _clear_sign(cap: str, mask: int) -> PBinOp:
    """``x & 0x7fff...`` -- the fabs() bit pattern. The operand is captured as a
    virtual variable rather than PAny: a call argument must bind a vvar, so
    matching a computed operand (``fabs(a - b)``) would only produce a match
    that cannot be outlined, silently consuming the site."""
    return PBinOp("And", (_sse_operand(cap), _scalar_mask(mask)), commutative=True)


def _unordered(x, y) -> PBinOp:
    """``((CmpF(x, y) & 69) >> 2) & 1`` -- the x86 ``ucomis[sd]`` result with the
    parity flag (unordered) extracted; 69 == ZF|PF|CF."""
    return PBinOp(
        "And",
        (
            PBinOp(
                "Shr",
                (
                    PBinOp("And", (PBinOp("CmpF", (x, y)), PConst(69)), commutative=True),
                    PConst(2),
                ),
            ),
            PConst(1),
        ),
        commutative=True,
    )


def _cmpf_operand(cap: str, width: int):
    """A ``CmpF`` operand: a bare 64-bit vvar (double) or a 32-bit vvar widened
    by ``Conv(32->64)``, which is how ``ucomiss`` lifts."""
    return PVVar(cap) if width == 64 else PConv(PVVar(cap), from_bits=32, to_bits=64)


def _build_fabs(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="libm_fabs",
        display_name="fabs",
        call_name="fabs",
        pattern=_clear_sign("x", ABS64),
        params=(PatternParam("x", type="double"),),
        returnty="double",
    )


def _build_fabsf(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="libm_fabsf",
        display_name="fabsf",
        call_name="fabsf",
        pattern=_clear_sign("x", ABS32),
        params=(PatternParam("x", type="float"),),
        returnty="float",
    )


def _build_fneg(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="libm_fneg",
        display_name="-x (double)",
        call_name="fneg",
        pattern=PBinOp("Xor", (_sse_operand("x"), PConst(SIGN64, bits=128)), commutative=True),
        params=(PatternParam("x", type="double"),),
        returnty="double",
    )


def _build_fnegf(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="libm_fnegf",
        display_name="-x (float)",
        call_name="fnegf",
        pattern=PBinOp("Xor", (_sse_operand("x"), PConst(SIGN32, bits=128)), commutative=True),
        params=(PatternParam("x", type="float"),),
        returnty="float",
    )


def _copysign_pattern(sign: int) -> PBinOp:
    """``(~signmask & x) | (signmask & y)`` -- andnpd / andpd / orpd."""
    return PBinOp(
        "Or",
        (
            PBinOp(
                "And",
                (PUnaryOp("BitwiseNeg", PConst(sign, bits=128)), _sse_operand("x")),
                commutative=True,
            ),
            PBinOp("And", (PConst(sign, bits=128), _sse_operand("y")), commutative=True),
        ),
        commutative=False,
    )


def _build_copysign(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="libm_copysign",
        display_name="copysign",
        call_name="copysign",
        pattern=_copysign_pattern(SIGN64),
        params=(PatternParam("x", type="double"), PatternParam("y", type="double")),
        returnty="double",
    )


def _build_copysignf(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="libm_copysignf",
        display_name="copysignf",
        call_name="copysignf",
        pattern=_copysign_pattern(SIGN32),
        params=(PatternParam("x", type="float"), PatternParam("y", type="float")),
        returnty="float",
    )


def _build_isnan(ctx: PatternContext) -> KnownPattern:
    # two independent spellings: the ucomisd self-compare the compilers emit for
    # the <math.h> macro, and the hand-rolled |bits| > +inf test
    return KnownPattern(
        name="libm_isnan",
        display_name="isnan",
        call_name="isnan",
        pattern=PChoice(
            _unordered(_cmpf_operand("x", 64), _cmpf_operand("x", 64)),
            PBinOp("CmpLT", (PConst(INF64), _clear_sign("x", ABS64))),
            PBinOp("CmpGT", (_clear_sign("x", ABS64), PConst(INF64))),
        ),
        params=(PatternParam("x", type="double"),),
        returnty="int",
    )


def _build_isnanf(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="libm_isnanf",
        display_name="isnanf",
        call_name="isnanf",
        pattern=_unordered(_cmpf_operand("x", 32), _cmpf_operand("x", 32)),
        params=(PatternParam("x", type="float"),),
        returnty="int",
    )


def _build_isunordered(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="libm_isunordered",
        display_name="isunordered",
        call_name="isunordered",
        pattern=_unordered(_cmpf_operand("x", 64), _cmpf_operand("y", 64)),
        params=(PatternParam("x", type="double"), PatternParam("y", type="double")),
        returnty="int",
    )


def _build_isinf(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="libm_isinf",
        display_name="isinf",
        call_name="isinf",
        pattern=PBinOp("CmpEQ", (_clear_sign("x", ABS64), PConst(INF64)), commutative=True),
        params=(PatternParam("x", type="double"),),
        returnty="int",
    )


# isnan registered before isunordered so a self-compare is named isnan(), not
# isunordered(x, x).
LIBM_ISNAN = make_template("isnan", _build_isnan, arches=INTEL)
LIBM_ISNANF = make_template("isnanf", _build_isnanf, arches=INTEL)
LIBM_ISUNORDERED = make_template("isunordered", _build_isunordered, arches=INTEL)
LIBM_ISINF = make_template("isinf", _build_isinf, arches=INTEL)
LIBM_COPYSIGN = make_template("copysign", _build_copysign, arches=INTEL)
LIBM_COPYSIGNF = make_template("copysignf", _build_copysignf, arches=INTEL)
LIBM_FNEG = make_template("fneg", _build_fneg, arches=INTEL)
LIBM_FNEGF = make_template("fnegf", _build_fnegf, arches=INTEL)
# `x & 0x7fffffff[ffffffff]` is also a plain integer "clear the top bit", so the
# fabs patterns are opt-in.
LIBM_FABS = make_template("fabs", _build_fabs, arches=INTEL, enabled_by_default=False)
LIBM_FABSF = make_template("fabsf", _build_fabsf, arches=INTEL, enabled_by_default=False)

ALL_LIBM_TEMPLATES = [
    LIBM_ISNAN,
    LIBM_ISNANF,
    LIBM_ISUNORDERED,
    LIBM_ISINF,
    LIBM_COPYSIGN,
    LIBM_COPYSIGNF,
    LIBM_FNEG,
    LIBM_FNEGF,
    LIBM_FABS,
    LIBM_FABSF,
]
