"""Linux kernel ``<linux/err.h>`` error-pointer idioms.

``IS_ERR(p)`` tests ``(unsigned long)p >= (unsigned long)-MAX_ERRNO``; the
threshold is derived from the context's word width, so one definition covers
32- and 64-bit.

gcc emits the test in four different shapes depending on where it lands, and a
pattern that covers only one of them silently misses most real code: the literal
``>= THR``, the strength-reduced ``> THR-1`` (the value form at -O2), and the
operand-swapped ``<=`` / ``<`` forms (the branch-condition form). All four are
matched. The comparison must be *unsigned* — a signed compare against the same
constant is an unrelated test — which is checked in ``where`` because the DSL
does not model ``BinaryOp.signed``.

``PTR_ERR`` and ``ERR_PTR`` are pure casts that compile to a bare register move
and leave no residue at all, so there is nothing to match and they are
deliberately absent.

Opt-in: these are kernel idioms, and renaming a comparison to ``IS_ERR()`` in a
user-space binary would be misleading even though the threshold constant is in
practice unique to err.h. Calibrated against
tests/x86_64/decompiler/known_patterns_kernel_macros (gcc -O2).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .dsl import PBinOp, PChoice, PConst, PVVar
from .pattern import KnownPattern, PatternParam
from .templates import make_template

if TYPE_CHECKING:
    from angr.ailment.expression import Expression

    from .context import PatternContext

MAX_ERRNO = 4095


def _is_err_value(cap: str, ctx: PatternContext) -> PChoice:
    """``(unsigned long)ptr >= (unsigned long)-MAX_ERRNO``, in every shape the
    compiler emits it."""
    thr = ((1 << ctx.bits) - MAX_ERRNO) & ((1 << ctx.bits) - 1)
    return PChoice(
        PBinOp("CmpGE", (PVVar(cap), PConst(thr)), commutative=False, name="err_cmp"),
        PBinOp("CmpGT", (PVVar(cap), PConst(thr - 1)), commutative=False, name="err_cmp"),
        PBinOp("CmpLE", (PConst(thr), PVVar(cap)), commutative=False, name="err_cmp"),
        PBinOp("CmpLT", (PConst(thr - 1), PVVar(cap)), commutative=False, name="err_cmp"),
    )


def _unsigned(bindings: dict[str, Expression]) -> bool:
    cmp_expr = bindings.get("err_cmp")
    return cmp_expr is not None and not cmp_expr.signed


def _build_is_err(ctx: PatternContext) -> KnownPattern:
    return KnownPattern(
        name="is_err",
        display_name="IS_ERR",
        call_name="IS_ERR",
        pattern=_is_err_value("ptr", ctx),
        params=(PatternParam("ptr", "void *"),),
        returnty="int",
        where=_unsigned,
        enabled_by_default=False,
    )


def _build_is_err_or_null(ctx: PatternContext) -> KnownPattern:
    # !ptr || IS_ERR_VALUE(ptr) -- branchless at -O2: (ptr == 0) | (ptr > THR-1)
    return KnownPattern(
        name="is_err_or_null",
        display_name="IS_ERR_OR_NULL",
        call_name="IS_ERR_OR_NULL",
        pattern=PBinOp(
            frozenset({"Or", "LogicalOr"}),
            (PBinOp("CmpEQ", (PVVar("ptr"), PConst(0))), _is_err_value("ptr", ctx)),
            commutative=True,
        ),
        params=(PatternParam("ptr", "void *"),),
        returnty="int",
        where=_unsigned,
        enabled_by_default=False,
    )


IS_ERR = make_template("IS_ERR", _build_is_err, enabled_by_default=False)
IS_ERR_OR_NULL = make_template("IS_ERR_OR_NULL", _build_is_err_or_null, enabled_by_default=False)

ALL_KERNEL_ERR_TEMPLATES = [IS_ERR_OR_NULL, IS_ERR]
