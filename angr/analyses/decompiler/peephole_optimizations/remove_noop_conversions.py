# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

from angr.ailment.expression import Convert, Extract
from angr.ailment.utils import is_lsb_extract

from .base import PeepholeOptimizationExprBase


class RemoveNoopConversions(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove no-op conversions"
    expr_classes = (Convert, Extract)

    def optimize(self, expr: Convert | Extract, **kwargs):
        if isinstance(expr, Convert):
            inner = expr.operand
            signed = expr.is_signed
            ints = expr.from_type == expr.to_type == Convert.TYPE_INT
        else:
            # Only an Extract of the *least-significant* bits is a truncation.
            # Every rule below assumes the low end of the value, so applying them
            # to an Extract at a higher offset silently drops that offset: on
            # x86 `test $0x20,%ah` lifts to Extract(8 bits @ byte 1) and came out
            # as a test of %al, which is how every glibc ctype macro compiled by
            # gcc -- isspace, isdigit, isalpha, ... -- decompiled to the wrong
            # bit without any diagnostic.
            if not is_lsb_extract(expr):
                return None
            inner = expr.base
            signed = False
            ints = True

        if inner.bits == expr.bits and ints:
            return inner

        if isinstance(inner, Convert):
            if (
                expr.bits < inner.bits
                and expr.bits == inner.operand.bits
                and ints
                and inner.from_type == inner.to_type == Convert.TYPE_INT
            ):
                # extension then truncation (e.g., 1->64->1) can be removed, but truncation then extension cannot be
                # removed (e.g., the high 32 bits must be removed during 64->32->64)
                return inner.operand
            if (
                expr.bits < inner.from_bits
                and inner.to_bits >= inner.from_bits
                and ints
                and inner.from_type == inner.to_type == Convert.TYPE_INT
            ):
                # merge extend and then bigtruncate into just truncate
                return Convert(
                    expr.idx,
                    inner.from_bits,
                    expr.bits,
                    signed,
                    inner.operand,
                    **expr.tags,
                )

        return None
