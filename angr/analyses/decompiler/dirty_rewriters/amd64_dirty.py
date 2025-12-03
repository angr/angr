from __future__ import annotations

from angr.ailment.statement import DirtyStatement, Statement, Call
from angr.ailment.expression import Const, DirtyExpression, Expression
from .rewriter_base import DirtyRewriterBase


class AMD64DirtyRewriter(DirtyRewriterBase):
    """
    Rewrites AMD64 DirtyStatement and DirtyExpression.
    """

    __slots__ = ()

    def _rewrite_stmt(self, dirty: DirtyStatement) -> Statement | None:
        # TODO: Rewrite more dirty statements
        return self._rewrite_expr_to_call(dirty.dirty)

    def _rewrite_expr(self, dirty: DirtyExpression) -> Expression | None:
        return self._rewrite_expr_to_call(dirty)

    def _rewrite_expr_to_call(self, dirty: DirtyExpression) -> Call | None:
        match dirty.callee:
            case "amd64g_dirtyhelper_IN":
                if len(dirty.operands) != 2:
                    return None
                portno, size = dirty.operands
                if not isinstance(size, Const):
                    return None
                bits = size.value_int * self.arch.byte_width
                return Call(
                    idx=dirty.idx,
                    target=f"__in{self._inout_intrinsic_suffix(bits)}",
                    calling_convention=None,
                    prototype=None,
                    args=(portno,),
                    ret_expr=None,
                    bits=dirty.bits,
                    **dirty.tags,
                )
            case "amd64g_dirtyhelper_OUT":
                if len(dirty.operands) != 3:
                    return None
                portno, data, size = dirty.operands
                if not isinstance(size, Const):
                    return None
                bits = size.value_int * self.arch.byte_width
                return Call(
                    dirty.idx,
                    target=f"__out{self._inout_intrinsic_suffix(bits)}",
                    calling_convention=None,
                    prototype=None,
                    args=(portno, data),
                    ret_expr=None,
                    bits=None,
                    **dirty.tags,
                )
        return None

    #
    # in, out
    #

    @staticmethod
    def _inout_intrinsic_suffix(bits: int) -> str:
        match bits:
            case 8:
                return "byte"
            case 16:
                return "word"
            case 32:
                return "dword"
            case _:
                return f"_{bits}"
