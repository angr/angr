from __future__ import annotations

from angr.ailment.statement import DirtyStatement, Statement, CallStmt
from angr.ailment.expression import CallExpr, Const, DirtyExpression, Expression
from .rewriter_base import DirtyRewriterBase


class AMD64DirtyRewriter(DirtyRewriterBase):
    """
    Rewrites AMD64 DirtyStatement and DirtyExpression.
    """

    __slots__ = ()

    def _rewrite_stmt(self, dirty: DirtyStatement) -> Statement | None:
        # TODO: Rewrite more dirty statements
        match dirty.dirty.callee:
            case "amd64g_dirtyhelper_IN":
                if len(dirty.dirty.operands) != 2:
                    return None
                portno, size = dirty.dirty.operands
                if not isinstance(size, Const):
                    return None
                bits = size.value_int * self.arch.byte_width
                return CallStmt(
                    idx=dirty.idx,
                    target=f"__in{self._inout_intrinsic_suffix(bits)}",
                    calling_convention=None,
                    prototype=None,
                    args=(portno,),
                    bits=dirty.bits,
                    **dirty.tags,
                )
            case "amd64g_dirtyhelper_OUT":
                if len(dirty.dirty.operands) != 3:
                    return None
                portno, data, size = dirty.dirty.operands
                if not isinstance(size, Const):
                    return None
                bits = size.value_int * self.arch.byte_width
                return CallStmt(
                    dirty.dirty.idx,
                    target=f"__out{self._inout_intrinsic_suffix(bits)}",
                    calling_convention=None,
                    prototype=None,
                    args=(portno, data),
                    bits=None,
                    **dirty.tags,
                )
        return None

    def _rewrite_expr(self, dirty: DirtyExpression) -> Expression | None:
        match dirty.callee:
            case "amd64g_dirtyhelper_IN":
                if len(dirty.operands) != 2:
                    return None
                portno, size = dirty.operands
                if not isinstance(size, Const):
                    return None
                bits = size.value_int * self.arch.byte_width
                return CallExpr(
                    idx=dirty.idx,
                    target=f"__in{self._inout_intrinsic_suffix(bits)}",
                    calling_convention=None,
                    prototype=None,
                    args=(portno,),
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
                return CallExpr(
                    dirty.idx,
                    target=f"__out{self._inout_intrinsic_suffix(bits)}",
                    calling_convention=None,
                    prototype=None,
                    args=(portno, data),
                    bits=None,
                    **dirty.tags,
                )
        return None

    def _rewrite_expr_to_call(self, dirty: DirtyExpression) -> CallExpr | None:
        match dirty.callee:
            case "amd64g_dirtyhelper_IN":
                if len(dirty.operands) != 2:
                    return None
                portno, size = dirty.operands
                if not isinstance(size, Const):
                    return None
                bits = size.value_int * self.arch.byte_width
                return CallExpr(
                    idx=dirty.idx,
                    target=f"__in{self._inout_intrinsic_suffix(bits)}",
                    calling_convention=None,
                    prototype=None,
                    args=(portno,),
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
                return CallExpr(
                    dirty.idx,
                    target=f"__out{self._inout_intrinsic_suffix(bits)}",
                    calling_convention=None,
                    prototype=None,
                    args=(portno, data),
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
