from __future__ import annotations

from angr.ailment import Const
from angr.ailment.statement import DirtyStatement, Statement, Call
from angr.ailment.expression import DirtyExpression, Expression
from .rewriter_base import DirtyRewriterBase


class AMD64DirtyRewriter(DirtyRewriterBase):
    """
    Rewrites AMD64 DirtyStatement and DirtyExpression.
    """

    __slots__ = ()

    def _rewrite_stmt(self, dirty: DirtyStatement) -> Statement | None:
        # TODO: Rewrite more dirty statements
        return None

    def _rewrite_expr(self, dirty: DirtyExpression) -> Expression | None:
        match dirty.callee:
            case "amd64g_dirtyhelper_IN":
                # in
                bits = (
                    dirty.operands[1].value * self.arch.byte_width
                    if len(dirty.operands) > 1 and isinstance(dirty.operands[1], Const)
                    else None
                )
                func_name = "__in"
                suffix = self._inout_intrinsic_suffix(bits) if bits is not None else None
                if suffix is not None:
                    func_name += f"{suffix}"
                else:
                    func_name += f"_{bits}"
                return Call(
                    dirty.idx, func_name, None, None, args=(dirty.operands[0],), ret_expr=None, bits=bits, **dirty.tags
                )
            case "amd64g_dirtyhelper_OUT":
                # out
                bits = (
                    dirty.operands[1].value * self.arch.byte_width
                    if len(dirty.operands) > 1 and isinstance(dirty.operands[1], Const)
                    else None
                )
                func_name = "__out"
                suffix = self._inout_intrinsic_suffix(bits) if bits is not None else None
                if suffix is not None:
                    func_name += f"{suffix}"
                else:
                    func_name += f"_{bits}"
                return Call(
                    dirty.idx, func_name, None, None, args=(dirty.operands[0],), ret_expr=None, bits=bits, **dirty.tags
                )
        return None

    #
    # in, out
    #

    @staticmethod
    def _inout_intrinsic_suffix(bits: int) -> str | None:
        match bits:
            case 8:
                return "byte"
            case 16:
                return "word"
            case 32:
                return "dword"
        return None
