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
        return self._rewrite_expr_to_call(dirty.dirty)

    def _rewrite_expr(self, dirty: DirtyExpression) -> Expression | None:
        return self._rewrite_expr_to_call(dirty)

    def _rewrite_expr_to_call(self, dirty: DirtyExpression) -> Call | None:
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
                portno = dirty.operands[0]
                data = dirty.operands[1]
                size = dirty.operands[2]
                bits = size.value * self.arch.byte_width
                func_name = "__out"
                suffix = self._inout_intrinsic_suffix(bits)
                if suffix is not None:
                    func_name += f"{suffix}"
                else:
                    func_name += f"_{bits}"
                return Call(
                    dirty.idx, func_name, None, None, args=(portno, data), ret_expr=None, bits=bits, **dirty.tags
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
