from typing import Optional

from ailment import Expr

from angr.engines.vex.claripy.ccall import data
from .rewriter_base import CCallRewriterBase


AMD64_CondTypes = data['AMD64']['CondTypes']
AMD64_OpTypes = data['AMD64']['OpTypes']


class AMD64CCallRewriter(CCallRewriterBase):
    """
    Implements ccall rewriter for AMD64.
    """

    __slots__ = ()

    def _rewrite(self, ccall: Expr.VEXCCallExpression) -> Optional[Expr.Expression]:
        if ccall.cee_name == "amd64g_calculate_condition":
            cond = ccall.operands[0]
            op = ccall.operands[1]
            dep_1 = ccall.operands[2]
            dep_2 = ccall.operands[3]
            if isinstance(cond, Expr.Const) and isinstance(op, Expr.Const):
                cond_v = cond.value
                op_v = op.value
                if cond_v == AMD64_CondTypes['CondLE'] and op_v == AMD64_OpTypes['G_CC_OP_SUBL']:
                    # dep_1 <=s dep_2
                    return Expr.BinaryOp(ccall.idx, "CmpLE",
                                         (dep_1, dep_2),
                                         True,
                                         **ccall.tags)
                if cond_v == AMD64_CondTypes['CondLE'] and op_v == AMD64_OpTypes['G_CC_OP_SUBB']:
                    # dep_1 <=s dep_2
                    return Expr.BinaryOp(ccall.idx, "CmpLE",
                                         (dep_1, dep_2),
                                         True,
                                         **ccall.tags)

        return None
