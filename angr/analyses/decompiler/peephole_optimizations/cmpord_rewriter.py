from ailment.statement import ConditionalJump
from ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationStmtBase


class CmpORDRewriter(PeepholeOptimizationStmtBase):
    """
    Rewrites CmpORD expressions (PowerPC and VEX-specific) into common comparison operations.
    """

    __slots__ = ()

    NAME = "CmpORD rewriter"
    stmt_classes = (ConditionalJump,)

    def optimize(self, stmt: ConditionalJump, stmt_idx: int = None, block=None, **kwargs):
        # example:
        # 05 | 0x4011d4 | if ((((gpr9<4> CmpORD 0x0<32>) & 0x2<32>) != 0x0<32>)) { Goto ... } else { Goto ... }
        # or
        # 02 | 0x401260 | if (((((gpr3<4> CmpORD 0x0<32>) & 0x2<32>) ^ 0x2<32>) != 0x0<32>)) { Goto ... } else
        #                   { Goto ... }

        if not isinstance(stmt.condition, BinaryOp) or stmt.condition.op not in {"CmpNE", "CmpEQ"}:
            return None
        cmp_rhs = stmt.condition.operands[1]
        if not isinstance(cmp_rhs, Const) or cmp_rhs.value != 0:
            return None
        negated = stmt.condition.op == "CmpEQ"

        cmp_lhs = stmt.condition.operands[0]
        xor_value = None
        if isinstance(cmp_lhs, BinaryOp) and cmp_lhs.op == "Xor" and isinstance(cmp_lhs.operands[1], Const):
            negated = not negated
            xor_value = cmp_lhs.operands[1].value
            # unpack
            cmp_lhs = cmp_lhs.operands[0]

        if not isinstance(cmp_lhs, BinaryOp) or cmp_lhs.op != "And":
            return None

        if not isinstance(cmp_lhs.operands[1], Const) or cmp_lhs.operands[1].value not in {2, 4, 8}:
            return None
        if xor_value is not None and cmp_lhs.operands[1].value != xor_value:
            return None

        real_cmp = cmp_lhs.operands[0]
        if not isinstance(real_cmp, BinaryOp) or real_cmp.op != "CmpORD":
            return None

        # determine the real comparison operator
        match cmp_lhs.operands[1].value:
            case 2:
                cmp_op = "CmpEQ" if not negated else "CmpNE"
            case 4:
                cmp_op = "CmpGE" if not negated else "CmpLT"
            case _:  # case 8
                cmp_op = "CmpLT" if not negated else "CmpGE"

        # generate the new comparison
        new_cond = BinaryOp(stmt.condition.idx, cmp_op, real_cmp.operands[::], real_cmp.signed, **real_cmp.tags)
        new_stmt = ConditionalJump(
            stmt.idx,
            new_cond,
            stmt.true_target,
            stmt.false_target,
            stmt.true_target_idx,
            stmt.false_target_idx,
            **stmt.tags,
        )

        return new_stmt
