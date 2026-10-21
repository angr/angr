from __future__ import annotations

from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, Convert
from angr.ailment.statement import ConditionalJump

from .base import PeepholeOptimizationStmtBase


class CmpORDRewriter(PeepholeOptimizationStmtBase):
    """
    Rewrites CmpORD expressions (PowerPC and VEX-specific) into common comparison operations.
    """

    __slots__ = ()

    NAME = "CmpORD rewriter"
    stmt_classes = (ConditionalJump,)

    def optimize(self, stmt: ConditionalJump, stmt_idx: int, block: Block, **kwargs):
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
        mask = cmp_lhs.operands[1].value
        if xor_value is not None and mask != xor_value:
            return None

        real_cmp = cmp_lhs.operands[0]
        while True:
            if (
                isinstance(real_cmp, Convert)
                and real_cmp.from_type == real_cmp.to_type == Convert.TYPE_INT
                and min(real_cmp.from_bits, real_cmp.to_bits) >= mask.bit_length()
            ):
                real_cmp = real_cmp.operand
            elif (
                isinstance(real_cmp, BinaryOp)
                and real_cmp.op == "And"
                and isinstance(real_cmp.operands[1], Const)
                and real_cmp.operands[1].value & mask == mask
            ):
                real_cmp = real_cmp.operands[0]
            else:
                break
        if not isinstance(real_cmp, BinaryOp) or real_cmp.op != "CmpORD":
            return None

        # determine the real comparison operator
        match mask:
            case 2:
                cmp_op = "CmpEQ" if not negated else "CmpNE"
            case 4:
                cmp_op = "CmpGT" if not negated else "CmpLE"
            case _:  # case 8
                cmp_op = "CmpLT" if not negated else "CmpGE"

        # generate the new comparison
        new_cond = BinaryOp(stmt.condition.idx, cmp_op, real_cmp.operands[::], real_cmp.signed, bits=1, **real_cmp.tags)
        return ConditionalJump(
            stmt.idx,
            new_cond,
            stmt.true_target,
            stmt.false_target,
            true_target_idx=stmt.true_target_idx,
            false_target_idx=stmt.false_target_idx,
            **stmt.tags,
        )
