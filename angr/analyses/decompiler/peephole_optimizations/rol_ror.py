from ailment.statement import Assignment
from ailment.expression import BinaryOp, Const, Tmp

from .base import PeepholeOptimizationStmtBase


class RolRorRewriter(PeepholeOptimizationStmtBase):
    """
    Rewrites consecutive statements into ROL (rotate shift left) or ROR (rotate shift right) statements.
    """

    __slots__ = ()

    NAME = "ROL/ROR rewriter"
    stmt_classes = (Assignment,)

    def optimize(self, stmt: Assignment, stmt_idx: int = None, block=None, **kwargs):
        # Rol example:
        #    61 | t304 = Shr32(t301,0x19)
        #    62 | t306 = Shl32(t301,0x07)
        #    63 | t303 = Or32(t306,t304)
        #
        # Ror example:
        #    98 | 0x140002a06 | t453 = (Conv(64->32, r9<8>) << 0x11<8>)
        #    99 | 0x140002a06 | t455 = (Conv(64->32, r9<8>) >> 0xf<8>)
        #    100 | 0x140002a06 | t452 = (t455 | t453)
        if stmt_idx < 2:
            return None
        if not (isinstance(stmt.src, BinaryOp) and stmt.src.op == "Or"):
            return None

        op0, op1 = stmt.src.operands
        if not (isinstance(op0, Tmp) and isinstance(op1, Tmp)):
            return None
        # check the previous two instructions
        stmt_1 = block.statements[stmt_idx - 1]
        stmt_2 = block.statements[stmt_idx - 2]
        if not (isinstance(stmt_1, Assignment) and isinstance(stmt_1.src, BinaryOp)):
            return None
        if not (isinstance(stmt_2, Assignment) and isinstance(stmt_2.src, BinaryOp)):
            return None

        if not isinstance(stmt_1.dst, Tmp):
            return None
        if not isinstance(stmt_2.dst, Tmp):
            return None

        if {stmt_1.dst.tmp_idx, stmt_2.dst.tmp_idx} != {op0.tmp_idx, op1.tmp_idx}:
            return None

        stmt1_op0, stmt1_op1 = stmt_1.src.operands
        stmt2_op0, stmt2_op1 = stmt_2.src.operands

        if not (stmt1_op0.likes(stmt2_op0)):
            return None

        if not (isinstance(stmt1_op1, Const) and isinstance(stmt2_op1, Const)):
            return None

        if stmt_1.src.op == "Shl" and stmt_2.src.op == "Shr" and stmt1_op1.value + stmt2_op1.value == stmt.dst.bits:
            new_stmt = Assignment(
                stmt.idx,
                stmt.dst,
                BinaryOp(None, "Rol", [stmt1_op0, stmt1_op1], False, bits=stmt.dst.bits, **stmt_1.src.tags),
                **stmt.tags,
            )
            return new_stmt
        elif stmt_1.src.op == "Shr" and stmt_2.src.op == "Shl" and stmt1_op1.value + stmt2_op1.value == stmt.dst.bits:
            new_stmt = Assignment(
                stmt.idx,
                stmt.dst,
                BinaryOp(None, "Ror", [stmt1_op0, stmt1_op1], False, bits=stmt.dst.bits, **stmt_1.src.tags),
                **stmt.tags,
            )
            return new_stmt

        return None
