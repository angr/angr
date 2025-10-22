from __future__ import annotations
from typing import TYPE_CHECKING

from angr.ailment import AILBlockWalkerBase
from angr.ailment.block import Block
from angr.ailment.expression import Expression, Const, BinaryOp, Convert, VirtualVariable, Phi
from angr.ailment.statement import Assignment, Statement, ConditionalJump

if TYPE_CHECKING:
    from angr.analyses.s_reaching_definitions import SRDAModel


def is_phi_assignment(stmt: Statement) -> bool:
    return isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and isinstance(stmt.src, Phi)


class HasExprWalker(AILBlockWalkerBase):
    """
    Test if any expressions in exprs_to_check is used in another AIL expression.
    """

    def __init__(self, exprs_to_check: set[Expression]) -> None:
        super().__init__()

        self.exprs_to_check: set[Expression] = exprs_to_check
        self.contains_exprs: bool = False

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> None:
        if expr in self.exprs_to_check:
            self.contains_exprs = True
        if not self.contains_exprs:
            super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


def is_head_controlled_loop_block(block: Block) -> bool:
    """
    Determine if the block is a "head-controlled loop." A head-controlled loop (for the lack of a better term) is a
    single-block that contains a conditional jump towards the beginning of the block. This conditional jump controls
    whether the loop body (the remaining statements after the conditional jump) will be executed or not. It is usually
    the result of lifting rep stosX instructions on x86 and amd64.

    A head-controlled loop block looks like the following (lifted from rep stosq qword ptr [rdi], rax):

    ## Block 4036df
    00 | 0x4036df | LABEL_4036df:
    01 | 0x4036df | vvar_27{reg 72} = 𝜙@64b []
    02 | 0x4036df | vvar_28{reg 24} = 𝜙@64b []
    03 | 0x4036df | t1 = rcx<8>
    04 | 0x4036df | t4 = (t1 == 0x0<64>)
    05 | 0x4036df | if (t4) { Goto 0x4036e2<64> } else { Goto 0x4036df<64> }
    06 | 0x4036df | t5 = (t1 - 0x1<64>)
    07 | 0x4036df | rcx<8> = t5
    08 | 0x4036df | t7 = d<8>
    09 | 0x4036df | t6 = (t7 << 0x3<8>)
    10 | 0x4036df | t2 = rax<8>
    11 | 0x4036df | t3 = rdi<8>
    12 | 0x4036df | STORE(addr=t3, data=t2, size=8, endness=Iend_LE, guard=None)
    13 | 0x4036df | t8 = (t3 + t6)
    14 | 0x4036df | rdi<8> = t8

    Where statement 5 is the conditional jump that controls the execution of the remaining statements of this block.

    :param block:   An AIL block.
    :return:        True if the block represents a head-controlled loop block, False otherwise.
    """

    if not block.statements:
        return False
    last_stmt = block.statements[-1]
    if isinstance(last_stmt, ConditionalJump):
        return False
    return any(isinstance(stmt, ConditionalJump) for stmt in block.statements[:-1])


def extract_partial_expr(base_expr: Expression, off: int, size: int, ail_manager, byte_width: int = 8) -> Expression:
    bits = size * byte_width
    if off == 0 and bits == base_expr.bits:
        return base_expr
    if off * byte_width >= base_expr.bits:
        raise ValueError("Offset is greater than or equal to expression size")
    if base_expr.bits - off * byte_width < bits:
        raise ValueError("Insufficient expression bits")

    base_mask = ((1 << bits) - 1) << (off * byte_width)
    base_mask = Const(ail_manager.next_atom(), None, base_mask, base_expr.bits)
    masked_base_expr = BinaryOp(
        ail_manager.next_atom(),
        "And",
        [base_expr, base_mask],
        False,
        bits=base_expr.bits,
        **base_expr.tags,
    )
    if off > 0:
        shift_amount = Const(ail_manager.next_atom(), None, off * byte_width, byte_width)
        shifted_vvar = BinaryOp(
            ail_manager.next_atom(),
            "Shr",
            [
                masked_base_expr,
                shift_amount,
            ],
            bits=masked_base_expr.bits,
            **masked_base_expr.tags,
        )
    else:
        shifted_vvar = masked_base_expr
    truncated_expr = Convert(
        ail_manager.next_atom(),
        shifted_vvar.bits,
        bits,
        False,
        shifted_vvar,
        **shifted_vvar.tags,
    )
    assert truncated_expr.bits == bits
    return truncated_expr


def is_expr_used_as_reg_base_value(stmt: Statement, expr: Expression, srda: SRDAModel) -> bool:
    """
    Determine if the expression `expr` is used as the base value of an assignment of a full register in `stmt`.

    This method returns True if the following conditions hold:
    - The statement is an assignment to a reg vvar A;
    - The src of the assignment statement is a bitwise-or expression;
    - One of the operands of the src expr is the high bits of `expr`;
    - `expr` is a phi var that relies on reg vvar A.
    """

    if not isinstance(stmt, Assignment):
        return False
    if not isinstance(stmt.dst, VirtualVariable):
        return False
    if not stmt.dst.was_reg:
        return False
    if not isinstance(expr, VirtualVariable):
        return False
    if not expr.was_reg:
        return False
    if expr.varid not in srda.phivarid_to_varids:
        return False
    if stmt.dst.varid not in srda.phivarid_to_varids[expr.varid]:
        return False

    if not (isinstance(stmt.src, BinaryOp) and stmt.src.op == "Or"):
        return False

    for op0 in stmt.src.operands:
        op1 = stmt.src.operands[0] if op0 is stmt.src.operands[1] else stmt.src.operands[1]
        if (
            isinstance(op1, Convert)
            and op1.from_type == Convert.TYPE_INT
            and op1.to_type == Convert.TYPE_INT
            and op1.from_bits < op1.to_bits
        ):
            expected_mask = ((1 << op1.to_bits) - 1) ^ ((1 << op1.from_bits) - 1)
            if isinstance(op0, BinaryOp) and op0.op == "And":
                if (
                    isinstance(op0.operands[0], Const)
                    and op0.operands[0].value == expected_mask
                    and isinstance(op0.operands[1], VirtualVariable)
                    and op0.operands[1].varid == expr.varid
                ):
                    return True
                if (
                    isinstance(op0.operands[1], Const)
                    and op0.operands[1].value == expected_mask
                    and isinstance(op0.operands[0], VirtualVariable)
                    and op0.operands[0].varid == expr.varid
                ):
                    return True

    return False
