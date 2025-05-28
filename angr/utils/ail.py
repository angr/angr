from __future__ import annotations

from angr.ailment import AILBlockWalkerBase
from angr.ailment.block import Block
from angr.ailment.expression import Expression, VirtualVariable, Phi
from angr.ailment.statement import Assignment, Statement, ConditionalJump


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
