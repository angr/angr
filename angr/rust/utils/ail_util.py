from typing import Any, Tuple

from ailment import Block, AILBlockWalker, Expression, UnaryOp, BinaryOp, Const
from ailment.expression import VirtualVariable
from ailment.statement import Call, Statement


class CallFinder(AILBlockWalker):
    def __init__(self):
        super().__init__()
        self.call = None

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
        super()._handle_Call(stmt_idx, stmt, block)
        if not self.call:
            self.call = stmt

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        super()._handle_CallExpr(expr_idx, expr, stmt_idx, stmt, block)
        if not self.call:
            self.call = expr


def get_terminal_call(block: Block):
    if block.statements:
        terminal = block.statements[-1]
        if isinstance(terminal, Call):
            return terminal
        finder = CallFinder()
        finder.walk_statement(terminal)
        return finder.call
    return None


def unwrap_stack_vvar_reference(expr) -> VirtualVariable | None:
    if (
        isinstance(expr, UnaryOp)
        and expr.op == "Reference"
        and isinstance(expr.operand, VirtualVariable)
        and expr.operand.was_stack
    ):
        return expr.operand
    return None


def unwrap_combo_reg_vvar_reference(expr) -> VirtualVariable | None:
    if (
        isinstance(expr, UnaryOp)
        and expr.op == "Reference"
        and isinstance(expr.operand, VirtualVariable)
        and expr.operand.was_combo_reg
    ):
        return expr.operand
    return None


def extract_vvar_and_offset(expr) -> Tuple[VirtualVariable, int] | Tuple[None, None]:
    if isinstance(expr, VirtualVariable):
        return expr, 0
    if (
        isinstance(expr, BinaryOp)
        and isinstance(expr.operands[0], VirtualVariable)
        and isinstance(expr.operands[1], Const)
    ):
        return expr.operands[0], expr.operands[1].value
    return None, None


def unwrap_stack_vvar_reference_with_offset(expr) -> Tuple[VirtualVariable, int] | Tuple[None, None]:
    if isinstance(expr, UnaryOp) and expr.op == "Reference":
        if isinstance(expr.operand, VirtualVariable) and expr.operand.was_stack:
            return expr.operand, 0
        elif (
            isinstance(expr.operand, BinaryOp)
            and expr.op == "Add"
            and isinstance(expr.operand.operands[0], VirtualVariable)
            and expr.operand.operands[0].was_stack
            and isinstance(expr.operand.operands[1], Const)
        ):
            return expr.operand.operands[0], expr.operand.operands[1].value
    return None, None
