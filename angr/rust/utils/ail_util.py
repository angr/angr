from typing import Any

from ailment import Block, AILBlockWalker, Expression, UnaryOp
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
