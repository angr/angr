# pylint:disable=unused-argument
from typing import Dict, Type, Callable, Any, Optional

from ailment import Block
from ailment.statement import Call, Statement, ConditionalJump, Assignment, Store
from ailment.expression import Load, Expression, BinaryOp, UnaryOp


class AILBlockWalker:
    """
    Walks all statements and expressions of an AIL node.
    """
    def __init__(self, stmt_handlers=None, expr_handlers=None):

        _default_stmt_handlers = {
            Assignment: self._handle_Assignment,
            Call: self._handle_Call,
            Store: self._handle_Store,
            ConditionalJump: self._handle_ConditionalJump,
        }

        _default_expr_handlers = {
            Call: self._handle_CallExpr,
            Load: self._handle_Load,
            BinaryOp: self._handle_BinaryOp,
            UnaryOp: self._handle_UnaryOp,
        }

        self.stmt_handlers: Dict[Type, Callable] = stmt_handlers if stmt_handlers else _default_stmt_handlers
        self.expr_handlers: Dict[Type, Callable] = expr_handlers if expr_handlers else _default_expr_handlers

    def walk(self, block: Block):
        i = 0
        while i < len(block.statements):
            stmt = block.statements[i]
            self._handle_stmt(i, stmt, block)
            i += 1

    def walk_statement(self, stmt: Statement):
        self._handle_stmt(0, stmt, None)

    def _handle_stmt(self, stmt_idx: int, stmt: Statement, block: Optional[Block]) -> Any:
        try:
            handler = self.stmt_handlers[type(stmt)]
        except KeyError:
            handler = None

        if handler:
            return handler(stmt_idx, stmt, block)
        return None

    def _handle_expr(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement,
                     block: Optional[Block]) -> Any:
        try:
            handler = self.expr_handlers[type(expr)]
        except KeyError:
            handler = None

        if handler:
            return handler(expr_idx, expr, stmt_idx, stmt, block)
        return None

    #
    # Default handlers
    #

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Optional[Block]):

        self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Optional[Block]):
        if stmt.args:
            i = 0
            while i < len(stmt.args):
                arg = stmt.args[i]
                self._handle_expr(i, arg, stmt_idx, stmt, block)
                i += 1

    def _handle_Store(self, stmt_idx: int, stmt: Store, block: Optional[Block]):
        self._handle_expr(0, stmt.addr, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.data, stmt_idx, stmt, block)

    def _handle_ConditionalJump(self, stmt_idx: int, stmt: ConditionalJump, block: Optional[Block]):
        self._handle_expr(0, stmt.condition, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.true_target, stmt_idx, stmt, block)
        self._handle_expr(2, stmt.false_target, stmt_idx, stmt, block)

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement, block: Optional[Block]):
        return self._handle_expr(0, expr.addr, stmt_idx, stmt, block)

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Optional[Block]):
        if expr.args:
            i = 0
            while i < len(expr.args):
                arg = expr.args[i]
                self._handle_expr(i, arg, stmt_idx, stmt, block)
                i += 1

    def _handle_BinaryOp(self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement, block: Optional[Block]):
        self._handle_expr(0, expr.operands[0], stmt_idx, stmt, block)
        self._handle_expr(1, expr.operands[1], stmt_idx, stmt, block)

    def _handle_UnaryOp(self, expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt: Statement, block: Optional[Block]):
        self._handle_expr(0, expr.operands[0], stmt_idx, stmt, block)
