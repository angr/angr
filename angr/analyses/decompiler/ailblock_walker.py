# pylint:disable=unused-argument
from typing import Dict, Type, Callable, Any, Optional

from ailment import Block
from ailment.statement import Call, Statement, ConditionalJump, Assignment, Store, Return
from ailment.expression import Load, Expression, BinaryOp, UnaryOp, Convert


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
            Return: self._handle_Return,
        }

        _default_expr_handlers = {
            Call: self._handle_CallExpr,
            Load: self._handle_Load,
            BinaryOp: self._handle_BinaryOp,
            UnaryOp: self._handle_UnaryOp,
            Convert: self._handle_Convert,
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

    def walk_expression(self, expr: Expression):
        self._handle_expr(0, expr, 0, None, None)

    def _handle_stmt(self, stmt_idx: int, stmt: Statement, block: Optional[Block]) -> Any:
        try:
            handler = self.stmt_handlers[type(stmt)]
        except KeyError:
            handler = None

        if handler:
            return handler(stmt_idx, stmt, block)
        return None

    def _handle_expr(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Optional[Statement],
                     block: Optional[Block]) -> Any:
        try:
            handler = self.expr_handlers[type(expr)]
        except KeyError:
            handler = None

        if handler:
            expr = handler(expr_idx, expr, stmt_idx, stmt, block)
            if expr is not None:
                r = self._handle_expr(expr_idx, expr, stmt_idx, stmt, block)
                return r if r is not None else expr
        return None

    #
    # Default handlers
    #

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Optional[Block]):
        changed = False

        dst = self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        if dst is not None and dst is not stmt.dst:
            changed = True
        else:
            dst = stmt.dst

        src = self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
        if src is not None and src is not stmt.src:
            changed = True
        else:
            src = stmt.src

        if changed:
            # update the statement directly in the block
            new_stmt = Assignment(stmt.idx, dst, src, **stmt.tags)
            block.statements[stmt_idx] = new_stmt

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Optional[Block]):
        if stmt.args:
            changed = False
            new_args = [ ]

            i = 0
            while i < len(stmt.args):
                arg = stmt.args[i]
                new_arg = self._handle_expr(i, arg, stmt_idx, stmt, block)
                if new_arg is not None and new_arg is not arg:
                    if not changed:
                        # initialize new_args
                        new_args = stmt.args[:i]
                    new_args.append(new_arg)
                    changed = True
                else:
                    if changed:
                        new_args.append(arg)
                i += 1

            if changed:
                new_stmt = Call(stmt.idx, stmt.target, calling_convention=stmt.calling_convention,
                                prototype=stmt.prototype, args=new_args, ret_expr=stmt.ret_expr,
                                **stmt.tags)
                block.statements[stmt_idx] = new_stmt

    def _handle_Store(self, stmt_idx: int, stmt: Store, block: Optional[Block]):

        changed = False

        addr = self._handle_expr(0, stmt.addr, stmt_idx, stmt, block)
        if addr is not None and addr is not stmt.addr:
            changed = True
        else:
            addr = stmt.addr

        data = self._handle_expr(1, stmt.data, stmt_idx, stmt, block)
        if data is not None and data is not stmt.data:
            changed = True
        else:
            data = stmt.data

        if changed:
            # update the statement directly in the block
            new_stmt = Store(stmt.idx, addr, data, stmt.size, stmt.endness, guard=stmt.guard, variable=stmt.variable,
                             offset=stmt.offset, **stmt.tags)
            block.statements[stmt_idx] = new_stmt

    def _handle_ConditionalJump(self, stmt_idx: int, stmt: ConditionalJump, block: Optional[Block]):

        changed = False

        condition = self._handle_expr(0, stmt.condition, stmt_idx, stmt, block)
        if condition is not None and condition is not stmt.condition:
            changed = True
        else:
            condition = stmt.condition

        true_target = self._handle_expr(1, stmt.true_target, stmt_idx, stmt, block)
        if true_target is not None and true_target is not stmt.true_target:
            changed = True
        else:
            true_target = stmt.true_target

        false_target = self._handle_expr(2, stmt.false_target, stmt_idx, stmt, block)
        if false_target is not None and false_target is not stmt.false_target:
            changed = True
        else:
            false_target = stmt.false_target

        if changed:
            new_stmt = ConditionalJump(stmt.idx, condition, true_target, false_target, **stmt.tags)
            block.statements[stmt_idx] = new_stmt

    def _handle_Return(self, stmt_idx: int, stmt: Return, block: Optional[Block]):
        if stmt.ret_exprs:
            i = 0
            while i < len(stmt.ret_exprs):
                self._handle_expr(i, stmt.ret_exprs[i], stmt_idx, stmt, block)
                i += 1

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement, block: Optional[Block]):
        addr = self._handle_expr(0, expr.addr, stmt_idx, stmt, block)

        if addr is not None and addr is not expr.addr:
            new_expr = expr.copy()
            new_expr.addr = addr
            return new_expr
        return None

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Optional[Block]):

        changed = False

        if expr.args:
            i = 0
            new_args = [ ]
            while i < len(expr.args):
                arg = expr.args[i]
                new_arg = self._handle_expr(i, arg, stmt_idx, stmt, block)
                if new_arg is not None and new_arg is not arg:
                    if not changed:
                        # initialize new_args
                        new_args = expr.args[:i]
                    new_args.append(new_arg)
                    changed = True
                else:
                    if changed:
                        new_args.append(arg)
                i += 1

            if changed:
                expr = expr.copy()
                expr.args = new_args
                return expr

        return None

    def _handle_BinaryOp(self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement, block: Optional[Block]):
        changed = False

        operand_0 = self._handle_expr(0, expr.operands[0], stmt_idx, stmt, block)
        if operand_0 is not None and operand_0 is not expr.operands[0]:
            changed = True
        else:
            operand_0 = expr.operands[0]

        operand_1 = self._handle_expr(1, expr.operands[1], stmt_idx, stmt, block)
        if operand_1 is not None and operand_1 is not expr.operands[1]:
            changed = True
        else:
            operand_1 = expr.operands[1]

        if changed:
            new_expr = expr.copy()
            new_expr.operands = (operand_0, operand_1)
            return new_expr
        return None

    def _handle_UnaryOp(self, expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt: Statement, block: Optional[Block]):
        new_operand = self._handle_expr(0, expr.operand, stmt_idx, stmt, block)
        if new_operand is not None and new_operand is not expr.operand:
            new_expr = expr.copy()
            new_expr.operand = new_operand
            return new_expr
        return None

    def _handle_Convert(self, expr_idx: int, expr: Convert, stmt_idx: int, stmt: Statement, block: Optional[Block]):
        new_operand = self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block)
        if new_operand is not None and new_operand is not expr.operand:
            return Convert(expr.idx, expr.from_bits, expr.to_bits, expr.is_signed, new_operand, **expr.tags)
        return None
