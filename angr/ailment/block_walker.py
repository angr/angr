# pylint:disable=unused-argument,no-self-use
# pyright: reportIncompatibleMethodOverride=false
from __future__ import annotations
from typing import Any
from collections.abc import Callable

from . import Block
from .statement import (
    Call,
    CAS,
    Statement,
    ConditionalJump,
    Assignment,
    Store,
    Return,
    Jump,
    DirtyStatement,
    WeakAssignment,
)
from .expression import (
    Load,
    Expression,
    BinaryOp,
    UnaryOp,
    Convert,
    ITE,
    DirtyExpression,
    VEXCCallExpression,
    Tmp,
    Register,
    Const,
    Reinterpret,
    MultiStatementExpression,
    VirtualVariable,
    Phi,
)


class AILBlockWalkerBase:
    """
    Walks all statements and expressions of an AIL node and do nothing.
    """

    def __init__(self, stmt_handlers=None, expr_handlers=None):
        _default_stmt_handlers = {
            Assignment: self._handle_Assignment,
            WeakAssignment: self._handle_WeakAssignment,
            CAS: self._handle_CAS,
            Call: self._handle_Call,
            Store: self._handle_Store,
            ConditionalJump: self._handle_ConditionalJump,
            Jump: self._handle_Jump,
            Return: self._handle_Return,
            DirtyStatement: self._handle_DirtyStatement,
        }

        _default_expr_handlers = {
            Call: self._handle_CallExpr,
            Load: self._handle_Load,
            BinaryOp: self._handle_BinaryOp,
            UnaryOp: self._handle_UnaryOp,
            Convert: self._handle_Convert,
            ITE: self._handle_ITE,
            DirtyExpression: self._handle_DirtyExpression,
            VEXCCallExpression: self._handle_VEXCCallExpression,
            Tmp: self._handle_Tmp,
            Register: self._handle_Register,
            Reinterpret: self._handle_Reinterpret,
            Const: self._handle_Const,
            MultiStatementExpression: self._handle_MultiStatementExpression,
            VirtualVariable: self._handle_VirtualVariable,
            Phi: self._handle_Phi,
        }

        self.stmt_handlers: dict[type, Callable] = stmt_handlers if stmt_handlers else _default_stmt_handlers
        self.expr_handlers: dict[type, Callable] = expr_handlers if expr_handlers else _default_expr_handlers

    def walk(self, block: Block) -> None:
        i = 0
        while i < len(block.statements):
            stmt = block.statements[i]
            self._handle_stmt(i, stmt, block)
            i += 1

    def walk_statement(self, stmt: Statement, block: Block | None = None):
        return self._handle_stmt(0, stmt, block)

    def walk_expression(
        self,
        expr: Expression,
        stmt_idx: int | None = None,
        stmt: Statement | None = None,
        block: Block | None = None,
    ):
        return self._handle_expr(0, expr, stmt_idx or 0, stmt, block)

    def _handle_stmt(self, stmt_idx: int, stmt: Statement, block: Block | None) -> Any:
        try:
            handler = self.stmt_handlers[type(stmt)]
        except KeyError:
            handler = None

        if handler:
            return handler(stmt_idx, stmt, block)
        return None

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Any:
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

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Block | None):
        self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)

    def _handle_WeakAssignment(self, stmt_idx: int, stmt: WeakAssignment, block: Block | None):
        self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)

    def _handle_CAS(self, stmt_idx: int, stmt: CAS, block: Block | None):
        self._handle_expr(0, stmt.addr, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.data_lo, stmt_idx, stmt, block)
        if stmt.data_hi is not None:
            self._handle_expr(2, stmt.data_hi, stmt_idx, stmt, block)
        self._handle_expr(3, stmt.expd_lo, stmt_idx, stmt, block)
        if stmt.expd_hi is not None:
            self._handle_expr(4, stmt.expd_hi, stmt_idx, stmt, block)
        self._handle_expr(5, stmt.old_lo, stmt_idx, stmt, block)
        if stmt.old_hi is not None:
            self._handle_expr(6, stmt.old_hi, stmt_idx, stmt, block)

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
        if not isinstance(stmt.target, str):
            self._handle_expr(-1, stmt.target, stmt_idx, stmt, block)
        if stmt.args:
            for i, arg in enumerate(stmt.args):
                self._handle_expr(i, arg, stmt_idx, stmt, block)

    def _handle_Store(self, stmt_idx: int, stmt: Store, block: Block | None):
        self._handle_expr(0, stmt.addr, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.data, stmt_idx, stmt, block)
        if stmt.guard is not None:
            self._handle_expr(2, stmt.guard, stmt_idx, stmt, block)

    def _handle_Jump(self, stmt_idx: int, stmt: Jump, block: Block | None):
        self._handle_expr(0, stmt.target, stmt_idx, stmt, block)

    def _handle_ConditionalJump(self, stmt_idx: int, stmt: ConditionalJump, block: Block | None):
        self._handle_expr(0, stmt.condition, stmt_idx, stmt, block)
        if stmt.true_target is not None:
            self._handle_expr(1, stmt.true_target, stmt_idx, stmt, block)
        if stmt.false_target is not None:
            self._handle_expr(2, stmt.false_target, stmt_idx, stmt, block)

    def _handle_Return(self, stmt_idx: int, stmt: Return, block: Block | None):
        if stmt.ret_exprs:
            for i, ret_expr in enumerate(stmt.ret_exprs):
                self._handle_expr(i, ret_expr, stmt_idx, stmt, block)

    def _handle_DirtyStatement(self, stmt_idx: int, stmt: DirtyStatement, block: Block | None):
        self._handle_expr(0, stmt.dirty, stmt_idx, stmt, block)

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement, block: Block | None):
        self._handle_expr(0, expr.addr, stmt_idx, stmt, block)

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        if not isinstance(expr.target, str):
            self._handle_expr(-1, expr.target, stmt_idx, stmt, block)
        if expr.args:
            for i, arg in enumerate(expr.args):
                self._handle_expr(i, arg, stmt_idx, stmt, block)

    def _handle_BinaryOp(self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement, block: Block | None):
        self._handle_expr(0, expr.operands[0], stmt_idx, stmt, block)
        self._handle_expr(1, expr.operands[1], stmt_idx, stmt, block)

    def _handle_UnaryOp(self, expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt: Statement, block: Block | None):
        self._handle_expr(0, expr.operand, stmt_idx, stmt, block)

    def _handle_Convert(self, expr_idx: int, expr: Convert, stmt_idx: int, stmt: Statement, block: Block | None):
        self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block)

    def _handle_Reinterpret(
        self, expr_idx: int, expr: Reinterpret, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block)

    def _handle_ITE(self, expr_idx: int, expr: ITE, stmt_idx: int, stmt: Statement, block: Block | None):
        self._handle_expr(0, expr.cond, stmt_idx, stmt, block)
        self._handle_expr(1, expr.iftrue, stmt_idx, stmt, block)
        self._handle_expr(2, expr.iffalse, stmt_idx, stmt, block)

    def _handle_Tmp(self, expr_idx: int, expr: Tmp, stmt_idx: int, stmt: Statement, block: Block | None):
        pass

    def _handle_Register(self, expr_idx: int, expr: Register, stmt_idx: int, stmt: Statement, block: Block | None):
        pass

    def _handle_Const(self, expr_idx: int, expr: Const, stmt_idx: int, stmt: Statement, block: Block | None):
        pass

    def _handle_VirtualVariable(
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        pass

    def _handle_Phi(self, expr_id: int, expr: Phi, stmt_idx: int, stmt: Statement, block: Block | None):
        for idx, (_, vvar) in enumerate(expr.src_and_vvars):
            if vvar is not None:
                self._handle_expr(idx, vvar, stmt_idx, stmt, block)

    def _handle_MultiStatementExpression(
        self, expr_idx, expr: MultiStatementExpression, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        for idx, stmt_ in enumerate(expr.stmts):
            self._handle_stmt(idx, stmt_, None)
        self._handle_expr(0, expr.expr, stmt_idx, stmt, block)

    def _handle_DirtyExpression(
        self, expr_idx: int, expr: DirtyExpression, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        for idx, operand in enumerate(expr.operands):
            self._handle_expr(idx, operand, stmt_idx, stmt, block)
        if expr.guard is not None:
            self._handle_expr(len(expr.operands) + 1, expr.guard, stmt_idx, stmt, block)

    def _handle_VEXCCallExpression(
        self, expr_idx: int, expr: VEXCCallExpression, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        for idx, operand in enumerate(expr.operands):
            self._handle_expr(idx, operand, stmt_idx, stmt, block)


class AILBlockWalker(AILBlockWalkerBase):
    """
    Walks all statements and expressions of an AIL node, and rebuilds expressions, statements, or blocks if needed.

    If you need a pure walker without rebuilding, use AILBlockWalkerBase instead.

    :ivar update_block: True if the block should be updated in place, False if a new block should be created and
                        returned as the result of walk().
    :ivar replace_phi_stmt: True if you want _handle_Phi be called and vvars potentially replaced; False otherwise.
                            Default to False because in the most majority cases you do not want vvars in a Phi
                            variable be replaced.
    """

    def __init__(
        self, stmt_handlers=None, expr_handlers=None, update_block: bool = True, replace_phi_stmt: bool = False
    ):
        super().__init__(stmt_handlers=stmt_handlers, expr_handlers=expr_handlers)
        self._update_block = update_block
        self._replace_phi_stmt = replace_phi_stmt

    def walk(self, block: Block) -> Block | None:
        """
        Walk the block and rebuild it if necessary. The block will be rebuilt in-place (by updating statements in the
        original block when self._update_block is set to True), or a new block will be created and returned.

        :param block:   The block to walk.
        :return:        The new block that is rebuilt, or None if the block is not changed or when self._update_block
                        is set to True.
        """

        changed = False
        new_block: Block | None = None

        i = 0
        while i < len(block.statements):
            stmt = block.statements[i]
            new_stmt = self._handle_stmt(i, stmt, block)
            if new_stmt is not None:
                changed = True
                if not self._update_block:
                    if new_block is None:
                        new_block = block.copy(statements=block.statements[:i])
                    new_block.statements.append(new_stmt)
            else:
                if new_block is not None:
                    new_block.statements.append(stmt)
            i += 1

        return new_block if changed else None

    def _handle_stmt(self, stmt_idx: int, stmt: Statement, block: Block | None) -> Any:
        try:
            handler = self.stmt_handlers[type(stmt)]
        except KeyError:
            handler = None

        if handler:
            return handler(stmt_idx, stmt, block)
        return None

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Any:
        try:
            handler = self.expr_handlers[type(expr)]
        except KeyError:
            handler = None

        if handler:
            expr = handler(expr_idx, expr, stmt_idx, stmt, block)
            if expr is not None:
                r = self._handle_expr(expr_idx, expr, stmt_idx, stmt, block)
                return r if r is not None else expr
        return None  # unchanged

    #
    # Default handlers
    #

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Block | None) -> Assignment | None:
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
            if self._update_block and block is not None:
                block.statements[stmt_idx] = new_stmt
            return new_stmt
        return None

    def _handle_WeakAssignment(self, stmt_idx: int, stmt: WeakAssignment, block: Block | None) -> WeakAssignment | None:
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
            new_stmt = WeakAssignment(stmt.idx, dst, src, **stmt.tags)
            if self._update_block and block is not None:
                block.statements[stmt_idx] = new_stmt
            return new_stmt
        return None

    def _handle_CAS(self, stmt_idx: int, stmt: CAS, block: Block | None) -> CAS | None:
        changed = False

        addr = self._handle_expr(0, stmt.addr, stmt_idx, stmt, block)
        if addr is not None and addr is not stmt.addr:
            changed = True
        else:
            addr = stmt.addr

        data_lo = self._handle_expr(1, stmt.data_lo, stmt_idx, stmt, block)
        if data_lo is not None and data_lo is not stmt.data_lo:
            changed = True
        else:
            data_lo = stmt.data_lo

        data_hi = None
        if stmt.data_hi is not None:
            data_hi = self._handle_expr(2, stmt.data_hi, stmt_idx, stmt, block)
            if data_hi is not None and data_hi is not stmt.data_hi:
                changed = True
            else:
                data_hi = stmt.data_hi

        expd_lo = self._handle_expr(3, stmt.expd_lo, stmt_idx, stmt, block)
        if expd_lo is not None and expd_lo is not stmt.expd_lo:
            changed = True
        else:
            expd_lo = stmt.expd_lo

        expd_hi = None
        if stmt.expd_hi is not None:
            expd_hi = self._handle_expr(4, stmt.expd_hi, stmt_idx, stmt, block)
            if expd_hi is not None and expd_hi is not stmt.expd_hi:
                changed = True
            else:
                expd_hi = stmt.expd_hi

        old_lo = self._handle_expr(5, stmt.old_lo, stmt_idx, stmt, block)
        if old_lo is not None and old_lo is not stmt.old_lo:
            changed = True
        else:
            old_lo = stmt.old_lo

        old_hi = None
        if stmt.old_hi is not None:
            old_hi = self._handle_expr(6, stmt.old_hi, stmt_idx, stmt, block)
            if old_hi is not None and old_hi is not stmt.old_hi:
                changed = True
            else:
                old_hi = stmt.old_hi

        if changed:
            # update the statement directly in the block
            new_stmt = CAS(
                stmt.idx,
                addr,
                data_lo,
                data_hi,
                expd_lo,
                expd_hi,
                old_lo,
                old_hi,
                stmt.endness,
                **stmt.tags,
            )
            if self._update_block and block is not None:
                block.statements[stmt_idx] = new_stmt
            return new_stmt
        return None

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
        changed = False

        if isinstance(stmt.target, str):
            new_target = None
        else:
            new_target = self._handle_expr(-1, stmt.target, stmt_idx, stmt, block)
            if new_target is not None and new_target is not stmt.target:
                changed = True

        new_args = None
        if stmt.args is not None:
            new_args = []

            i = 0
            while i < len(stmt.args):
                arg = stmt.args[i]
                new_arg = self._handle_expr(i, arg, stmt_idx, stmt, block)
                if new_arg is not None and new_arg is not arg:
                    if not changed:
                        # initialize new_args
                        new_args = list(stmt.args[:i])
                    new_args.append(new_arg)
                    changed = True
                else:
                    if changed:
                        new_args.append(arg)
                i += 1

        if changed:
            new_stmt = Call(
                stmt.idx,
                new_target if new_target is not None else stmt.target,
                calling_convention=stmt.calling_convention,
                prototype=stmt.prototype,
                args=new_args,
                ret_expr=stmt.ret_expr,
                **stmt.tags,
            )
            if self._update_block and block is not None:
                block.statements[stmt_idx] = new_stmt
            return new_stmt
        return None

    def _handle_Store(self, stmt_idx: int, stmt: Store, block: Block | None):
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

        guard = None if stmt.guard is None else self._handle_expr(2, stmt.guard, stmt_idx, stmt, block)
        if guard is not None and guard is not stmt.guard:
            changed = True
        else:
            guard = stmt.guard

        if changed:
            # update the statement directly in the block
            new_stmt = Store(
                stmt.idx,
                addr,
                data,
                stmt.size,
                stmt.endness,
                guard=guard,
                variable=stmt.variable,
                offset=stmt.offset,
                **stmt.tags,
            )
            if self._update_block and block is not None:
                block.statements[stmt_idx] = new_stmt
            return new_stmt
        return None

    def _handle_Jump(self, stmt_idx: int, stmt: Jump, block: Block | None):
        changed = False

        target = self._handle_expr(0, stmt.target, stmt_idx, stmt, block)
        if target is not None and target is not stmt.target:
            changed = True
        else:
            target = stmt.target

        if changed:
            new_stmt = Jump(
                stmt.idx,
                target,
                target_idx=stmt.target_idx,
                **stmt.tags,
            )
            if self._update_block and block is not None:
                block.statements[stmt_idx] = new_stmt
            return new_stmt
        return None

    def _handle_ConditionalJump(self, stmt_idx: int, stmt: ConditionalJump, block: Block | None):
        changed = False

        condition = self._handle_expr(0, stmt.condition, stmt_idx, stmt, block)
        if condition is not None and condition is not stmt.condition:
            changed = True
        else:
            condition = stmt.condition

        true_target = None
        if stmt.true_target is not None:
            true_target = self._handle_expr(1, stmt.true_target, stmt_idx, stmt, block)
            if true_target is not None and true_target is not stmt.true_target:
                changed = True
            else:
                true_target = stmt.true_target

        false_target = None
        if stmt.false_target is not None:
            false_target = self._handle_expr(2, stmt.false_target, stmt_idx, stmt, block)
            if false_target is not None and false_target is not stmt.false_target:
                changed = True
            else:
                false_target = stmt.false_target

        if changed:
            new_stmt = ConditionalJump(
                stmt.idx,
                condition,
                true_target,
                false_target,
                true_target_idx=stmt.true_target_idx,
                false_target_idx=stmt.false_target_idx,
                **stmt.tags,
            )
            if self._update_block and block is not None:
                block.statements[stmt_idx] = new_stmt
            return new_stmt
        return None

    def _handle_Return(self, stmt_idx: int, stmt: Return, block: Block | None):
        if stmt.ret_exprs:
            i = 0
            changed = False
            new_ret_exprs = [None] * len(stmt.ret_exprs)
            while i < len(stmt.ret_exprs):
                new_ret_expr = self._handle_expr(i, stmt.ret_exprs[i], stmt_idx, stmt, block)
                if new_ret_expr is not None:
                    new_ret_exprs[i] = new_ret_expr
                    changed = True
                else:
                    new_ret_exprs[i] = stmt.ret_exprs[i]
                i += 1

            if changed:
                new_stmt = Return(stmt.idx, new_ret_exprs, **stmt.tags)
                if self._update_block and block is not None:
                    block.statements[stmt_idx] = new_stmt
                return new_stmt
        return None

    def _handle_DirtyStatement(self, stmt_idx: int, stmt: DirtyStatement, block: Block | None):
        changed = False

        dirty = self._handle_expr(0, stmt.dirty, stmt_idx, stmt, block)
        if dirty is not None and dirty is not stmt.dirty:
            changed = True
        else:
            dirty = stmt.dirty

        if changed:
            new_stmt = DirtyStatement(stmt.idx, dirty, **stmt.tags)
            if self._update_block and block is not None:
                block.statements[stmt_idx] = new_stmt
            return new_stmt
        return None

    #
    # Expression handlers
    #

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement, block: Block | None):
        addr = self._handle_expr(0, expr.addr, stmt_idx, stmt, block)

        if addr is not None and addr is not expr.addr:
            new_expr = expr.copy()
            new_expr.addr = addr
            return new_expr
        return None

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        changed = False

        if isinstance(expr.target, str):
            new_target = None
        else:
            new_target = self._handle_expr(-1, expr.target, stmt_idx, stmt, block)
            if new_target is not None and new_target is not expr.target:
                changed = True

        new_args = None
        if expr.args is not None:
            i = 0
            new_args = []
            while i < len(expr.args):
                arg = expr.args[i]
                new_arg = self._handle_expr(i, arg, stmt_idx, stmt, block)
                if new_arg is not None and new_arg is not arg:
                    if not changed:
                        # initialize new_args
                        new_args = list(expr.args[:i])
                    new_args.append(new_arg)
                    changed = True
                else:
                    if changed:
                        new_args.append(arg)
                i += 1

        if changed:
            expr = expr.copy()
            if new_target is not None:
                expr.target = new_target
            expr.args = new_args
            return expr
        return None

    def _handle_BinaryOp(self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement, block: Block | None):
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
            new_expr.depth = max(operand_0.depth, operand_1.depth) + 1
            return new_expr
        return None

    def _handle_UnaryOp(self, expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt: Statement, block: Block | None):
        new_operand = self._handle_expr(0, expr.operand, stmt_idx, stmt, block)
        if new_operand is not None and new_operand is not expr.operand:
            new_expr = expr.copy()
            new_expr.operand = new_operand
            return new_expr
        return None

    def _handle_Convert(self, expr_idx: int, expr: Convert, stmt_idx: int, stmt: Statement, block: Block | None):
        new_operand = self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block)
        if new_operand is not None and new_operand is not expr.operand:
            return Convert(expr.idx, expr.from_bits, expr.to_bits, expr.is_signed, new_operand, **expr.tags)
        return None

    def _handle_Reinterpret(
        self, expr_idx: int, expr: Reinterpret, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        new_operand = self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block)
        if new_operand is not None and new_operand is not expr.operand:
            return Reinterpret(
                expr.idx, expr.from_bits, expr.from_type, expr.to_bits, expr.to_type, new_operand, **expr.tags
            )
        return None

    def _handle_ITE(self, expr_idx: int, expr: ITE, stmt_idx: int, stmt: Statement, block: Block | None):
        changed = False

        cond = self._handle_expr(0, expr.cond, stmt_idx, stmt, block)
        if cond is not None and cond is not expr.cond:
            changed = True
        else:
            cond = expr.cond

        iftrue = self._handle_expr(1, expr.iftrue, stmt_idx, stmt, block)
        if iftrue is not None and iftrue is not expr.iftrue:
            changed = True
        else:
            iftrue = expr.iftrue

        iffalse = self._handle_expr(2, expr.iffalse, stmt_idx, stmt, block)
        if iffalse is not None and iffalse is not expr.iffalse:
            changed = True
        else:
            iffalse = expr.iffalse

        if changed:
            new_expr = expr.copy()
            new_expr.cond = cond
            new_expr.iftrue = iftrue
            new_expr.iffalse = iffalse
            return new_expr
        return None

    def _handle_Phi(self, expr_id: int, expr: Phi, stmt_idx: int, stmt: Statement, block: Block | None) -> Phi | None:
        if not self._replace_phi_stmt:
            # fallback to the read-only version
            return super()._handle_Phi(expr_id, expr, stmt_idx, stmt, block)

        changed = False

        src_and_vvars = []
        for idx, (src, vvar) in enumerate(expr.src_and_vvars):
            if vvar is None:
                if src_and_vvars is not None:
                    src_and_vvars.append((src, None))
                continue
            new_vvar = self._handle_expr(idx, vvar, stmt_idx, stmt, block)
            if new_vvar is not None and new_vvar is not vvar:
                changed = True
                if src_and_vvars is None:
                    src_and_vvars = expr.src_and_vvars[:idx]
                src_and_vvars.append((src, new_vvar))
            elif src_and_vvars is not None:
                src_and_vvars.append((src, vvar))

        return Phi(expr.idx, expr.bits, src_and_vvars, **expr.tags) if changed else None

    def _handle_DirtyExpression(
        self, expr_idx: int, expr: DirtyExpression, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        changed = False
        new_operands = []
        for operand in expr.operands:
            new_operand = self._handle_expr(0, operand, stmt_idx, stmt, block)
            if new_operand is not None and new_operand is not operand:
                changed = True
                new_operands.append(new_operand)
            else:
                new_operands.append(operand)

        new_guard = expr.guard
        if expr.guard is not None:
            new_guard = self._handle_expr(2, expr.guard, stmt_idx, stmt, block)
            if new_guard is not None and new_guard is not expr.guard:
                changed = True

        if changed:
            return DirtyExpression(
                expr.idx,
                expr.callee,
                new_operands,
                guard=new_guard,
                mfx=expr.mfx,
                maddr=expr.maddr,
                msize=expr.msize,
                bits=expr.bits,
                **expr.tags,
            )
        return None

    def _handle_VEXCCallExpression(
        self, expr_idx: int, expr: VEXCCallExpression, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        changed = False
        new_operands = []
        for idx, operand in enumerate(expr.operands):
            new_operand = self._handle_expr(idx, operand, stmt_idx, stmt, block)
            if new_operand is not None and new_operand is not operand:
                changed = True
                new_operands.append(new_operand)
            else:
                new_operands.append(operand)

        if changed:
            new_expr = expr.copy()
            new_expr.operands = tuple(new_operands)
            return new_expr
        return None

    def _handle_MultiStatementExpression(
        self, expr_idx, expr: MultiStatementExpression, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        changed = False
        new_statements = []
        for idx, stmt_ in enumerate(expr.stmts):
            new_stmt = self._handle_stmt(idx, stmt_, None)
            if new_stmt is not None and new_stmt is not stmt_:
                changed = True
                new_statements.append(new_stmt)
            else:
                new_statements.append(stmt_)

        new_expr = self._handle_expr(0, expr.expr, stmt_idx, stmt, block)
        if new_expr is not None and new_expr is not expr.expr:
            changed = True
        else:
            new_expr = expr.expr

        if changed:
            expr_ = expr.copy()
            expr_.expr = new_expr
            expr_.stmts = new_statements
            return expr_
        return None
