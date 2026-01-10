# pylint:disable=unused-argument,no-self-use
from __future__ import annotations
from abc import abstractmethod
from typing import Any, Generic, TypeVar, cast
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
    Atom,
)

ExprType = TypeVar("ExprType")
StmtType = TypeVar("StmtType")
BlockType = TypeVar("BlockType")


class AILBlockWalker(Generic[ExprType, StmtType, BlockType]):
    """
    Walks all statements and expressions of an AIL node and construct arbitrary values based on them.
    """

    def __init__(self, stmt_handlers=None, expr_handlers=None):
        _default_stmt_handlers: dict[type, Callable[[int, Any, Block | None], StmtType]] = {
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

        _default_expr_handlers: dict[type, Callable[[int, Any, int, Statement | None, Block | None], ExprType]] = {
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

        self.stmt_handlers: dict[type, Callable[[int, Any, Block | None], StmtType]] = (
            stmt_handlers if stmt_handlers else _default_stmt_handlers
        )
        self.expr_handlers: dict[type, Callable[[int, Any, int, Statement | None, Block | None], ExprType]] = (
            expr_handlers if expr_handlers else _default_expr_handlers
        )

    def walk(self, block: Block) -> BlockType:
        i = 0
        results = []
        while i < len(block.statements):
            stmt = block.statements[i]
            results.append(self._handle_stmt(i, stmt, block))
            i += 1
        return self._handle_block_end(results, block)

    @abstractmethod
    def _handle_block_end(self, stmt_results: list[StmtType], block: Block) -> BlockType:
        raise NotImplementedError

    def walk_statement(self, stmt: Statement, block: Block | None = None) -> StmtType:
        return self._handle_stmt(0, stmt, block)

    def walk_expression(
        self,
        expr: Expression,
        stmt_idx: int | None = None,
        stmt: Statement | None = None,
        block: Block | None = None,
    ) -> ExprType:
        return self._handle_expr(0, expr, stmt_idx or 0, stmt, block)

    def _handle_stmt(self, stmt_idx: int, stmt: Statement, block: Block | None) -> StmtType:
        handler = self.stmt_handlers.get(type(stmt), self._stmt_top)
        return handler(stmt_idx, stmt, block)

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        handler = self.expr_handlers.get(type(expr), self._top)
        return handler(expr_idx, expr, stmt_idx, stmt, block)

    @abstractmethod
    def _top(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        raise NotImplementedError

    @abstractmethod
    def _stmt_top(self, stmt_idx: int, stmt: Statement, block: Block | None) -> StmtType:
        raise NotImplementedError

    #
    # Default handlers
    #

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Block | None) -> StmtType:
        self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
        return self._stmt_top(stmt_idx, stmt, block)

    def _handle_WeakAssignment(self, stmt_idx: int, stmt: WeakAssignment, block: Block | None) -> StmtType:
        self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
        return self._stmt_top(stmt_idx, stmt, block)

    def _handle_CAS(self, stmt_idx: int, stmt: CAS, block: Block | None) -> StmtType:
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
        return self._stmt_top(stmt_idx, stmt, block)

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None) -> StmtType:
        if not isinstance(stmt.target, str):
            self._handle_expr(-1, stmt.target, stmt_idx, stmt, block)
        if stmt.args:
            for i, arg in enumerate(stmt.args):
                self._handle_expr(i, arg, stmt_idx, stmt, block)
        return self._stmt_top(stmt_idx, stmt, block)

    def _handle_Store(self, stmt_idx: int, stmt: Store, block: Block | None) -> StmtType:
        self._handle_expr(0, stmt.addr, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.data, stmt_idx, stmt, block)
        if stmt.guard is not None:
            self._handle_expr(2, stmt.guard, stmt_idx, stmt, block)
        return self._stmt_top(stmt_idx, stmt, block)

    def _handle_Jump(self, stmt_idx: int, stmt: Jump, block: Block | None) -> StmtType:
        self._handle_expr(0, stmt.target, stmt_idx, stmt, block)
        return self._stmt_top(stmt_idx, stmt, block)

    def _handle_ConditionalJump(self, stmt_idx: int, stmt: ConditionalJump, block: Block | None) -> StmtType:
        self._handle_expr(0, stmt.condition, stmt_idx, stmt, block)
        if stmt.true_target is not None:
            self._handle_expr(1, stmt.true_target, stmt_idx, stmt, block)
        if stmt.false_target is not None:
            self._handle_expr(2, stmt.false_target, stmt_idx, stmt, block)
        return self._stmt_top(stmt_idx, stmt, block)

    def _handle_Return(self, stmt_idx: int, stmt: Return, block: Block | None) -> StmtType:
        if stmt.ret_exprs:
            for i, ret_expr in enumerate(stmt.ret_exprs):
                self._handle_expr(i, ret_expr, stmt_idx, stmt, block)
        return self._stmt_top(stmt_idx, stmt, block)

    def _handle_DirtyStatement(self, stmt_idx: int, stmt: DirtyStatement, block: Block | None) -> StmtType:
        self._handle_expr(0, stmt.dirty, stmt_idx, stmt, block)
        return self._stmt_top(stmt_idx, stmt, block)

    def _handle_Load(
        self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        self._handle_expr(0, expr.addr, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_CallExpr(
        self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        if not isinstance(expr.target, str):
            self._handle_expr(-1, expr.target, stmt_idx, stmt, block)
        if expr.args:
            for i, arg in enumerate(expr.args):
                self._handle_expr(i, arg, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_BinaryOp(
        self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        self._handle_expr(0, expr.operands[0], stmt_idx, stmt, block)
        self._handle_expr(1, expr.operands[1], stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_UnaryOp(
        self, expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        self._handle_expr(0, expr.operand, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Convert(
        self, expr_idx: int, expr: Convert, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Reinterpret(
        self, expr_idx: int, expr: Reinterpret, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_ITE(
        self, expr_idx: int, expr: ITE, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        self._handle_expr(0, expr.cond, stmt_idx, stmt, block)
        self._handle_expr(1, expr.iftrue, stmt_idx, stmt, block)
        self._handle_expr(2, expr.iffalse, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Tmp(
        self, expr_idx: int, expr: Tmp, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Register(
        self, expr_idx: int, expr: Register, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Const(
        self, expr_idx: int, expr: Const, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_VirtualVariable(
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Phi(
        self, expr_idx: int, expr: Phi, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        for idx, (_, vvar) in enumerate(expr.src_and_vvars):
            if vvar is not None:
                self._handle_expr(idx, vvar, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_MultiStatementExpression(
        self, expr_idx, expr: MultiStatementExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        for idx, stmt_ in enumerate(expr.stmts):
            self._handle_stmt(idx, stmt_, None)
        self._handle_expr(0, expr.expr, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_DirtyExpression(
        self, expr_idx: int, expr: DirtyExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        for idx, operand in enumerate(expr.operands):
            self._handle_expr(idx, operand, stmt_idx, stmt, block)
        if expr.guard is not None:
            self._handle_expr(len(expr.operands) + 1, expr.guard, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_VEXCCallExpression(
        self, expr_idx: int, expr: VEXCCallExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        for idx, operand in enumerate(expr.operands):
            self._handle_expr(idx, operand, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)


class AILBlockViewer(AILBlockWalker[None, None, None]):
    """
    Walks all statements and expressions of an AIL node and do nothing.
    """

    def _top(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None):
        return None

    def _stmt_top(self, stmt_idx: int, stmt: Statement, block: Block | None):
        return None

    def _handle_block_end(self, stmt_results: list[StmtType], block: Block):
        return None

    # Duplicate all handlers for performance...

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

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self._handle_expr(0, expr.addr, stmt_idx, stmt, block)

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement | None, block: Block | None):
        if not isinstance(expr.target, str):
            self._handle_expr(-1, expr.target, stmt_idx, stmt, block)
        if expr.args:
            for i, arg in enumerate(expr.args):
                self._handle_expr(i, arg, stmt_idx, stmt, block)

    def _handle_BinaryOp(
        self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        self._handle_expr(0, expr.operands[0], stmt_idx, stmt, block)
        self._handle_expr(1, expr.operands[1], stmt_idx, stmt, block)

    def _handle_UnaryOp(self, expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self._handle_expr(0, expr.operand, stmt_idx, stmt, block)

    def _handle_Convert(self, expr_idx: int, expr: Convert, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block)

    def _handle_Reinterpret(
        self, expr_idx: int, expr: Reinterpret, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block)

    def _handle_ITE(self, expr_idx: int, expr: ITE, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self._handle_expr(0, expr.cond, stmt_idx, stmt, block)
        self._handle_expr(1, expr.iftrue, stmt_idx, stmt, block)
        self._handle_expr(2, expr.iffalse, stmt_idx, stmt, block)

    def _handle_Tmp(self, expr_idx: int, expr: Tmp, stmt_idx: int, stmt: Statement | None, block: Block | None):
        return None

    def _handle_Register(
        self, expr_idx: int, expr: Register, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        return None

    def _handle_Const(self, expr_idx: int, expr: Const, stmt_idx: int, stmt: Statement | None, block: Block | None):
        return None

    def _handle_VirtualVariable(
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        return None

    def _handle_Phi(self, expr_idx: int, expr: Phi, stmt_idx: int, stmt: Statement | None, block: Block | None):
        for idx, (_, vvar) in enumerate(expr.src_and_vvars):
            if vvar is not None:
                self._handle_expr(idx, vvar, stmt_idx, stmt, block)

    def _handle_MultiStatementExpression(
        self, expr_idx, expr: MultiStatementExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        for idx, stmt_ in enumerate(expr.stmts):
            self._handle_stmt(idx, stmt_, None)
        self._handle_expr(0, expr.expr, stmt_idx, stmt, block)

    def _handle_DirtyExpression(
        self, expr_idx: int, expr: DirtyExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        for idx, operand in enumerate(expr.operands):
            self._handle_expr(idx, operand, stmt_idx, stmt, block)
        if expr.guard is not None:
            self._handle_expr(len(expr.operands) + 1, expr.guard, stmt_idx, stmt, block)

    def _handle_VEXCCallExpression(
        self, expr_idx: int, expr: VEXCCallExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        for idx, operand in enumerate(expr.operands):
            self._handle_expr(idx, operand, stmt_idx, stmt, block)


class AILBlockRewriter(AILBlockWalker[Expression, Statement, Block]):
    """
    Walks all statements and expressions of an AIL node, and rebuilds expressions, statements, or blocks if needed.

    If you need a pure walker without rebuilding, use AILBlockViewer instead.

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

    def _top(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        return expr

    def _stmt_top(self, stmt_idx: int, stmt: Statement, block: Block | None) -> Statement:
        return stmt

    def _handle_block_end(self, stmt_results: list[Statement], block: Block) -> Block:
        if all(new is None or new is old for new, old in zip(stmt_results, block.statements)):
            return block
        statements = [new or old for new, old in zip(stmt_results, block.statements)]
        if not self._update_block:
            return block.copy(statements=statements)
        block.statements = statements
        return block

    #
    # Default handlers
    #

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Block | None) -> Statement:
        dst = self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        assert isinstance(dst, Atom)
        changed = dst is not stmt.dst

        src = self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
        changed |= src is not stmt.src

        if changed:
            return Assignment(stmt.idx, dst, src, **stmt.tags)
        return stmt

    def _handle_WeakAssignment(self, stmt_idx: int, stmt: WeakAssignment, block: Block | None) -> Statement:
        dst = self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        assert isinstance(dst, Atom)
        changed = dst is not stmt.dst

        src = self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
        changed |= src is not stmt.src

        if changed:
            return WeakAssignment(stmt.idx, dst, src, **stmt.tags)
        return stmt

    def _handle_CAS(self, stmt_idx: int, stmt: CAS, block: Block | None) -> Statement:
        addr = self._handle_expr(0, stmt.addr, stmt_idx, stmt, block)
        changed = addr is not stmt.addr

        data_lo = self._handle_expr(1, stmt.data_lo, stmt_idx, stmt, block)
        changed |= data_lo is not stmt.data_lo

        data_hi = None
        if stmt.data_hi is not None:
            data_hi = self._handle_expr(2, stmt.data_hi, stmt_idx, stmt, block)
            changed |= data_hi is not stmt.data_hi

        expd_lo = self._handle_expr(3, stmt.expd_lo, stmt_idx, stmt, block)
        changed |= expd_lo is not stmt.expd_lo

        expd_hi = None
        if stmt.expd_hi is not None:
            expd_hi = self._handle_expr(4, stmt.expd_hi, stmt_idx, stmt, block)
            changed |= expd_hi is not stmt.expd_hi

        old_lo = self._handle_expr(5, stmt.old_lo, stmt_idx, stmt, block)
        assert isinstance(old_lo, Atom)
        changed |= old_lo is not stmt.old_lo

        old_hi = None
        if stmt.old_hi is not None:
            old_hi = self._handle_expr(6, stmt.old_hi, stmt_idx, stmt, block)
            assert isinstance(old_hi, Atom)
            changed |= old_hi is not stmt.old_hi

        if changed:
            return CAS(
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
        return stmt

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None) -> Statement:
        changed = False

        if isinstance(stmt.target, str):
            new_target = None
        else:
            new_target = self._handle_expr(-1, stmt.target, stmt_idx, stmt, block)
            changed = new_target is not stmt.target

        new_args = None
        if stmt.args is not None:
            new_args = [self._handle_expr(idx, arg, stmt_idx, stmt, block) for idx, arg in enumerate(stmt.args)]
            changed |= any(old is not new for new, old in zip(new_args, stmt.args))

        if changed:
            return Call(
                stmt.idx,
                new_target if new_target is not None else stmt.target,
                calling_convention=stmt.calling_convention,
                prototype=stmt.prototype,
                args=new_args,
                ret_expr=stmt.ret_expr,
                **stmt.tags,
            )
        return stmt

    def _handle_Store(self, stmt_idx: int, stmt: Store, block: Block | None) -> Statement:
        addr = self._handle_expr(0, stmt.addr, stmt_idx, stmt, block)
        changed = addr is not stmt.addr

        data = self._handle_expr(1, stmt.data, stmt_idx, stmt, block)
        changed |= data is not stmt.data

        guard = None if stmt.guard is None else self._handle_expr(2, stmt.guard, stmt_idx, stmt, block)
        changed |= guard is not stmt.guard

        if changed:
            return Store(
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
        return stmt

    def _handle_Jump(self, stmt_idx: int, stmt: Jump, block: Block | None) -> Statement:
        target = self._handle_expr(0, stmt.target, stmt_idx, stmt, block)
        changed = target is not stmt.target

        if changed:
            return Jump(
                stmt.idx,
                target,
                target_idx=stmt.target_idx,
                **stmt.tags,
            )
        return stmt

    def _handle_ConditionalJump(self, stmt_idx: int, stmt: ConditionalJump, block: Block | None) -> Statement:
        condition = self._handle_expr(0, stmt.condition, stmt_idx, stmt, block)
        changed = condition is not stmt.condition

        true_target = None
        if stmt.true_target is not None:
            true_target = self._handle_expr(1, stmt.true_target, stmt_idx, stmt, block)
            changed |= true_target is not stmt.true_target

        false_target = None
        if stmt.false_target is not None:
            false_target = self._handle_expr(2, stmt.false_target, stmt_idx, stmt, block)
            changed |= false_target is not stmt.false_target

        if changed:
            return ConditionalJump(
                stmt.idx,
                condition,
                true_target,
                false_target,
                true_target_idx=stmt.true_target_idx,
                false_target_idx=stmt.false_target_idx,
                **stmt.tags,
            )
        return stmt

    def _handle_Return(self, stmt_idx: int, stmt: Return, block: Block | None) -> Statement:
        if stmt.ret_exprs:
            new_ret_exprs = [
                self._handle_expr(idx, expr, stmt_idx, stmt, block) for idx, expr in enumerate(stmt.ret_exprs)
            ]
            changed = any(old is not new for new, old in zip(new_ret_exprs, stmt.ret_exprs))

            if changed:
                return Return(stmt.idx, new_ret_exprs, **stmt.tags)
        return stmt

    def _handle_DirtyStatement(self, stmt_idx: int, stmt: DirtyStatement, block: Block | None) -> Statement:
        dirty = self._handle_expr(0, stmt.dirty, stmt_idx, stmt, block)
        assert isinstance(dirty, DirtyExpression)
        changed = dirty is not stmt.dirty

        if changed:
            return DirtyStatement(stmt.idx, dirty, **stmt.tags)
        return stmt

    #
    # Expression handlers

    def _handle_expr(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None):
        # reach a fixed point
        while True:
            result = super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)
            if result is expr:
                break
            expr = result
        return expr

    def _handle_Load(
        self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        addr = self._handle_expr(0, expr.addr, stmt_idx, stmt, block)
        changed = addr is not expr.addr

        if changed:
            new_expr = expr.copy()
            new_expr.addr = addr
            return new_expr
        return expr

    def _handle_CallExpr(
        self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        changed = False

        if isinstance(expr.target, str):
            new_target = expr.target
        else:
            new_target = self._handle_expr(-1, expr.target, stmt_idx, stmt, block)
            changed |= new_target is not expr.target

        new_args = None
        if expr.args is not None:
            new_args = [self._handle_expr(idx, arg, stmt_idx, stmt, block) for idx, arg in enumerate(expr.args)]
            changed |= any(old is not new for new, old in zip(new_args, expr.args))

        if changed:
            expr = expr.copy()
            expr.target = new_target
            expr.args = new_args
            return expr
        return expr

    def _handle_BinaryOp(
        self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        operand_0 = self._handle_expr(0, expr.operands[0], stmt_idx, stmt, block)
        changed = operand_0 is not expr.operands[0]

        operand_1 = self._handle_expr(1, expr.operands[1], stmt_idx, stmt, block)
        changed |= operand_1 is not expr.operands[1]

        if changed:
            new_expr = expr.copy()
            new_expr.operands = (operand_0, operand_1)
            new_expr.depth = max(operand_0.depth, operand_1.depth) + 1
            return new_expr
        return expr

    def _handle_UnaryOp(
        self, expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        new_operand = self._handle_expr(0, expr.operand, stmt_idx, stmt, block)
        changed = new_operand is not expr.operand

        if changed:
            new_expr = expr.copy()
            new_expr.operand = new_operand
            return new_expr
        return expr

    def _handle_Convert(
        self, expr_idx: int, expr: Convert, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        new_operand = self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block)
        changed = new_operand is not expr.operand

        if changed:
            return Convert(expr.idx, expr.from_bits, expr.to_bits, expr.is_signed, new_operand, **expr.tags)
        return expr

    def _handle_Reinterpret(
        self, expr_idx: int, expr: Reinterpret, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        new_operand = self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block)
        changed = new_operand is not expr.operand

        if changed:
            return Reinterpret(
                expr.idx, expr.from_bits, expr.from_type, expr.to_bits, expr.to_type, new_operand, **expr.tags
            )
        return expr

    def _handle_ITE(
        self, expr_idx: int, expr: ITE, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        cond = self._handle_expr(0, expr.cond, stmt_idx, stmt, block)
        changed = cond is not expr.cond

        iftrue = self._handle_expr(1, expr.iftrue, stmt_idx, stmt, block)
        changed |= iftrue is not expr.iftrue

        iffalse = self._handle_expr(2, expr.iffalse, stmt_idx, stmt, block)
        changed |= iffalse is not expr.iffalse

        if changed:
            new_expr = expr.copy()
            new_expr.cond = cond
            new_expr.iftrue = iftrue
            new_expr.iffalse = iffalse
            return new_expr
        return expr

    def _handle_Phi(
        self, expr_idx: int, expr: Phi, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        if not self._replace_phi_stmt:
            # fallback to the read-only version
            super()._handle_Phi(expr_idx, expr, stmt_idx, stmt, block)
            return expr

        changed = False

        src_and_vvars = [
            (src, self._handle_expr(idx, vvar, stmt_idx, stmt, block) if vvar is not None else None)
            for idx, (src, vvar) in enumerate(expr.src_and_vvars)
        ]
        changed = any(new is not old for (_, new), (_, old) in zip(src_and_vvars, expr.src_and_vvars))

        if changed:
            assert all(vvar is None or isinstance(vvar, VirtualVariable) for _, vvar in src_and_vvars)
            return Phi(
                expr.idx,
                expr.bits,
                cast(list[tuple[tuple[int, int | None], VirtualVariable | None]], src_and_vvars),
                **expr.tags,
            )
        return expr

    def _handle_DirtyExpression(
        self, expr_idx: int, expr: DirtyExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        changed = False
        new_operands = [self._handle_expr(0, operand, stmt_idx, stmt, block) for operand in expr.operands]
        changed = any(new is not old for new, old in zip(new_operands, expr.operands))

        new_guard = None
        if expr.guard is not None:
            new_guard = self._handle_expr(2, expr.guard, stmt_idx, stmt, block)
            changed |= new_guard is not expr.guard

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
        return expr

    def _handle_VEXCCallExpression(
        self, expr_idx: int, expr: VEXCCallExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        new_operands = [
            self._handle_expr(idx, operand, stmt_idx, stmt, block) for idx, operand in enumerate(expr.operands)
        ]
        changed = any(new is not old for new, old in zip(new_operands, expr.operands))

        if changed:
            new_expr = expr.copy()
            new_expr.operands = tuple(new_operands)
            return new_expr
        return expr

    def _handle_MultiStatementExpression(
        self, expr_idx, expr: MultiStatementExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        new_statements = [self._handle_stmt(idx, stmt_, None) for idx, stmt_ in enumerate(expr.stmts)]
        changed = any(new is not old for new, old in zip(new_statements, expr.stmts))

        new_expr = self._handle_expr(0, expr.expr, stmt_idx, stmt, block)
        changed |= new_expr is not expr.expr

        if changed:
            expr_ = expr.copy()
            expr_.expr = new_expr
            expr_.stmts = new_statements
            return expr_
        return expr
