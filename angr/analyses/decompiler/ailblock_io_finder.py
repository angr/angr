from collections import defaultdict
from typing import Any, Optional, Union, List

from ailment import Block
from ailment.statement import Call, Statement, ConditionalJump, Assignment, Store, Return
from ailment.expression import (
    Load,
    Expression,
    BinaryOp,
    UnaryOp,
    Convert,
    ITE,
    Tmp,
    Const,
    StackBaseOffset,
)


from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation, Register, SpOffset, ConstantSrc

from ailment.block_walker import AILBlockWalkerBase


class AILStmtIOFinder(AILBlockWalkerBase):
    """
    Finds the input and output locations of each statement in an AIL block.
    I/O locations can be a Register, MemoryLocation, or SpOffset (wrapped in a Memory Location).
    """

    def __init__(self, ail_obj: Union[Block, List[Statement]], project, as_atom=True):
        super().__init__()
        self.expr_handlers[StackBaseOffset] = self._handle_StackBaseOffset
        self._as_atom = as_atom
        self._project = project

        self.inputs_by_stmt = defaultdict(set)
        self.outputs_by_stmt = defaultdict(set)

        block = Block(0, len(ail_obj), statements=ail_obj) if isinstance(ail_obj, list) else ail_obj
        self.walk(block)

    @staticmethod
    def _add_or_update_dict(d, k, v):
        if isinstance(v, set):
            d[k].update(v)
        else:
            d[k].add(v)

    @staticmethod
    def _add_or_update_set(s, v):
        if isinstance(v, set):
            s.update(v)
        else:
            s.add(v)

    #
    # I/O helpers
    #

    def depends_on(self, idx, target_idx):
        # TODO: MUST FINISH THIS
        return self.inputs_by_stmt[idx].intersection(self.outputs_by_stmt[target_idx])

    #
    # Statements (all with side effects)
    #

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Optional[Block]):
        output_loc = self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        self._add_or_update_dict(self.outputs_by_stmt, stmt_idx, output_loc)

        input_loc = self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
        self._add_or_update_dict(self.inputs_by_stmt, stmt_idx, input_loc)

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Optional[Block]):
        if stmt.args:
            for i, arg in enumerate(stmt.args):
                input_loc = self._handle_expr(i, arg, stmt_idx, stmt, block)
                self._add_or_update_dict(self.inputs_by_stmt, stmt_idx, input_loc)

        out_loc = self._handle_expr(0, stmt.ret_expr, stmt_idx, stmt, block)
        self._add_or_update_dict(self.outputs_by_stmt, stmt_idx, out_loc)

    def _handle_Store(self, stmt_idx: int, stmt: Store, block: Optional[Block]):
        out_loc = self._handle_expr(0, stmt.addr, stmt_idx, stmt, block, is_memory=True)
        self._add_or_update_dict(self.outputs_by_stmt, stmt_idx, out_loc)

        input_loc = self._handle_expr(1, stmt.data, stmt_idx, stmt, block)
        self._add_or_update_dict(self.inputs_by_stmt, stmt_idx, input_loc)

    def _handle_ConditionalJump(self, stmt_idx: int, stmt: ConditionalJump, block: Optional[Block]):
        input1 = self._handle_expr(0, stmt.condition, stmt_idx, stmt, block)
        input2 = self._handle_expr(1, stmt.true_target, stmt_idx, stmt, block)
        input3 = self._handle_expr(2, stmt.false_target, stmt_idx, stmt, block)
        self._add_or_update_dict(self.inputs_by_stmt, stmt_idx, input1)
        self._add_or_update_dict(self.inputs_by_stmt, stmt_idx, input2)
        self._add_or_update_dict(self.inputs_by_stmt, stmt_idx, input3)

    def _handle_Return(self, stmt_idx: int, stmt: Return, block: Optional[Block]):
        if stmt.ret_exprs:
            for i, ret_expr in enumerate(stmt.ret_exprs):
                loc = self._handle_expr(i, ret_expr, stmt_idx, stmt, block)
                self._add_or_update_dict(self.inputs_by_stmt, stmt_idx, loc)
                self._add_or_update_dict(self.outputs_by_stmt, stmt_idx, loc)

    #
    # Expressions
    #

    def _handle_expr(
        self,
        expr_idx: int,
        expr: Expression,
        stmt_idx: int,
        stmt: Optional[Statement],
        block: Optional[Block],
        is_memory=False,
    ) -> Any:
        try:
            handler = self.expr_handlers[type(expr)]
        except KeyError:
            handler = None

        if handler:
            return handler(expr_idx, expr, stmt_idx, stmt, block, is_memory=is_memory)
        return None

    def _handle_Load(
        self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement, block: Optional[Block], is_memory=True
    ):
        return self._handle_expr(0, expr.addr, stmt_idx, stmt, block, is_memory=True)

    def _handle_CallExpr(
        self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Optional[Block], is_memory=False
    ):
        args = set()
        if expr.args:
            for i, arg in enumerate(expr.args):
                self._add_or_update_set(args, self._handle_expr(i, arg, stmt_idx, stmt, block, is_memory=is_memory))

        return args

    def _handle_BinaryOp(
        self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement, block: Optional[Block], is_memory=False
    ):
        input_locs = set()
        self._add_or_update_set(
            input_locs, self._handle_expr(0, expr.operands[0], stmt_idx, stmt, block, is_memory=is_memory)
        )
        self._add_or_update_set(
            input_locs, self._handle_expr(1, expr.operands[1], stmt_idx, stmt, block, is_memory=is_memory)
        )

        return input_locs

    def _handle_UnaryOp(
        self, expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt: Statement, block: Optional[Block], is_memory=False
    ):
        return self._handle_expr(0, expr.operand, stmt_idx, stmt, block, is_memory=is_memory)

    def _handle_Convert(
        self, expr_idx: int, expr: Convert, stmt_idx: int, stmt: Statement, block: Optional[Block], is_memory=False
    ):
        return self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block, is_memory=is_memory)

    def _handle_ITE(
        self, expr_idx: int, expr: ITE, stmt_idx: int, stmt: Statement, block: Optional[Block], is_memory=False
    ):
        input_locs = set()
        self._add_or_update_set(
            input_locs,
            self._handle_expr(0, expr.cond, stmt_idx, stmt, block, is_memory=is_memory),
        )
        self._add_or_update_set(
            input_locs,
            self._handle_expr(1, expr.iftrue, stmt_idx, stmt, block, is_memory=is_memory),
        )
        self._add_or_update_set(
            input_locs,
            self._handle_expr(2, expr.iffalse, stmt_idx, stmt, block, is_memory=is_memory),
        )

        return input_locs

    #
    # Base locations
    #

    def _handle_Tmp(
        self, expr_idx: int, expr: Tmp, stmt_idx: int, stmt: Statement, block: Optional[Block], is_memory=False
    ):
        if self._as_atom:
            return None
        else:
            return expr

    def _handle_Register(
        self, expr_idx: int, expr: Register, stmt_idx: int, stmt: Statement, block: Optional[Block], is_memory=False
    ):
        if self._as_atom:
            return Register(expr.reg_offset, expr.size)
        else:
            return expr

    def _handle_Const(
        self, expr_idx: int, expr: Const, stmt_idx: int, stmt: Statement, block: Optional[Block], is_memory=False
    ):
        if self._as_atom:
            return MemoryLocation(expr.value, expr.size) if is_memory else ConstantSrc(expr.value, expr.size)

        return (
            expr,
            is_memory,
        )

    def _handle_StackBaseOffset(
        self,
        expr_idx: int,
        expr: StackBaseOffset,
        stmt_idx: int,
        stmt: Statement,
        block: Optional[Block],
        is_memory=False,
    ):
        if self._as_atom:
            return MemoryLocation(
                SpOffset(self._project.arch.bits, expr.size), expr.size * self._project.arch.byte_width
            )
        return expr
