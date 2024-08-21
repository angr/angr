from collections import defaultdict
from typing import Any

from ailment import Block
from ailment.statement import Call, Statement, ConditionalJump, Assignment, Store, Return, Jump
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
from ailment.block_walker import AILBlockWalkerBase


from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation, Register, SpOffset, ConstantSrc


class BlockIOFinder(AILBlockWalkerBase):
    """
    Finds the input and output locations of each statement in an AIL block.
    I/O locations can be a Register, MemoryLocation, or SpOffset (wrapped in a Memory Location).
    """

    def __init__(self, ail_obj: Block | list[Statement], project, as_atom=True):
        super().__init__()
        self.expr_handlers[StackBaseOffset] = self._handle_StackBaseOffset
        self._as_atom = as_atom
        self._project = project

        self.inputs_by_stmt = defaultdict(set)
        self.outputs_by_stmt = defaultdict(set)
        self.derefed_at = defaultdict(set)

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

    @staticmethod
    def _is_dangerous_memory(loc):
        """
        Assume any memory location that is NOT on the stack is a dangerous memory location.
        """
        return isinstance(loc, MemoryLocation) and not loc.is_on_stack

    def _has_dangerous_deref(self, stmt_idx):
        derefs = self.derefed_at.get(stmt_idx, set())
        return any(self._is_dangerous_memory(d) for d in derefs)

    def _input_defined_by_other_stmt(self, target_idx, other_idx):
        target_inputs = self.inputs_by_stmt[target_idx]
        # any memory location, not on stack, is not movable
        if any(self._is_dangerous_memory(i) for i in target_inputs):
            return True

        other_outputs = self.outputs_by_stmt[other_idx]
        return target_inputs.intersection(other_outputs)

    def _output_used_by_other_stmt(self, target_idx, other_idx):
        target_output = self.outputs_by_stmt[target_idx]
        # any memory location, not on stack, is not movable
        if any(self._is_dangerous_memory(o) for o in target_output):
            return True

        other_input = self.inputs_by_stmt[other_idx]
        return target_output.intersection(other_input)

    def can_swap(self, stmt, ail_obj: Block | list[Statement], offset: int):
        all_stmts = (ail_obj.statements or []) if isinstance(ail_obj, Block) else ail_obj
        if stmt not in all_stmts:
            raise RuntimeError("Statement not in block, and we can't compute moving a stmt to a new block!")

        curr_idx = all_stmts.index(stmt)
        new_idx = curr_idx + offset
        if (
            # movement must be within bounds
            (new_idx < 0 or new_idx >= len(all_stmts))
            or
            # you can never move jumps
            isinstance(stmt, (ConditionalJump, Jump))
            or
            # we can't handle memory locations
            self._has_dangerous_deref(curr_idx)
            or self._has_dangerous_deref(new_idx)
        ):
            return False

        # equivalent to swapping "down"
        if offset == 1:
            if self._output_used_by_other_stmt(curr_idx, new_idx):
                return False
        # equivalent to swapping "up"
        elif offset == -1:
            if self._input_defined_by_other_stmt(curr_idx, new_idx):
                return False
        else:
            raise RuntimeError("Offset must be -1 or 1")

        return True

    #
    # Statements (all with side effects)
    #

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Block | None):
        output_loc = self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        self._add_or_update_dict(self.outputs_by_stmt, stmt_idx, output_loc)

        input_loc = self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
        self._add_or_update_dict(self.inputs_by_stmt, stmt_idx, input_loc)

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
        if stmt.args:
            for i, arg in enumerate(stmt.args):
                input_loc = self._handle_expr(i, arg, stmt_idx, stmt, block)
                self._add_or_update_dict(self.inputs_by_stmt, stmt_idx, input_loc)

        out_loc = self._handle_expr(0, stmt.ret_expr, stmt_idx, stmt, block)
        self._add_or_update_dict(self.outputs_by_stmt, stmt_idx, out_loc)

    def _handle_Store(self, stmt_idx: int, stmt: Store, block: Block | None):
        out_loc = self._handle_expr(0, stmt.addr, stmt_idx, stmt, block, is_memory=True)
        self._add_or_update_dict(self.outputs_by_stmt, stmt_idx, out_loc)

        input_loc = self._handle_expr(1, stmt.data, stmt_idx, stmt, block)
        self._add_or_update_dict(self.inputs_by_stmt, stmt_idx, input_loc)

    def _handle_ConditionalJump(self, stmt_idx: int, stmt: ConditionalJump, block: Block | None):
        input1 = self._handle_expr(0, stmt.condition, stmt_idx, stmt, block)
        input2 = self._handle_expr(1, stmt.true_target, stmt_idx, stmt, block)
        input3 = self._handle_expr(2, stmt.false_target, stmt_idx, stmt, block)
        self._add_or_update_dict(self.inputs_by_stmt, stmt_idx, input1)
        self._add_or_update_dict(self.inputs_by_stmt, stmt_idx, input2)
        self._add_or_update_dict(self.inputs_by_stmt, stmt_idx, input3)

    def _handle_Return(self, stmt_idx: int, stmt: Return, block: Block | None):
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
        stmt: Statement | None,
        block: Block | None,
        is_memory=False,
    ) -> Any:
        try:
            handler = self.expr_handlers[type(expr)]
        except KeyError:
            handler = None

        if handler:
            return handler(expr_idx, expr, stmt_idx, stmt, block, is_memory=is_memory)
        return None

    # pylint: disable=unused-argument
    def _handle_Load(
        self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement, block: Block | None, is_memory=True
    ):
        load_loc = self._handle_expr(0, expr.addr, stmt_idx, stmt, block, is_memory=True)
        self._add_or_update_dict(self.derefed_at, stmt_idx, load_loc)
        return load_loc

    def _handle_CallExpr(
        self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None, is_memory=False
    ):
        args = set()
        if expr.args:
            for i, arg in enumerate(expr.args):
                self._add_or_update_set(args, self._handle_expr(i, arg, stmt_idx, stmt, block, is_memory=is_memory))

        return args

    def _handle_BinaryOp(
        self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement, block: Block | None, is_memory=False
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
        self, expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt: Statement, block: Block | None, is_memory=False
    ):
        return self._handle_expr(0, expr.operand, stmt_idx, stmt, block, is_memory=is_memory)

    def _handle_Convert(
        self, expr_idx: int, expr: Convert, stmt_idx: int, stmt: Statement, block: Block | None, is_memory=False
    ):
        return self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block, is_memory=is_memory)

    def _handle_ITE(
        self, expr_idx: int, expr: ITE, stmt_idx: int, stmt: Statement, block: Block | None, is_memory=False
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

    # pylint: disable=unused-argument
    def _handle_Tmp(
        self, expr_idx: int, expr: Tmp, stmt_idx: int, stmt: Statement, block: Block | None, is_memory=False
    ):
        if self._as_atom:
            return None
        else:
            return expr

    # pylint: disable=unused-argument
    def _handle_Register(
        self, expr_idx: int, expr: Register, stmt_idx: int, stmt: Statement, block: Block | None, is_memory=False
    ):
        if self._as_atom:
            return Register(expr.reg_offset, expr.size)
        else:
            return expr

    def _handle_Const(
        self, expr_idx: int, expr: Const, stmt_idx: int, stmt: Statement, block: Block | None, is_memory=False
    ):
        if self._as_atom:
            return MemoryLocation(expr.value, expr.size) if is_memory else ConstantSrc(expr.value, expr.size)

        return (
            expr,
            is_memory,
        )

    # pylint: disable=unused-argument
    def _handle_StackBaseOffset(
        self,
        expr_idx: int,
        expr: StackBaseOffset,
        stmt_idx: int,
        stmt: Statement,
        block: Block | None,
        is_memory=False,
    ):
        if self._as_atom:
            return MemoryLocation(
                SpOffset(self._project.arch.bits, expr.offset), expr.size * self._project.arch.byte_width
            )
        return expr
