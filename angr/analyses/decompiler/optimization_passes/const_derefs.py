# pylint:disable=unused-argument
from __future__ import annotations
from typing import TYPE_CHECKING
import logging

from angr.ailment import Block, AILBlockWalker
from angr.ailment.expression import Load, Const, BinaryOp, UnaryOp
from angr.ailment.statement import Statement, Assignment, Call, ConditionalJump

from angr.analyses.decompiler.ailgraph_walker import AILGraphWalker
from .optimization_pass import OptimizationPass, OptimizationPassStage

if TYPE_CHECKING:
    from angr import Project


_l = logging.getLogger(name=__name__)


class BlockWalker(AILBlockWalker):
    def __init__(self, project: Project):
        super().__init__()
        self._project = project
        self._new_block: Block | None = None  # output

    def walk(self, block: Block):
        self._new_block = None
        super().walk(block)
        return self._new_block

    def _addr_belongs_to_ro_region(self, addr: int) -> bool:
        section = self._project.loader.find_section_containing(addr)
        if section is not None:
            return not section.is_writable
        segment = self._project.loader.find_segment_containing(addr)
        if segment is not None:
            return not segment.is_writable
        return False

    def _addr_belongs_to_got(self, addr: int) -> bool:
        section = self._project.loader.find_section_containing(addr)
        if section is not None:
            return section.name and "got" in section.name
        return False

    def _addr_belongs_to_object(self, addr: int) -> bool:
        obj = self._project.loader.find_object_containing(addr)
        return obj is not None

    def _handle_stmt(self, stmt_idx: int, stmt: Statement, block: Block):
        r = super()._handle_stmt(stmt_idx, stmt, block)
        if r is not None:
            # replace the original statement
            if self._new_block is None:
                self._new_block = block.copy()
            self._new_block.statements[stmt_idx] = r

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Block):
        new_dst = self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        new_src = self._handle_expr(1, stmt.src, stmt_idx, stmt, block)

        if new_dst is not None or new_src is not None:
            return Assignment(
                stmt.idx,
                stmt.dst if new_dst is None else new_dst,
                stmt.src if new_src is None else new_src,
                **stmt.tags,
            )
        return None

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        new_target = self._handle_expr(-1, expr.target, stmt_idx, stmt, block)

        new_args = None
        if expr.args:
            i = 0
            new_exprs = []
            while i < len(expr.args):
                arg = expr.args[i]
                new_expr = self._handle_expr(i, arg, stmt_idx, stmt, block)
                new_exprs.append(new_expr)
                i += 1
            if any(expr_ is not None for expr_ in new_exprs):
                # create new args
                new_args = [
                    (new_arg if new_arg is not None else old_arg) for new_arg, old_arg in zip(new_exprs, expr.args)
                ]

        if new_target is not None or new_args is not None:
            # create a new call expr
            return Call(
                expr.idx,
                expr.target if new_target is None else new_target,
                calling_convention=expr.calling_convention,
                prototype=expr.prototype,
                args=new_args if new_args is not None else expr.args,
                ret_expr=expr.ret_expr,
                **expr.tags,
            )
        return None

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block):
        new_target = self._handle_expr(-1, stmt.target, stmt_idx, stmt, block)

        new_args = None
        if stmt.args:
            i = 0
            new_exprs = []
            while i < len(stmt.args):
                arg = stmt.args[i]
                new_expr = self._handle_expr(i, arg, stmt_idx, stmt, block)
                new_exprs.append(new_expr)
                i += 1
            if any(expr is not None for expr in new_exprs):
                # create new args
                new_args = [
                    (new_arg if new_arg is not None else old_arg) for new_arg, old_arg in zip(new_exprs, stmt.args)
                ]

        if new_target is not None or new_args is not None:
            # create a new statement
            return Call(
                stmt.idx,
                stmt.target if new_target is None else new_target,
                calling_convention=stmt.calling_convention,
                prototype=stmt.prototype,
                args=new_args if new_args is not None else stmt.args,
                ret_expr=stmt.ret_expr,
                **stmt.tags,
            )
        return None

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement, block: Block):
        if isinstance(expr.addr, Const):
            # *(const_addr)
            # does it belong to a read-only section/segment?
            is_got = self._addr_belongs_to_got(expr.addr.value)
            if is_got or self._addr_belongs_to_ro_region(expr.addr.value):
                try:
                    w = self._project.loader.memory.unpack_word(
                        expr.addr.value,
                        expr.addr.bits // self._project.arch.byte_width,
                        endness=self._project.arch.memory_endness,
                    )
                except KeyError:
                    # we don't have enough bytes to read out
                    w = None
                if w is not None and not (is_got and w == 0):
                    # nice! replace it with the actual value
                    return Const(None, None, w, expr.bits, **expr.tags)
        elif (
            isinstance(expr.addr, Load)
            and expr.addr.bits == self._project.arch.bits
            and isinstance(expr.addr.addr, Const)
            and (
                # *(*(const_addr))
                # does it belong to a read-only section/segment?
                self._addr_belongs_to_got(expr.addr.addr.value)
                or self._addr_belongs_to_ro_region(expr.addr.addr.value)
            )
        ):
            w = self._project.loader.memory.unpack_word(
                expr.addr.addr.value,
                expr.addr.addr.bits // self._project.arch.byte_width,
                endness=self._project.arch.memory_endness,
            )
            if w is not None and self._addr_belongs_to_object(w):
                # nice! replace it with a load from that address
                return Load(
                    expr.idx,
                    Const(None, None, w, expr.addr.size, **expr.addr.addr.tags),
                    expr.size,
                    expr.endness,
                    variable=expr.variable,
                    variable_offset=expr.variable_offset,
                    guard=expr.guard,
                    alt=expr.alt,
                    **expr.tags,
                )

        return super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_BinaryOp(self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement, block: Block):
        new_operands = [
            self._handle_expr(0, expr.operands[0], stmt_idx, stmt, block),
            self._handle_expr(1, expr.operands[1], stmt_idx, stmt, block),
        ]
        if any(op is not None for op in new_operands):
            new_operands = [
                (new_op if new_op is not None else old_op) for new_op, old_op in zip(new_operands, expr.operands)
            ]
            return BinaryOp(
                expr.idx,
                expr.op,
                new_operands,
                expr.signed,
                variable=expr.variable,
                variable_offset=expr.variable_offset,
                floating_point=expr.floating_point,
                rounding_mode=expr.rounding_mode,
                **expr.tags,
            )
        return None

    def _handle_UnaryOp(self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement, block: Block):
        new_operand = self._handle_expr(0, expr.operands[0], stmt_idx, stmt, block)
        if new_operand is not None:
            return UnaryOp(
                expr.idx,
                expr.op,
                new_operand,
                expr.signed,
                variable=expr.variable,
                variable_offset=expr.variable_offset,
                bits=expr.bits,
                **expr.tags,
            )
        return None

    def _handle_ConditionalJump(self, stmt_idx: int, stmt: ConditionalJump, block: Block):
        new_cond = self._handle_expr(0, stmt.condition, stmt_idx, stmt, block)
        new_true_target = self._handle_expr(1, stmt.true_target, stmt_idx, stmt, block)
        new_false_target = self._handle_expr(2, stmt.false_target, stmt_idx, stmt, block)

        if new_cond is not None or new_true_target is not None or new_false_target is not None:
            return ConditionalJump(
                stmt.idx,
                new_cond if new_cond is not None else stmt.condition,
                new_true_target if new_true_target is not None else stmt.true_target,
                new_false_target if new_false_target is not None else stmt.false_target,
                true_target_idx=stmt.true_target_idx,
                false_target_idx=stmt.false_target_idx,
                **stmt.tags,
            )
        return None


class ConstantDereferencesSimplifier(OptimizationPass):
    """
    Makes the following simplifications::

        *(*(const_addr))  ==>  *(value) iff  *const_addr == value
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_SINGLE_BLOCK_SIMPLIFICATION
    NAME = "Simplify constant dereferences"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self._block_walker = BlockWalker(self.project)
        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        # walk the entire graph and traverse each expression
        walker = AILGraphWalker(self._graph, handler=self._walk_block, replace_nodes=True)
        walker.walk()

    def _walk_block(self, block: Block) -> Block | None:
        return self._block_walker.walk(block)
