# pylint:disable=too-many-boolean-expressions
from __future__ import annotations
import logging
from typing import TYPE_CHECKING
from collections.abc import Iterable

from ailment.statement import Statement, Assignment, Call, Store, Jump
from ailment.expression import Tmp, Load, Const, Register, Convert
from ailment import AILBlockWalkerBase

from angr.code_location import ExternalCodeLocation, CodeLocation

from ...analyses.s_propagator import SPropagatorAnalysis
from ...analyses.s_reaching_definitions import SReachingDefinitionsAnalysis, SRDAModel
from .. import Analysis, register_analysis
from .peephole_optimizations import (
    MULTI_STMT_OPTS,
    STMT_OPTS,
    EXPR_OPTS,
    PeepholeOptimizationStmtBase,
    PeepholeOptimizationExprBase,
    PeepholeOptimizationMultiStmtBase,
)
from .utils import peephole_optimize_exprs, peephole_optimize_stmts, peephole_optimize_multistmts

if TYPE_CHECKING:
    from angr.knowledge_plugins.key_definitions.live_definitions import Definition
    from ailment.block import Block


_l = logging.getLogger(name=__name__)


class HasCallExprWalker(AILBlockWalkerBase):
    """
    Test if an expression contains a call expression inside.
    """

    def __init__(self):
        super().__init__()
        self.has_call_expr = False

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):  # pylint:disable=unused-argument
        self.has_call_expr = True

    def _handle_CallExpr(  # pylint:disable=unused-argument
        self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        self.has_call_expr = True


class BlockSimplifier(Analysis):
    """
    Simplify an AIL block.
    """

    def __init__(
        self,
        block: Block | None,
        func_addr: int | None = None,
        remove_dead_memdefs=False,
        stack_pointer_tracker=None,
        peephole_optimizations: None | (
            Iterable[type[PeepholeOptimizationStmtBase] | type[PeepholeOptimizationExprBase]]
        ) = None,
        cached_reaching_definitions=None,
        cached_propagator=None,
    ):
        """
        :param block:   The AIL block to simplify. Setting it to None to skip calling self._analyze(), which is useful
                        in test cases.
        """

        self.block = block
        self.func_addr = func_addr

        self._remove_dead_memdefs = remove_dead_memdefs
        self._stack_pointer_tracker = stack_pointer_tracker

        if peephole_optimizations is None:
            self._expr_peephole_opts = [cls(self.project, self.kb, self.func_addr) for cls in EXPR_OPTS]
            self._stmt_peephole_opts = [cls(self.project, self.kb, self.func_addr) for cls in STMT_OPTS]
            self._multistmt_peephole_opts = [cls(self.project, self.kb, self.func_addr) for cls in MULTI_STMT_OPTS]
        else:
            self._expr_peephole_opts = [
                cls(self.project, self.kb, self.func_addr)
                for cls in peephole_optimizations
                if issubclass(cls, PeepholeOptimizationExprBase)
            ]
            self._stmt_peephole_opts = [
                cls(self.project, self.kb, self.func_addr)
                for cls in peephole_optimizations
                if issubclass(cls, PeepholeOptimizationStmtBase)
            ]
            self._multistmt_peephole_opts = [
                cls(self.project, self.kb, self.func_addr)
                for cls in peephole_optimizations
                if issubclass(cls, PeepholeOptimizationMultiStmtBase)
            ]

        self.result_block = None

        # cached Propagator and ReachingDefinitions results. Clear them if the block is updated
        self._propagator = cached_propagator
        self._reaching_definitions = cached_reaching_definitions

        if self.block is not None:
            self._analyze()

    def _analyze(self):
        block = self.block
        ctr = 0
        max_ctr = 30

        new_block = self._eliminate_self_assignments(block)
        if self._count_nonconstant_statements(new_block) >= 2 and self._has_propagatable_assignments(new_block):
            new_block = self._eliminate_dead_assignments(new_block)
        if new_block != block:
            self._clear_cache()
            block = new_block

        while True:
            ctr += 1
            # print(str(block))
            new_block = self._simplify_block_once(block)
            # print()
            # print(str(new_block))
            if new_block == block:
                break
            self._clear_cache()
            block = new_block
            if ctr >= max_ctr:
                _l.error(
                    "Simplification does not reach a fixed point after %d iterations. "
                    "Block comparison is probably incorrect.",
                    max_ctr,
                )
                break

        self.result_block = block

    def _compute_propagation(self, block):
        if self._propagator is None:
            self._propagator = self.project.analyses[SPropagatorAnalysis].prep()(
                subject=block,
                func_addr=self.func_addr,
                stack_pointer_tracker=self._stack_pointer_tracker,
            )
        return self._propagator

    def _compute_reaching_definitions(self, block) -> SRDAModel:
        if self._reaching_definitions is None:
            self._reaching_definitions = (
                self.project.analyses[SReachingDefinitionsAnalysis]
                .prep()(
                    subject=block,
                    track_tmps=True,
                    stack_pointer_tracker=self._stack_pointer_tracker,
                    func_addr=self.func_addr,
                )
                .model
            )
        return self._reaching_definitions

    def _clear_cache(self):
        self._reaching_definitions = None
        self._propagator = None

    @staticmethod
    def _has_propagatable_assignments(block) -> bool:
        return any(isinstance(stmt, (Assignment, Store)) for stmt in block.statements)

    @staticmethod
    def _count_nonconstant_statements(block) -> int:
        return sum(1 for stmt in block.statements if not (isinstance(stmt, Jump) and isinstance(stmt.target, Const)))

    def _simplify_block_once(self, block):
        block = self._peephole_optimize(block)

        nonconstant_stmts = self._count_nonconstant_statements(block)
        has_propagatable_assignments = self._has_propagatable_assignments(block)

        # propagator
        if nonconstant_stmts >= 2 and has_propagatable_assignments:
            propagator = self._compute_propagation(block)
            new_block = block
            if propagator.model is not None:
                replacements = propagator.model.replacements
                if replacements:
                    _, new_block = self._replace_and_build(block, replacements, replace_registers=True)
                    new_block = self._eliminate_self_assignments(new_block)
                    self._clear_cache()
        else:
            # Skipped calling Propagator
            new_block = block

        if nonconstant_stmts >= 2 and has_propagatable_assignments:
            new_block = self._eliminate_dead_assignments(new_block)

        return self._peephole_optimize(new_block)

    @staticmethod
    def _replace_and_build(
        block,
        replacements,
        replace_assignment_dsts: bool = False,
        replace_loads: bool = False,
        gp: int | None = None,
        replace_registers: bool = True,
    ) -> tuple[bool, Block]:
        new_statements = block.statements[::]
        replaced = False

        stmts_to_remove = set()
        for codeloc, repls in replacements.items():
            for old, new in repls.items():
                stmt_to_remove = None
                if isinstance(new, dict):
                    stmt_to_remove = new["stmt_to_remove"]
                    new = new["expr"]

                stmt = new_statements[codeloc.stmt_idx]
                if (
                    not replace_loads
                    and isinstance(old, Load)
                    and not isinstance(stmt, Call)
                    and not (gp is not None and isinstance(new, Const) and new.value == gp)
                ):
                    # skip memory-based replacement for non-Call and non-gp-loading statements
                    continue
                if stmt == old:
                    # replace this statement
                    r = True
                    new_stmt = new
                else:
                    # replace the expressions involved in this statement

                    if not replace_registers and isinstance(old, Register):
                        # don't replace
                        r = False
                        new_stmt = None
                    elif isinstance(stmt, Call) and isinstance(new, Call) and old == stmt.ret_expr:
                        # special case: do not replace the ret_expr of a call statement to another call statement
                        r = False
                        new_stmt = None
                    elif isinstance(stmt, Assignment) and not replace_assignment_dsts:
                        # special case: do not replace the dst
                        new_stmt = None
                        if stmt.src == old:
                            r = True
                            new_src = new.copy()
                        else:
                            r, new_src = stmt.src.replace(old, new)
                        if r:
                            new_stmt = Assignment(stmt.idx, stmt.dst, new_src, **stmt.tags)
                    else:
                        r, new_stmt = stmt.replace(old, new)

                if r:
                    replaced = True
                    new_statements[codeloc.stmt_idx] = new_stmt
                    if stmt_to_remove is not None:
                        stmts_to_remove.add(stmt_to_remove)

        if not replaced:
            return False, block

        if stmts_to_remove:
            stmt_ids_to_remove = {a.stmt_idx for a in stmts_to_remove}
            all_stmts = {idx: stmt for idx, stmt in enumerate(new_statements) if idx not in stmt_ids_to_remove}
            filtered_stmts = sorted(all_stmts.items(), key=lambda x: x[0])
            new_statements = [stmt for _, stmt in filtered_stmts]

        new_block = block.copy()
        new_block.statements = new_statements
        return True, new_block

    @staticmethod
    def _eliminate_self_assignments(block):
        new_statements = []

        for stmt in block.statements:
            if type(stmt) is Assignment:
                if stmt.dst.likes(stmt.src):
                    continue
                if (
                    isinstance(stmt.dst, Register)
                    and isinstance(stmt.src, Convert)
                    and isinstance(stmt.src.operand, Register)
                ) and (
                    stmt.dst.size == stmt.src.size
                    and stmt.dst.reg_offset == stmt.src.operand.reg_offset
                    and not stmt.src.is_signed
                ):
                    # ignore statements like edi = convert(rdi, 32)
                    continue
            new_statements.append(stmt)

        return block.copy(statements=new_statements)

    def _eliminate_dead_assignments(self, block):
        new_statements = []
        if not block.statements:
            return block

        rd = self._compute_reaching_definitions(block)
        block_loc = CodeLocation(block.addr, None, block_idx=block.idx)

        # Find dead assignments
        dead_defs_stmt_idx = set()
        all_defs: Iterable[Definition] = rd.get_all_tmp_definitions(block_loc)
        for d in all_defs:
            assert not isinstance(d.codeloc, ExternalCodeLocation)
            assert not d.dummy

            uses = rd.get_tmp_uses(d.atom, block_loc)
            if not uses:
                dead_defs_stmt_idx.add(d.codeloc.stmt_idx)

        used_tmps: set[int] = set()
        # micro optimization: if all statements that use a tmp are going to be removed, we remove this tmp as well
        for tmp, used_locs in rd.all_tmp_uses[block_loc].items():
            used_at = {stmt_idx for _, stmt_idx in used_locs}
            if used_at.issubset(dead_defs_stmt_idx):
                continue
            used_tmps.add(tmp.tmp_idx)

        # Remove dead assignments
        for idx, stmt in enumerate(block.statements):
            if type(stmt) is Assignment:
                # tmps can't execute new code
                if type(stmt.dst) is Tmp and stmt.dst.tmp_idx not in used_tmps:
                    continue

                # is it a dead virgin?
                if idx in dead_defs_stmt_idx:
                    # does .src involve any Call expressions? if so, we cannot remove it
                    walker = HasCallExprWalker()
                    walker.walk_expression(stmt.src)
                    if not walker.has_call_expr:
                        continue

                if stmt.src == stmt.dst:
                    continue

            new_statements.append(stmt)

        return block.copy(statements=new_statements)

    #
    # Peephole optimization
    #

    def _peephole_optimize(self, block):
        # expressions are updated in place
        peephole_optimize_exprs(block, self._expr_peephole_opts)

        # run statement-level optimizations
        statements, stmts_updated = peephole_optimize_stmts(block, self._stmt_peephole_opts)

        new_block = block.copy(statements=statements) if stmts_updated else block

        statements, multi_stmts_updated = peephole_optimize_multistmts(new_block, self._multistmt_peephole_opts)

        if not multi_stmts_updated:
            return new_block
        return new_block.copy(statements=statements)


register_analysis(BlockSimplifier, "AILBlockSimplifier")
