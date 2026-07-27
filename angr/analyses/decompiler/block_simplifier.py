# pylint:disable=too-many-boolean-expressions
from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING

from angr.ailment.expression import Call, Const, Convert, Expression, Load, Register, Tmp, VirtualVariable
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment, Jump, SideEffectStatement, Statement, Store
from angr.analyses.s_propagator import SPropagator
from angr.analyses.s_reaching_definitions import SRDAModel, SReachingDefinitions
from angr.code_location import AILCodeLocation
from angr.knowledge_plugins.key_definitions import atoms
from angr.utils.ssa import has_reference_to_vvar

from .block_walkers import HasCallExprWalker, HasCallNotification
from .peephole_optimizations import (
    EXPR_OPTS,
    MULTI_STMT_OPTS,
    STMT_OPTS,
    PeepholeOptimizationExprBase,
    PeepholeOptimizationMultiStmtBase,
    PeepholeOptimizationStmtBase,
)
from .utils import (
    _PeepholeExprsWalker,
    build_stmt_opts_by_kind,
    peephole_optimize_exprs,
    peephole_optimize_multistmts,
    peephole_optimize_stmts,
)

if TYPE_CHECKING:
    from angr.ailment.block import Block
    from angr.project import Project


_l = logging.getLogger(name=__name__)


_HAS_CALL_EXPR_WALKER = HasCallExprWalker()


class PeepholeOptimizationBundle:
    """
    PeepholeOptimizationBundle describes a set of initialized peephole optimizer instances and the dispatch structures
    derived from them. This bundle of peephole optimizations is reusable across `BlockSimplifier` invocations (so we
    avoid rebuilding the same optimizer instances).
    """

    __slots__ = (
        "_params",
        "expr_opts",
        "expr_walker",
        "multistmt_opts",
        "stmt_opts",
        "stmt_opts_by_kind",
    )

    def __init__(
        self,
        project,
        kb,
        ail_manager: Manager,
        func_addr: int | None = None,
        preserve_vvar_ids: set[int] | None = None,
        type_hints: list[tuple[atoms.VirtualVariable | atoms.MemoryLocation, str]] | None = None,
        peephole_optimizations: None
        | (
            Iterable[
                type[PeepholeOptimizationStmtBase]
                | type[PeepholeOptimizationExprBase]
                | type[PeepholeOptimizationMultiStmtBase]
            ]
        ) = None,
    ):
        if peephole_optimizations is None:
            expr_classes: Iterable = EXPR_OPTS
            stmt_classes: Iterable = STMT_OPTS
            multistmt_classes: Iterable = MULTI_STMT_OPTS
        else:
            peephole_optimizations = tuple(peephole_optimizations)
            expr_classes = [cls for cls in peephole_optimizations if issubclass(cls, PeepholeOptimizationExprBase)]
            stmt_classes = [cls for cls in peephole_optimizations if issubclass(cls, PeepholeOptimizationStmtBase)]
            multistmt_classes = [
                cls for cls in peephole_optimizations if issubclass(cls, PeepholeOptimizationMultiStmtBase)
            ]

        args = (project, kb, ail_manager, func_addr, preserve_vvar_ids, type_hints)
        self.expr_opts = [cls(*args) for cls in expr_classes]
        self.stmt_opts = [cls(*args) for cls in stmt_classes]
        self.multistmt_opts = [cls(*args) for cls in multistmt_classes]
        self.stmt_opts_by_kind = build_stmt_opts_by_kind(self.stmt_opts)
        self.expr_walker = _PeepholeExprsWalker(expr_opts=self.expr_opts)
        self._params = (project, ail_manager, func_addr, preserve_vvar_ids, type_hints, peephole_optimizations)

    def matches(
        self,
        project,
        ail_manager: Manager,
        func_addr: int | None,
        preserve_vvar_ids: set[int] | None,
        type_hints: list | None,
        peephole_optimizations,
    ) -> bool:
        p_project, p_manager, p_func_addr, p_preserve, p_hints, p_opts = self._params
        return (
            p_project is project
            and p_manager is ail_manager
            and p_func_addr == func_addr
            and p_preserve is preserve_vvar_ids
            and p_hints is type_hints
            and (
                p_opts is peephole_optimizations
                or (
                    p_opts is not None
                    and peephole_optimizations is not None
                    and p_opts == tuple(peephole_optimizations)
                )
            )
        )


class BlockSimplifier:
    """
    Simplify an AIL block.

    Deliberately not an :class:`Analysis`: it is instantiated once per block, hundreds of times per decompilation,
    so it skips the analysis-factory ceremony. Instantiate it directly with the project as the first argument;
    exceptions always propagate.
    """

    def __init__(
        self,
        project: Project,
        block: Block | None,
        ail_manager: Manager,
        func_addr: int | None = None,
        stack_pointer_tracker=None,
        peephole_optimizations: None
        | (
            Iterable[
                type[PeepholeOptimizationStmtBase]
                | type[PeepholeOptimizationExprBase]
                | type[PeepholeOptimizationMultiStmtBase]
            ]
        ) = None,
        preserve_vvar_ids: set[int] | None = None,
        type_hints: list[tuple[atoms.VirtualVariable | atoms.MemoryLocation, str]] | None = None,
        cached_reaching_definitions=None,
        cached_propagator=None,
        peephole_bundle: PeepholeOptimizationBundle | None = None,
    ):
        """
        :param block:   The AIL block to simplify. Setting it to None to skip calling self._analyze(), which is useful
                        in test cases.
        :param peephole_bundle: A pre-built PeepholeOptimizationBundle to reuse. Its construction parameters must
                        match this BlockSimplifier's; callers that simplify many blocks should build one bundle and
                        pass it to every BlockSimplifier they create.
        """

        self.project = project
        self.kb = project.kb
        self.block = block
        self.func_addr = func_addr

        self._stack_pointer_tracker = stack_pointer_tracker
        self._preserve_vvar_ids = preserve_vvar_ids
        self._type_hints = type_hints
        self._ail_manager = ail_manager

        if peephole_bundle is None:
            peephole_bundle = PeepholeOptimizationBundle(
                self.project,
                self.kb,
                ail_manager,
                func_addr=self.func_addr,
                preserve_vvar_ids=self._preserve_vvar_ids,
                type_hints=self._type_hints,
                peephole_optimizations=peephole_optimizations,
            )
        self._expr_peephole_opts = peephole_bundle.expr_opts
        self._stmt_peephole_opts = peephole_bundle.stmt_opts
        self._multistmt_peephole_opts = peephole_bundle.multistmt_opts
        self._stmt_peephole_opts_by_kind = peephole_bundle.stmt_opts_by_kind

        self.result_block = None

        # cached peephole expression walker
        self._expr_peephole_walker = peephole_bundle.expr_walker

        # cached Propagator and ReachingDefinitions results. Clear them if the block is updated
        self._propagator = cached_propagator
        self._reaching_definitions = cached_reaching_definitions

        if self.block is not None:
            self._analyze()

    def _analyze(self):
        block = self.block
        ctr = 0
        max_ctr = 30

        new_block, changed = self._eliminate_self_assignments(block)
        # True once dead-assignment elimination is known to have nothing to do on the block the loop below starts
        # from -- either because it just ran over it without a change, or because its gate is off for that block.
        dead_assignments_clean = True
        if self._count_nonconstant_statements(new_block) >= 2 and self._has_propagatable_assignments(new_block):
            new_block, dead_changed = self._eliminate_dead_assignments(new_block)
            changed |= dead_changed
            dead_assignments_clean = not dead_changed
        if changed:
            self._clear_cache()
            block = new_block

        while True:
            ctr += 1
            # the entry peephole pass is only useful on the first iteration: every later iteration receives the
            # output of the previous iteration's exit peephole pass, so running peephole again on entry is redundant.
            new_block, changed = self._simplify_block_once(
                block, entry_peephole=ctr == 1, dead_assignments_clean=dead_assignments_clean
            )
            if not changed:
                break

            assert block is not None
            # TODO: We should be able to get rid of this check if we rely on Block.likes() to determine whether the
            # block has changed or not.
            if new_block.likes(block):
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

    def _compute_propagation(self, block) -> SPropagator:
        if self._propagator is None:
            self._propagator = SPropagator(
                self.project,
                subject=block,
                func_addr=self.func_addr,
                stack_pointer_tracker=self._stack_pointer_tracker,
                ail_manager=self._ail_manager,
            )
        return self._propagator

    def _compute_reaching_definitions(self, block) -> SRDAModel:
        if self._reaching_definitions is None:
            self._reaching_definitions = SReachingDefinitions(
                self.project,
                subject=block,
                track_tmps=True,
                func_addr=self.func_addr,
            ).model
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

    def _simplify_block_once(
        self, block, entry_peephole: bool = True, dead_assignments_clean: bool = False
    ) -> tuple[Block, bool]:
        """
        Run one round of simplification. Returns the new block and if any step reported a change.

        :param dead_assignments_clean:  True if dead-assignment elimination is known to have nothing to do on
                                        ``block`` as passed in. Only meaningful together with ``entry_peephole``.
        """
        changed = False
        # True once we know ``block`` is untouched and already at the fixpoint of every pass that has run over it:
        # re-running those passes on it cannot report a change.
        clean = False
        if entry_peephole:
            block, peephole_changed, exprs_updated = self._peephole_optimize(block)
            changed |= peephole_changed
            clean = dead_assignments_clean and not peephole_changed and not exprs_updated

        nonconstant_stmts = self._count_nonconstant_statements(block)
        has_propagatable_assignments = self._has_propagatable_assignments(block)

        # only call propagation if something is potentially propagatable
        if nonconstant_stmts >= 2 and has_propagatable_assignments:
            propagator = self._compute_propagation(block)
            new_block = block
            if propagator.model is not None:
                replacements = propagator.model.replacements
                if replacements:
                    replaced, new_block = self.replace_and_build(
                        block, replacements, self._ail_manager, replace_registers=True
                    )
                    changed |= replaced
                    new_block, self_assign_changed = self._eliminate_self_assignments(new_block)
                    changed |= self_assign_changed
                    self._clear_cache()
        else:
            new_block = block

        if clean and new_block is block:
            return block, False

        if nonconstant_stmts >= 2 and has_propagatable_assignments:
            new_block, dead_changed = self._eliminate_dead_assignments(new_block)
            changed |= dead_changed

        new_block, peephole_changed, _ = self._peephole_optimize(new_block)
        return new_block, changed | peephole_changed

    @staticmethod
    def replace_and_build(
        block: Block,
        replacements: Mapping[AILCodeLocation, Mapping[Expression, Expression]],
        ail_manager: Manager,
        replace_assignment_dsts: bool = False,
        replace_loads: bool = False,
        gp: int | None = None,
        replace_registers: bool = True,
        max_expr_depth: int | None = 13,
    ) -> tuple[bool, Block]:
        new_statements = block.statements[::]
        replaced = False

        for codeloc, repls in replacements.items():
            for old, new in repls.items():
                new = new.deep_copy(ail_manager)
                assert codeloc.stmt_idx is not None
                stmt = new_statements[codeloc.stmt_idx]
                if (
                    not replace_loads
                    and isinstance(old, Load)
                    and not isinstance(stmt, SideEffectStatement)
                    and not (gp is not None and isinstance(new, Const) and new.value == gp)
                ):
                    # skip memory-based replacement for non-Call and non-gp-loading statements
                    continue
                if isinstance(stmt, SideEffectStatement) and stmt.expr == old:
                    # the replacement must be a call, since replacements can only be expressions
                    assert isinstance(new, Call)
                    r = True
                    new_stmt = SideEffectStatement(
                        stmt.idx, new, ret_expr=stmt.ret_expr, fp_ret_expr=stmt.fp_ret_expr, **stmt.tags
                    )
                else:
                    # replace the expressions involved in this statement

                    if not replace_registers and isinstance(old, Register):
                        # don't replace
                        r = False
                        new_stmt = None
                    elif isinstance(old, VirtualVariable) and has_reference_to_vvar(stmt, old.varid):
                        # never replace an l-value with an r-value
                        r = False
                        new_stmt = None
                    elif isinstance(stmt, SideEffectStatement) and isinstance(new, Call) and old == stmt.ret_expr:
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
                            if (
                                r
                                and max_expr_depth is not None
                                and new_src.depth >= old.depth
                                and new_src.depth > max_expr_depth
                            ):
                                # avoid replacing if the new expression is too deep, to prevent exponential blowup
                                r = False
                        if r:
                            new_stmt = Assignment(stmt.idx, stmt.dst, new_src, **stmt.tags)
                    else:
                        r, new_stmt = stmt.replace(old, new)
                        if (
                            r
                            and max_expr_depth is not None
                            and new_stmt.depth >= stmt.depth
                            and new_stmt.depth > max_expr_depth - 1
                        ):
                            # avoid replacing if the new statement is too deep, to prevent exponential blowup
                            r = False

                if r:
                    assert new_stmt is not None
                    replaced = True
                    new_statements[codeloc.stmt_idx] = new_stmt

        if not replaced:
            return False, block

        new_block = block.copy()
        new_block.statements = new_statements
        return True, new_block

    @staticmethod
    def _eliminate_self_assignments(block) -> tuple[Block, bool]:
        new_statements = []

        for stmt in block.statements:
            if isinstance(stmt, Assignment):
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

        if len(new_statements) == len(block.statements):
            # nothing was eliminated; keep the original block
            return block, False
        return block.copy(statements=new_statements), True

    def _eliminate_dead_assignments(self, block) -> tuple[Block, bool]:
        def _statement_has_calls(stmt: Statement) -> bool:
            """
            Check if a statement has any Call expressions.
            """
            try:
                _HAS_CALL_EXPR_WALKER.walk_statement(stmt)
            except HasCallNotification:
                return True
            return False

        def _expression_has_calls(expr: Expression) -> bool:
            """
            Check if an expression has any Call expressions.
            """
            try:
                _HAS_CALL_EXPR_WALKER.walk_expression(expr)
            except HasCallNotification:
                return True
            return False

        new_statements = []
        if not block.statements:
            return block, False

        rd = self._compute_reaching_definitions(block)
        block_loc = (block.addr, block.idx)

        # Find dead assignments
        dead_defs_stmt_idx = set()
        all_defs = rd.get_all_tmp_definitions(block_loc)
        for d in all_defs:
            assert not d.codeloc.is_extern
            assert not d.dummy

            uses = rd.get_tmp_uses(d.atom, block_loc)
            if not uses:
                dead_defs_stmt_idx.add(d.codeloc.stmt_idx)

        used_tmps: set[int] = set()
        # micro optimization: if all statements that use a tmp are going to be removed, we remove this tmp as well
        for tmp, used_locs in rd.all_tmp_uses[block_loc].items():
            used_at = {stmt_idx for _, stmt_idx in used_locs}
            if used_at.issubset(dead_defs_stmt_idx):  # noqa:SIM102
                # cannot remove this tmp if any use sites involve call expressions; this is basically a duplicate of
                # the logic in the larger loop below
                if all(not _statement_has_calls(block.statements[i]) for i in used_at):
                    continue
            used_tmps.add(tmp.tmp_idx)

        # Remove dead assignments
        changed = False
        for idx, stmt in enumerate(block.statements):
            if isinstance(stmt, Assignment):
                # tmps can't execute new code
                if (isinstance(stmt.dst, Tmp) and stmt.dst.tmp_idx not in used_tmps) or idx in dead_defs_stmt_idx:
                    # is it assigning to an unused tmp or a dead virgin?

                    # does .src involve any Call expressions? if so, we cannot remove it
                    if not _expression_has_calls(stmt.src):
                        changed = True
                        continue

                    if isinstance(stmt.dst, Tmp) and isinstance(stmt.src, Call):
                        # eliminate the assignment and replace it with the call
                        stmt = SideEffectStatement(self._ail_manager.next_atom(), stmt.src, **stmt.tags)
                        changed = True

                if isinstance(stmt, Assignment) and stmt.src == stmt.dst:
                    changed = True
                    continue

            new_statements.append(stmt)

        if not changed:
            # nothing was eliminated; keep the original block
            return block, False
        return block.copy(statements=new_statements), True

    #
    # Peephole optimization
    #

    def _peephole_optimize(self, block) -> tuple[Block, bool, bool]:
        """
        Run all three peephole optimization levels on the block.

        :return:    (block, changed, exprs_updated), where ``changed`` is True if any optimization applied and
                    ``exprs_updated`` is True if the expression walker rewrote any expression.
        """
        exprs_updated = peephole_optimize_exprs(block, self._expr_peephole_opts, walker=self._expr_peephole_walker)

        # run statement-level optimizations
        statements, stmts_updated = peephole_optimize_stmts(
            block,
            self._stmt_peephole_opts,
            stmt_opts_by_kind=self._stmt_peephole_opts_by_kind,
            fixpoint_exprs=self._expr_peephole_walker.fixpoint_stmts,
        )

        new_block = block.copy(statements=statements) if stmts_updated else block

        statements, multi_stmts_updated = peephole_optimize_multistmts(new_block, self._multistmt_peephole_opts)

        if multi_stmts_updated:
            new_block = new_block.copy(statements=statements)
        return new_block, stmts_updated or multi_stmts_updated, exprs_updated
