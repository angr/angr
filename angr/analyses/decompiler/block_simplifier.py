# pylint:disable=too-many-boolean-expressions
import logging
from typing import Optional, Union, Type, Iterable, Tuple, Set, TYPE_CHECKING

from ailment.statement import Statement, Assignment, Call, Store, Jump
from ailment.expression import Expression, Tmp, Load, Const, Register, Convert

from ...engines.light.data import SpOffset
from ...knowledge_plugins.key_definitions.constants import OP_AFTER
from ...knowledge_plugins.key_definitions import atoms
from ...analyses.reaching_definitions.external_codeloc import ExternalCodeLocation
from ...analyses.propagator import PropagatorAnalysis
from ...analyses.reaching_definitions import ReachingDefinitionsAnalysis
from ...errors import SimMemoryMissingError
from .. import Analysis, register_analysis
from .peephole_optimizations import STMT_OPTS, EXPR_OPTS, PeepholeOptimizationStmtBase, PeepholeOptimizationExprBase
from .ailblock_walker import AILBlockWalker

if TYPE_CHECKING:
    from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
    from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions, Definition
    from ailment.block import Block


_l = logging.getLogger(name=__name__)


class BlockSimplifier(Analysis):
    """
    Simplify an AIL block.
    """

    def __init__(
        self,
        block: Optional["Block"],
        func_addr: Optional[int] = None,
        remove_dead_memdefs=False,
        stack_pointer_tracker=None,
        peephole_optimizations: Optional[
            Iterable[Union[Type[PeepholeOptimizationStmtBase], Type[PeepholeOptimizationExprBase]]]
        ] = None,
        stack_arg_offsets: Optional[Set[Tuple[int, int]]] = None,
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
        self._stack_arg_offsets = stack_arg_offsets
        self._stack_pointer_tracker = stack_pointer_tracker

        if peephole_optimizations is None:
            self._expr_peephole_opts = [cls(self.project, self.kb, self.func_addr) for cls in EXPR_OPTS]
            self._stmt_peephole_opts = [cls(self.project, self.kb, self.func_addr) for cls in STMT_OPTS]
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
            self._propagator = self.project.analyses[PropagatorAnalysis].prep()(
                block=block,
                func_addr=self.func_addr,
                stack_pointer_tracker=self._stack_pointer_tracker,
            )
        return self._propagator

    def _compute_reaching_definitions(self, block):
        if self._reaching_definitions is None:
            self._reaching_definitions = self.project.analyses[ReachingDefinitionsAnalysis].prep()(
                subject=block, track_tmps=True, observation_points=[("node", block.addr, OP_AFTER)]
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
        nonconstant_stmts = self._count_nonconstant_statements(block)
        has_propagatable_assignments = self._has_propagatable_assignments(block)

        # propagator
        if nonconstant_stmts >= 2 and has_propagatable_assignments:
            propagator = self._compute_propagation(block)
            replacements = list(propagator._states.values())[0]._replacements
            if replacements:
                _, new_block = self._replace_and_build(block, replacements, replace_registers=True)
                new_block = self._eliminate_self_assignments(new_block)
                self._clear_cache()
            else:
                new_block = block
        else:
            # Skipped calling Propagator
            new_block = block

        if nonconstant_stmts >= 2 and has_propagatable_assignments:
            new_block = self._eliminate_dead_assignments(new_block)

        new_block = self._peephole_optimize(new_block)
        return new_block

    @staticmethod
    def _replace_and_build(
        block,
        replacements,
        replace_assignment_dsts: bool = False,
        replace_loads: bool = False,
        gp: Optional[int] = None,
        replace_registers: bool = True,
    ) -> Tuple[bool, "Block"]:
        new_statements = block.statements[::]
        replaced = False

        for codeloc, repls in replacements.items():
            for old, new in repls.items():
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

        if not replaced:
            return False, block

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
                ):
                    if (
                        stmt.dst.size == stmt.src.size
                        and stmt.dst.reg_offset == stmt.src.operand.reg_offset
                        and not stmt.src.is_signed
                    ):
                        # ignore statements like edi = convert(rdi, 32)
                        continue
            new_statements.append(stmt)

        new_block = block.copy(statements=new_statements)
        return new_block

    def _eliminate_dead_assignments(self, block):
        new_statements = []
        if not block.statements:
            return block

        rd = self._compute_reaching_definitions(block)
        live_defs: "LiveDefinitions" = rd.one_result

        # Find dead assignments
        dead_defs_stmt_idx = set()
        all_defs: Iterable["Definition"] = rd.all_definitions
        stackarg_offsets = {tpl[1] for tpl in self._stack_arg_offsets} if self._stack_arg_offsets is not None else None
        for d in all_defs:
            if isinstance(d.codeloc, ExternalCodeLocation) or d.dummy:
                continue
            if isinstance(d.atom, atoms.MemoryLocation):
                if not self._remove_dead_memdefs:
                    # we always remove definitions for stack arguments
                    if stackarg_offsets is not None and isinstance(d.atom.addr, atoms.SpOffset):
                        if d.atom.addr.offset not in stackarg_offsets:
                            continue
                    else:
                        continue

            if isinstance(d.atom, atoms.Tmp):
                uses = live_defs.tmp_uses[d.atom.tmp_idx]
                if not uses:
                    dead_defs_stmt_idx.add(d.codeloc.stmt_idx)
            else:
                uses = rd.all_uses.get_uses(d)
                if not uses:
                    # it's entirely possible that at the end of the block, a register definition is not used.
                    # however, it might be used in future blocks.
                    # so we only remove a definition if the definition is not alive anymore at the end of the block
                    defs_ = set()
                    if isinstance(d.atom, atoms.Register):
                        try:
                            vs: "MultiValues" = live_defs.register_definitions.load(d.atom.reg_offset, size=d.atom.size)
                        except SimMemoryMissingError:
                            vs = None
                    elif isinstance(d.atom, atoms.MemoryLocation) and isinstance(d.atom.addr, SpOffset):
                        stack_addr = live_defs.stack_offset_to_stack_addr(d.atom.addr.offset)
                        try:
                            vs: "MultiValues" = live_defs.stack_definitions.load(
                                stack_addr, size=d.atom.size, endness=d.atom.endness
                            )
                        except SimMemoryMissingError:
                            vs = None
                    else:
                        continue
                    if vs is not None:
                        for values in vs.values():
                            for value in values:
                                defs_.update(live_defs.extract_defs(value))

                    if d not in defs_:
                        dead_defs_stmt_idx.add(d.codeloc.stmt_idx)

        used_tmps = set()
        # micro optimization: if all statements that use a tmp are going to be removed, we remove this tmp as well
        for tmp, used_locs in rd.one_result.tmp_uses.items():
            used_at = {loc.stmt_idx for loc in used_locs}
            if used_at.issubset(dead_defs_stmt_idx):
                continue
            used_tmps.add(tmp)

        # Remove dead assignments
        for idx, stmt in enumerate(block.statements):
            if type(stmt) is Assignment:
                if type(stmt.dst) is Tmp:
                    if stmt.dst.tmp_idx not in used_tmps:
                        continue

                # is it a dead virgin?
                if idx in dead_defs_stmt_idx:
                    continue

                if stmt.src == stmt.dst:
                    continue

            new_statements.append(stmt)

        new_block = block.copy(statements=new_statements)
        return new_block

    #
    # Peephole optimization
    #

    def _peephole_optimize(self, block):
        # expressions are updated in place
        self._peephole_optimize_exprs(block, self._expr_peephole_opts)

        statements, stmts_updated = self._peephole_optimize_stmts(block, self._stmt_peephole_opts)

        if not stmts_updated:
            return block
        new_block = block.copy(statements=statements)
        return new_block

    @staticmethod
    def _peephole_optimize_exprs(block, expr_opts):
        class _any_update:
            v = False

        def _handle_expr(
            expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement, block
        ) -> Optional[Expression]:
            old_expr = expr

            redo = True
            while redo:
                redo = False
                for expr_opt in expr_opts:
                    if isinstance(expr, expr_opt.expr_classes):
                        r = expr_opt.optimize(expr)
                        if r is not None and r is not expr:
                            expr = r
                            redo = True
                            break

            if expr is not old_expr:
                _any_update.v = True
                # continue to process the expr
                r = AILBlockWalker._handle_expr(walker, expr_idx, expr, stmt_idx, stmt, block)
                return expr if r is None else r

            return AILBlockWalker._handle_expr(walker, expr_idx, expr, stmt_idx, stmt, block)

        # run expression optimizers
        walker = AILBlockWalker()
        walker._handle_expr = _handle_expr
        walker.walk(block)

        return _any_update.v

    @staticmethod
    def _peephole_optimize_stmts(block, stmt_opts):
        any_update = False
        statements = []

        # run statement optimizers
        for stmt in block.statements:
            old_stmt = stmt
            redo = True
            while redo:
                redo = False
                for opt in stmt_opts:
                    if isinstance(stmt, opt.stmt_classes):
                        r = opt.optimize(stmt)
                        if r is not None and r is not stmt:
                            stmt = r
                            redo = True
                            break

            if stmt is not None and stmt is not old_stmt:
                statements.append(stmt)
                any_update = True
            else:
                statements.append(old_stmt)

        return statements, any_update


register_analysis(BlockSimplifier, "AILBlockSimplifier")
