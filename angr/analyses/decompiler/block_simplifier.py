# pylint:disable=too-many-boolean-expressions
import logging
from typing import Optional, Union, Type, Iterable, TYPE_CHECKING

from ailment.statement import Statement, Assignment, Call
from ailment.expression import Expression, Tmp, Register, Load

from ...engines.light.data import SpOffset
from ...knowledge_plugins.key_definitions.constants import OP_AFTER
from ...knowledge_plugins.key_definitions import atoms
from ...analyses.reaching_definitions.external_codeloc import ExternalCodeLocation
from .. import Analysis, register_analysis
from .peephole_optimizations import STMT_OPTS, EXPR_OPTS, PeepholeOptimizationStmtBase, PeepholeOptimizationExprBase
from .ailblock_walker import AILBlockWalker

if TYPE_CHECKING:
    from ailment.block import Block


_l = logging.getLogger(name=__name__)


class BlockSimplifier(Analysis):
    """
    Simplify an AIL block.
    """
    def __init__(self, block: Optional['Block'], remove_dead_memdefs=False, stack_pointer_tracker=None,
                 peephole_optimizations: Optional[Iterable[Union[Type[PeepholeOptimizationStmtBase],Type[PeepholeOptimizationExprBase]]]]=None,
                 ):
        """
        :param block:   The AIL block to simplify. Setting it to None to skip calling self._analyze(), which is useful
                        in test cases.
        """

        self.block = block

        self._remove_dead_memdefs = remove_dead_memdefs
        self._stack_pointer_tracker = stack_pointer_tracker

        if peephole_optimizations is None:
            self._expr_peephole_opts = [ cls(self.project) for cls in EXPR_OPTS ]
            self._stmt_peephole_opts = [ cls(self.project) for cls in STMT_OPTS ]
        else:
            self._expr_peephole_opts = [ cls(self.project) for cls in peephole_optimizations
                                         if issubclass(cls, PeepholeOptimizationExprBase) ]
            self._stmt_peephole_opts = [ cls(self.project) for cls in peephole_optimizations
                                         if issubclass(cls, PeepholeOptimizationStmtBase) ]

        self.result_block = None

        if self.block is not None:
            self._analyze()

    def _analyze(self):

        block = self.block
        ctr = 0
        max_ctr = 30

        block = self._eliminate_self_assignments(block)
        block = self._eliminate_dead_assignments(block)

        while True:
            ctr += 1
            # print(str(block))
            new_block = self._simplify_block_once(block)
            # print()
            # print(str(new_block))
            if new_block == block:
                break
            block = new_block
            if ctr >= max_ctr:
                _l.error("Simplification does not reach a fixed point after %d iterations. "
                         "Block comparison is probably incorrect.", max_ctr)
                break

        self.result_block = block

    def _simplify_block_once(self, block):

        # propagator
        propagator = self.project.analyses.Propagator(block=block, stack_pointer_tracker=self._stack_pointer_tracker)
        replacements = list(propagator._states.values())[0]._replacements
        if not replacements:
            return block
        new_block = self._replace_and_build(block, replacements)
        new_block = self._eliminate_dead_assignments(new_block)
        new_block = self._peephole_optimize(new_block)
        return new_block

    @staticmethod
    def _replace_and_build(block, replacements):

        new_statements = block.statements[::]

        for codeloc, repls in replacements.items():
            for old, new in repls.items():
                if isinstance(old, Load):
                    # skip memory-based replacement
                    continue
                stmt = new_statements[codeloc.stmt_idx]
                if stmt == old:
                    # replace this statement
                    r = True
                    new_stmt = new
                else:
                    # replace the expressions involved in this statement
                    if isinstance(stmt, Call) and isinstance(new, Call) and old == stmt.ret_expr:
                        # special case: do not replace the ret_expr of a call statement to another call statement
                        r = False
                        new_stmt = None
                    else:
                        r, new_stmt = stmt.replace(old, new)

                if r:
                    new_statements[codeloc.stmt_idx] = new_stmt

        new_block = block.copy()
        new_block.statements = new_statements
        return new_block

    @staticmethod
    def _eliminate_self_assignments(block):

        new_statements = [ ]

        for stmt in block.statements:
            if type(stmt) is Assignment:
                if stmt.dst.likes(stmt.src):
                    continue
            new_statements.append(stmt)

        new_block = block.copy(statements=new_statements)
        return new_block

    def _eliminate_dead_assignments(self, block):

        new_statements = [ ]
        if not block.statements:
            return block

        rd = self.project.analyses.ReachingDefinitions(subject=block,
                                                       track_tmps=True,
                                                       observation_points=[('node', block.addr, OP_AFTER)]
                                                       )

        used_tmp_indices = set(rd.one_result.tmp_uses.keys())
        live_defs = rd.one_result

        # Find dead assignments
        dead_defs_stmt_idx = set()
        all_defs = rd.all_definitions
        for d in all_defs:
            if isinstance(d.codeloc, ExternalCodeLocation) or d.dummy:
                continue
            if not self._remove_dead_memdefs and isinstance(d.atom, (atoms.MemoryLocation, SpOffset)):
                continue

            if isinstance(d.atom, atoms.Tmp):
                uses = live_defs.tmp_uses[d.atom.tmp_idx]
                if not uses:
                    dead_defs_stmt_idx.add(d.codeloc.stmt_idx)
            else:
                uses = rd.all_uses.get_uses(d)
                if not uses:
                    # is entirely possible that at the end of the block, a register definition is not used.
                    # however, it might be used in future blocks.
                    # so we only remove a definition if the definition is not alive anymore at the end of the block
                    if isinstance(d.atom, atoms.Register):
                        if d not in live_defs.register_definitions.get_variables_by_offset(d.atom.reg_offset):
                            dead_defs_stmt_idx.add(d.codeloc.stmt_idx)
                    if isinstance(d.atom, atoms.MemoryLocation) and isinstance(d.atom.addr, SpOffset):
                        if d not in live_defs.stack_definitions.get_variables_by_offset(d.atom.addr.offset):
                            dead_defs_stmt_idx.add(d.codeloc.stmt_idx)

        # Remove dead assignments
        for idx, stmt in enumerate(block.statements):
            if type(stmt) is Assignment:
                if type(stmt.dst) is Tmp:
                    if stmt.dst.tmp_idx not in used_tmp_indices:
                        continue

                # is it a dead virgin?
                if idx in dead_defs_stmt_idx:
                    continue

                # is it an assignment to an artificial register?
                if type(stmt.dst) is Register and self.project.arch.is_artificial_register(stmt.dst.reg_offset, stmt.dst.size):
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

        def _handle_expr(expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement, block) -> Optional[Expression]:

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
        statements = [ ]

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


register_analysis(BlockSimplifier, 'AILBlockSimplifier')
