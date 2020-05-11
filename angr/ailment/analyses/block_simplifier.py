# pylint:disable=unused-import
import logging

from angr import Analysis, register_analysis
from angr.engines.light.data import SpOffset
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER
from angr.knowledge_plugins.key_definitions import atoms
from angr.analyses.reaching_definitions.external_codeloc import ExternalCodeLocation

from ..block import Block
from ..statement import Assignment
from ..expression import Tmp, Register, Load

_l = logging.getLogger(name=__name__)


class BlockSimplifier(Analysis):
    """
    Simplify an AIL block.
    """
    def __init__(self, block, remove_dead_memdefs=False, stack_pointer_tracker=None):
        """

        :param Block block:
        """

        self.block = block

        self._remove_dead_memdefs = remove_dead_memdefs
        self._stack_pointer_tracker = stack_pointer_tracker

        self.result_block = None

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


register_analysis(BlockSimplifier, 'AILBlockSimplifier')
