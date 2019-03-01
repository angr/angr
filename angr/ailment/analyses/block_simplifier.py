
import logging

from angr import Analysis, register_analysis
from angr.analyses.reaching_definitions import OP_AFTER
from angr.analyses.reaching_definitions.external_codeloc import ExternalCodeLocation

from ..block import Block
from ..statement import Assignment
from ..expression import Tmp, Register

_l = logging.getLogger(name=__name__)


class BlockSimplifier(Analysis):
    """
    Simplify an AIL block.
    """
    def __init__(self, block, stack_pointer_tracker=None):
        """

        :param Block block:
        """

        self.block = block
        self._stack_pointer_tracker = stack_pointer_tracker

        self.result_block = None

        self._analyze()

    def _analyze(self):

        block = self.block
        ctr = 0
        max_ctr = 30

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
                         "Block comparison is probably incorrect." % max_ctr)
                break

        self.result_block = block

    def _simplify_block_once(self, block):

        # propagator
        propagator = self.project.analyses.AILPropagator(block=block, stack_pointer_tracker=self._stack_pointer_tracker)
        replacements = list(propagator._states.values())[0]._final_replacements
        new_block = self._replace_and_build(block, replacements)
        new_block = self._eliminate_dead_assignments(new_block)

        return new_block

    @staticmethod
    def _replace_and_build(block, replacements):

        new_statements = block.statements[::]

        for codeloc, old, new in replacements:
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

    def _eliminate_dead_assignments(self, block):

        new_statements = [ ]
        if not block.statements:
            return block

        rd = self.project.analyses.ReachingDefinitions(block=block,
                                                       track_tmps=True,
                                                       observation_points=[('insn', block.statements[-1].ins_addr, OP_AFTER)]
                                                       )

        used_tmp_indices = set(rd.one_result.tmp_uses.keys())
        dead_virgins = rd.one_result._dead_virgin_definitions
        dead_virgins_stmt_idx = set([ d.codeloc.stmt_idx for d in dead_virgins
                                      if not isinstance(d.codeloc, ExternalCodeLocation) and not d.dummy ])

        for idx, stmt in enumerate(block.statements):
            if type(stmt) is Assignment:
                if type(stmt.dst) is Tmp:
                    if stmt.dst.tmp_idx not in used_tmp_indices:
                        continue

                # is it a dead virgin?
                if idx in dead_virgins_stmt_idx:
                    continue

                # is it an assignment to an artificial register?
                if type(stmt.dst) is Register and self.project.arch.is_artificial_register(stmt.dst.reg_offset, stmt.dst.size):
                    continue

                if stmt.src == stmt.dst:
                    continue

            new_statements.append(stmt)

        new_block = block.copy()
        new_block.statements = new_statements

        return new_block


register_analysis(BlockSimplifier, 'AILBlockSimplifier')
