
from angr import Analysis, register_analysis
from angr.analyses.reaching_definitions import OP_AFTER
from angr.analyses.reaching_definitions.external_codeloc import ExternalCodeLocation

from ..block import Block
from ..statement import Assignment
from ..expression import Tmp, Register


class Simplifier(Analysis):
    def __init__(self, block):
        """

        :param Block block:
        """

        self.block = block

        self.result_block = None

        self._analyze()

    def _analyze(self):

        block = self.block
        block = self._simplify_block_once(block)
        #print str(block)
        block = self._simplify_block_once(block)
        #print str(block)
        #block = self._simplify_block_once(block)
        #print str(block)

        self.result_block = block

    def _simplify_block_once(self, block):

        # reaching definition analysis
        rd = self.project.analyses.ReachingDefinitions(block=block)

        # propagator
        propagator = self.project.analyses.AILPropagator(block=block, reaching_definitions=rd)
        replacements = list(propagator._states.values())[0]._final_replacements
        new_block = self._replace_and_build(block, replacements)
        new_block = self._eliminate_dead_assignments(new_block)

        return new_block

    def _replace_and_build(self, block, replacements):

        new_statements = block.statements[::]

        for codeloc, old_expr, new_expr in replacements:
            stmt = new_statements[codeloc.stmt_idx]
            r, new_stmt = stmt.replace(old_expr, new_expr)

            if r:
                new_statements[codeloc.stmt_idx] = new_stmt

        new_block = block.copy()
        new_block.statements = new_statements

        return new_block

    def _eliminate_dead_assignments(self, block):

        new_statements = [ ]

        rd = self.project.analyses.ReachingDefinitions(block=block,
                                                       track_tmps=True,
                                                       observation_points=[ (block.statements[-1].ins_addr, OP_AFTER )]
                                                       )

        used_tmp_indices = set(rd.one_result.tmp_uses.keys())
        dead_virgins = rd.one_result._dead_virgin_definitions
        dead_virgins_stmt_idx = set([ d.codeloc.stmt_idx for d in dead_virgins
                                      if not isinstance(d.codeloc, ExternalCodeLocation) ])

        for idx, stmt in enumerate(block.statements):
            if type(stmt) is Assignment:
                if type(stmt.dst) is Tmp:
                    if stmt.dst.tmp_idx not in used_tmp_indices:
                        continue

                # is it a dead virgin?
                if idx in dead_virgins_stmt_idx:
                    continue

            new_statements.append(stmt)

        new_block = block.copy()
        new_block.statements = new_statements

        return new_block


register_analysis(Simplifier, 'AILSimplifier')
