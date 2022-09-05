from typing import Any, List

import ailment

from .optimization_pass import OptimizationPass, OptimizationPassStage


class RedundantGotoSimplifier(OptimizationPass):
    """
    Remove redundant goto statements.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_SINGLE_BLOCK_SIMPLIFICATION
    NAME = "Remove redundant gotos"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):

        gotos = self._find_gotos()

        return True, {
            'gotos': gotos,
        }

    def _analyze(self, cache=None):

        gotos = None

        if cache is not None:
            gotos = cache.get('gotos', None)

        if gotos is None:
            gotos = self._find_gotos()

        if not gotos:
            return

        # since we will mess with the graph, we initialize out_graph by ourselves
        self.out_graph = self._graph

        # update each block
        for block_key in gotos:

            old_block = self.blocks_by_addr_and_idx[block_key]
            if len(old_block.statements) == 1:
                # we can get rid of this block entirely
                preds = list(self._graph.predecessors(old_block))
                succs = list(self._graph.successors(old_block))
                if len(succs) == 1:
                    self.out_graph.remove_node(old_block)
                    for pred in preds:
                        self.out_graph.add_edge(pred, succs[0])
            else:
                # simply remove the last statement
                block = old_block.copy()
                block.statements = block.statements[:-1]
                self._update_block(old_block, block)

    def _find_gotos(self) -> List[Any]:
        """
        Find all blocks that end with goto statements whose targets are constant values.

        :return:    A list of tuples.
        """

        results = [ ]
        for key, block in self._blocks_by_addr_and_idx.items():
            if block.statements \
                    and isinstance(block.statements[-1], ailment.Stmt.Jump) \
                    and isinstance(block.statements[-1].target, ailment.Expr.Const):
                results.append(key)
        return results
