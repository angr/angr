from itertools import count
import copy
import logging
import inspect

from .optimization_pass import OptimizationPassStage, StructuringOptimizationPass
from ..utils import AILCallCounter

l = logging.getLogger(__name__)


class CrossJumpReverter(StructuringOptimizationPass):
    """
    Copies bad blocks
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.DURING_REGION_IDENTIFICATION
    NAME = "Duplicate linear blocks with gotos"
    DESCRIPTION = inspect.cleandoc(__doc__).strip()

    def __init__(
        self,
        func,
        # internal parameters that should be used by Clinic
        node_idx_start: int = 0,
        # settings
        max_call_duplications: int = 2,
        **kwargs,
    ):
        super().__init__(func, **kwargs)

        self.node_idx = count(start=node_idx_start)
        self._max_call_dup = max_call_duplications
        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        to_update = {}
        for node in self.out_graph.nodes:
            gotos = self._goto_manager.gotos_in_block(node)
            # TODO: support if-stmts
            if not gotos or len(gotos) >= 2:
                continue

            # only single reaching gotos
            goto = list(gotos)[0]
            for goto_target in self.out_graph.successors(node):
                if goto_target.addr == goto.dst_addr:
                    break
            else:
                goto_target = None

            if goto_target is None:
                continue

            if self.out_graph.out_degree(goto_target) != 1:
                continue

            counter = AILCallCounter()
            counter.walk(goto_target)
            if counter.calls > self._max_call_dup:
                continue

            # og_block -> suc_block (goto target)
            to_update[node] = goto_target

        if not to_update:
            return False

        for target_node, goto_node in to_update.items():
            # always make a copy if there is a goto edge
            cp = copy.deepcopy(goto_node)
            cp.idx = next(self.node_idx)

            # remove this goto edge from original
            self.out_graph.remove_edge(target_node, goto_node)

            # add a new edge to the copy
            self.out_graph.add_edge(target_node, cp)

            # make sure the copy has the same successor as before!
            suc = list(self.out_graph.successors(goto_node))[0]
            self.out_graph.add_edge(cp, suc)

            # kill the original if we made enough copies to drain in-degree
            if self.out_graph.in_degree(goto_node) == 0:
                self.out_graph.remove_node(goto_node)

        # TODO: add single chain later:
        # i.e., we need to copy the entire chain of single successor nodes in
        # this goto chain.
        return True
