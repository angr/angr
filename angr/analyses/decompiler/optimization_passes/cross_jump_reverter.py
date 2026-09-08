from __future__ import annotations

import inspect
import logging
from collections import defaultdict
from itertools import count
from typing import cast

import networkx

from angr.analyses.decompiler.counters import AILBlockCallCounter
from angr.analyses.decompiler.goto_manager import GotoManager

from .optimization_pass import OptimizationPassStage, StructuringOptimizationPass

l = logging.getLogger(__name__)


class CrossJumpReverter(StructuringOptimizationPass):
    """
    This is an implementation to revert the compiler optimization Cross Jumping, an ISC optimization discussed
    in the USENIX 2024 paper SAILR. This optimization is somewhat aggressive and as such should be run last in your
    decompiler deoptimization chain. This deoptimization will take any goto it finds and attempt to duplicate its
    target block if its target only has one outgoing edge.

    There are some heuristics in place to prevent duplication everywhere. First, this deoptimization will only run
    a max of max_opt_iters times. Second, it will not duplicate a block with too many calls.
    """

    STAGE = OptimizationPassStage.DURING_REGION_IDENTIFICATION
    NAME = "Duplicate linear blocks with gotos"
    DESCRIPTION = inspect.cleandoc(__doc__ or "").strip()

    def __init__(
        self,
        *args,
        # internal parameters that should be used by Clinic
        node_idx_start: int = 0,
        # settings
        max_opt_iters: int = 3,
        max_call_duplications: int = 1,
        **kwargs,
    ):
        super().__init__(*args, max_opt_iters=max_opt_iters, strictly_less_gotos=True, **kwargs)

        self.node_idx = count(start=node_idx_start)
        self._max_call_dup = max_call_duplications
        self._processed_targets: set[tuple[int, int | None]] = set()
        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        to_update = defaultdict(list)
        for node in self.out_graph.nodes:
            gotos = self._goto_manager.gotos_in_block(node, graph=self.out_graph)
            # TODO: support if-stmts
            if not gotos or len(gotos) >= 2:
                continue

            # only blocks that have a single outgoing goto are candidates
            # for duplicates
            goto = next(iter(gotos))
            goto_target = cast(GotoManager, self._goto_manager).find_destination_block(
                cast(networkx.DiGraph, self.out_graph), goto
            )
            if goto_target is None or (goto_target.addr, goto_target.idx) in self._processed_targets:
                continue

            # the target goto block should only have a single outgoing edge
            # this prevents duplication of conditions
            if not self.out_graph.has_edge(node, goto_target) or self.out_graph.out_degree(goto_target) != 1:
                continue

            # minimize the number of calls in the target block that can be duplicated
            # to prevent duplication of big blocks
            counter = AILBlockCallCounter()
            counter.walk(goto_target)
            if counter.calls > self._max_call_dup:
                continue

            # [goto_target] = (pred1, pred2, ...)
            to_update[goto_target].append(node)

        if not to_update:
            return False

        updates = False
        sorted_targets = sorted(to_update.items(), key=lambda x: x[0].addr)
        for goto_target, pred_to_update in sorted_targets:
            pred_to_update = sorted(pred_to_update, key=lambda x: x.addr)
            # do some sanity checks
            update_edges = [(pred, goto_target) for pred in pred_to_update]
            if not all(self.out_graph.has_edge(*edge) for edge in update_edges):
                continue

            current_preds = list(self.out_graph.predecessors(goto_target))
            delete_original = len(current_preds) == len(pred_to_update)

            # update the edges
            for src, goto_blk in update_edges:
                cp = goto_blk.deep_copy(self.manager)
                cp.idx = next(self.node_idx)
                self.out_graph.remove_edge(src, goto_blk)
                self.out_graph.add_edge(src, cp)

            self._processed_targets.add((goto_target.addr, goto_target.idx))
            updates = True
            if delete_original:
                self.out_graph.remove_node(goto_target)

        return updates
