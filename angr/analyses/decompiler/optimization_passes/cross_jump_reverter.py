from __future__ import annotations
from collections import defaultdict
from itertools import count
import copy
import logging
import inspect

from angr.analyses.decompiler.counters import AILBlockCallCounter
from angr.ailment.statement import ConditionalJump
from angr.ailment.expression import Const
from .optimization_pass import OptimizationPassStage, StructuringOptimizationPass

l = logging.getLogger(__name__)


class CrossJumpReverter(StructuringOptimizationPass):
    """
    This is an implementation to revert the compiler optimization Cross Jumping, and ISC optimization discussed
    in the USENIX 2024 paper SAILR. This optimization is somewhat aggressive and as such should be run last in your
    decompiler deoptimization chain. This deoptimization will take any goto it finds and attempt to duplicate its
    target block if its target only has one outgoing edge.

    There are some heuristics in place to prevent duplication everywhere. First, this deoptimization will only run
    a max of max_opt_iters times. Second, it will not duplicate a block with too many calls.
    """

    STAGE = OptimizationPassStage.DURING_REGION_IDENTIFICATION
    NAME = "Duplicate linear blocks with gotos"
    DESCRIPTION = inspect.cleandoc(__doc__).strip()

    def __init__(
        self,
        func,
        # internal parameters that should be used by Clinic
        node_idx_start: int = 0,
        # settings
        max_opt_iters: int = 3,
        max_call_duplications: int = 1,
        **kwargs,
    ):
        super().__init__(func, max_opt_iters=max_opt_iters, strictly_less_gotos=True, **kwargs)

        self.node_idx = count(start=node_idx_start)
        self._max_call_dup = max_call_duplications
        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        to_update = defaultdict(list)
        for node in self.out_graph.nodes:
            gotos = self._goto_manager.gotos_in_block(node)
            if not gotos or len(gotos) >= 2:
                continue

            goto_dst_addrs = []
            if node.statements:
                last_stmt = node.statements[-1]
                if isinstance(last_stmt, ConditionalJump):
                    if isinstance(last_stmt.true_target, Const):
                        goto_dst_addrs.append(last_stmt.true_target.value)
                    if isinstance(last_stmt.false_target, Const):
                        goto_dst_addrs.append(last_stmt.false_target.value)
            if not goto_dst_addrs:
                goto = next(iter(gotos))
                goto_dst_addrs.append(goto.dst_addr)

            # only blocks that have a single outgoing goto are candidates
            # for duplicates
            for goto_target in self.out_graph.successors(node):
                if goto_target.addr in goto_dst_addrs:
                    # the target goto block should only have a single outgoing edge
                    # this prevents duplication of conditions
                    # FIXME: Check a super block instead of a single block that may end with a call
                    if self.out_graph.out_degree(goto_target) != 0:
                        continue

                    # minimize the number of calls in the target block that can be duplicated
                    # to prevent duplication of big blocks
                    counter = AILBlockCallCounter()
                    counter.walk(goto_target)
                    if counter.calls > self._max_call_dup:
                        continue

                    # [goto_target] = (pred1, pred2, ...)
                    to_update[goto_target].append(node)
                    break

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
                cp = copy.deepcopy(goto_blk)
                cp.idx = next(self.node_idx)
                self.out_graph.remove_edge(src, goto_blk)
                self.out_graph.add_edge(src, cp)

            updates = True
            if delete_original:
                self.out_graph.remove_node(goto_target)

        return updates
