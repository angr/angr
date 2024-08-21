# pylint:disable=too-many-boolean-expressions
from itertools import count
import logging

import networkx

from angr.knowledge_plugins.cfg import IndirectJumpType
from .optimization_pass import OptimizationPass, OptimizationPassStage


_l = logging.getLogger(name=__name__)


def s2u(s, bits):
    if s > 0:
        return s
    return (1 << bits) + s


class SwitchDefaultCaseDuplicator(OptimizationPass):
    """
    For each switch-case construct (identified by jump tables), duplicate the default-case node when we detect
    situations where the default-case node is seemingly reused by edges outside the switch-case construct. This code
    reuse is usually caused by compiler code deduplication.

    Ideally this pass should be implemented as an ISC optimization reversion.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_REGION_IDENTIFICATION
    NAME = "Duplicate default-case nodes to undo default-case node reuse caused by compiler code deduplication"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.node_idx = count(start=0)

        self.analyze()

    def _check(self):
        jumptables = self.kb.cfgs.get_most_accurate().jump_tables
        switch_jump_block_addrs = {
            jumptable.addr
            for jumptable in jumptables.values()
            if jumptable.type
            in {IndirectJumpType.Jumptable_AddressComputed, IndirectJumpType.Jumptable_AddressLoadedFromMemory}
        }
        jump_node_addrs = self._func.block_addrs_set.intersection(switch_jump_block_addrs)
        if not jump_node_addrs:
            return False, None

        default_case_node_addrs = set()
        for node_addr in jump_node_addrs:
            node = self._func.get_node(node_addr)
            if self._func.graph.in_degree[node] == 1:
                pred = list(self._func.graph.predecessors(node))[0]
                if self._func.graph.out_degree[pred] == 2:
                    default_case_node = next(
                        iter(nn for nn in self._func.graph.successors(pred) if nn.addr != node_addr)
                    )
                    if self._func.graph.out_degree[default_case_node] == 1:
                        default_case_node_addrs.add((pred.addr, node_addr, default_case_node.addr))

        if not default_case_node_addrs:
            return False, None

        cache = {"default_case_node_addrs": default_case_node_addrs}
        return True, cache

    def _analyze(self, cache=None):

        default_case_node_addrs = cache["default_case_node_addrs"]

        out_graph = None

        for switch_head_addr, jump_node_addr, default_addr in default_case_node_addrs:
            default_case_node = self._func.get_node(default_addr)
            unexpected_pred_addrs = {
                pred.addr
                for pred in self._func.graph.predecessors(default_case_node)
                if pred.addr not in {switch_head_addr, jump_node_addr}
            }
            if unexpected_pred_addrs:
                default_case_block = self._get_block(default_addr)
                default_case_succ_block = list(self._graph.successors(default_case_block))[0]

                jump_nodes = self._get_blocks(jump_node_addr)
                jump_node_descedents = set()
                for jump_node in jump_nodes:
                    jump_node_descedents |= networkx.descendants(self._graph, jump_node)

                # duplicate default_case_node for each unexpected predecessor
                for unexpected_pred_addr in unexpected_pred_addrs:
                    for unexpected_pred in self._get_blocks(unexpected_pred_addr):
                        # is this predecessor reachable from the jump node? if so, we believe this is a legitimate edge
                        # and do not duplicate it.
                        if unexpected_pred in jump_node_descedents:
                            continue

                        default_case_block_copy = default_case_block.copy()
                        default_case_block_copy.idx = next(self.node_idx)
                        if out_graph is None:
                            out_graph = self._graph
                        out_graph.remove_edge(unexpected_pred, default_case_block)
                        out_graph.add_edge(unexpected_pred, default_case_block_copy)
                        out_graph.add_edge(default_case_block_copy, default_case_succ_block)

        self.out_graph = out_graph
