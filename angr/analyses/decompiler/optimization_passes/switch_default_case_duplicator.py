# pylint:disable=too-many-boolean-expressions
from __future__ import annotations
from itertools import count
from collections import defaultdict
import logging

import networkx

from angr.ailment.block import Block
from angr.ailment.statement import Jump
from angr.ailment.expression import Const

from angr.knowledge_plugins.cfg import IndirectJumpType
from .optimization_pass import OptimizationPass, OptimizationPassStage


_l = logging.getLogger(name=__name__)


class SwitchDefaultCaseDuplicator(OptimizationPass):
    """
    For each switch-case construct (identified by jump tables), duplicate the default-case node when we detect
    situations where the default-case node is seemingly reused by edges outside the switch-case construct. This code
    reuse is usually caused by compiler code deduplication.

    Ideally this pass should be implemented as an ISC optimization reversion.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_AIL_GRAPH_CREATION
    NAME = "Duplicate default-case nodes to undo default-case node reuse caused by compiler code deduplication"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.node_idx = count(start=self._scratch.get("node_idx", 0))

        self.analyze()

        self._scratch["node_idx"] = next(self.node_idx)

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
                pred = next(iter(self._func.graph.predecessors(node)))
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
        duplicated_default_addrs: set[int] = set()

        default_addr_count = defaultdict(int)
        goto_rewritten_default_addrs = set()
        for _, _, default_addr in default_case_node_addrs:
            default_addr_count[default_addr] += 1
        for default_addr, cnt in default_addr_count.items():
            if cnt > 1:
                # rewrite all of them into gotos
                default_node = self._get_block(default_addr)
                for switch_head_addr in sorted((sa for sa, _, da in default_case_node_addrs if da == default_addr)):
                    switch_head_node = self._get_block(switch_head_addr)
                    goto_stmt = Jump(
                        None,
                        Const(None, None, default_addr, self.project.arch.bits, ins_addr=default_addr),
                        target_idx=None,  # I'm assuming the ID of the default node is None here
                        ins_addr=default_addr,
                    )
                    goto_node = Block(
                        default_addr,
                        0,
                        statements=[goto_stmt],
                        idx=next(self.node_idx),
                    )

                    if out_graph is None:
                        out_graph = self._graph
                    out_graph.remove_edge(switch_head_node, default_node)
                    out_graph.add_edge(switch_head_node, goto_node)
                    out_graph.add_edge(goto_node, default_node)

                goto_rewritten_default_addrs.add(default_addr)

        for switch_head_addr, jump_node_addr, default_addr in default_case_node_addrs:
            if default_addr in duplicated_default_addrs or default_addr in goto_rewritten_default_addrs:
                continue

            default_case_node = self._func.get_node(default_addr)
            unexpected_pred_addrs = {
                pred.addr
                for pred in self._func.graph.predecessors(default_case_node)
                if pred.addr not in {switch_head_addr, jump_node_addr}
            }
            if unexpected_pred_addrs:
                default_case_block = self._get_block(default_addr)
                default_case_succ_block = next(iter(self._graph.successors(default_case_block)))

                jump_nodes = self._get_blocks(jump_node_addr)
                jump_node_descedents = set()
                for jump_node in jump_nodes:
                    jump_node_descedents |= networkx.descendants(self._graph, jump_node)

                duplicated_default_addrs.add(default_addr)

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
