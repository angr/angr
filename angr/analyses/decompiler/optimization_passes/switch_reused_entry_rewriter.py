# pylint:disable=too-many-boolean-expressions
from __future__ import annotations
from itertools import count
import logging

from angr.ailment.block import Block
from angr.ailment.statement import Jump
from angr.ailment.expression import Const

from angr.knowledge_plugins.cfg import IndirectJumpType

from .optimization_pass import OptimizationPass, OptimizationPassStage


_l = logging.getLogger(name=__name__)


class SwitchReusedEntryRewriter(OptimizationPass):
    """
    For each switch-case construct (identified by jump tables), rewrite the entry into a goto block when we detect
    situations where an entry node is reused by edges in switch-case constructs that are not the current one. This code
    reuse is usually caused by compiler code deduplication.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_AIL_GRAPH_CREATION
    NAME = "Rewrite switch-case entry nodes with multiple predecessors into goto statements."
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

        # ensure each jump table entry node has only one predecessor
        reused_entries: dict[Block, set[Block]] = {}
        for jumptable in jumptables.values():
            for entry_addr in sorted(set(jumptable.jumptable_entries)):
                entry_nodes = self._get_blocks(entry_addr)
                for entry_node in entry_nodes:
                    preds = list(self._graph.predecessors(entry_node))
                    if len(preds) > 1:
                        non_current_jumptable_preds = [pred for pred in preds if pred.addr != jumptable.addr]
                        if any(p.addr in switch_jump_block_addrs for p in non_current_jumptable_preds):
                            reused_entries[entry_node] = {
                                pred for pred in preds if pred.addr in switch_jump_block_addrs
                            }

        if not reused_entries:
            return False, None
        cache = {"reused_entries": reused_entries}
        return True, cache

    def _analyze(self, cache=None):

        reused_entries: dict[Block, set[Block]] = cache["reused_entries"]
        out_graph = None

        for entry_node, pred_nodes in reused_entries.items():
            # we assign the entry node to the predecessor with the lowest address
            sorted_pred_nodes = sorted(pred_nodes, key=lambda x: (x.addr, x.idx))

            for head_node in sorted_pred_nodes[1:]:

                # create the new goto node
                goto_stmt = Jump(
                    None,
                    Const(None, None, entry_node.addr, self.project.arch.bits, ins_addr=entry_node.addr),
                    target_idx=entry_node.idx,
                    ins_addr=entry_node.addr,
                )
                goto_node = Block(
                    entry_node.addr,
                    0,
                    statements=[goto_stmt],
                    idx=next(self.node_idx),
                )

                if out_graph is None:
                    out_graph = self._graph
                out_graph.remove_edge(head_node, entry_node)
                out_graph.add_edge(head_node, goto_node)
                # we are virtualizing these edges, so we don't need to add the edge from goto_node to the entry_node

        self.out_graph = out_graph
