from __future__ import annotations
from collections import defaultdict
import logging

import networkx

from angr.ailment import Block
from angr.ailment.expression import Phi, Const
from angr.ailment.statement import Assignment, ConditionalJump, Jump
from angr.analyses import Analysis, register_analysis
from angr.utils.ail import is_phi_assignment

_l = logging.getLogger(__name__)


class LoopUnroller(Analysis):
    """
    Unroll a loop in an AIL graph for a specified number of iterations.
    """

    def __init__(
        self,
        graph: networkx.DiGraph,
        loop_body: set[tuple[int, int | None]],
        unroll_times: int,
        save_original: bool,
        loop_body_incomplete: bool = False,
    ):
        self.graph = graph
        self.loop_body = loop_body
        self.unroll_times = unroll_times
        self.save_original = save_original
        self.loop_body_nodes = set()
        self._block_min_ids: defaultdict[int, int] = defaultdict(int)

        for node in self.graph.nodes:
            if (node.addr, node.idx) in self.loop_body:
                self.loop_body_nodes.add(node)

        if loop_body_incomplete:
            # fill in the loop body by including missing nodes between existing ones
            full_nodes = self._find_missing_loop_body_nodes(self.loop_body_nodes, self.graph)
            if full_nodes:
                _l.debug(
                    "Loop body was incomplete. Filled in %d missing nodes.", len(full_nodes) - len(self.loop_body_nodes)
                )
                self.loop_body_nodes |= full_nodes

        for node in self.loop_body_nodes:
            self._block_min_ids[node.addr] = max(
                self._block_min_ids[node.addr], node.idx if node.idx is not None else 0
            )

        self.out_graph: networkx.DiGraph | None = networkx.DiGraph(self.graph)

        self._analyze()

    def _analyze(self):
        loop_exits: list[tuple[Block, Block]] = []
        loop_heads: list[Block] = []
        for node in self.loop_body_nodes:
            if any(pred not in self.loop_body_nodes for pred in self.graph.predecessors(node)):
                loop_heads.append(node)
            for succ in self.graph.successors(node):
                if succ not in self.loop_body_nodes:
                    loop_exits.append((node, succ))

        assert len(loop_heads) == 1, "Multiple loop heads detected. Currently only single-entry loops are supported."
        loop_head = loop_heads[0]
        loop_exit_srcs = [src for src, _ in loop_exits]

        graph = self.out_graph
        for _i in range(self.unroll_times):
            # make a copy of the loop body
            copied_graph, copied_head, copied_exit_srcs = self._copy_subgraph(
                graph, self.loop_body_nodes, loop_head, loop_exit_srcs
            )

            # alter the graph

            # patch in the copied subgraph, but break the back edges to the original loop head
            backedge_srcs = []
            for src, dst, data in copied_graph.edges(data=True):
                if dst is copied_head:
                    backedge_srcs.append(src)
                    continue
                graph.add_edge(src, dst, **data)

            loop_inedges = graph.in_edges(loop_head, data=True)
            external_loop_inedges = [
                (src, dst, data) for src, dst, data in loop_inedges if src not in self.loop_body_nodes
            ]

            # remove edges from external predecessors to the original loop head, and add edges to the copied loop head
            for src, _, data in external_loop_inedges:
                graph.remove_edge(src, loop_head)
                graph.add_edge(src, copied_head, **data)

            # connect the copied exit srcs to the original loop exits
            for idx, src in enumerate(copied_exit_srcs):
                original_dst = loop_exits[idx][1]
                graph.add_edge(src, original_dst)

            # connect backedge source nodes to the original loop head
            for src in backedge_srcs:
                graph.add_edge(src, loop_head)

    def _copy_subgraph(
        self, graph: networkx.DiGraph, subgraph_nodes: set[Block], loop_head: Block, loop_exit_srcs: list[Block]
    ) -> tuple[networkx.DiGraph, Block, list[Block]]:
        mapping = {}
        for node in subgraph_nodes:
            # get the new block ID
            if node.addr in self._block_min_ids:
                new_idx = self._block_min_ids[node.addr] + 1
                self._block_min_ids[node.addr] = new_idx
            else:
                new_idx = 0
                self._block_min_ids[node.addr] = new_idx

            new_node = Block(node.addr, node.original_size, statements=list(node.statements), idx=new_idx)
            mapping[node] = new_node

        # update statements if necessary
        block_addr_mapping = {
            (old_node.addr, old_node.idx): (new_node.addr, new_node.idx) for old_node, new_node in mapping.items()
        }
        for new_node in mapping.values():
            self._update_block_statements(new_node, block_addr_mapping)

        copied_subgraph = graph.subgraph(subgraph_nodes).copy()
        relabelled: networkx.DiGraph = networkx.relabel_nodes(copied_subgraph, mapping, copy=True)

        return relabelled, mapping[loop_head], [mapping[src] for src in loop_exit_srcs]

    @staticmethod
    def _update_block_statements(
        block: Block,
        block_addr_mapping: dict[tuple[int, int | None], tuple[int, int | None]],
    ) -> None:
        for idx, stmt in enumerate(block.statements):
            if is_phi_assignment(stmt):
                assert isinstance(stmt, Assignment) and isinstance(stmt.src, Phi)
                # update the sources of the phi assignment
                new_src_and_vvars = []
                for src, vvar in stmt.src.src_and_vvars:
                    new_src_and_vvars.append((block_addr_mapping.get(src, src), vvar))
                new_stmt = Assignment(
                    stmt.idx,
                    stmt.dst,
                    Phi(stmt.src.idx, stmt.src.bits, new_src_and_vvars, **stmt.src.tags),
                    **stmt.tags,
                )
                block.statements[idx] = new_stmt
            elif isinstance(stmt, ConditionalJump):
                # update jump targets if necessary
                true_target = stmt.true_target
                false_target = stmt.false_target

                new_true_target = None
                new_false_target = None
                if isinstance(true_target, Const):
                    new_true_target = block_addr_mapping.get(
                        (true_target.value_int, stmt.true_target_idx), (true_target.value_int, stmt.true_target_idx)
                    )
                if isinstance(false_target, Const):
                    new_false_target = block_addr_mapping.get(
                        (false_target.value_int, stmt.false_target_idx), (false_target.value_int, stmt.false_target_idx)
                    )
                if new_true_target is not None or new_false_target is not None:
                    new_stmt = ConditionalJump(
                        stmt.idx,
                        stmt.condition,
                        (
                            Const(None, None, new_true_target[0], true_target.bits, **true_target.tags)
                            if new_true_target is not None
                            else true_target
                        ),
                        (
                            Const(None, None, new_false_target[0], stmt.false_target.bits, **false_target.tags)
                            if new_false_target is not None
                            else false_target
                        ),
                        true_target_idx=new_true_target[1] if new_true_target is not None else stmt.true_target_idx,
                        false_target_idx=new_false_target[1] if new_false_target is not None else stmt.false_target_idx,
                        **stmt.tags,
                    )
                    block.statements[idx] = new_stmt
            elif isinstance(stmt, Jump):
                target = stmt.target
                new_target = None
                if isinstance(target, Const):
                    new_target = block_addr_mapping.get(
                        (target.value_int, stmt.target_idx), (target.value_int, stmt.target_idx)
                    )
                if new_target is not None:
                    new_stmt = Jump(
                        stmt.idx,
                        Const(None, None, new_target[0], target.bits, **target.tags),
                        target_idx=new_target[1],
                        **stmt.tags,
                    )
                    block.statements[idx] = new_stmt

    @staticmethod
    def _find_missing_loop_body_nodes(existing_nodes: set, graph):
        nodes = set(existing_nodes)
        updated = True
        while updated:
            updated = False
            for node in list(nodes):
                for succ in graph.successors(node):
                    if succ in nodes:
                        continue
                    succ_succs = list(graph.successors(succ))
                    if any(s in nodes for s in succ_succs):
                        updated = True
                        nodes.add(succ)
        return nodes


register_analysis(LoopUnroller, "LoopUnroller")
