from __future__ import annotations
import itertools

import networkx
from ailment.expression import VirtualVariable
from ailment.statement import Assignment, Label

from angr.analyses import Analysis, register_analysis
from angr.utils.ssa import is_phi_assignment, VVarUsesCollector
from angr.utils.graph import dfs_back_edges, GraphUtils


class SLivenessModel:
    def __init__(self):
        self.live_ins = {}
        self.live_outs = {}


class SLivenessAnalysis(Analysis):
    """
    Calculates LiveIn and LiveOut sets for each block in a partial-SSA function.

    Implements "Computing Liveness Sets for SSA-Form Programs"
    ref: https://inria.hal.science/inria-00558509v2/document
    """

    def __init__(
        self,
        func,
        func_graph=None,
        func_addr: int | None = None,
    ):
        self.func = func
        self.func_addr = func_addr if func_addr is not None else func.addr
        self.func_graph = func_graph if func_graph is not None else func.graph

        self.model = SLivenessModel()

        self._analyze()

    def _analyze(self):
        # TODO: Support irreducible graphs

        graph = self.func_graph
        entry = next(iter(node for node in graph if node.addr == self.func_addr))

        # initialize the live_in and live_out sets
        phi_defs = {}
        phi_uses = {}
        phi_unuses = {}
        live_ins = {}
        live_outs = {}
        for block in graph.nodes():
            block_key = block.addr, block.idx
            live_ins[block_key] = set()
            live_outs[block_key] = set()

        # find loop back edges
        back_edges = set(dfs_back_edges(graph, entry))

        # generate phi-uses and phi-defs
        for block in graph:
            # update phidefs
            block_phi_defs = set()
            for stmt in block.statements:
                if isinstance(stmt, Label):
                    continue
                is_phi, _ = is_phi_assignment(stmt)
                if is_phi:
                    block_phi_defs.add(stmt.dst.varid)
                else:
                    # all phi-var assignments are at the beginning of the block
                    break

            # update phiuses
            block_phi_uses = set()
            block_phi_unuses = set()
            for succ in graph.successors(block):
                for stmt in succ.statements:
                    if isinstance(stmt, Label):
                        continue
                    is_phi, _ = is_phi_assignment(stmt)
                    if is_phi:
                        unused = False
                        for src, vvar in stmt.src.src_and_vvars:
                            if src == (block.addr, block.idx):
                                if vvar is not None:
                                    block_phi_uses.add(vvar.varid)
                                else:
                                    unused = True
                                    break

                        if unused:
                            for _, vvar in stmt.src.src_and_vvars:
                                if vvar is not None:
                                    block_phi_unuses.add(vvar.varid)
                    else:
                        break

            phi_defs[(block.addr, block.idx)] = block_phi_defs
            phi_uses[(block.addr, block.idx)] = block_phi_uses
            phi_unuses[(block.addr, block.idx)] = block_phi_unuses

        # first pass: DFS without considering loop back edges
        for block in networkx.dfs_postorder_nodes(graph):
            live = phi_uses[(block.addr, block.idx)].copy()
            for succ in graph.successors(block):
                if (block, succ) in back_edges:
                    continue
                live |= live_ins[(succ.addr, succ.idx)].difference(phi_defs[(succ.addr, succ.idx)])

            live = live.difference(phi_unuses[(block.addr, block.idx)])
            live_outs[(block.addr, block.idx)] = live.copy()

            for stmt in reversed(block.statements):
                # handle assignments: a defined vvar is not live before the assignment
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    live.discard(stmt.dst.varid)

                # handle the statement: add used vvars to the live set
                vvar_use_collector = VVarUsesCollector()
                vvar_use_collector.walk_statement(stmt)
                live |= vvar_use_collector.vvars

            live_ins[(block.addr, block.idx)] = live | phi_defs[(block.addr, block.idx)]

        # second pass: Propagate live variables within loop bodies
        loop_head_to_loop_nodes = GraphUtils.loop_nesting_forest(graph, entry)
        traversed_loopheads = set()
        for loop_head, loop_nodes in reversed(loop_head_to_loop_nodes.items()):
            if loop_head in traversed_loopheads:
                continue
            self._looptree_dfs(loop_head_to_loop_nodes, live_ins, live_outs, phi_defs, loop_head, traversed_loopheads)

        # set the model accordingly
        self.model.live_ins = live_ins
        self.model.live_outs = live_outs

    def _looptree_dfs(self, loops, live_ins, live_outs, phi_defs, loop_head, traversed_loopheads: set):
        loop_head_key = loop_head.addr, loop_head.idx
        live_loop = live_ins[loop_head_key].difference(phi_defs[loop_head_key])
        for m in itertools.chain({loop_head}, networkx.descendants(loops[loop_head], loop_head)):
            m_key = m.addr, m.idx
            live_ins[m_key] |= live_loop
            live_outs[m_key] |= live_loop
            if m is not loop_head and m in loops:
                self._looptree_dfs(loops, live_ins, live_outs, phi_defs, m, traversed_loopheads)
        traversed_loopheads.add(loop_head)

    def interference_graph(self) -> networkx.Graph:
        """
        Generate an interference graph based on the liveness analysis result.

        :return: A networkx.Graph instance.
        """

        graph = networkx.Graph()

        for block in self.func_graph.nodes():
            live = self.model.live_outs[(block.addr, block.idx)]
            for stmt in reversed(block.statements):
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    def_vvar = stmt.dst.varid
                else:
                    def_vvar = None

                # handle the statement: add used vvars to the live set
                vvar_use_collector = VVarUsesCollector()
                vvar_use_collector.walk_statement(stmt)

                if def_vvar is not None:
                    for live_vvar in live:
                        graph.add_edge(def_vvar, live_vvar)
                    live.discard(def_vvar)
                live |= vvar_use_collector.vvars

        return graph


register_analysis(SLivenessAnalysis, "SLiveness")
