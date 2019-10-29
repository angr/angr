import logging

import networkx
from . import Analysis

l = logging.getLogger(name=__name__)

class Loop(object):
    def __init__(self, entry, entry_edges, break_edges, continue_edges, body_nodes, graph, subloops):
        self.entry = entry
        self.entry_edges = entry_edges
        self.break_edges = break_edges
        self.continue_edges = continue_edges
        self.body_nodes = body_nodes
        self.graph = graph
        self.subloops = subloops

        self.has_calls = any(map(lambda loop: loop.has_calls, subloops))

        if not self.has_calls:
            for _, _, data in self.graph.edges(data=True):
                if 'type' in data and data['type'] == 'fake_return':
                    # this is a function call.
                    self.has_calls = True
                    break

    def __repr__(self):
        s = "<Loop @ %s, %d blocks>" % (self.entry.addr, len(self.body_nodes))
        return s

class LoopFinder(Analysis):
    """
    Extracts all the loops from all the functions in a binary.
    """

    def __init__(self, functions=None, normalize=True):
        if functions is None:
            functions = self.kb.functions.values()

        found_any = False
        self.loops = []
        self.loops_hierarchy = {}
        for function in functions:

            if self.project.is_hooked(function.addr) or \
                    self.project.simos.is_syscall_addr(function.addr):
                # skip SimProcedures and syscalls
                continue

            found_any = True
            with self._resilience():
                if normalize:
                    function.normalize()
                tops, alls = self._parse_loops_from_graph(function.graph)
                self.loops += alls
                self.loops_hierarchy[function.addr] = tops

        if not found_any:
            l.error("No knowledge of functions is present. Did you forget to construct a CFG?")

    def _parse_loop_graph(self, subg, bigg):
        """
        Create a Loop object for a strongly connected graph, and any strongly
        connected subgraphs, if possible.

        :param subg:    A strongly connected subgraph.
        :param bigg:    The graph which subg is a subgraph of.

        :return:        A list of Loop objects, some of which may be inside others,
                        but all need to be documented.
        """
        loop_body_nodes = list(subg.nodes())[:]
        entry_edges = []
        break_edges = []
        continue_edges = []
        entry_node = None
        for node in loop_body_nodes:
            for pred_node in bigg.predecessors(node):
                if pred_node not in loop_body_nodes:
                    if entry_node is not None and entry_node != node:
                        l.warning("Bad loop: more than one entry point (%s, %s)", entry_node, node)
                        return None, []
                    entry_node = node
                    entry_edges.append((pred_node, node))
                    subg.add_edge(pred_node, node)
            for succ_node in bigg.successors(node):
                if succ_node not in loop_body_nodes:
                    break_edges.append((node, succ_node))
                    subg.add_edge(node, succ_node)
        if entry_node is None:
            entry_node = min(loop_body_nodes, key=lambda n: n.addr)
            l.info("Couldn't find entry point, assuming it's the first by address (%s)", entry_node)

        acyclic_subg = subg.copy()
        for pred_node in subg.predecessors(entry_node):
            if pred_node in loop_body_nodes:
                continue_edge = (pred_node, entry_node)
                acyclic_subg.remove_edge(*continue_edge)
                continue_edges.append(continue_edge)

        removed_exits = {}
        removed_entries = {}
        tops, alls = self._parse_loops_from_graph(acyclic_subg)
        for subloop in tops:
            if subloop.entry in loop_body_nodes:
                # break existing entry edges, exit edges
                # re-link in loop object
                # the exception logic is to handle when you have two loops adjacent to each other
                # you gotta link the two loops together and remove the dangling edge
                for entry_edge in subloop.entry_edges:
                    try:
                        subg.remove_edge(*entry_edge)
                    except networkx.NetworkXError:
                        if entry_edge in removed_entries:
                            subg.add_edge(removed_entries[entry_edge], subloop)
                            try:
                                subg.remove_edge(removed_entries[entry_edge], entry_edge[1])
                            except networkx.NetworkXError:
                                pass
                        else:
                            raise
                    else:
                        subg.add_edge(entry_edge[0], subloop)
                        removed_entries[entry_edge] = subloop
                for exit_edge in subloop.break_edges:
                    try:
                        subg.remove_edge(*exit_edge)
                    except networkx.NetworkXError:
                        if exit_edge in removed_entries:
                            subg.add_edge(subloop, removed_entries[exit_edge])
                            try:
                                subg.remove_edge(exit_edge[0], removed_entries[exit_edge])
                            except networkx.NetworkXError:
                                pass
                        else:
                            raise
                    else:
                        subg.add_edge(subloop, exit_edge[1])
                        removed_exits[exit_edge] = subloop
                _subgraphs = (networkx.induced_subgraph(subg, nodes).copy() for nodes in
                             networkx.weakly_connected_components(subg))
                subg = next(filter( lambda g: entry_node in g.nodes(),
                                    _subgraphs))
        me = Loop(entry_node,
             entry_edges,
             break_edges,
             continue_edges,
             loop_body_nodes,
             subg,
             tops[:])
        return me, [me] + alls

    def _parse_loops_from_graph(self, graph):
        """
        Return all Loop instances that can be extracted from a graph.

        :param graph:   The graph to analyze.

        :return:        A list of all the Loop instances that were found in the graph.
        """
        outtop = []
        outall = []
        for subg in ( networkx.induced_subgraph(graph, nodes).copy() for nodes in networkx.strongly_connected_components(graph)):
            if len(subg.nodes()) == 1:
                if len(list(subg.successors(list(subg.nodes())[0]))) == 0:
                    continue
            thisloop, allloops = self._parse_loop_graph(subg, graph)
            if thisloop is not None:
                outall += allloops
                outtop.append(thisloop)
        return outtop, outall

from angr.analyses import AnalysesHub
AnalysesHub.register_default('LoopFinder', LoopFinder)
