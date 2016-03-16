import networkx
import logging

from ..analysis import Analysis, register_analysis

l = logging.getLogger('angr.analyses.loops')

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
            for _, _, data in self.graph.edges_iter(data=True):
                if 'type' in data and data['type'] == 'fake_return':
                    # this is a function call.
                    self.has_calls = True
                    break

class LoopFinder(Analysis):
    """
    Extracts all the loops from all the functions in a binary.
    """

    def __init__(self, functions=None):
        if functions is None:
            functions = self.kb.functions.itervalues()

        found_any = False
        self.loops = []
        for function in functions:
            found_any = True
            with self._resilience():
                function.normalize()
                self.loops += self._parse_loops_from_graph(function.graph)

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
        loop_body_nodes = subg.nodes()[:]
        entry_edges = []
        break_edges = []
        continue_edges = []
        entry_node = None
        for node in loop_body_nodes:
            for pred_node in bigg.predecessors(node):
                if pred_node not in loop_body_nodes:
                    if entry_node is not None and entry_node != node:
                        l.warning("Bad loop: more than one entry point (%#x, %#x)", entry_node, node)
                        return []
                    entry_node = node
                    entry_edges.append((pred_node, node))
                    subg.add_edge(pred_node, node)
            for succ_node in bigg.successors(node):
                if succ_node not in loop_body_nodes:
                    break_edges.append((node, succ_node))
                    subg.add_edge(node, succ_node)
        if entry_node is None:
            entry_node = min(loop_body_nodes, key=lambda n: n.addr)
            l.info("Couldn't find entry point, assuming it's the first by address (%#x)", entry_node)

        acyclic_subg = subg.copy()
        for pred_node in subg.predecessors(entry_node):
            if pred_node in loop_body_nodes:
                continue_edge = (pred_node, entry_node)
                acyclic_subg.remove_edge(*continue_edge)
                continue_edges.append(continue_edge)

        subloops = self._parse_loops_from_graph(acyclic_subg)
        for subloop in subloops:
            if subloop.entry in loop_body_nodes:
                # break existing entry edges, exit edges
                # re-link in loop object
                for entry_edge in subloop.entry_edges:
                    subg.remove_edge(*entry_edge)
                    subg.add_edge(entry_edge[0], subloop)
                for exit_edge in subloop.break_edges:
                    subg.remove_edge(*exit_edge)
                    subg.add_edge(subloop, exit_edge[1])
                subg = filter(lambda g: entry_node in g.nodes(),
                        networkx.weakly_connected_component_subgraphs(subg))[0]

        subloops.append(Loop(entry_node,
                             entry_edges,
                             break_edges,
                             continue_edges,
                             loop_body_nodes,
                             subg,
                             subloops[:]))
        return subloops

    def _parse_loops_from_graph(self, graph):
        """
        Return all Loop instances that can be extracted from a graph.

        :param graph:   The graph to analyze.

        :return:        A list of all the Loop instances that were found in the graph.
        """
        out = []
        for subg in networkx.strongly_connected_component_subgraphs(graph):
            if len(subg.nodes()) == 1:
                if len(subg.successors(subg.nodes()[0])) == 0:
                    continue
            out += self._parse_loop_graph(subg, graph)
        return out

register_analysis(LoopFinder, 'LoopFinder')
