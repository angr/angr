
import logging
from typing import Optional

import networkx

from .. import Analysis, register_analysis
from ...utils.graph import dfs_back_edges, subgraph_between_nodes, dominates

l = logging.getLogger(name=__name__)


class MultiNode:
    def __init__(self, nodes):
        self.nodes = [ ]

        for node in nodes:
            if type(node) is MultiNode:
                self.nodes += node.nodes
            elif type(node) is GraphRegion:
                self.nodes += node.nodes
            else:
                self.nodes.append(node)

    def copy(self):
        return MultiNode(self.nodes[::])

    def __repr__(self):

        addrs = [ ]
        s = ""
        for node in self.nodes:
            if hasattr(node, 'addr'):
                addrs.append(node.addr)
            s = ": %#x-%#x" % (min(addrs), max(addrs))

        return "<MultiNode of %d nodes%s>" % (len(self.nodes), s)

    @property
    def addr(self):
        return self.nodes[0].addr


class GraphRegion:
    """
    GraphRegion represents a region of nodes.

    :ivar head:             The head of the region.
    :ivar graph:            The region graph.
    :ivar successors:       A set of successors of nodes in the graph. These successors do not belong to the current
                            region.
    :ivar graph_with_successors:    The region graph that includes successor nodes.
    """

    __slots__ = ('head', 'graph', 'successors', 'graph_with_successors', )

    def __init__(self, head, graph, successors: Optional[set], graph_with_successors):
        self.head = head
        self.graph = graph
        self.successors = successors
        self.graph_with_successors = graph_with_successors

    def __repr__(self):

        addrs = [ ]
        s = ""
        for node in self.graph.nodes():
            if hasattr(node, 'addr'):
                addrs.append(node.addr)
            if addrs:
                s = ": %#x-%#x" % (min(addrs), max(addrs))

        if not s:
            s = ": %s" % self.head

        return "<GraphRegion of %d nodes%s>" % (self.graph.number_of_nodes(), s)

    def recursive_copy(self):

        nodes_map = { }
        new_graph = self._recursive_copy(self.graph, nodes_map)

        if self.graph_with_successors is not None:
            new_graph_with_successors = self._recursive_copy(self.graph_with_successors, nodes_map)
            successors = set(nodes_map[succ] for succ in self.successors)
        else:
            new_graph_with_successors = None
            successors = None

        return GraphRegion(nodes_map[self.head], new_graph, successors, new_graph_with_successors)

    @staticmethod
    def _recursive_copy(old_graph, nodes_map):
        new_graph = networkx.DiGraph()

        # make copy of each node and add the mapping from old nodes to new nodes into nodes_map
        for node in old_graph.nodes():
            if node not in nodes_map:
                if type(node) is GraphRegion:
                    new_node = node.recursive_copy()
                    nodes_map[node] = new_node
                elif type(node) is MultiNode:
                    new_node = node.copy()
                    nodes_map[node] = new_node
                else:
                    new_node = node
                    nodes_map[node] = new_node
                new_graph.add_node(new_node)
            else:
                new_graph.add_node(nodes_map[node])

        # add all edges
        for src, dst in old_graph.edges():
            new_graph.add_edge(nodes_map[src], nodes_map[dst])

        return new_graph

    @property
    def addr(self):
        return self.head.addr

    @staticmethod
    def dbg_get_repr(obj, ident=0):
        if type(obj) is GraphRegion:
            s = obj.dbg_print(ident=ident)
        else:
            s = " " * ident + str(obj)

        return s

    def dbg_print(self, ident=0):

        s = self.dbg_get_repr(self.head, ident=ident) + "\n"

        successors = list(self.graph.successors(self.head))
        if len(successors) == 2:
            left_kid, right_kid = successors
            s += " " * ident + "if (...) {\n" + \
                 self.dbg_get_repr(left_kid, ident=ident + 2) + "\n" + \
                 " " * ident + "}\n" + \
                 " " * ident + "else if (...) {\n" + \
                 self.dbg_get_repr(right_kid, ident=ident + 2) + "\n" + \
                 " " * ident + "}"
            # TODO: other nodes
        elif len(successors) == 1:
            s += self.dbg_get_repr(successors[0], ident=ident)

        return s

    def replace_region(self, sub_region, replace_with):

        if sub_region not in self.graph:
            l.error("The sub-region to replace must be in the current region. Note that this method is not recursive.")
            raise Exception()

        if sub_region is self.head:
            self.head = replace_with

        self._replace_node_in_graph(self.graph, sub_region, replace_with)
        if self.graph_with_successors is not None:
            self._replace_node_in_graph(self.graph_with_successors, sub_region, replace_with)

    @staticmethod
    def _replace_node_in_graph(graph, node, replace_with):

        in_edges = list(graph.in_edges(node))
        out_edges = list(graph.out_edges(node))

        graph.remove_node(node)
        graph.add_node(replace_with)

        for src, _ in in_edges:
            if src is node:
                graph.add_edge(replace_with, replace_with)
            else:
                graph.add_edge(src, replace_with)

        for _, dst in out_edges:
            if dst is node:
                graph.add_edge(replace_with, replace_with)
            else:
                graph.add_edge(replace_with, dst)

        assert node not in graph


class RegionIdentifier(Analysis):
    """
    Identifies regions within a function.
    """
    def __init__(self, func, graph=None):
        self.function = func
        self._graph = graph if graph is not None else self.function.graph

        self.region = None
        self._start_node = None
        self._loop_headers = None

        self._analyze()

    @staticmethod
    def slice_graph(graph, node, frontier, include_frontier=False):
        """
        Generate a slice of the graph from the head node to the given frontier.

        :param networkx.DiGraph graph: The graph to work on.
        :param node: The starting node in the graph.
        :param frontier: A list of frontier nodes.
        :param bool include_frontier: Whether the frontier nodes are included in the slice or not.
        :return: A subgraph.
        :rtype: networkx.DiGraph
        """

        subgraph = subgraph_between_nodes(graph, node, frontier, include_frontier=include_frontier)
        if not list(subgraph.nodes):
            # HACK: FIXME: for infinite loop nodes, this would return an empty set, so we include the loop body itself
            # Make sure this makes sense (EDG thinks it does)
            if (node, node) in graph.edges:
                subgraph.add_edge(node, node)
        return subgraph

    def _analyze(self):

        # make a copy of the graph
        graph = networkx.DiGraph(self._graph)

        # preprocess: make it a super graph
        self._make_supergraph(graph)

        self._update_start_node(graph)

        # preprocess: find loop headers
        self._loop_headers = self._find_loop_headers(graph)

        self._make_regions(graph)

        if len(graph.nodes()) > 1:
            l.warning("RegionIdentifier is unable to make one region out of the function graph of %s.",
                      repr(self.function))

        self.region = next(iter(graph.nodes()))

    def _update_start_node(self, graph):
        self._start_node = next(n for n in graph.nodes() if graph.in_degree(n) == 0)

    def _test_reducibility(self):

        # make a copy of the graph
        graph = networkx.DiGraph(self.function.graph)

        # preprocess: make it a super graph
        self._make_supergraph(graph)

        while True:

            changed = False

            # find a node with a back-edge, remove the edge (deleting the loop), and replace it with a MultiNode
            changed |= self._remove_self_loop(graph)

            # find a node that has only one predecessor, and merge it with its predecessor (replace them with a
            # MultiNode)
            changed |= self._merge_single_entry_node(graph)

            if not changed:
                # a fixed-point is reached
                break

    def _make_supergraph(self, graph):

        while True:
            for src, dst, data in graph.edges(data=True):
                if data['type'] == 'fake_return':
                    if len(list(graph.successors(src))) == 1 and len(list(graph.predecessors(dst))) == 1:
                        self._merge_nodes(graph, src, dst, force_multinode=True)
                        break
                if data['type'] == 'call':
                    graph.remove_node(dst)
                    break
            else:
                break

    def _find_loop_headers(self, graph):
        return { t for _,t in dfs_back_edges(graph, self._start_node) }

    def _find_initial_loop_nodes(self, graph, head):
        # TODO optimize
        latching_nodes = { s for s,t in dfs_back_edges(graph, self._start_node) if t == head }
        loop_subgraph = self.slice_graph(graph, head, latching_nodes, include_frontier=True)
        nodes = set(loop_subgraph.nodes())
        return nodes

    def _refine_loop(self, graph, head, initial_loop_nodes, initial_exit_nodes):
        refined_loop_nodes = initial_loop_nodes.copy()
        refined_exit_nodes = initial_exit_nodes.copy()

        idom = networkx.immediate_dominators(graph, self._start_node)

        new_exit_nodes = refined_exit_nodes
        while len(refined_exit_nodes) > 1 and len(new_exit_nodes) != 0:
            new_exit_nodes = set()
            for n in list(refined_exit_nodes):
                if all(pred in refined_loop_nodes for pred in graph.predecessors(n)) and dominates(idom, head, n):
                    refined_loop_nodes.add(n)
                    refined_exit_nodes.remove(n)
                    for u in (set(graph.successors(n)) - refined_loop_nodes):
                        new_exit_nodes.add(u)
            refined_exit_nodes |= new_exit_nodes
        return refined_loop_nodes, refined_exit_nodes

    def _remove_self_loop(self, graph):

        r = False

        while True:
            for node in graph.nodes():
                if node in graph[node]:
                    # found a self loop
                    self._remove_node(graph, node)
                    r = True
                    break
            else:
                break

        return r

    def _merge_single_entry_node(self, graph):

        r = False

        while True:
            for node in networkx.dfs_postorder_nodes(graph):
                preds = graph.predecessors(node)
                if len(preds) == 1:
                    # merge the two nodes
                    self._absorb_node(graph, preds[0], node)
                    r = True
                    break
            else:
                break

        return r

    def _make_regions(self, graph):

        r = False
        structured_loop_headers = set()

        while True:
            restart = False
            df = None

            self._update_start_node(graph)

            # Start from loops
            for node in self._loop_headers:
                if node in structured_loop_headers:
                    continue

                l.debug("Found cyclic region at %#08x", node.addr)
                initial_loop_nodes = self._find_initial_loop_nodes(graph, node)
                l.debug("Initial loop nodes %s", self._dbg_block_list(initial_loop_nodes))

                # Make sure there is no other loop contained in the current loop
                if { n for n in initial_loop_nodes if n.addr != node.addr }.intersection(self._loop_headers):
                    continue

                normal_entries = { n for n in graph.predecessors(node) if n not in initial_loop_nodes }
                abnormal_entries = set()
                for n in initial_loop_nodes:
                    if n == node:
                        continue
                    preds = set(graph.predecessors(n))
                    abnormal_entries |= (preds - initial_loop_nodes)
                l.debug("Normal entries %s", self._dbg_block_list(normal_entries))
                l.debug("Abnormal entries %s", self._dbg_block_list(abnormal_entries))

                initial_exit_nodes = set()
                for n in initial_loop_nodes:
                    succs = set(graph.successors(n))
                    initial_exit_nodes |= (succs - initial_loop_nodes)

                l.debug("Initial exit nodes %s", self._dbg_block_list(initial_exit_nodes))

                refined_loop_nodes, refined_exit_nodes = self._refine_loop(graph, node, initial_loop_nodes,
                                                                           initial_exit_nodes)
                l.debug("Refined loop nodes %s", self._dbg_block_list(refined_loop_nodes))
                l.debug("Refined exit nodes %s", self._dbg_block_list(refined_exit_nodes))

                if len(refined_exit_nodes) > 1:
                    self._update_start_node(graph)
                    node_post_order = list(networkx.dfs_postorder_nodes(graph, node))
                    sorted_exit_nodes = sorted(list(refined_exit_nodes), key=node_post_order.index)
                    normal_exit_node = sorted_exit_nodes[0]
                    abnormal_exit_nodes = set(sorted_exit_nodes[1:])
                else:
                    normal_exit_node = next(iter(refined_exit_nodes)) if len(refined_exit_nodes) > 0 else None
                    abnormal_exit_nodes = set()

                self._abstract_cyclic_region(graph, refined_loop_nodes, node, normal_entries, abnormal_entries,
                                             normal_exit_node, abnormal_exit_nodes)

                structured_loop_headers.add(node)
                restart = True
                break

            if restart:
                continue

            # No more loops left. Structure acyclic regions.
            for node in networkx.dfs_postorder_nodes(graph, source=self._start_node):
                out_degree = graph.out_degree[node]
                if out_degree == 0:
                    # the root element of the region hierarchy should always be a GraphRegion,
                    # so we transform it into one, if necessary
                    if graph.in_degree(node) == 0 and not isinstance(node, GraphRegion):
                        subgraph = networkx.DiGraph()
                        subgraph.add_node(node)
                        self._abstract_acyclic_region(graph, GraphRegion(node, subgraph, None, None), [])
                    continue

                if df is None:
                    self._update_start_node(graph)
                    df = networkx.algorithms.dominance_frontiers(graph, self._start_node)
                frontier = df[node]
                if len(frontier) <= 1:
                    region = self._compute_region(graph, node, frontier)
                    if region is None:
                        continue

                    self._abstract_acyclic_region(graph, region, frontier)
                    break
                else:
                    continue
                    #raise NotImplementedError()
            else:
                break

        return r

    @staticmethod
    def _compute_region(graph, node, frontier, include_frontier=False):

        subgraph = networkx.DiGraph()
        frontier_edges = [ ]
        queue = [ node ]
        traversed = set()

        while queue:
            node_ = queue.pop()
            if node_ in frontier:
                continue
            traversed.add(node_)
            subgraph.add_node(node_)

            for succ in graph.successors(node_):

                if node_ in frontier and succ in traversed:
                    if include_frontier:
                        # if frontier nodes are included, do not keep traversing their successors
                        # however, if it has an edge to an already traversed node, we should add that edge
                        subgraph.add_edge(node_, succ)
                    else:
                        frontier_edges.append((node_, succ))
                    continue

                if succ in frontier:
                    if not include_frontier:
                        # skip all frontier nodes
                        frontier_edges.append((node_, succ))
                        continue
                subgraph.add_edge(node_, succ)
                if succ in traversed:
                    continue
                queue.append(succ)

        if subgraph.number_of_nodes() > 1:
            subgraph_with_frontier = networkx.DiGraph(subgraph)
            for src, dst in frontier_edges:
                subgraph_with_frontier.add_edge(src, dst)
            return GraphRegion(node, subgraph, frontier, subgraph_with_frontier)
        else:
            return None

    def _abstract_acyclic_region(self, graph, region, frontier):

        in_edges = self._region_in_edges(graph, region, data=True)

        nodes_set = set()
        for node_ in list(region.graph.nodes()):
            nodes_set.add(node_)
            graph.remove_node(node_)

        graph.add_node(region)

        for src, _, data in in_edges:
            if src not in nodes_set:
                graph.add_edge(src, region, **data)

        if frontier:
            for frontier_node in frontier:
                graph.add_edge(region, frontier_node)

    @staticmethod
    def _abstract_cyclic_region(graph, loop_nodes, head, normal_entries, abnormal_entries, normal_exit_node,
                                abnormal_exit_nodes):
        region = GraphRegion(head, None, None, None)

        subgraph = networkx.DiGraph()
        region_outedges = [ ]

        graph.add_node(region)
        for node in loop_nodes:
            subgraph.add_node(node)
            in_edges = graph.in_edges(node, data=True)
            out_edges = graph.out_edges(node, data=True)

            for src, dst, data in in_edges:
                if src in normal_entries:
                    graph.add_edge(src, region, **data)
                elif src in abnormal_entries:
                    data['region_dst_node'] = dst
                    graph.add_edge(src, region, **data)
                elif src in loop_nodes:
                    subgraph.add_edge(src, dst, **data)
                else:
                    assert 0

            for src, dst, data in out_edges:
                if dst in loop_nodes:
                    subgraph.add_edge(src, dst, **data)
                else:
                    if dst is normal_exit_node:
                        region_outedges.append((node, dst))
                        graph.add_edge(region, dst, **data)
                    elif dst in abnormal_exit_nodes:
                        region_outedges.append((node, dst))
                        data['region_src_node'] = src
                        graph.add_edge(region, dst, **data)
                    else:
                        assert 0

        subgraph_with_exits = networkx.DiGraph(subgraph)
        for src, dst in region_outedges:
            subgraph_with_exits.add_edge(src, dst)
        region.graph = subgraph
        region.graph_with_successors = subgraph_with_exits
        if normal_exit_node is not None:
            region.successors = [normal_exit_node]
        else:
            region.successors = [ ]
        region.successors += list(abnormal_exit_nodes)

        for node in loop_nodes:
            graph.remove_node(node)

    @staticmethod
    def _region_in_edges(graph, region, data=False):

        return list(graph.in_edges(region.head, data=data))

    def _remove_node(self, graph, node):  # pylint:disable=no-self-use

        in_edges = [ (src, dst, data) for (src, dst, data) in graph.in_edges(node, data=True) if not src is node ]
        out_edges = [ (src, dst, data) for (src, dst, data) in graph.out_edges(node, data=True) if not dst is node ]

        if len(in_edges) <= 1 and len(out_edges) <= 1:
            # it forms a region by itself :-)
            new_node = None

        else:
            new_node = MultiNode([ node ])

        graph.remove_node(node)

        if new_node is not None:
            for src, _, data in in_edges:
                graph.add_edge(src, new_node, **data)

            for _, dst, data in out_edges:
                graph.add_edge(new_node, dst, **data)

    def _merge_nodes(self, graph, node_a, node_b, force_multinode=False):  # pylint:disable=no-self-use

        in_edges = list(graph.in_edges(node_a, data=True))
        out_edges = list(graph.out_edges(node_b, data=True))

        if not force_multinode and len(in_edges) <= 1 and len(out_edges) <= 1:
            # it forms a region by itself :-)
            new_node = None

        else:
            new_node = MultiNode([ node_a, node_b ])

        graph.remove_node(node_a)
        graph.remove_node(node_b)

        if new_node is not None:
            graph.add_node(new_node)

            for src, _, data in in_edges:
                if src is node_b:
                    src = new_node
                graph.add_edge(src, new_node, **data)

            for _, dst, data in out_edges:
                if dst is node_a:
                    dst = new_node
                graph.add_edge(new_node, dst, **data)

        assert not node_a in graph
        assert not node_b in graph

    def _absorb_node(self, graph, node_mommy, node_kiddie, force_multinode=False):  # pylint:disable=no-self-use

        in_edges_mommy = graph.in_edges(node_mommy, data=True)
        out_edges_mommy = graph.out_edges(node_mommy, data=True)
        out_edges_kiddie = graph.out_edges(node_kiddie, data=True)

        if not force_multinode and len(in_edges_mommy) <= 1 and len(out_edges_kiddie) <= 1:
            # it forms a region by itself :-)
            new_node = None

        else:
            new_node = MultiNode([node_mommy, node_kiddie])

        graph.remove_node(node_mommy)
        graph.remove_node(node_kiddie)

        if new_node is not None:
            graph.add_node(new_node)

            for src, _, data in in_edges_mommy:
                if src == node_kiddie:
                    src = new_node
                graph.add_edge(src, new_node, **data)

            for _, dst, data in out_edges_mommy:
                if dst == node_kiddie:
                    continue
                if dst == node_mommy:
                    dst = new_node
                graph.add_edge(new_node, dst, **data)

            for _, dst, data in out_edges_kiddie:
                if dst == node_mommy:
                    dst = new_node
                graph.add_edge(new_node, dst, **data)

        assert not node_mommy in graph
        assert not node_kiddie in graph

    @staticmethod
    def _dbg_block_list(blocks):
        return [hex(b.addr) for b in blocks]


register_analysis(RegionIdentifier, 'RegionIdentifier')
