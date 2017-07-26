
import logging

import networkx

from . import Analysis, register_analysis

l = logging.getLogger('angr.analyses.region_identifier')


class MultiNode(object):
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


class GraphRegion(object):
    def __init__(self, head, graph):
        self.head = head
        self.graph = graph

    def __repr__(self):

        addrs = [ ]
        s = ""
        for node in self.graph.nodes_iter():
            if hasattr(node, 'addr'):
                addrs.append(node.addr)
            if addrs:
                s = ": %#x-%#x" % (min(addrs), max(addrs))

        if not s:
            s = ": %s" % self.head

        return "<GraphRegion of %d nodes%s>" % (self.graph.number_of_nodes(), s)

    def recursive_copy(self):

        new_graph = networkx.DiGraph()

        nodes_map = { }
        for node in self.graph.nodes_iter():
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

        for src, dst in self.graph.edges_iter():
            new_graph.add_edge(nodes_map[src], nodes_map[dst])

        return GraphRegion(nodes_map[self.head], new_graph)

    @property
    def addr(self):
        return self.head.addr

    def dbg_get_repr(self, obj, ident=0):
        if type(obj) is GraphRegion:
            s = obj.dbg_print(ident=ident)
        else:
            s = " " * ident + str(obj)

        return s

    def dbg_print(self, ident=0):

        s = self.dbg_get_repr(self.head, ident=ident) + "\n"

        successors = self.graph.successors(self.head)
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

        in_edges = self.graph.in_edges(sub_region)
        out_edges = self.graph.out_edges(sub_region)

        self.graph.remove_node(sub_region)

        for src, _ in in_edges:
            if src is sub_region:
                self.graph.add_edge(replace_with, replace_with)
            else:
                self.graph.add_edge(src, replace_with)

        for _, dst in out_edges:
            if dst is sub_region:
                self.graph.add_edge(replace_with, replace_with)
            else:
                self.graph.add_edge(replace_with, dst)

        assert sub_region not in self.graph


class RegionIdentifier(Analysis):
    def __init__(self, func, graph=None):
        self.function = func
        self._graph = graph if graph is not None else self.function.graph

        self.region = None

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

        subgraph = networkx.DiGraph()

        for frontier_node in frontier:
            for simple_path in networkx.all_simple_paths(graph, node, frontier_node):
                for src, dst in zip(simple_path, simple_path[1:]):
                    if include_frontier or (src not in frontier and dst not in frontier):
                        subgraph.add_edge(src, dst)

        return subgraph

    def _analyze(self):

        # make a copy of the graph
        graph = networkx.DiGraph(self._graph)

        # preprocess: make it a super graph
        self._make_supergraph(graph)

        # preprocess: find loop headers
        self._loop_headers = self._find_loop_headers(graph)

        self._make_regions(graph)

        assert len(graph.nodes()) == 1

        self.region = graph.nodes()[0]

    def _test_reducibility(self):

        # make a copy of the graph
        graph = networkx.DiGraph(self.function.graph)

        # preprocess: make it a super graph
        self._make_supergraph(graph)

        while True:

            changed = False

            # find a node with a back-edge, remove the edge (deleting the loop), and replace it with a MultiNode
            changed |= self._remove_self_loop(graph)

            # find a node that has only one predecessor, and merge it with its predecessor (replace them with a MultiNode)
            changed |= self._merge_single_entry_node(graph)

            if not changed:
                # a fixed-point is reached
                break

    def _make_supergraph(self, graph):

        while True:
            for src, dst, data in graph.edges(data=True):
                if data['type'] == 'fake_return':
                    if len(graph.successors(src)) == 1 and len(graph.predecessors(dst)) == 1:
                        self._merge_nodes(graph, src, dst, force_multinode=True)
                        break
                if data['type'] == 'call':
                    graph.remove_node(dst)
                    break
            else:
                break

    def _find_loop_headers(self, graph):
        # raise NotImplementedError()
        pass

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

    def _make_regions(self, graph, start=None):

        r = False

        if start is None:
            start = next(n for n in graph.nodes_iter() if graph.in_degree(n) == 0)

        while True:

            df = None

            for node in networkx.dfs_postorder_nodes(graph):
                succs = graph.successors(node)
                if not succs:
                    continue
                # TODO: handling loops
                # compute its region
                if df is None:
                    df = networkx.algorithms.dominance_frontiers(graph, start)
                frontier = df[node]
                if len(frontier) <= 1:
                    region = self._compute_region(graph, node, frontier)
                    if region is None:
                        continue
                    else:
                        self._abstract_region(graph, region, frontier)
                        break
                else:
                    raise NotImplementedError()
            else:
                break

        return r

    def _compute_region(self, graph, node, frontier, include_frontier=False):

        subgraph = networkx.DiGraph()
        queue = [ node ]
        traversed = set()

        while queue:
            node_ = queue.pop()
            if node_ in frontier:
                continue
            traversed.add(node_)
            subgraph.add_node(node_)

            for succ in graph.successors(node_):

                if include_frontier and node_ in frontier and succ in traversed:
                    # if frontier nodes are included, do not keep traversing their successors
                    # however, if it has an edge to an already traversed node, we should add that edge
                    subgraph.add_edge(node_, succ)
                    continue

                if succ in frontier:
                    if not include_frontier:
                        # skip all frontier nodes
                        continue
                subgraph.add_edge(node_, succ)
                if succ in traversed:
                    continue
                queue.append(succ)

        if subgraph.number_of_nodes() > 1:
            return GraphRegion(node, subgraph)
        else:
            return None

    def _abstract_region(self, graph, region, frontier):

        in_edges = self._region_in_edges(graph, region, data=True)

        nodes_set = set()
        for node_ in region.graph.nodes_iter():
            nodes_set.add(node_)
            graph.remove_node(node_)

        graph.add_node(region)

        for src, _, data in in_edges:
            if src not in nodes_set:
                graph.add_edge(src, region, **data)

        if frontier:
            for frontier_node in frontier:
                graph.add_edge(region, frontier_node)

    def _region_in_edges(self, graph, region, data=False):

        return graph.in_edges(region.head, data=data)

    def _remove_node(self, graph, node):

        in_edges = [ (src, dst, data) for (src, dst, data) in graph.in_edges(node, data=True) if not src is node ]
        out_edges = [ (src, dst, data) for (src, dst, data) in graph.out_edges(node, data=True) if not dst is node ]

        if len(in_edges) <= 1 and len(out_edges) <= 1:
            # it forms a region :-)
            new_node = GraphRegion([ node ])
            self.regions.append(new_node)

        else:
            new_node = MultiNode([ node ])

        graph.remove_node(node)
        for src, _, data in in_edges:
            graph.add_edge(src, new_node, **data)

        for _, dst, data in out_edges:
            graph.add_edge(new_node, dst, **data)

    def _merge_nodes(self, graph, node_a, node_b, force_multinode=False):

        in_edges = [ (src, dst, data) for (src, dst, data) in graph.in_edges(node_a, data=True) ]
        out_edges = [ (src, dst, data) for (src, dst, data) in graph.out_edges(node_b, data=True) ]

        if not force_multinode and len(in_edges) <= 1 and len(out_edges) <= 1:
            # it forms a region :-)
            new_node = GraphRegion([ node_a, node_b ])
            self.regions.append(new_node)

        else:
            new_node = MultiNode([ node_a, node_b ])

        graph.remove_node(node_a)
        graph.remove_node(node_b)

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

    def _absorb_node(self, graph, node_mommy, node_kiddie, force_multinode=False):

        in_edges_mommy = graph.in_edges(node_mommy, data=True)
        out_edges_mommy = graph.out_edges(node_mommy, data=True)
        out_edges_kiddie = graph.out_edges(node_kiddie, data=True)

        if not force_multinode and len(in_edges_mommy) <= 1 and len(out_edges_kiddie) <= 1:
            # it forms a region :-)
            new_node = GraphRegion([node_mommy, node_kiddie])
            self.regions.append(new_node)

        else:
            new_node = MultiNode([node_mommy, node_kiddie])

        graph.remove_node(node_mommy)
        graph.remove_node(node_kiddie)

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


register_analysis(RegionIdentifier, 'RegionIdentifier')
