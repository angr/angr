from collections import defaultdict
import logging

import networkx

l = logging.getLogger("angr.analyses.cdg")

from ..analysis import Analysis

# Control dependency graph

class TempNode(object):
    def __init__(self, label):
        self._label = label

    def __repr__(self):
        return self._label

class CDG(Analysis):
    """
    Implements a control dependence graph.
    """

    def __init__(self, cfg=None, start=None, full_control_depencences=False):
        """
        Constructor.

        :param cfg: The control flow graph upon which this control dependence graph will build
        :param start: The starting point to begin constructing the control dependence graph
        :param full_control_depencences: Set to True to include all dependants of a node in the final graph, otherwise
                                        only those strict dominators are included. The former is constructed on
                                        the post dominance frontier mapping, while the latter is based on a post
                                        dominator tree.
        """
        self._project = self._p
        self._binary = self._project.loader.main_bin
        self._start = start
        self._full_control_dependences = full_control_depencences

        self._cfg = cfg if cfg is not None else self._p.analyses.CFG()
        self._acyclic_cfg = self._cfg.copy()
        # The CFG we use should be acyclic!
        self._acyclic_cfg.remove_cycles()

        self._ancestor = None
        self._semi = None
        self._post_dom = None

        self._graph = None
        self._label = None
        # Debugging purpose
        if hasattr(self._cfg, "get_node"):
            # FIXME: We should not use get_any_irsb in such a real setting...
            self._entry = self._cfg.get_any_node(self._p.entry)

        self._construct()

    #
    # Properties
    #

    @property
    def graph(self):
        return self._graph

    #
    # Public methods
    #

    def get_post_dominators(self):
        """
        Return the post-dom tree
        """
        return self._post_dom

    def get_dependants(self, run):
        """
        Return a list of nodes that are control dependent on the given node in the control dependence graph
        """
        if run in self._graph.nodes():
            return self._graph.predecessors(run)
        else:
            return []

    def get_guardians(self, run):
        """
        Return a list of nodes on whom the specific node is control dependent in the control dependence graph
        """
        if run in self._graph.nodes():
            return self._graph.successors(run)
        else:
            return []

    #
    # Private methods
    #

    def _construct(self):
        """
        Construct a control dependence graph.

        This implementtion is based on figure 6 of paper An Efficient Method of Computing Static Single Assignment
        Form by Ron Cytron, etc.
        """

        # Construct post-dominator tree
        self._pd_construct()

        self._graph = networkx.DiGraph()

        if self._full_control_dependences:
            # Construct the reversed dominance frontier mapping
            rdf = self._df_construct(self._post_dom)

            for y in self._cfg.graph.nodes_iter():
                if y not in rdf:
                    continue
                for x in rdf[y]:
                    self._graph.add_edge(x, y)

        else:
            for y in self._cfg.graph.nodes_iter():
                if y not in self._post_dom:
                    continue
                for x in self._post_dom.successors_iter(y):
                    self._graph.add_edge(x, y)

        self._post_process()

    def _post_process(self):
        """
        There are cases where a loop has two overlapping loop headers thanks
        to the way VEX is dealing with continuous instructions. As we were
        breaking the connection between the second loop header and its
        successor, we shall restore them in our CDG.
        """
        # TODO: Verify its correctness
        loop_back_edges = self._cfg.get_loop_back_edges()
        for b1, b2 in loop_back_edges:
            self._graph.add_edge(b1, b2)

    #
    # Dominance frontier related
    #

    def _df_construct(self, postdom):
        """
        Construct a dominance frontier based on the given post-dominator tree.

        This implementation is based on figure 2 of paper An Efficient Method of Computing Static Single Assignment
        Form by Ron Cytron, etc.

        :param postdom: The post-dominator tree
        :return: A dict of dominance frontier
        """

        DF = { }

        # Perform a post-order search on the post-dom tree
        for x in networkx.dfs_postorder_nodes(postdom):
            DF[x] = set()

            # local set
            for y in postdom.successors_iter(x):
                if postdom[y] is not x:
                    DF[x].add(y)

            # up set
            if x is None:
                continue

            for z in networkx.dfs_postorder_nodes(postdom, x):
                if z is x:
                    continue
                for y in DF[z]:
                    if postdom[y] is not x:
                        DF[x].add(y)

        return DF

    #
    # Post-dominator tree related
    #

    def _pd_construct(self):
        """
        Find post-dominators for each node in CFG.

        This implementation is based on paper A Fast Algorithm for Finding Dominators in a Flow Graph by Thomas
        Lengauer and Robert E. Tarjan from Stanford University, ACM Transactions on Programming Languages and Systems,
        Vol. 1, No. 1, July 1979
        """
        normalized_graph, vertices, parent = self._pd_normalize_graph()

        bucket = defaultdict(set)
        dom = [None] * (len(vertices))
        self._ancestor = [None] * (len(vertices) + 1)

        range_ = range(1, len(vertices))
        range_.reverse()
        for i in range_:
            w = vertices[i]
            if w not in parent:
                # It's one of the start nodes
                continue
            predecessors = normalized_graph.predecessors(w)
            for v in predecessors:
                u = self._pd_eval(v)
                if self._semi[u.index].index < self._semi[w.index].index:
                    self._semi[w.index] = self._semi[u.index]
            bucket[vertices[self._semi[w.index].index].index].add(w)
            self._pd_link(parent[w], w)
            for v in bucket[parent[w].index]:
                u = self._pd_eval(v)
                if self._semi[u.index].index < self._semi[v.index].index:
                    dom[v.index] = u
                else:
                    dom[v.index] = parent[w]
            bucket[parent[w].index].clear()

        for i in range(1, len(vertices)):
            w = vertices[i]
            if w not in parent:
                continue
            if dom[w.index] != vertices[self._semi[w.index].index]:
                dom[w.index] = dom[dom[w.index].index]

        self._post_dom = networkx.DiGraph() # The post-dom tree described in a directional graph
        for i in xrange(1, len(vertices)):
            self._post_dom.add_edge(vertices[i], dom[i])

        self._pd_post_process()

    def _pd_post_process(self):
        '''
        Take care of those loop headers/tails where we manually broke their
        connection to the next BBL
        '''
        loop_back_edges = self._cfg.get_loop_back_edges()
        for b1, b2 in loop_back_edges:
            # The edge between b1 and b2 is manually broken
            # The post dominator of b1 should be b2 (or not?)
            successors = self._acyclic_cfg.get_successors(b1)
            if len(successors) == 0:
                if b2 in self._post_dom:
                    self._post_dom.add_edge(b1, b2)
                else:
                    l.debug("%s is not in post dominator dict.", b2)

    def _pd_normalize_graph(self):
        # We want to reverse the CFG, and label each node according to its
        # order in a DFS
        graph = networkx.DiGraph()

        n = self._start if self._start is not None else self._entry
        assert n is not None
        queue = [n]
        start_node = TempNode("start_node")
        traversed_nodes = set()
        while len(queue) > 0:
            node = queue.pop()
            traversed_nodes.add(node)
            successors = self._acyclic_cfg.get_successors(node)
            if len(successors) == 0:
                # Add an edge between this node and our start node
                graph.add_edge(start_node, node)
            for s in successors:
                graph.add_edge(s, node) # Reversed
                if s not in traversed_nodes:
                    queue.append(s)

        # Add a start node and an end node
        graph.add_edge(n, TempNode("end_node"))

        all_nodes_count = len(traversed_nodes) + 2 # A start node and an end node
        l.debug("There should be %d nodes in all", all_nodes_count)
        counter = 0
        vertices = ["placeholder"]
        scanned_nodes = set()
        parent = {}
        while True:
            # DFS from the current start node
            stack = [start_node]
            while len(stack) > 0:
                node = stack.pop()
                counter += 1
                node.index = counter
                scanned_nodes.add(node)
                vertices.append(node)
                successors = graph.successors(node)
                for s in successors:
                    if s not in scanned_nodes:
                        stack.append(s)
                        parent[s] = node
                        scanned_nodes.add(s)

            if counter >= all_nodes_count:
                break

            l.debug("%d nodes are left out during the DFS. They must formed a cycle themselves.", all_nodes_count - counter)
            # Find those nodes
            leftovers = [s for s in traversed_nodes if s not in scanned_nodes]
            graph.add_edge(start_node, leftovers[0])
            # We have to start over...
            counter = 0
            parent = {}
            scanned_nodes = set()
            vertices = ["placeholder"]

        self._semi = vertices[::]
        self._label = vertices[::]

        return (graph, vertices, parent)

    def _pd_link(self, v, w):
        self._ancestor[w.index] = v

    def _pd_eval(self, v):
        if self._ancestor[v.index] is None:
            return v
        else:
            self._pd_compress(v)
            return self._label[v.index]

    def _pd_compress(self, v):
        if self._ancestor[self._ancestor[v.index].index] != None:
            self._pd_compress(self._ancestor[v.index])
            if self._semi[self._label[self._ancestor[v.index].index].index].index < self._semi[self._label[v.index].index].index:
                self._label[v.index] = self._label[self._ancestor[v.index].index]
            self._ancestor[v.index] = self._ancestor[self._ancestor[v.index].index]
