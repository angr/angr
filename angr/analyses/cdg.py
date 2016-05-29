from collections import defaultdict
import logging

import networkx

l = logging.getLogger("angr.analyses.cdg")

from ..analysis import Analysis, register_analysis


class TemporaryNode(object):
    """
    A temporary node.

    Used as the start node and end node in post-dominator tree generation. Also used in some test cases.
    """
    def __init__(self, label):
        self._label = label

    def __repr__(self):
        return 'TemporaryNode[%s]' % self._label

    def __eq__(self, other):
        if isinstance(other, TemporaryNode) and other._label == self._label:
            return True
        return False

    def __hash__(self):
        return hash('%s' % self._label)


class ContainerNode(object):
    """
    A container node.

    Only used in post-dominator tree generation. We did this so we can set the index property without modifying the
    original object.
    """
    def __init__(self, obj):
        self._obj = obj
        self.index = None

    @property
    def obj(self):
        return self._obj

    def __eq__(self, other):
        if isinstance(other, ContainerNode):
            return self._obj == other._obj and self.index == other.index
        return False


class CDG(Analysis):
    """
    Implements a control dependence graph.
    """

    def __init__(self, cfg, start=None, no_construct=False):
        """
        Constructor.

        :param cfg:             The control flow graph upon which this control dependence graph will build
        :param start:           The starting point to begin constructing the control dependence graph
        :param no_construct:    Skip the construction step. Only used in unit-testing.
        """
        self._binary = self.project.loader.main_bin
        self._start = start if start is not None else self.project.entry
        self._cfg = cfg

        self._ancestor = None
        self._semi = None
        self._post_dom = None

        self._graph = None
        self._label = None
        self._normalized_cfg = None

        if not no_construct:
            if self._cfg is None:
                self._cfg = self.project.analyses.CFGAccurate()

            # FIXME: We should not use get_any_irsb in such a real setting...
            self._entry = self._cfg.get_any_node(self._start)

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
            return self._graph.successors(run)
        else:
            return []

    def get_guardians(self, run):
        """
        Return a list of nodes on whom the specific node is control dependent in the control dependence graph
        """
        if run in self._graph.nodes():
            return self._graph.predecessors(run)
        else:
            return []

    #
    # Private methods
    #

    def _construct(self):
        """
        Construct a control dependence graph.

        This implementation is based on figure 6 of paper An Efficient Method of Computing Static Single Assignment
        Form by Ron Cytron, etc.
        """

        self._acyclic_cfg = self._cfg.copy()
        # TODO: Cycle-removing is not needed - confirm it later
        # The CFG we use should be acyclic!
        #self._acyclic_cfg.remove_cycles()

        # Pre-process the acyclic CFG
        self._pre_process_cfg()

        # Construct post-dominator tree
        self._pd_construct()

        self._graph = networkx.DiGraph()

        # Construct the reversed dominance frontier mapping
        rdf = self._df_construct(self._post_dom)

        for y in self._cfg.graph.nodes_iter():
            if y not in rdf:
                continue
            for x in rdf[y]:
                self._graph.add_edge(x, y)

        # self._post_process()

    def _pre_process_cfg(self):
        """
        Pre-process the acyclic CFG by changing all FakeRet edges to normal edges when necessary (e.g. the normal return
        edge does not exist)
        """
        for src, dst, data in self._acyclic_cfg.graph.edges(data=True):
            if 'jumpkind' in data and data['jumpkind'] == 'Ijk_FakeRet':
                all_edges_to_dst = self._acyclic_cfg.graph.in_edges([ dst ], data=True)
                if not any((s, d) for s, d, da in all_edges_to_dst if da['jumpkind'] != 'Ijk_FakeRet' ):
                    # All in edges are FakeRets
                    # Change them to a normal edge
                    for _, _, data in all_edges_to_dst:
                        data['jumpkind'] = 'Ijk_Boring'

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
        :returns:        A dict of dominance frontier
        """

        DF = { }

        # Perform a post-order search on the post-dom tree
        for x in networkx.dfs_postorder_nodes(postdom):
            DF[x] = set()

            # local set
            for y in self._normalized_cfg.successors_iter(x):
                if x not in postdom.predecessors(y):
                    DF[x].add(y)

            # up set
            if x is None:
                continue

            for z in postdom.successors(x):
                if z is x:
                    continue
                if z not in DF:
                    continue
                for y in DF[z]:
                    if x not in postdom.predecessors(y):
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

        # Step 1

        _normalized_cfg, vertices, parent = self._pd_normalize_graph()
        # vertices is a list of ContainerNode(CFGNode) instances
        # parent is a dict storing the mapping from ContainerNode(CFGNode) to ContainerNode(CFGNode)
        # Each node in normalized_cfg is a ContainerNode(CFGNode) instance

        bucket = defaultdict(set)
        dom = [None] * (len(vertices))
        self._ancestor = [None] * (len(vertices) + 1)

        for i in xrange(len(vertices) - 1, 0, -1):
            w = vertices[i]

            # Step 2
            if w not in parent:
                # It's one of the start nodes
                continue

            predecessors = _normalized_cfg.predecessors(w)
            for v in predecessors:
                u = self._pd_eval(v)
                if self._semi[u.index].index < self._semi[w.index].index:
                    self._semi[w.index] = self._semi[u.index]

            bucket[vertices[self._semi[w.index].index].index].add(w)

            self._pd_link(parent[w], w)

            # Step 3
            for v in bucket[parent[w].index]:
                u = self._pd_eval(v)
                if self._semi[u.index].index < self._semi[v.index].index:
                    dom[v.index] = u
                else:
                    dom[v.index] = parent[w]

            bucket[parent[w].index].clear()

        for i in xrange(1, len(vertices)):
            w = vertices[i]
            if w not in parent:
                continue
            if dom[w.index].index != vertices[self._semi[w.index].index].index:
                dom[w.index] = dom[dom[w.index].index]

        self._post_dom = networkx.DiGraph() # The post-dom tree described in a directional graph
        for i in xrange(1, len(vertices)):
            if dom[i] is not None and vertices[i] is not None:
                self._post_dom.add_edge(dom[i].obj, vertices[i].obj)

        self._pd_post_process()

        # Create the normalized_cfg without the annoying ContainerNodes
        self._normalized_cfg = networkx.DiGraph()
        for src, dst in _normalized_cfg.edges_iter():
            self._normalized_cfg.add_edge(src.obj, dst.obj)

    def _pd_post_process(self):
        """
        Take care of those loop headers/tails where we manually broke their
        connection to the next BBL
        """
        loop_back_edges = self._cfg.get_loop_back_edges()
        for b1, b2 in loop_back_edges:
            # The edge between b1 and b2 is manually broken
            # The post dominator of b1 should be b2 (or not?)

            if type(b1) is TemporaryNode:
                # This is for testing
                successors = self._acyclic_cfg.graph.successors(b1)
            else:
                # Real CFGNode!
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

        n = self._entry

        queue = [ n ]
        start_node = TemporaryNode("start_node")
        # Put the start_node into a Container as well
        start_node = ContainerNode(start_node)

        container_nodes = { }

        traversed_nodes = set()
        while len(queue) > 0:
            node = queue.pop()

            if type(node) is TemporaryNode:
                # This is for testing
                successors = self._acyclic_cfg.graph.successors(node)
            else:
                # Real CFGNode!
                successors = self._acyclic_cfg.get_successors(node)

            # Put it into a container
            if node in container_nodes:
                container_node = container_nodes[node]
            else:
                container_node = ContainerNode(node)
                container_nodes[node] = container_node

            traversed_nodes.add(container_node)

            if len(successors) == 0:
                # Add an edge between this node and our start node
                graph.add_edge(start_node, container_node)

            for s in successors:
                if s in container_nodes:
                    container_s = container_nodes[s]
                else:
                    container_s = ContainerNode(s)
                    container_nodes[s] = container_s
                graph.add_edge(container_s, container_node) # Reversed
                if container_s not in traversed_nodes:
                    queue.append(s)

        # Add a start node and an end node
        graph.add_edge(container_nodes[n], ContainerNode(TemporaryNode("end_node")))

        all_nodes_count = len(traversed_nodes) + 2 # A start node and an end node
        l.debug("There should be %d nodes in all", all_nodes_count)
        counter = 0
        vertices = [ ContainerNode("placeholder") ]
        scanned_nodes = set()
        parent = {}
        while True:
            # DFS from the current start node
            stack = [ start_node ]
            while len(stack) > 0:
                node = stack.pop()
                counter += 1

                # Mark it as scanned
                scanned_nodes.add(node)

                # Put the container node into vertices list
                vertices.append(node)

                # Put each successors into the stack
                successors = graph.successors(node)

                # Set the index property of it
                node.index = counter

                for s in successors:
                    if s not in scanned_nodes:
                        stack.append(s)
                        parent[s] = node
                        scanned_nodes.add(s)

            if counter >= all_nodes_count:
                break

            l.debug("%d nodes are left out during the DFS. They must formed a cycle themselves.", all_nodes_count - counter)
            # Find those nodes
            leftovers = [ s for s in traversed_nodes if s not in scanned_nodes ]
            graph.add_edge(start_node, leftovers[0])
            # We have to start over...
            counter = 0
            parent = {}
            scanned_nodes = set()
            vertices = [ ContainerNode("placeholder") ]

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

register_analysis(CDG, 'CDG')
