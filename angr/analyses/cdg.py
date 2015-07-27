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
    def __init__(self, cfg=None, start=None):
        self._project = self._p
        self._binary = self._project.loader.main_bin
        self._start = start

        self._cfg = cfg if cfg is not None else self._p.analyses.CFG()
        self._acyclic_cfg = self._cfg.copy()
        # The CFG we use should be acyclic!
        self._acyclic_cfg.remove_cycles()

        self._ancestor = None
        self._semi = None
        self._post_dom = None

        self._cdg = None
        self._label = None
        # Debugging purpose
        if hasattr(self._cfg, "get_node"):
            # FIXME: We should not use get_any_irsb in such a real setting...
            self._entry = self._cfg.get_any_node(self._p.entry)

        self.construct()

    def construct(self):
        # Construct post-dominator tree
        self.pd_construct()
        # l.debug("Post dominators: \n%s", self._post_dom)

        self._cdg = networkx.DiGraph()
        # For each node (A,B), traverse back from B until the parent node of A,
        # and label them as control dependent on A
        for a in self._cfg.nodes():
            # FIXME: Dirty fix!
            if a not in self._post_dom:
                continue

            successors = self._cfg.get_successors(a)
            for b in successors:
                # # FIXME: Dirty fix!
                # if b not in self._post_dom:
                #     continue
                # Let's first check whether A's parent lies on B's path to the root
                dependent_flag = False
                tmp = b
                while tmp != None:
                    if tmp == self._post_dom[a]:
                        dependent_flag = True
                        break
                    tmp = self._post_dom[tmp]

                if self._post_dom[a] != b and dependent_flag:
                    # B doesn't post-dominate A
                    tmp = b
                    while tmp != self._post_dom[a]: # and tmp != None: # FIXME: tmp != None is a dirty fix
                        self._cdg.add_edge(a, tmp) # tmp is dependent on A
                        if b in self._post_dom:
                            tmp = self._post_dom[tmp]
                        else:
                            break

        self._post_process()

    def get_post_dominators(self):
        return self._post_dom

    def _post_process(self):
        '''
        There are cases where a loop has two overlapping loop headers thanks
        to the way VEX is dealing with continuous instructions. As we were
        breaking the connection between the second loop header and its
        successor, we shall restore them in our CDG.
        '''
        # TODO: Verify its correctness
        loop_back_edges = self._cfg.get_loop_back_edges()
        for b1, b2 in loop_back_edges:
            self._cdg.add_edge(b1, b2)

    def get_predecessors(self, run):
        if run in self._cdg.nodes():
            return self._cdg.predecessors(run)
        else:
            return []

    def pd_construct(self):
        normalized_graph, vertices, parent = self.pd_normalize_graph()

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
                u = self.pd_eval(v)
                if self._semi[u.index].index < self._semi[w.index].index:
                    self._semi[w.index] = self._semi[u.index]
            bucket[vertices[self._semi[w.index].index].index].add(w)
            self.pd_link(parent[w], w)
            for v in bucket[parent[w].index]:
                u = self.pd_eval(v)
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

        self._post_dom = {}
        for i in range(1, len(vertices)):
            self._post_dom[vertices[i]] = dom[i]

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
                    self._post_dom[b1] = b2
                else:
                    l.debug("%s is not in post dominator dict.", b2)

    def pd_normalize_graph(self):
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

    def pd_link(self, v, w):
        self._ancestor[w.index] = v

    def pd_eval(self, v):
        if self._ancestor[v.index] is None:
            return v
        else:
            self.pd_compress(v)
            return self._label[v.index]

    def pd_compress(self, v):
        if self._ancestor[self._ancestor[v.index].index] != None:
            self.pd_compress(self._ancestor[v.index])
            if self._semi[self._label[self._ancestor[v.index].index].index].index < self._semi[self._label[v.index].index].index:
                self._label[v.index] = self._label[self._ancestor[v.index].index]
            self._ancestor[v.index] = self._ancestor[self._ancestor[v.index].index]
