import logging
import weakref
import networkx
import itertools

import claripy

l = logging.getLogger('angr.path_hierarchy')

class PathHierarchy(object):
    def __init__(self, weakkey_path_mapping=False):

        if weakkey_path_mapping:
            self._path_mapping = weakref.WeakKeyDictionary()
        else:
            self._path_mapping = weakref.WeakValueDictionary()

        # The New Order
        self._graph = networkx.DiGraph()
        self._leaves = set() # nodes with no children
        self._twigs = set() # nodes with one child

    def __getstate__(self):
        histories = [ h() for h in networkx.algorithms.dfs_postorder_nodes(self._graph) ]
        return dict(self._path_mapping), histories

    def __setstate__(self, s):
        self._graph = networkx.DiGraph()
        self._leaves = set()
        self._twigs = set()

        path_mapping, nodes = s
        for n in nodes:
            self.add_history(n)
        self._path_mapping = weakref.WeakValueDictionary(path_mapping)

    #
    # Graph management
    #

    def _remove_history(self, h):
        try:
            predecessors = self._graph.predecessors(h)
            successors = self._graph.successors(h)

            for p,s in itertools.product(predecessors, successors):
                self._graph.add_edge(p, s)

            self._graph.remove_node(h)
        except networkx.NetworkXError:
            pass

        self._leaves.discard(h)
        self._twigs.discard(h)
        self._path_mapping.pop(h(), None)

    def add_path(self, p):
        h = p.history
        self._path_mapping[h] = p
        self.add_history(h)

    def add_history(self, h):
        cur_node = weakref.ref(h, self._remove_history)
        self._graph.add_node(cur_node)
        if h._parent is not None:
            prev_node = weakref.ref(h._parent, self._remove_history)
            self._graph.add_edge(prev_node, cur_node)

            self._leaves.discard(prev_node)
            if len(self._graph.successors(prev_node)) == 1:
                self._twigs.add(prev_node)
            else:
                self._twigs.discard(prev_node)

        self._leaves.add(cur_node)

    def simplify(self):
        tw = self._twigs
        self._twigs = set()
        for h in tw:
            self._remove_history(h)

    def full_simplify(self):
        for h in self._graph.nodes():
            if self._graph.out_degree(h) == 1:
                self._remove_history(h)

    def lineage(self, h):
        """
        Returns the lineage of histories leading up to `h`.
        """

        lineage = [ ]

        predecessors = self._graph.predecessors(h)
        while len(predecessors):
            lineage.append(predecessors[0])
            predecessors = self._graph.predecessors(predecessors[0])

        lineage.reverse()
        return lineage

    def all_successors(self, h):
        nodes = list(networkx.algorithms.dfs_postorder_nodes(self._graph, h))[:-1]
        nodes.reverse()
        return nodes

    def history_successors(self, h):
        return [ ref() for ref in self._graph.successors(weakref.ref(h)) ]

    def history_predecessors(self, h):
        return [ ref() for ref in self._graph.predecessors(weakref.ref(h)) ]

    def history_contains(self, h):
        return weakref.ref(h) in self._graph

    #
    # LAZY_SOLVES support
    #

    def _find_root_unreachable(self, h):
        lineage = self.lineage(h)
        if len(lineage) == 0 or lineage[-1]().reachable():
            return h

        good = 0
        bad = len(lineage) - 1

        while True:
            l.debug("... looking between %d and %d in %d paths", good, bad, len(lineage))
            cur = (bad+good)/2

            if cur == good or cur == bad:
                if lineage[bad]().reachable():
                    bad += 1

                root = lineage[bad]
                l.debug("... returning %d (%s)", bad, root)
                return root
            elif lineage[cur]().reachable():
                l.debug("... %d is reachable", cur)
                good = cur
            else:
                l.debug("... %d is unreachable", bad)
                bad = cur

    def _prune_subtree(self, h):
        ph = self._graph.predecessors(h)
        if len(ph) == 1 and len(self._graph.successors(ph[0])) == 1:
            self._twigs.add(ph[0])

        all_children = list(networkx.algorithms.dfs_postorder_nodes(self._graph, h))
        for n in all_children:
            n()._satisfiable = False
            if n().state is not None:
                n().state.add_constraints(claripy.false)
        self._graph.remove_nodes_from(all_children)

    def unreachable_path(self, p):
        self.unreachable_history(p.history)

    def unreachable_history(self, h):
        href = weakref.ref(h)

        l.debug("Pruning tree given unreachable %s", h)
        root = self._find_root_unreachable(href)
        l.debug("... root is %s", root)
        self._prune_subtree(href)

    #
    # Smart merging support
    #

    def most_mergeable(self, paths):
        """
        Find the "most mergeable" set of paths from those provided.

        :param paths: a list of paths
        :returns: a tuple of: (a list of paths to merge, those paths' common history, a list of paths to not merge yet)
        """

        histories = set(weakref.ref(p.history) for p in paths)

        for n in networkx.algorithms.dfs_postorder_nodes(self._graph):
            intersection = histories.intersection(self.all_successors(n))
            if len(intersection) > 1:
                return (
                    [ p for p in paths if weakref.ref(p.history) in intersection ],
                    n(),
                    [ p for p in paths if weakref.ref(p.history) not in intersection ]
                )

        # didn't find any?
        import ipdb; ipdb.set_trace()
        return set(), None, paths
