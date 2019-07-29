import logging
import weakref
import networkx
import itertools

import claripy

l = logging.getLogger(name=__name__)


class StateHierarchy(object):
    def __init__(self):

        # The New Order
        self._graph = networkx.DiGraph()
        self._leaves = set() # nodes with no children
        self._twigs = set() # nodes with one child
        self._weakref_cache = {} # map from object id to weakref
        self._reverse_weakref_cache = {} # map from weakref to object id

    def __getstate__(self):
        histories = [ h() for h in networkx.algorithms.dfs_postorder_nodes(self._graph) ]
        return (histories,)

    def __setstate__(self, s):
        self._graph = networkx.DiGraph()
        self._leaves = set()
        self._twigs = set()
        self._weakref_cache = {}
        self._reverse_weakref_cache = {}

        nodes = s[0]
        for n in nodes:
            self.add_history(n)

    def get_ref(self, obj):
        if id(obj) not in self._weakref_cache:
            ref = weakref.ref(obj, self.clear_ref)
            self._weakref_cache[id(obj)] = ref
            self._reverse_weakref_cache[ref] = id(obj)
            return ref
        else:
            return self._weakref_cache[id(obj)]

    def clear_ref(self, ref):
        if ref not in self._reverse_weakref_cache:
            l.error("Cleaning mystery weakref %s", ref)
            return

        self._remove_history(ref)

        # TODO: this nonsense is very much not thread safe
        del self._weakref_cache[self._reverse_weakref_cache[ref]]
        del self._reverse_weakref_cache[ref]

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
        hh = h()
        if hh is not None:
            hh.demote()

    def add_state(self, s):
        h = s.history
        self.add_history(h)

    def add_history(self, h):
        cur_node = self.get_ref(h)
        self._graph.add_node(cur_node)
        if h.parent is not None:
            prev_node = self.get_ref(h.parent)
            self._graph.add_edge(prev_node, cur_node)

            self._leaves.discard(prev_node)
            if len(list(self._graph.successors(prev_node))) == 1:
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

        predecessors = list(self._graph.predecessors(h))
        while len(predecessors):
            lineage.append(predecessors[0])
            predecessors = list(self._graph.predecessors(predecessors[0]))

        lineage.reverse()
        return lineage

    def all_successors(self, h):
        nodes = list(networkx.algorithms.dfs_postorder_nodes(self._graph, h))[:-1]
        nodes.reverse()
        return nodes

    def history_successors(self, h):
        return [ ref() for ref in self._graph.successors(self.get_ref(h)) ]

    def history_predecessors(self, h):
        return [ ref() for ref in self._graph.predecessors(self.get_ref(h)) ]

    def history_contains(self, h):
        return self.get_ref(h) in self._graph

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
            l.debug("... looking between %d and %d in %d states", good, bad, len(lineage))
            cur = (bad+good)//2

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
        ph = list(self._graph.predecessors(h))
        if len(ph) == 1 and len(list(self._graph.successors(ph[0]))) == 1:
            self._twigs.add(ph[0])

        all_children = list(networkx.algorithms.dfs_postorder_nodes(self._graph, h))
        for n in all_children:
            n()._satisfiable = False
            if n().state is not None:
                n().state.add_constraints(claripy.false)
        self._graph.remove_nodes_from(all_children)

    def unreachable_state(self, state):
        self.unreachable_history(state.history)

    def unreachable_history(self, h):
        href = self.get_ref(h)

        try:
            l.debug("Pruning tree given unreachable %s", h)
            root = self._find_root_unreachable(href)
        except networkx.NetworkXError:
            l.debug("... not present in graph")
        else:
            l.debug("... root is %s", root)
            self._prune_subtree(root)

    #
    # Smart merging support
    #

    def most_mergeable(self, states):
        """
        Find the "most mergeable" set of states from those provided.

        :param states: a list of states
        :returns: a tuple of: (a list of states to merge, those states' common history, a list of states to not merge yet)
        """

        histories = set(self.get_ref(s.history) for s in states)

        for n in networkx.algorithms.dfs_postorder_nodes(self._graph):
            intersection = histories.intersection(self.all_successors(n))
            if len(intersection) > 1:
                return (
                    [ s for s in states if self.get_ref(s.history) in intersection ],
                    n(),
                    [ s for s in states if self.get_ref(s.history) not in intersection ]
                )

        # didn't find any?
        return set(), None, states
