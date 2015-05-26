from collections import defaultdict

import networkx

from ..surveyor import Surveyor

class Sser(Surveyor):
    """
    Sser implements a _static_ symbolic execution engine!
    """
    def __init__(self, project, start=None, ends=None, max_repeats=None):
        Surveyor.__init__(self, project, start=start)

        self._ends = ends

        self._max_repeats = max_repeats

        # We generate a CFG beginning from the starting point
        self._cfg = self._project.CFG(
            starts=(self.active[0].ip, ),
            context_sensitivity_level=0,
            call_depth=0
        )
        # Normalize it!
        self._cfg.nomalize()

        # Get all deadends
        # We cannot directly use cfg.deadends because we want to eliminate all transitions to function
        # calls and syscalls
        deadends = self._deadends()

        # Compute post-dominators
        self._post_dominators = defaultdict(list)
        for d in deadends:
            post_dominators = self._cfg.immediate_postdominators(d)
            for i, j in post_dominators.iteritems():
                self._post_dominators[i].append(j)

        # Create the inverse-post-dominator dict
        self._inverse_post_dominators = defaultdict(set)
        for n, l in self._post_dominators:
            for dom in l:
                self._inverse_post_dominators[dom].add(n)

    @property
    def done(self):
        return len(self.active) == 0

    def tick_path(self, p):
        pass

    def _deadends(self):
        """
        Get all deadends for self._cfg
        """
        graph = networkx.DiGraph()

        # Make a copy of the nodes and edges in self._cfg, but only with jumpkinds that we care about
        for src, dst, data in self._cfg.graph.edges(data=True):
            if data['jumpkind'] == 'Ijk_Boring':
                graph.add_edge(src, dst)

        deadends = [ i for i in graph.nodes() if graph.out_degree(i) == 0 ]

        return deadends