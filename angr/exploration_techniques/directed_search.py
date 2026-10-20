from __future__ import annotations

from bisect import insort
from collections import deque

from angr.knowledge_plugins.cfg import CFGModel

from .base import ExplorationTechnique


class DirectedSearch(ExplorationTechnique):
    """
    Best-first search toward a target address, ranked by distance in a CFG.

    After every step, the states in the stepped stash and in ``deferred_stash`` are ranked together by their distance
    to ``target_addr``, and the ``beam_width`` closest stay in the stepped stash. The rest wait in ``deferred_stash``,
    so a deferred state comes back as soon as it is among the closest. Ties keep the earlier-deferred state first.
    The technique keeps ``deferred_stash`` sorted by distance.

    The distance of a state is the fewest CFG edges from the block holding its address to the block holding the
    target. It is a heuristic: every block counts as one hop, and it ignores calling context, so from inside a
    function the shortest return to *any* caller counts. States whose address is not in the CFG, or that cannot reach
    the target, rank last.

    A state that loops close to the target stays ahead of farther ones indefinitely; pair this technique with
    :class:`LoopSeer` or :class:`LengthLimiter` when that can happen. Use one instance per stepped stash: states in
    ``deferred_stash`` can move into whichever stash is stepped, and successors sent elsewhere with ``target_stash``
    are not ranked.
    """

    def __init__(self, cfg, target_addr: int, beam_width: int = 1, deferred_stash: str = "directed_deferred"):
        """
        :param cfg:            A CFG analysis (e.g. ``project.analyses.CFGFast()``) or its :class:`CFGModel`.
        :param target_addr:    The address to steer toward. It need not start a block.
        :param beam_width:     How many of the closest states to keep after each step (at least 1).
        :param deferred_stash: The stash for states that are not among the closest.
        :raises ValueError:    If ``beam_width`` is below 1, or no CFG node contains ``target_addr``.
        """
        super().__init__()
        if beam_width < 1:
            raise ValueError("beam_width must be at least 1")
        self._model: CFGModel = cfg if isinstance(cfg, CFGModel) else cfg.model
        self.target_addr = target_addr
        self.beam_width = beam_width
        self.deferred_stash = deferred_stash
        self._block_distance = self._distances_to(target_addr)
        self._addr_distance: dict[int, float] = {}

    def _distances_to(self, target_addr: int) -> dict[int, int]:
        # Breadth-first search backwards from the target gives each block's fewest edges to it. One address can host
        # several context nodes, so keep the smallest distance per block address.
        target = self._model.get_any_node(target_addr, anyaddr=True)
        if target is None:
            raise ValueError(f"No CFG node contains the target address {target_addr:#x}")
        graph = self._model.graph
        distances: dict[int, int] = {}
        seen = {target}
        queue = deque([(target, 0)])
        while queue:
            node, dist = queue.popleft()
            distances[node.addr] = min(dist, distances.get(node.addr, dist))
            for pred in graph.predecessors(node):
                if pred not in seen:
                    seen.add(pred)
                    queue.append((pred, dist + 1))
        return distances

    def distance(self, addr: int) -> float:
        """
        The CFG distance from ``addr`` to the target, or ``inf`` when ``addr`` is not in the CFG or cannot reach it.
        """
        dist = self._addr_distance.get(addr)
        if dist is None:
            node = self._model.get_any_node(addr, anyaddr=True)
            hops = None if node is None else self._block_distance.get(node.addr)
            dist = float("inf") if hops is None else float(hops)
            self._addr_distance[addr] = dist
        return dist

    def setup(self, simgr):
        if self.deferred_stash not in simgr.stashes:
            simgr.stashes[self.deferred_stash] = []

    def step(self, simgr, stash="active", **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        # The deferred stash stays sorted by distance. insort places a state after the equally close ones already there,
        # so ties keep the earlier-deferred state first.
        ranked = simgr.stashes[self.deferred_stash]
        for state in simgr.stashes[stash]:
            insort(ranked, state, key=lambda s: self.distance(s.addr))
        simgr.stashes[stash] = ranked[: self.beam_width]
        del ranked[: self.beam_width]
        return simgr
