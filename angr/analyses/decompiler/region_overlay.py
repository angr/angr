from __future__ import annotations

import logging
import os
from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import Any

import networkx

from .graph_region import GraphRegion

l = logging.getLogger(name=__name__)


class OverlayManager:
    """
    OverlayManager owns the single shared control-flow graph that all RegionOverlay objects are views of, plus the
    node-to-innermost-overlay ownership map.

    All structural mutations of the shared graph must go through this class (usually via RegionOverlay methods) so
    that ownership, caches, and the undo log stay consistent.
    """

    __slots__ = (
        "_adj_epoch",
        "_node_version",
        "_owner",
        "_undo_log",
        "_version",
        "complete_successors",
        "graph",
        "root",
    )

    def __init__(self, graph: networkx.DiGraph, complete_successors: bool = False):
        self.graph = graph
        self.complete_successors = complete_successors
        self._version: int = 0
        # per-node topology version: bumped when an edge incident to a node changes (in the shared graph or in the
        # overlay-visibility state). RegionOverlayGraph's adjacency cache keys on this so an unrelated mutation no
        # longer evicts a node's cached adjacency. _adj_epoch is a coarse counter bumped by the lifecycle ops that
        # flip node ownership/representatives broadly (create_subregion/dissolve/finalize) and by rollback (whose
        # inverse closures mutate the graph outside the touch-instrumented primitives); a change forces a full
        # cache clear.
        self._node_version: dict[Any, int] = {}
        self._adj_epoch: int = 0
        self._undo_log: list[Callable[[], None]] | None = None

        self.root = RegionOverlay(self, None, cyclic=False)
        self.root._under = set(graph)
        self.root._members = set(graph)
        self._owner: dict[Any, RegionOverlay] = dict.fromkeys(graph, self.root)

    @property
    def version(self) -> int:
        return self._version

    def owner_of(self, node) -> RegionOverlay | None:
        return self._owner.get(node)

    def _bump(self) -> None:
        self._version += 1

    def _touch(self, node) -> None:
        """Bump a node's topology version (its cached view-adjacency must be rebuilt). Also bump every enclosing
        overlay: in an enclosing region's view the node is represented by the child overlay that contains it, so a
        change to the node's edges changes that representative's adjacency too. Monotonic; not undone on rollback,
        which bumps _adj_epoch to clear everything instead."""
        nv = self._node_version
        nv[node] = nv.get(node, 0) + 1
        o = self._owner.get(node)
        while o is not None:
            nv[o] = nv.get(o, 0) + 1
            o = o.parent

    def _bump_epoch(self) -> None:
        self._adj_epoch += 1

    #
    # Undo log
    #
    # Every mutation primitive appends an inverse closure when a transaction is active. rollback() replays the
    # inverses in reverse order, restoring both the shared graph and all overlay bookkeeping.
    #

    def checkpoint(self) -> int:
        if self._undo_log is None:
            self._undo_log = []
        return len(self._undo_log)

    def _record(self, inverse: Callable[[], None]) -> None:
        if self._undo_log is not None:
            self._undo_log.append(inverse)

    def rollback(self, to: int) -> None:
        assert self._undo_log is not None
        while len(self._undo_log) > to:
            self._undo_log.pop()()
        self._bump()
        # inverse closures mutate self.graph directly, bypassing the per-node touch instrumentation; force a full
        # adjacency-cache clear
        self._bump_epoch()

    def commit(self, to: int) -> None:
        """
        Discard undo information past the given checkpoint. If the checkpoint is 0, stop recording entirely.
        """
        assert self._undo_log is not None
        del self._undo_log[to:]
        if to == 0:
            self._undo_log = None

    #
    # Shared-graph mutation primitives. These do not touch overlay membership; RegionOverlay methods compose them
    # with membership updates.
    #

    def _graph_add_node(self, node) -> None:
        if node not in self.graph:
            self.graph.add_node(node)
            self._record(lambda: self.graph.remove_node(node))
        self._touch(node)
        self._bump()

    def _graph_remove_node(self, node) -> None:
        in_edges = [(src, data) for src, _, data in self.graph.in_edges(node, data=True)]
        out_edges = [(dst, data) for _, dst, data in self.graph.out_edges(node, data=True)]
        self.graph.remove_node(node)

        def inverse():
            self.graph.add_node(node)
            for src, data in in_edges:
                self.graph.add_edge(src, node, **data)
            for dst, data in out_edges:
                self.graph.add_edge(node, dst, **data)

        self._record(inverse)
        # the node and every former neighbor lose an incident edge
        self._touch(node)
        for src, _ in in_edges:
            self._touch(src)
        for dst, _ in out_edges:
            self._touch(dst)
        self._bump()

    def _graph_add_edge(self, src, dst, **data) -> None:
        existed = self.graph.has_edge(src, dst)
        old_data = dict(self.graph[src][dst]) if existed else None
        self.graph.add_edge(src, dst, **data)

        if existed:

            def inverse():
                self.graph[src][dst].clear()
                self.graph[src][dst].update(old_data)

        else:

            def inverse():
                self.graph.remove_edge(src, dst)

        self._record(inverse)
        self._touch(src)
        self._touch(dst)
        self._bump()

    def _graph_remove_edge(self, src, dst) -> None:
        old_data = dict(self.graph[src][dst])
        self.graph.remove_edge(src, dst)
        self._record(lambda: self.graph.add_edge(src, dst, **old_data))
        self._touch(src)
        self._touch(dst)
        self._bump()

    def _set_owner(self, node, new_owner: RegionOverlay | None) -> None:
        old_owner = self._owner.get(node)
        if new_owner is None:
            self._owner.pop(node, None)
        else:
            self._owner[node] = new_owner

        def inverse():
            if old_owner is None:
                self._owner.pop(node, None)
            else:
                self._owner[node] = old_owner

        self._record(inverse)


class RegionOverlay(GraphRegion):
    """
    A single-entry region marked over the shared graph held by an OverlayManager, replacing per-region graph copies
    of GraphRegion.

    Overlays form a tree (nested, never overlapping). An overlay's *members* are either shared-graph nodes it owns
    directly or child overlays. The region graph and the region graph-with-successors are derived on demand from the
    shared graph by quotienting child overlays into single nodes; *successors* are likewise derived from edges that
    cross the region boundary, so they can never go stale.

    Mutation verbs:

    - true structural changes (``add_node``, ``remove_node``, ``add_edge``, ``detach_edge``, ``replace_nodes``)
      pass through to the shared graph, so the effects are immediately visible to all enclosing regions;
    - ``hide_edge`` removes an edge from this overlay's views only (the old "remove it from region graphs but keep
      the parent edge" pattern);
    - ``finalize(result_node)`` collapses a fully-structured region into a single node of its parent;
    - ``dissolve()`` merges an unsuccessfully-structured region back into its parent.

    This class subclasses GraphRegion only so that isinstance checks in existing consumers keep working during the
    migration; ``graph``/``graph_with_successors``/``successors`` are materialized lazily and cached.
    """

    __slots__ = (
        "_cache_succs",
        "_extra_full_edges",
        "_hidden",
        "_hidden_full",
        "_members",
        "_mgr",
        "_rog_cache",
        "_under",
        "children",
        "edge_marks",
        "parent",
        "replacement",
    )

    def __init__(
        self,
        mgr: OverlayManager,
        head,
        cyclic: bool,
        cyclic_ancestor: bool = False,
        parent: RegionOverlay | None = None,
    ):
        # do not call GraphRegion.__init__: graph/graph_with_successors/successors are shadowed by properties here
        self._mgr = mgr
        self.head = head
        self.cyclic = cyclic
        self.cyclic_ancestor = cyclic_ancestor
        self.parent = parent
        self.children: list[RegionOverlay] = []
        self._members: set = set()
        self._under: set = set()
        # edges (pairs of shared-graph nodes) hidden from this overlay's views only
        self._hidden: set[tuple[Any, Any]] = set()
        # view-level edge pairs hidden from the with-successors view only
        self._hidden_full: set[tuple[Any, Any]] = set()
        # view-level edge pairs injected into the with-successors view only (successor absorption)
        self._extra_full_edges: set[tuple[Any, Any]] = set()
        # scratch edge marks (e.g., Phoenix's cyclic_refinement_outgoing), scoped to this overlay
        self.edge_marks: set[tuple[Any, Any]] = set()
        # the node this overlay was finalized into, if any
        self.replacement = None

        self._cache_succs: tuple[int, set, set] | None = None
        # cached RegionOverlayGraph view objects, keyed by (full, include_marked)
        self._rog_cache: dict[tuple[bool, bool], RegionOverlayGraph] = {}

    def __repr__(self):
        if not self._members:
            return f"<RegionOverlay {self.head!r} (empty)>"
        return f"<RegionOverlay {self.head!r} of {len(self._members)} members, {len(self._under)} nodes>"

    #
    # Tree and membership
    #

    @property
    def manager(self) -> OverlayManager:
        return self._mgr

    @property
    def members(self) -> set:
        return self._members

    def ancestors(self) -> set[RegionOverlay]:
        """All overlays enclosing this one, including this one itself."""
        result = set()
        node: RegionOverlay | None = self
        while node is not None:
            result.add(node)
            node = node.parent
        return result

    def underlying_nodes(self) -> set:
        """All shared-graph nodes inside this region (including nodes of nested regions)."""
        return self._under

    @staticmethod
    def _underlying(x) -> set:
        return x._under if isinstance(x, RegionOverlay) else {x}

    def create_subregion(self, head, members: Iterable, cyclic: bool, cyclic_ancestor: bool = False) -> RegionOverlay:
        """
        Carve a new child overlay out of this overlay. ``members`` must be a subset of this overlay's members
        (shared-graph nodes owned by this overlay and/or existing child overlays); ``head`` must be one of them.
        """
        members = set(members)
        assert members
        assert head in members
        assert members.issubset(self._members), "subregion members must be members of the parent overlay"

        sub = RegionOverlay(self._mgr, head, cyclic, cyclic_ancestor=cyclic_ancestor, parent=self)
        sub._members = members
        for m in members:
            if isinstance(m, RegionOverlay):
                m.parent = sub
                self.children.remove(m)
                sub.children.append(m)
                sub._under |= m._under
            else:
                self._mgr._set_owner(m, sub)
                sub._under.add(m)
        self._members -= members
        self._members.add(sub)
        self.children.append(sub)
        # sub._under is a subset of self._under (and of all ancestors); no _under updates needed upward
        self._mgr._record(lambda: self._undo_create_subregion(sub))
        # reparenting flips the representatives of the moved nodes for enclosing views
        self._mgr._bump_epoch()
        self._mgr._bump()
        return sub

    def _undo_create_subregion(self, sub: RegionOverlay) -> None:
        # note: _set_owner inverses are recorded separately and run after this in reverse order
        self._members.discard(sub)
        self.children.remove(sub)
        for m in sub._members:
            if isinstance(m, RegionOverlay):
                m.parent = self
                self.children.append(m)
            self._members.add(m)
        self._mgr._bump()

    def _representative_in(self, node):
        """
        Map a shared-graph node to the member of this overlay that represents it (the node itself, or the child
        overlay containing it). Returns None if the node is not inside this overlay.
        """
        o = self._mgr.owner_of(node)
        if o is None:
            return None
        if o is self:
            return node
        cur = o
        while cur.parent is not None and cur.parent is not self:
            cur = cur.parent
        return cur if cur.parent is self else None

    def _representative_outside(self, node):
        """
        Map a shared-graph node outside this overlay to its representative at the closest enclosing level: the node
        itself if it is directly owned by an ancestor, otherwise the topmost overlay around it that does not
        enclose this overlay.
        """
        anc = self.ancestors()
        o = self._mgr.owner_of(node)
        if o is None:
            return None
        if o in anc:
            return node
        cur = o
        while cur.parent is not None and cur.parent not in anc:
            cur = cur.parent
        return cur

    #
    # Derived views
    #

    def _is_hidden(self, src, dst) -> bool:
        return (src, dst) in self._hidden

    def _hidden_context_head_under(self) -> frozenset | set:
        """
        Crossing edges that target the head of the region's processing context (the nearest cyclic ancestor, or
        the root region) were invisible during region identification: in-edges of the head are stripped before
        acyclic analysis. RegionIdentifier's complete_successors mode used to re-add them from the secondary
        graph, so they are only hidden when that mode is off. Cyclic regions themselves are identified before any
        stripping, so their views are unaffected.
        """
        if self.cyclic or self._mgr.complete_successors:
            return frozenset()
        anc = self.parent
        while anc is not None and not anc.cyclic and anc.parent is not None:
            anc = anc.parent
        if anc is None or anc.head is None or anc.head in self._under:
            return frozenset()
        return self._underlying(anc.head)

    def _crossing_out_edges(self) -> Iterator[tuple[Any, Any, dict]]:
        """All shared-graph edges leaving this region, except hidden ones."""
        graph = self._mgr.graph
        under = self._under
        hidden_head = self._hidden_context_head_under()
        for u in under:
            if u not in graph:
                continue
            for v, data in graph.adj[u].items():
                if v not in under and v not in hidden_head and not self._is_hidden(u, v):
                    yield u, v, data

    @property
    def _in_loop(self) -> bool:
        return self.cyclic or self.cyclic_ancestor

    @property
    def _complete_mode(self) -> bool:
        # RegionIdentifier's complete_successors mode only ever applied to acyclic regions nested inside cyclic
        # regions (it required a secondary graph)
        return self._mgr.complete_successors and self.cyclic_ancestor and not self.cyclic

    def _enclosing_loop(self) -> RegionOverlay | None:
        loop = self.parent
        while loop is not None and not loop.cyclic:
            loop = loop.parent
        return loop

    def _successor_hop_edges(self, direct_succs: set) -> Iterator[tuple[Any, Any, dict]]:
        """
        In complete-successors mode, a region inside a loop sees one extra hop of edges from its successors, but
        only when the hop target is the loop's continue target (the loop head): "this successor goes back to the
        loop head" is the control-flow fact that break/continue placement during structuring relies on. Successor
        edges to other loop-body nodes (or onward from the loop head) are sibling-structure details and stay
        hidden.
        """
        loop = self._enclosing_loop()
        if loop is None:
            return
        head_under = self._underlying(loop.head)
        graph = self._mgr.graph
        for s in direct_succs:
            under_s = self._underlying(s)
            for u in under_s:
                if u not in graph:
                    continue
                for v, data in graph.adj[u].items():
                    if v in under_s or v in self._under or v not in head_under:
                        continue
                    rep_v = self._representative_outside(v)
                    if rep_v is None or rep_v is s:
                        continue
                    yield s, rep_v, data

    def successor_nodes(self) -> set:
        """
        The derived successor set of this region: representatives of all shared-graph nodes targeted by edges
        leaving the region (plus, in complete-successors mode, the restricted one-hop targets; see
        _successor_hop_edges).
        """
        cached = self._cache_succs
        if cached is not None and cached[0] == self._mgr.version:
            return cached[1]
        succs = set()
        for _, v, _ in self._crossing_out_edges():
            rep = self._representative_outside(v)
            if rep is not None:
                succs.add(rep)
        direct = set(succs)
        if self._complete_mode:
            for _, rep_v, _ in self._successor_hop_edges(direct):
                succs.add(rep_v)
        self._cache_succs = (self._mgr.version, succs, direct)
        return succs

    def _direct_successor_set(self) -> set:
        self.successor_nodes()
        assert self._cache_succs is not None
        return self._cache_succs[2]

    def _quotient_edges(self, with_successors: bool) -> Iterator[tuple[Any, Any, dict]]:
        """
        Derive the edges of the region view (member -> member, and if requested member -> successor and
        successor -> successor) from the shared graph.
        """
        graph = self._mgr.graph
        under = self._under
        member_of: dict[Any, Any] = {}
        for m in self._members:
            for n in self._underlying(m):
                member_of[n] = m

        succs = self.successor_nodes() if with_successors else None
        hidden_head = self._hidden_context_head_under()

        for u in under:
            if u not in graph:
                continue
            rep_u = member_of.get(u)
            if rep_u is None:
                continue
            for v, data in graph.adj[u].items():
                if self._is_hidden(u, v):
                    continue
                if v in under:
                    rep_v = member_of.get(v)
                    if rep_v is None or (rep_u is rep_v and isinstance(rep_u, RegionOverlay)):
                        # edge internal to a child overlay
                        continue
                    yield rep_u, rep_v, data
                elif with_successors and v not in hidden_head:
                    rep_v = self._representative_outside(v)
                    if rep_v is not None:
                        yield rep_u, rep_v, data

        if with_successors and self._in_loop:
            # successor -> successor edges: RegionIdentifier only added these for cyclic regions and for acyclic
            # regions nested inside cyclic regions
            assert succs is not None
            for s0 in succs:
                under_s0 = self._underlying(s0)
                for u in under_s0:
                    if u not in graph:
                        continue
                    for v in graph.adj[u]:
                        if v in under_s0:
                            continue
                        for s1 in succs:
                            if s1 is not s0 and v in self._underlying(s1):
                                yield s0, s1, graph.adj[u][v]
                                break

    def view_graph(
        self, full: bool = False, include_marked: bool = False, blacklisted_edges: frozenset = frozenset()
    ) -> RegionOverlayGraph:
        """A zero-copy, networkx-compatible view of this region (see RegionOverlayGraph)."""
        if blacklisted_edges:
            return RegionOverlayGraph(
                self, full=full, include_marked=include_marked, blacklisted_edges=blacklisted_edges
            )
        key = (full, include_marked)
        rog = self._rog_cache.get(key)
        if rog is None:
            rog = RegionOverlayGraph(self, full=full, include_marked=include_marked)
            self._rog_cache[key] = rog
        return rog

    #
    # Per-node view-edge iterators: the same visibility rules as _quotient_edges, computed for a single view
    # node so that RegionOverlayGraph can answer adjacency queries without materializing anything.
    #

    def _iter_view_out_edges(self, n, full: bool) -> Iterator[tuple[Any, dict]]:
        """Visible out-edges of view node ``n`` (a member, or a successor in the full view), deduplicated."""
        graph = self._mgr.graph
        under = self._under
        seen: set = set()
        if n in self._members:
            hidden_head = self._hidden_context_head_under() if full else None
            for u in self._underlying(n):
                if u not in graph:
                    continue
                for v, data in graph.adj[u].items():
                    if (u, v) in self._hidden:
                        continue
                    if v in under:
                        rep_v = self._representative_in(v)
                        if rep_v is None or (rep_v is n and isinstance(n, RegionOverlay)):
                            # edge internal to a child overlay
                            continue
                        if rep_v not in seen:
                            seen.add(rep_v)
                            yield rep_v, data
                    elif full and v not in hidden_head:
                        rep_v = self._representative_outside(v)
                        if rep_v is not None and rep_v not in seen:
                            seen.add(rep_v)
                            yield rep_v, data
            if full:
                for u, v in self._extra_full_edges:
                    if u is n and v not in seen:
                        seen.add(v)
                        yield v, {}
            return

        if not full:
            return
        # n is a successor node
        succs = self.successor_nodes()
        if n not in succs:
            return
        if self._in_loop:
            under_n = self._underlying(n)
            for u in under_n:
                if u not in graph:
                    continue
                for v, data in graph.adj[u].items():
                    if v in under_n:
                        continue
                    for s1 in succs:
                        if s1 is not n and v in self._underlying(s1):
                            if s1 not in seen:
                                seen.add(s1)
                                yield s1, data
                            break
        if self._complete_mode and n in self._direct_successor_set():
            for _, rep_v, data in self._successor_hop_edges({n}):
                if rep_v not in seen:
                    seen.add(rep_v)
                    yield rep_v, data
        for u, v in self._extra_full_edges:
            if u is n and v not in seen:
                seen.add(v)
                yield v, {}

    def _iter_view_in_edges(self, n, full: bool) -> Iterator[tuple[Any, dict]]:
        """Visible in-edges of view node ``n``, deduplicated. The transpose of _iter_view_out_edges."""
        graph = self._mgr.graph
        under = self._under
        seen: set = set()
        if n in self._members:
            # in-edges of members only ever come from fellow members (successor-to-member edges are never part
            # of region views)
            for u in self._underlying(n):
                if u not in graph:
                    continue
                for p, data in graph.pred[u].items():
                    if (p, u) in self._hidden:
                        continue
                    if p in under:
                        rep_p = self._representative_in(p)
                        if rep_p is None or (rep_p is n and isinstance(n, RegionOverlay)):
                            continue
                        if rep_p not in seen:
                            seen.add(rep_p)
                            yield rep_p, data
            if full:
                for u, v in self._extra_full_edges:
                    if v is n and u not in seen:
                        seen.add(u)
                        yield u, {}
            return

        if not full:
            return
        # n is a successor node
        succs = self.successor_nodes()
        if n not in succs:
            return
        hidden_head = self._hidden_context_head_under()
        in_loop = self._in_loop
        under_n = self._underlying(n)
        for u in under_n:
            if u not in graph:
                continue
            for p, data in graph.pred[u].items():
                if p in under:
                    # a member's crossing edge into this successor
                    if (p, u) in self._hidden or u in hidden_head:
                        continue
                    rep_p = self._representative_in(p)
                    if rep_p is not None and rep_p not in seen:
                        seen.add(rep_p)
                        yield rep_p, data
                elif in_loop and p not in under_n:
                    # a successor-to-successor edge
                    rep_p = self._representative_outside(p)
                    if rep_p is not None and rep_p is not n and rep_p in succs and rep_p not in seen:
                        seen.add(rep_p)
                        yield rep_p, data
        if self._complete_mode:
            # hop edges targeting this successor
            for s, rep_v, data in self._successor_hop_edges(self._direct_successor_set()):
                if rep_v is n and s not in seen:
                    seen.add(s)
                    yield s, data
        for u, v in self._extra_full_edges:
            if v is n and u not in seen:
                seen.add(u)
                yield u, {}

    def view(self) -> RegionOverlayGraph:
        """The region graph (members only): a zero-copy networkx-compatible view; treat it as read-only."""
        return self.view_graph(full=False)

    def view_with_successors(self) -> RegionOverlayGraph:
        """The region graph including successor nodes: a zero-copy view; treat it as read-only."""
        return self.view_graph(full=True)

    @property
    def raw_graph(self) -> RegionOverlayGraph:
        """The member view including marked edges (the old graph with cyclic_refinement_outgoing attrs present)."""
        return self.view_graph(full=False, include_marked=True)

    @property
    def raw_graph_with_successors(self) -> RegionOverlayGraph:
        """The with-successors view including marked edges."""
        return self.view_graph(full=True, include_marked=True)

    #
    # GraphRegion-compatible read-only API
    #

    @property
    def graph(self) -> networkx.DiGraph:  # type: ignore[override]
        return self.view()

    @property
    def graph_with_successors(self) -> networkx.DiGraph:  # type: ignore[override]
        return self.view_with_successors()

    @property
    def successors(self) -> set:  # type: ignore[override]
        return self.successor_nodes()

    @property
    def full_graph(self) -> None:  # type: ignore[override]
        return None

    #
    # Mutations
    #

    def _invalidate(self) -> None:
        self._mgr._bump()

    def _on_node_added(self, node) -> None:
        self._mgr._set_owner(node, self)
        self._members.add(node)
        node_ = node
        anc: RegionOverlay | None = self
        while anc is not None:
            anc._under.add(node_)
            anc = anc.parent

        def inverse():
            self._members.discard(node)
            a: RegionOverlay | None = self
            while a is not None:
                a._under.discard(node)
                a = a.parent

        self._mgr._record(inverse)

    def _on_node_removed(self, node) -> None:
        owner = self._mgr.owner_of(node)
        assert owner is not None
        self._mgr._set_owner(node, None)
        owner._members.discard(node)
        anc: RegionOverlay | None = owner
        while anc is not None:
            anc._under.discard(node)
            anc = anc.parent

        def inverse():
            owner._members.add(node)
            a: RegionOverlay | None = owner
            while a is not None:
                a._under.add(node)
                a = a.parent

        self._mgr._record(inverse)

    def add_node(self, node) -> None:
        """Insert a new node into the shared graph as a direct member of this region."""
        assert node not in self._mgr.graph
        self._mgr._graph_add_node(node)
        self._on_node_added(node)
        self._invalidate()

    def remove_node(self, node, absorbed_into=None, absorb_out_edges: bool = False) -> None:
        """
        Remove a node. If ``node`` is a member (or a member overlay's node), it is removed from the shared graph
        for real. If it is a successor of this region, the removal is interpreted as hiding all edges from this
        region to it (the successor belongs to an enclosing region and must survive).

        When the node's content has been absorbed into another node during structuring, pass that node as
        ``absorbed_into``: in-edges from outside this region (e.g. abnormal loop entries) are then rewired to it
        instead of being dropped, so enclosing regions keep their entry edges. With ``absorb_out_edges``,
        out-edges crossing the region boundary (e.g. loop exits) are rewired to it as well; leave it off when the
        caller re-establishes successor edges explicitly.
        """
        if isinstance(node, RegionOverlay) or node not in self._under:
            # successor removal: hide all crossing edges into it
            self.hide_edge_to_successor(node)
            return
        external_in_edges = []
        rewire_out_edges = []  # (dst, data, hide): edges to rewire onto absorbed_into in the shared graph
        if absorbed_into is not None:
            external_in_edges = [
                (src, data)
                for src, _, data in self._mgr.graph.in_edges(node, data=True)
                if src not in self._under and src is not absorbed_into and (src, node) not in self._hidden
            ]
            if absorb_out_edges:
                hidden_head = self._hidden_context_head_under()
                for _, dst, data in self._mgr.graph.out_edges(node, data=True):
                    if dst is absorbed_into or (node, dst) in self._hidden:
                        continue
                    # rewire every out-edge onto the absorbing node so the shared graph keeps the loop's exit;
                    # hide from this region's own views the ones that were not visible there to begin with — edges
                    # leaving the region (external exits, kept by enclosing regions) and edges to the region's
                    # processing-context head (stripped during region identification). edges to fellow members
                    # stay visible (the loop's exit to its in-region successor).
                    rewire_out_edges.append((dst, data, dst not in self._under or dst in hidden_head))
        self._mgr._graph_remove_node(node)
        self._on_node_removed(node)
        for src, data in external_in_edges:
            self._mgr._graph_add_edge(src, absorbed_into, **data)
        hidden_added = []
        for dst, data, hide in rewire_out_edges:
            self._mgr._graph_add_edge(absorbed_into, dst, **data)
            if hide and (absorbed_into, dst) not in self._hidden:
                self._hidden.add((absorbed_into, dst))
                hidden_added.append((absorbed_into, dst))
        if hidden_added:
            self._mgr._record(lambda: self._hidden.difference_update(hidden_added))
        self._invalidate()

    def hide_edge_to_successor(self, succ) -> None:
        under_succ = self._underlying(succ)
        graph = self._mgr.graph
        added = []
        for u in self._under:
            if u not in graph:
                continue
            for v in graph.adj[u]:
                if v in under_succ and (u, v) not in self._hidden:
                    self._hidden.add((u, v))
                    added.append((u, v))
        if added:
            self._mgr._record(lambda: self._hidden.difference_update(added))
            self._mgr._touch(succ)
            for u, _ in added:
                rep = self._representative_in(u)
                if rep is not None:
                    self._mgr._touch(rep)
            self._invalidate()

    def _underlying_edge_pairs(self, src, dst) -> list[tuple[Any, Any]]:
        graph = self._mgr.graph
        under_src = self._underlying(src)
        under_dst = self._underlying(dst)
        pairs = []
        for u in under_src:
            if u not in graph:
                continue
            for v in graph.adj[u]:
                if v in under_dst:
                    pairs.append((u, v))
        return pairs

    def add_edge(self, src, dst, **data) -> None:
        """
        Add a real edge to the shared graph. Overlay endpoints are resolved to underlying nodes: the destination
        resolves to its entry (head chain); overlay sources are not supported. Endpoints that are not in the
        shared graph yet become members of this region (mirroring networkx's implicit node creation).
        """
        assert not isinstance(src, RegionOverlay), "edges from a region object are ambiguous; use a concrete node"
        dst_ = dst
        while isinstance(dst_, RegionOverlay):
            dst_ = dst_.head
        if src not in self._mgr.graph:
            self.add_node(src)
        if dst_ not in self._mgr.graph:
            self.add_node(dst_)
        self._mgr._graph_add_edge(src, dst_, **data)
        if (src, dst_) in self._hidden:
            self._hidden.discard((src, dst_))
            self._mgr._record(lambda: self._hidden.add((src, dst_)))
        self._invalidate()

    def detach_edge(self, src, dst) -> None:
        """
        Remove an edge from the shared graph for real (e.g., when the edge has been virtualized into a goto).
        Overlay endpoints remove all underlying edges between the two node sets.
        """
        for u, v in self._underlying_edge_pairs(src, dst):
            self._mgr._graph_remove_edge(u, v)
        self._invalidate()

    def mark_edge(self, src, dst, **attrs) -> None:
        """
        Mark a view-level edge (e.g. cyclic_refinement_outgoing) so RegionOverlayGraph hides it by default.
        Marks live in overlay state, never reach the shared graph, and are remapped/cleared with the region.
        """
        if (src, dst) not in self.edge_marks:
            self.edge_marks.add((src, dst))
            self._mgr._record(lambda: self.edge_marks.discard((src, dst)))
            self._mgr._touch(src)
            self._mgr._touch(dst)
            self._invalidate()

    def absorb_successor_into(self, succ, new_node) -> None:
        """
        Absorb a successor node into a structured member node in this region's with-successors view only (the
        successor still belongs to an enclosing region): the successor's view out-edges are re-attached to the
        member node as view-only extra edges, then the successor disappears from this region's views.
        """
        added = []
        for dst, _ in self.view_with_successors().overlay._iter_view_out_edges(succ, full=True):
            if dst is not new_node and (new_node, dst) not in self._extra_full_edges:
                self._extra_full_edges.add((new_node, dst))
                added.append((new_node, dst))
        if added:
            self._mgr._record(lambda: self._extra_full_edges.difference_update(added))
            self._mgr._touch(new_node)
            for _, dst in added:
                self._mgr._touch(dst)
        self.hide_edge_to_successor(succ)

    def drop_edge_marks_from(self, node, key: str = "cyclic_refinement_outgoing") -> None:
        """Clear marks on all out-edges of a node (the new_node after a replace), undoably."""
        removed = [(u, v) for (u, v) in self.edge_marks if u is node]
        if removed:
            self.edge_marks.difference_update(removed)
            self._mgr._record(lambda: self.edge_marks.update(removed))
            self._mgr._touch(node)
            for _, v in removed:
                self._mgr._touch(v)
            self._invalidate()

    def remove_edge_with_successors_only(self, src, dst) -> None:
        """
        Hide an edge from the with-successors view only, leaving the member view and the shared graph alone (a
        rare asymmetric bookkeeping pattern in Phoenix's switch-case structuring).
        """
        if (src, dst) not in self._hidden_full:
            self._hidden_full.add((src, dst))
            self._mgr._record(lambda: self._hidden_full.discard((src, dst)))
            self._mgr._touch(src)
            self._mgr._touch(dst)
            self._invalidate()

    def hide_edge(self, src, dst) -> None:
        """
        Remove an edge from this overlay's views only. Enclosing regions still see the underlying edge(s).
        """
        added = []
        for u, v in self._underlying_edge_pairs(src, dst):
            if (u, v) not in self._hidden:
                self._hidden.add((u, v))
                added.append((u, v))
        if added:
            self._mgr._record(lambda: self._hidden.difference_update(added))
            self._mgr._touch(src)
            self._mgr._touch(dst)
            self._invalidate()

    def replace_nodes(self, old_node_0, new_node, old_node_1=None, self_loop: bool = True) -> None:
        """
        Replace one or two member nodes with a new node, preserving and rewiring all underlying edges (including
        edges from/to nodes outside this region, which is how results become visible to enclosing regions).

        Mirrors StructurerBase.replace_nodes, with one deliberate difference: in-edges of ``old_node_1`` from
        outside this region are rewired to ``new_node`` instead of being dropped (they are entry edges owned by
        enclosing regions, e.g. abnormal loop entries).
        """
        graph = self._mgr.graph
        assert old_node_0 in graph
        assert old_node_0 in self._under

        in_edges = [(src, data) for src, _, data in graph.in_edges(old_node_0, data=True)]
        out_edges = list(graph.out_edges(old_node_0, data=True))
        in_edges_1 = []
        if old_node_1 is not None:
            assert old_node_1 in graph and old_node_1 in self._under
            in_edges_1 = [(src, data) for src, _, data in graph.in_edges(old_node_1, data=True)]
            out_edges += list(graph.out_edges(old_node_1, data=True))

        old_nodes = {old_node_0} if old_node_1 is None else {old_node_0, old_node_1}

        self._mgr._graph_remove_node(old_node_0)
        self._on_node_removed(old_node_0)
        if old_node_1 is not None:
            self._mgr._graph_remove_node(old_node_1)
            self._on_node_removed(old_node_1)
        if new_node not in self._mgr.graph:
            # note: new_node may be one of the old nodes (e.g., a node is merged into an existing structured node
            # that takes its place), or an existing member that absorbs the old nodes
            self._mgr._graph_add_node(new_node)
            self._on_node_added(new_node)

        for src, data in in_edges:
            if src not in old_nodes:
                self._mgr._graph_add_edge(src, new_node, **data)
            elif src is old_node_1 and self_loop:
                self._mgr._graph_add_edge(new_node, new_node, **data)
        for src, data in in_edges_1:
            if src not in old_nodes and src not in self._under:
                # entry edge from an enclosing region (e.g., abnormal loop entry): keep it attached
                self._mgr._graph_add_edge(src, new_node, **data)
            # in-edges of old_node_1 from inside the region are dropped, matching StructurerBase.replace_nodes
        for src, dst, data in out_edges:
            if dst not in old_nodes:
                self._mgr._graph_add_edge(new_node, dst, **data)
            elif src is old_node_1 and dst is old_node_0 and self_loop:
                self._mgr._graph_add_edge(new_node, new_node, **data)

        self._remap_bookkeeping(old_nodes, new_node)

        if self.head in old_nodes:
            old_head = self.head
            self.head = new_node
            self._mgr._record(lambda: setattr(self, "head", old_head))
        self._invalidate()

    def _remap_bookkeeping(self, old_nodes: set, new_node) -> None:
        """Remap hidden edges and edge marks that reference replaced nodes, here and in all enclosing overlays."""
        anc: RegionOverlay | None = self
        while anc is not None:
            for attr in ("_hidden", "_hidden_full", "_extra_full_edges", "edge_marks"):
                pairs: set[tuple[Any, Any]] = getattr(anc, attr)
                stale = [(u, v) for u, v in pairs if u in old_nodes or v in old_nodes]
                if stale:
                    remapped = [
                        (new_node if u in old_nodes else u, new_node if v in old_nodes else v) for u, v in stale
                    ]
                    pairs.difference_update(stale)
                    pairs.update(remapped)

                    def inverse(pairs=pairs, stale=stale, remapped=remapped):
                        pairs.difference_update(remapped)
                        pairs.update(stale)

                    self._mgr._record(inverse)
            anc = anc.parent

    #
    # Region lifecycle
    #

    def snapshot_successors(self) -> dict:
        """
        Capture this region's structural successors and how many member edges reach each, taken before the region
        is structured. finalize() uses it to re-establish the region-to-successor edges that structuring removes
        when it virtualizes/refines the corresponding control-flow edges into gotos or breaks.
        """
        return set(self.successor_nodes())

    def _resolve_entry(self, node):
        while isinstance(node, RegionOverlay):
            node = node.head
        return node

    def finalize(self, result_node=None, succ_snapshot=None, virtualized_edges=None):
        """
        Collapse this fully-structured region into its parent: the region must consist of a single member node
        (the structuring result), which takes the region's place among the parent's members. Returns that node.

        ``succ_snapshot`` (from snapshot_successors() before structuring) and ``virtualized_edges`` are used to
        re-establish the edges from result_node to the region's successors: structuring may have removed the live
        control-flow edges (refining them into breaks/gotos), but the structured region still flows to those
        successors and enclosing regions must see that. A successor whose every member edge was virtualized is a
        pure goto target and is not reconnected.
        """
        parent = self.parent
        assert parent is not None, "cannot finalize the root overlay"
        if result_node is None:
            assert len(self._members) == 1
            (result_node,) = self._members
        assert result_node in self._members
        assert not isinstance(result_node, RegionOverlay)
        assert len(self._members) == 1, "finalize requires the region to have been reduced to a single node"

        # region-internal edges never escape to enclosing regions; a leftover self-loop on the result node (e.g.
        # a structured-away back edge) must not surface as a parent-level edge
        if self._mgr.graph.has_edge(result_node, result_node):
            self._mgr._graph_remove_edge(result_node, result_node)

        # re-establish the region-to-successor edges (see docstring). forward exits are reconnected; the one
        # exception is the immediate enclosing loop head: an edge to it is this region's continue (back) edge,
        # which structuring turns into a continue rather than a graph edge, so reconnecting it would add a
        # spurious predecessor that breaks the enclosing loop's do-while / loop detection.
        if succ_snapshot:
            graph = self._mgr.graph
            parent_loop_head = None
            if self.parent is not None and self.parent.cyclic and self.parent.head is not None:
                parent_loop_head = self._resolve_entry(self.parent.head)
            for s in succ_snapshot:
                s_entry = self._resolve_entry(s)
                if (
                    s_entry is not result_node
                    and s_entry is not parent_loop_head
                    and s_entry in graph
                    and not graph.has_edge(result_node, s_entry)
                ):
                    self._mgr._graph_add_edge(result_node, s_entry)

        self._members.discard(result_node)
        self._under.discard(result_node)
        self._mgr._set_owner(result_node, parent)
        parent._members.discard(self)
        parent._members.add(result_node)
        parent.children.remove(self)
        self.replacement = result_node
        old_hidden = self._hidden
        old_hidden_full = self._hidden_full
        old_extra_full = self._extra_full_edges
        old_marks = self.edge_marks
        self._hidden = set()
        self._hidden_full = set()
        self._extra_full_edges = set()
        self.edge_marks = set()
        if parent.head is self:
            parent.head = result_node

        def inverse():
            if parent.head is result_node:
                parent.head = self
            self.replacement = None
            self._hidden = old_hidden
            self._hidden_full = old_hidden_full
            self._extra_full_edges = old_extra_full
            self.edge_marks = old_marks
            parent.children.append(self)
            parent._members.discard(result_node)
            parent._members.add(self)
            self._members.add(result_node)
            self._under.add(result_node)

        self._mgr._record(inverse)
        # result_node's ownership moves child -> parent, flipping its representative for the parent/enclosing views
        self._mgr._bump_epoch()
        self._invalidate()
        return result_node

    def collapse_to(self, result_node, succ_snapshot=None, virtualized_edges=None):
        """
        Collapse this region into its parent by replacing all of its member nodes with a single external result
        node (the structuring result). Used by structurers that compute their result without destructively
        reducing the shared graph (e.g. DreamStructurer): the region's members are still present, so their
        crossing in/out edges are rewired onto ``result_node`` and the members are removed. Returns result_node.

        This is the non-self-collapsing counterpart of finalize(); the legacy GraphRegion path called
        replace_region() for the same purpose. ``succ_snapshot``/``virtualized_edges`` are accepted for a uniform
        call site but are unused: the crossing edges are read directly from the (unmutated) shared graph.
        """
        parent = self.parent
        assert parent is not None, "cannot collapse the root overlay"
        graph = self._mgr.graph
        assert result_node not in graph, "collapse result node must not already be in the shared graph"

        under = list(self._under)
        underset = self._under

        # capture crossing edges (one endpoint inside the region, the other outside) before removing the members
        in_edges: list[tuple[Any, dict]] = []
        out_edges: list[tuple[Any, dict]] = []
        seen_in: set = set()
        seen_out: set = set()
        for u in under:
            if u not in graph:
                continue
            for src, _, data in graph.in_edges(u, data=True):
                if src not in underset and src not in seen_in:
                    seen_in.add(src)
                    in_edges.append((src, data))
            for _, dst, data in graph.out_edges(u, data=True):
                if dst not in underset and dst not in seen_out:
                    seen_out.add(dst)
                    out_edges.append((dst, data))

        # remove every member node from the shared graph (region-internal edges vanish with them)
        for u in under:
            if u in graph:
                self._mgr._graph_remove_node(u)
            self._on_node_removed(u)

        # insert the result node in the region's place and rewire its crossing edges onto it
        self._mgr._graph_add_node(result_node)
        parent._on_node_added(result_node)
        for src, data in in_edges:
            if src in graph and not graph.has_edge(src, result_node):
                self._mgr._graph_add_edge(src, result_node, **data)
        for dst, data in out_edges:
            if dst in graph and not graph.has_edge(result_node, dst):
                self._mgr._graph_add_edge(result_node, dst, **data)

        # reparent: drop this overlay from its parent, leaving result_node in its place
        parent._members.discard(self)
        parent.children.remove(self)
        self.replacement = result_node
        old_hidden = self._hidden
        old_hidden_full = self._hidden_full
        old_extra_full = self._extra_full_edges
        old_marks = self.edge_marks
        self._hidden = set()
        self._hidden_full = set()
        self._extra_full_edges = set()
        self.edge_marks = set()
        if parent.head is self:
            parent.head = result_node

        def inverse():
            if parent.head is result_node:
                parent.head = self
            self.replacement = None
            self._hidden = old_hidden
            self._hidden_full = old_hidden_full
            self._extra_full_edges = old_extra_full
            self.edge_marks = old_marks
            parent.children.append(self)
            parent._members.add(self)

        self._mgr._record(inverse)
        self._mgr._bump_epoch()
        self._invalidate()
        return result_node

    def dissolve(self) -> None:
        """
        Merge this region back into its parent (the failure path of structuring): members are reparented, and
        edges hidden in this region stay hidden in the parent (matching how partially-structured region graphs
        were merged back before).
        """
        parent = self.parent
        assert parent is not None, "cannot dissolve the root overlay"

        members = set(self._members)
        for m in members:
            if isinstance(m, RegionOverlay):
                m.parent = parent
                self.children.remove(m)
                parent.children.append(m)
            else:
                self._mgr._set_owner(m, parent)
            parent._members.add(m)
        self._members.clear()
        parent._members.discard(self)
        parent.children.remove(self)
        hidden = self._hidden - parent._hidden
        parent._hidden |= hidden
        if parent.head is self:
            parent.head = self.head

        def inverse():
            if parent.head is self.head:
                parent.head = self
            parent._hidden -= hidden
            parent.children.append(self)
            parent._members.add(self)
            self._members.update(members)
            for m in members:
                if isinstance(m, RegionOverlay):
                    m.parent = self
                    parent.children.remove(m)
                    self.children.append(m)
                parent._members.discard(m)

        self._mgr._record(inverse)
        # reparenting members flips their representatives for the parent/enclosing views
        self._mgr._bump_epoch()
        self._invalidate()


# When True, every adjacency-cache HIT is re-derived and asserted equal to the cached value. This is the
# verifier for the per-node invalidation: if any mutation fails to touch a node whose adjacency it changed, a
# stale hit will mismatch and raise. Expensive; off by default, opt in with ANGR_PARANOID_ADJ=1 for validation.
_PARANOID_ADJ_CHECK = bool(os.environ.get("ANGR_PARANOID_ADJ"))


class _OverlayNodeAtlas(Mapping):
    """Lazy node mapping of a RegionOverlayGraph: the overlay's view nodes, attributes from the shared graph."""

    __slots__ = ("_rog",)

    def __init__(self, rog: RegionOverlayGraph):
        self._rog = rog

    def __len__(self):
        return len(self._rog._node_set())

    def __iter__(self):
        return iter(self._rog._node_set())

    def __contains__(self, n):
        try:
            return n in self._rog._node_set()
        except TypeError:
            return False

    def __getitem__(self, n):
        if n not in self._rog._node_set():
            raise KeyError(n)
        shared = self._rog.overlay.manager.graph
        return shared.nodes[n] if n in shared else {}


class _OverlayAdjInner(Mapping):
    """Adjacency of one view node: target -> edge data, derived on construction from the overlay."""

    __slots__ = ("_d",)

    def __init__(self, rog: RegionOverlayGraph, n, pred: bool):
        overlay = rog.overlay
        it = overlay._iter_view_in_edges(n, rog.full) if pred else overlay._iter_view_out_edges(n, rog.full)
        if pred:
            self._d = {t: data for t, data in it if rog._pair_visible(t, n)}
        else:
            self._d = {t: data for t, data in it if rog._pair_visible(n, t)}

    def __len__(self):
        return len(self._d)

    def __iter__(self):
        return iter(self._d)

    def __contains__(self, n):
        return n in self._d

    def __getitem__(self, n):
        return self._d[n]


class _OverlayAdjAtlas(Mapping):
    """Outer adjacency mapping of a RegionOverlayGraph: view node -> _OverlayAdjInner."""

    __slots__ = ("_cache", "_epoch", "_pred", "_rog")

    def __init__(self, rog: RegionOverlayGraph, pred: bool):
        self._rog = rog
        self._pred = pred
        # Phoenix queries the same node's adjacency repeatedly (.successors/.predecessors/.in_degree/.out_degree/
        # .has_edge all route through here); cache the derived _OverlayAdjInner per node, keyed by that node's
        # topology version so an unrelated mutation does not evict it. _epoch tracks the manager's coarse epoch
        # (bumped by lifecycle ops / rollback) and forces a full clear when it changes.
        self._cache: dict[Any, tuple[int, _OverlayAdjInner]] = {}
        self._epoch: int | None = None

    def __len__(self):
        return len(self._rog._node_set())

    def __iter__(self):
        return iter(self._rog._node_set())

    def __contains__(self, n):
        try:
            return n in self._rog._node_set()
        except TypeError:
            return False

    def __getitem__(self, n):
        if n not in self._rog._node_set():
            raise KeyError(n)
        overlay = self._rog.overlay
        # Only member nodes are cached: their view-adjacency is a function of graph.adj[n] (plus this overlay's
        # own visibility state), all of which bump n's node version when they change, so the cached order and
        # keyset stay correct. A successor node's adjacency instead depends on the whole region's successor set
        # (which can change without touching that node), so it is always rebuilt fresh. Members are the hot path.
        if n not in overlay.members:
            return _OverlayAdjInner(self._rog, n, self._pred)
        mgr = overlay.manager
        if self._epoch != mgr._adj_epoch:
            self._cache.clear()
            self._epoch = mgr._adj_epoch
        nv = mgr._node_version.get(n, 0)
        entry = self._cache.get(n)
        if entry is None or entry[0] != nv:
            inner = _OverlayAdjInner(self._rog, n, self._pred)
            self._cache[n] = (nv, inner)
            return inner
        if _PARANOID_ADJ_CHECK:
            fresh = _OverlayAdjInner(self._rog, n, self._pred)
            # order-sensitive: Phoenix structuring depends on neighbor iteration order, not just the set
            assert list(fresh._d.items()) == list(entry[1]._d.items()), (
                f"stale adjacency for node {n!r} (pred={self._pred}) in overlay {overlay!r}: "
                f"a mutation changed its neighbors (or their order) without bumping its node version"
            )
        return entry[1]


class RegionOverlayGraph(networkx.DiGraph):
    """
    A read-only, networkx-compatible view of a RegionOverlay that stores no copy of the region's subgraph: all
    queries traverse the original shared graph through the overlay's membership. Compatible with every networkx
    algorithm and DiGraph read method because the graph's storage mappings are replaced with lazy atlases.

    - ``full`` selects the with-successors view (the old graph_with_successors) over the member view.
    - Edges marked through RegionOverlay.mark_edge (e.g. cyclic_refinement_outgoing) are filtered out by
      default; pass ``all_edges=True`` to the query methods, or use with_all_edges(), to include them.
    - to_acyclic() derives a view with additional edges blacklisted (e.g. the region head's in-edges), replacing
      the acyclic graph copies that structuring used to make.
    """

    def __init__(
        self,
        overlay: RegionOverlay,
        full: bool = False,
        include_marked: bool = False,
        blacklisted_edges: frozenset[tuple[Any, Any]] = frozenset(),
    ):
        super().__init__()
        self.overlay = overlay
        self.full = full
        self.include_marked = include_marked
        self.blacklisted_edges = frozenset(blacklisted_edges)
        self._ns_cache: tuple[int, frozenset] | None = None
        # replace the graph's storage with lazy atlases; assigning _adj also assigns _succ
        self._adj = _OverlayAdjAtlas(self, pred=False)
        self._pred = _OverlayAdjAtlas(self, pred=True)
        self._node = _OverlayNodeAtlas(self)
        networkx.freeze(self)

    #
    # internals
    #

    def _node_set(self) -> frozenset:
        version = self.overlay.manager.version
        cached = self._ns_cache
        if cached is not None and cached[0] == version:
            return cached[1]
        if self.full:
            nodes = self.overlay.members | self.overlay.successor_nodes()
            # absorbed-successor edges introduce view-only nodes that are not crossing-edge successors
            nodes |= {v for _, v in self.overlay._extra_full_edges}
            ns = frozenset(nodes)
        else:
            ns = frozenset(self.overlay.members)
        self._ns_cache = (version, ns)
        return ns

    def _pair_visible(self, src, dst) -> bool:
        if not self.include_marked and (src, dst) in self.overlay.edge_marks:
            return False
        if (src, dst) in self.blacklisted_edges:
            return False
        return not (self.full and (src, dst) in self.overlay._hidden_full)

    def _variant(self, fullgraph, all_edges) -> RegionOverlayGraph:
        full = self.full if fullgraph is None else fullgraph
        include_marked = self.include_marked if all_edges is None else all_edges
        if full == self.full and include_marked == self.include_marked:
            return self
        return self.overlay.view_graph(
            full=full, include_marked=include_marked, blacklisted_edges=self.blacklisted_edges
        )

    #
    # derived views
    #

    @property
    def full_view(self) -> RegionOverlayGraph:
        """The with-successors sibling of this view (zero-copy)."""
        return self._variant(True, None)

    @property
    def member_view(self) -> RegionOverlayGraph:
        """The members-only sibling of this view (zero-copy)."""
        return self._variant(False, None)

    def with_all_edges(self) -> RegionOverlayGraph:
        """A sibling view that includes edges marked through RegionOverlay.mark_edge."""
        return self._variant(None, True)

    def filtered(self) -> RegionOverlayGraph:
        """A sibling view that hides edges marked through RegionOverlay.mark_edge (the default)."""
        return self._variant(None, False)

    def to_acyclic_by_order(self, node_order) -> RegionOverlayGraph:
        """
        An acyclic view of this graph, obtained by blacklisting back edges (edges whose source is ordered at or
        after their destination in ``node_order``). Replaces utils.graph.to_acyclic_graph without a copy.
        """
        back_edges = [(u, v) for u, v in self.edges if node_order[u] >= node_order[v]]
        return self.to_acyclic(back_edges)

    def to_acyclic(self, blacklisted_edges) -> RegionOverlayGraph:
        """
        A new view with the given (view-level) edges additionally blacklisted; used to traverse the region as an
        acyclic graph without copying it.
        """
        extra = frozenset((u, v) for u, v in blacklisted_edges)
        return RegionOverlayGraph(
            self.overlay,
            full=self.full,
            include_marked=self.include_marked,
            blacklisted_edges=self.blacklisted_edges | extra,
        )

    def materialize(self) -> networkx.DiGraph:
        """An independent networkx.DiGraph copy of this view."""
        g: networkx.DiGraph = networkx.DiGraph()
        g.add_nodes_from(self._node_set())
        for u in self._node_set():
            for v, data in self._adj[u].items():
                g.add_edge(u, v, **data)
        return g

    #
    # queries with view-selection keyword arguments (methods only; subscripted degree views cannot take kwargs,
    # use .full_view / .member_view for those)
    #

    def edge_marked(self, u, v) -> bool:
        return (u, v) in self.overlay.edge_marks

    def successors(self, n, fullgraph: bool | None = None, all_edges: bool | None = None):
        g = self._variant(fullgraph, all_edges)
        if g is self:
            return super().successors(n)
        return g.successors(n)

    def predecessors(self, n, fullgraph: bool | None = None, all_edges: bool | None = None):
        g = self._variant(fullgraph, all_edges)
        if g is self:
            return super().predecessors(n)
        return g.predecessors(n)

    def has_edge(self, u, v, fullgraph: bool | None = None, all_edges: bool | None = None) -> bool:
        g = self._variant(fullgraph, all_edges)
        if g is self:
            return super().has_edge(u, v)
        return g.has_edge(u, v)

    #
    # overrides for inherited methods that would construct self.__class__() without arguments
    #

    def copy(self, as_view: bool = False) -> networkx.DiGraph:
        return self.materialize()

    def subgraph(self, nodes) -> networkx.DiGraph:
        return self.materialize().subgraph(nodes)

    def to_directed(self, as_view: bool = False) -> networkx.DiGraph:
        return self.materialize()
