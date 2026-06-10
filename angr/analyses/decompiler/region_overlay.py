from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Iterator
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
        self._bump()

    def _graph_remove_edge(self, src, dst) -> None:
        old_data = dict(self.graph[src][dst])
        self.graph.remove_edge(src, dst)
        self._record(lambda: self.graph.add_edge(src, dst, **old_data))
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
        "_cache_graph",
        "_cache_gws",
        "_cache_succs",
        "_hidden",
        "_members",
        "_mgr",
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
        # scratch edge marks (e.g., Phoenix's cyclic_refinement_outgoing), scoped to this overlay
        self.edge_marks: set[tuple[Any, Any]] = set()
        # the node this overlay was finalized into, if any
        self.replacement = None

        self._cache_graph: tuple[int, networkx.DiGraph] | None = None
        self._cache_gws: tuple[int, networkx.DiGraph, set] | None = None
        self._cache_succs: tuple[int, set] | None = None

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

    def _crossing_out_edges(self) -> Iterator[tuple[Any, Any, dict]]:
        """All shared-graph edges leaving this region, except hidden ones."""
        graph = self._mgr.graph
        under = self._under
        for u in under:
            if u not in graph:
                continue
            for v, data in graph.adj[u].items():
                if v not in under and not self._is_hidden(u, v):
                    yield u, v, data

    def successor_nodes(self) -> set:
        """
        The derived successor set of this region: representatives of all shared-graph nodes targeted by edges
        leaving the region.
        """
        cached = self._cache_succs
        if cached is not None and cached[0] == self._mgr.version:
            return cached[1]
        succs = set()
        for _, v, _ in self._crossing_out_edges():
            rep = self._representative_outside(v)
            if rep is not None:
                succs.add(rep)
        self._cache_succs = (self._mgr.version, succs)
        return succs

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
                elif with_successors:
                    rep_v = self._representative_outside(v)
                    if rep_v is not None:
                        yield rep_u, rep_v, data

        if with_successors:
            assert succs is not None
            # successor -> successor edges
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

    def view(self) -> networkx.DiGraph:
        """
        Materialize the region graph (members only). The result is cached until the next mutation; treat it as
        read-only.
        """
        cached = self._cache_graph
        if cached is not None and cached[0] == self._mgr.version:
            return cached[1]
        g: networkx.DiGraph = networkx.DiGraph()
        g.add_nodes_from(self._members)
        for u, v, data in self._quotient_edges(with_successors=False):
            if not g.has_edge(u, v):
                g.add_edge(u, v, **data)
        self._cache_graph = (self._mgr.version, g)
        return g

    def view_with_successors(self) -> networkx.DiGraph:
        """
        Materialize the region graph including successor nodes. The result is cached until the next mutation;
        treat it as read-only.
        """
        cached = self._cache_gws
        if cached is not None and cached[0] == self._mgr.version:
            return cached[1]
        g: networkx.DiGraph = networkx.DiGraph()
        g.add_nodes_from(self._members)
        succs = self.successor_nodes()
        g.add_nodes_from(succs)
        for u, v, data in self._quotient_edges(with_successors=True):
            if not g.has_edge(u, v):
                g.add_edge(u, v, **data)
        if self._mgr.complete_successors:
            # one extra hop: all out-edges of successor nodes, mirroring RegionIdentifier's complete_successors mode
            extra_succs = set()
            for s in succs:
                under_s = self._underlying(s)
                for u in under_s:
                    if u not in self._mgr.graph:
                        continue
                    for v, data in self._mgr.graph.adj[u].items():
                        if v in under_s:
                            continue
                        rep_v = self._representative_in(v) if v in self._under else self._representative_outside(v)
                        if rep_v is None or rep_v is s:
                            continue
                        if not g.has_edge(s, rep_v):
                            g.add_edge(s, rep_v, **data)
                        if rep_v not in self._members and rep_v not in succs:
                            extra_succs.add(rep_v)
            g.add_nodes_from(extra_succs)
        self._cache_gws = (self._mgr.version, g, succs)
        return g

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

    def copy(self) -> GraphRegion:
        """
        Snapshot this overlay into a plain GraphRegion with independent graphs (for consumers that mutate region
        graphs in place).
        """
        return GraphRegion(
            self.head,
            networkx.DiGraph(self.view()),
            set(self.successor_nodes()),
            networkx.DiGraph(self.view_with_successors()),
            self.cyclic,
            None,
            cyclic_ancestor=self.cyclic_ancestor,
        )

    def recursive_copy(self, nodes_map=None) -> GraphRegion:
        """
        Convert this overlay subtree into an independent tree of plain GraphRegion objects (the pre-overlay data
        structure), for consumers that destructively restructure the region tree.
        """
        if nodes_map is None:
            nodes_map = {}
        return self._to_graph_region(nodes_map)

    def _to_graph_region(self, mapping: dict) -> GraphRegion:
        if self in mapping:
            return mapping[self]
        region = GraphRegion(None, None, None, None, self.cyclic, None, cyclic_ancestor=self.cyclic_ancestor)
        mapping[self] = region

        def conv(x):
            if isinstance(x, RegionOverlay):
                return x._to_graph_region(mapping)
            return x

        graph = networkx.DiGraph()
        for m in self._members:
            graph.add_node(conv(m))
        for u, v, data in self._quotient_edges(with_successors=False):
            graph.add_edge(conv(u), conv(v), **data)

        if self.parent is None:
            # the root region carries no successor information, matching RegionIdentifier's top-level GraphRegion
            successors = None
            gws = None
        else:
            successors = {conv(s) for s in self.successor_nodes()}
            gws = networkx.DiGraph()
            for n in self.view_with_successors().nodes:
                gws.add_node(conv(n))
            for u, v, data in self._quotient_edges(with_successors=True):
                gws.add_edge(conv(u), conv(v), **data)

        region.head = conv(self.head)
        region.graph = graph
        region.successors = successors
        region.graph_with_successors = gws
        return region

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

    def remove_node(self, node) -> None:
        """
        Remove a node. If ``node`` is a member (or a member overlay's node), it is removed from the shared graph
        for real. If it is a successor of this region, the removal is interpreted as hiding all edges from this
        region to it (the successor belongs to an enclosing region and must survive).
        """
        if isinstance(node, RegionOverlay) or node not in self._under:
            # successor removal: hide all crossing edges into it
            self.hide_edge_to_successor(node)
            return
        self._mgr._graph_remove_node(node)
        self._on_node_removed(node)
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
        resolves to its entry (head chain); overlay sources are not supported.
        """
        assert not isinstance(src, RegionOverlay), "edges from a region object are ambiguous; use a concrete node"
        dst_ = dst
        while isinstance(dst_, RegionOverlay):
            dst_ = dst_.head
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

        if new_node in graph:
            # an existing member node absorbs the old nodes
            assert new_node in self._under
            new_is_fresh = False
        else:
            new_is_fresh = True

        self._mgr._graph_remove_node(old_node_0)
        self._on_node_removed(old_node_0)
        if old_node_1 is not None:
            self._mgr._graph_remove_node(old_node_1)
            self._on_node_removed(old_node_1)
        if new_is_fresh:
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
            for attr in ("_hidden", "edge_marks"):
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

    def finalize(self, result_node=None):
        """
        Collapse this fully-structured region into its parent: the region must consist of a single member node
        (the structuring result), which takes the region's place among the parent's members. Returns that node.
        """
        parent = self.parent
        assert parent is not None, "cannot finalize the root overlay"
        if result_node is None:
            assert len(self._members) == 1
            (result_node,) = self._members
        assert result_node in self._members
        assert not isinstance(result_node, RegionOverlay)
        assert len(self._members) == 1, "finalize requires the region to have been reduced to a single node"

        self._members.discard(result_node)
        self._under.discard(result_node)
        self._mgr._set_owner(result_node, parent)
        parent._members.discard(self)
        parent._members.add(result_node)
        parent.children.remove(self)
        self.replacement = result_node
        old_hidden = self._hidden
        old_marks = self.edge_marks
        self._hidden = set()
        self.edge_marks = set()
        if parent.head is self:
            parent.head = result_node

        def inverse():
            if parent.head is result_node:
                parent.head = self
            self.replacement = None
            self._hidden = old_hidden
            self.edge_marks = old_marks
            parent.children.append(self)
            parent._members.discard(result_node)
            parent._members.add(self)
            self._members.add(result_node)
            self._under.add(result_node)

        self._mgr._record(inverse)
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
        self._invalidate()

    #
    # Disabled GraphRegion mutation API
    #

    def replace_region(self, *args, **kwargs):
        raise NotImplementedError("RegionOverlay does not support replace_region; use finalize() instead")

    def replace_region_with_region(self, *args, **kwargs):
        raise NotImplementedError("RegionOverlay does not support replace_region_with_region; use dissolve() instead")
