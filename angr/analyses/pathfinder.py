# pylint:disable=missing-class-docstring
from __future__ import annotations
from enum import Enum, auto
from dataclasses import dataclass
from weakref import ref
from collections import defaultdict

from networkx import DiGraph
from networkx.algorithms.shortest_paths import single_target_shortest_path_length

from angr.sim_state import SimState
from angr.engines.successors import SimSuccessors
from angr.knowledge_plugins.cfg import CFGModel, CFGNode
from .analysis import Analysis, AnalysesHub


class Unreachable(Exception):
    pass


@dataclass(eq=False)
class SimStateMarker:
    addr: int
    parent: SimStateMarker | None = None
    banned: bool = False
    misses: int = 0

    def __repr__(self):
        inner_repr = "None" if self.parent is None else "..."
        return f"SimStateMarker(addr={self.addr:#x}, parent={inner_repr}, banned={self.banned}, misses={self.misses})"


class SuccessorsKind(Enum):
    SAT = auto()
    UNSAT = auto()
    MISSING = auto()


@dataclass
class TestPathReport:
    path_markers: dict[int, SimStateMarker]
    termination: SuccessorsKind


def nilref():
    return None


class Pathfinder(Analysis):
    def __init__(self, start_state: SimState, goal_addr: int, cfg: CFGModel, cache_size=10000):
        self.start_state = start_state
        self.goal_addr = goal_addr
        self.goal_state: SimState | None = None
        self.cfg = cfg
        self.cache_size = cache_size

        # HACK HACK HACK HACK TODO FIXME FISH PLEASE GET RID OF THIS
        extra_edges = []
        for node in self.cfg.graph.nodes:
            if node.is_syscall:
                for pred in self.cfg.graph.pred[node]:
                    for succ, data in self.cfg.graph.succ[pred].items():
                        if data["jumpkind"] == "Ijk_FakeRet":
                            extra_edges.append((node, succ))
        for node, succ in extra_edges:
            self.cfg.graph.add_edge(node, succ, jumpkind="Ijk_Ret")

        goal_node = self.cfg.get_any_node(goal_addr)
        if goal_node is None:
            raise ValueError(f"Node {goal_addr:#x} is not in graph")

        self.start_marker = SimStateMarker(start_state.addr)
        self.transition_cache: DiGraph[SimStateMarker] = DiGraph()
        self.transition_cache.add_node(self.start_marker, state=ref(start_state))
        self.base_heuristic: dict[int, int] = {
            node.addr: dist for node, dist in single_target_shortest_path_length(cfg.graph, goal_node)
        }
        self.state_cache = {}
        self.unsat_markers = set()
        self.extra_weight = defaultdict(int)

        self._search_frontier_marker = self.start_marker
        self._search_path: list[tuple[int, str]] = [(self.start_marker.addr, "Ijk_Boring")]
        self._search_stack = []
        self._search_backtrack_to = {self.start_marker}
        self._search_address_backtrack_points = {self.start_marker.addr: self.start_marker}

    def cache_state(self, state: SimState):
        self.state_cache[state] = self.state_cache.pop(state, None)
        if len(self.state_cache) > self.cache_size:
            self.state_cache.pop(next(iter(self.state_cache)))

    def marker_to_state(self, marker: SimStateMarker) -> SimState | None:
        return self.transition_cache.nodes[marker]["state"]()

    def analyze(self) -> bool:
        while True:
            search_path = self.find_best_hypothesis_path()
            result = self.test_path(search_path)
            if result.termination == SuccessorsKind.SAT:
                self.goal_state = self.marker_to_state(result.path_markers[len(search_path) - 1])
                return True
            marker = result.path_markers[max(result.path_markers)]
            marker.banned = True
            self._search_backtrack_to.add(marker)
            if result.termination == SuccessorsKind.UNSAT:
                self.unsat_markers.add(marker)

    def _search_backtrack(self):
        if self._search_address_backtrack_points[self._search_frontier_marker.addr] is self._search_frontier_marker:
            self._search_address_backtrack_points.pop(self._search_frontier_marker.addr)

        self._search_frontier_marker = self._search_frontier_marker.parent
        if self._search_frontier_marker is None:
            raise Unreachable

        addr, jumpkind = self._search_path.pop()
        if jumpkind == "Ijk_Ret":
            self._search_stack.append(addr)
        elif jumpkind == "Ijk_Call" or jumpkind.startswith("Ijk_Sys"):
            self._search_stack.pop()

    def find_best_hypothesis_path(self) -> tuple[int, ...]:
        assert self._search_backtrack_to, "Uhh every iteration should set at least one backtrack point"
        if self.start_marker in self._search_backtrack_to:
            self._search_frontier_marker = self.start_marker
            self._search_path: list[tuple[int, str]] = [(self.start_marker.addr, "Ijk_Boring")]
            self._search_stack = []
            self._search_backtrack_to = set()
        else:
            while self._search_backtrack_to:
                self._search_backtrack_to.discard(self._search_frontier_marker)
                try:
                    self._search_backtrack()
                except Unreachable as e:
                    raise RuntimeError("oops") from e

        while self._search_path[-1][0] != self.goal_addr:
            banned = {
                marker.addr for marker in self.transition_cache.succ[self._search_frontier_marker] if marker.banned
            }
            current_node = self.cfg.get_any_node(self._search_path[-1][0])
            options = [
                (node, data["jumpkind"], self.base_heuristic[node.addr] + self.extra_weight[node.addr])
                for node, data in self.cfg.graph.succ[current_node].items()
                if data["jumpkind"] != "Ijk_FakeRet"
                and node.addr not in banned
                and node.addr in self.base_heuristic
                and (data["jumpkind"] != "Ijk_Ret" or node.addr == self._search_stack[-1])
            ]
            if not options:
                # backtrack
                self._search_frontier_marker.banned = True
                self._search_backtrack()
                continue

            best_node, best_jumpkind, best_weight = min(
                options,
                default=(None, None),
                key=lambda xyz: xyz[2],
            )

            assert isinstance(best_jumpkind, str)
            assert isinstance(best_node, CFGNode)
            self.extra_weight[best_node.addr] += 1
            self._search_path.append((best_node.addr, best_jumpkind))

            if best_jumpkind == "Ijk_Call" or best_jumpkind.startswith("Ijk_Sys"):
                self._search_stack.append(
                    next(
                        iter(
                            node.addr
                            for node, data in self.cfg.graph.succ[current_node].items()
                            if data["jumpkind"] == "Ijk_FakeRet"
                        ),
                        None,
                    )
                )
            elif best_jumpkind == "Ijk_Ret":
                self._search_stack.pop()

            frontier_marker_nullable = next(
                (
                    marker
                    for marker in self.transition_cache.succ[self._search_frontier_marker]
                    if marker.addr == best_node.addr
                ),
                None,
            )
            if frontier_marker_nullable is None:
                new_marker = SimStateMarker(best_node.addr, self._search_frontier_marker)
                self.transition_cache.add_node(new_marker, state=nilref)
                self.transition_cache.add_edge(self._search_frontier_marker, new_marker)
                self._search_frontier_marker = new_marker
            else:
                self._search_frontier_marker = frontier_marker_nullable

            if self._search_frontier_marker.addr not in self._search_address_backtrack_points:
                self._search_address_backtrack_points[self._search_frontier_marker.addr] = self._search_frontier_marker

            # TODO does this go above the above stanza?
            if sum(weight == best_weight for _, _, weight in options) != 1:
                self._search_backtrack_to.add(self._search_address_backtrack_points[self._search_frontier_marker.addr])

        return tuple(addr for addr, _ in self._search_path)

    def diagnose_unsat(self, state: SimState):
        pass

    def test_path(self, bbl_addr_trace: tuple[int, ...]) -> TestPathReport:
        assert bbl_addr_trace[0] == self.start_marker.addr, "Paths must begin with the start state"

        known_markers = [self.start_marker]
        for addr in bbl_addr_trace[1:]:
            for succ in self.transition_cache.succ[known_markers[-1]]:
                if succ.addr == addr:
                    break
            else:
                break
            known_markers.append(succ)

        marker = None
        for ri, marker_ in enumerate(reversed(known_markers)):
            i = len(known_markers) - 1 - ri
            state: SimState = self.transition_cache.nodes[marker_]["state"]()
            marker = marker_
            if state is not None:
                break
        else:
            assert False, "The first item in known_markers should always have a resolvable weakref"

        while i != len(bbl_addr_trace) - 1:
            assert state.addr == bbl_addr_trace[i]

            marker.misses += 1
            successors = state.step(strict_block_end=True)
            succ, kind = find_successor(successors, bbl_addr_trace[i + 1])

            # cache state
            if i + 1 < len(known_markers):
                succ_marker = known_markers[i + 1]
            else:
                succ_marker = SimStateMarker(bbl_addr_trace[i + 1], parent=marker)
                self.transition_cache.add_node(succ_marker)
            self.transition_cache.add_edge(marker, succ_marker)
            self.transition_cache.nodes[succ_marker]["state"] = ref(succ) if succ is not None else nilref
            if succ is not None:
                self.cache_state(succ)

            if kind == SuccessorsKind.SAT:
                assert succ is not None
                state = succ
                marker = succ_marker
                i += 1
                continue
            if kind == SuccessorsKind.UNSAT:
                assert succ is not None
                return TestPathReport(
                    path_markers={i: marker, i + 1: succ_marker},
                    termination=SuccessorsKind.UNSAT,
                )
            return TestPathReport(path_markers={i: marker, i + 1: succ_marker}, termination=SuccessorsKind.MISSING)

        return TestPathReport(path_markers={i: marker}, termination=SuccessorsKind.SAT)


def find_successor(successors: SimSuccessors, target_addr: int) -> tuple[SimState | None, SuccessorsKind]:
    for succ in successors.flat_successors:
        if succ.addr == target_addr:
            return succ, SuccessorsKind.SAT
    for succ in successors.unsat_successors:
        if succ.addr == target_addr:
            return succ, SuccessorsKind.UNSAT
    for succ in successors.unconstrained_successors:
        succ2 = succ.copy()
        succ2.add_constraints(succ2._ip == target_addr)
        if succ2.satisfiable():
            return succ2, SuccessorsKind.SAT
    return None, SuccessorsKind.MISSING


AnalysesHub.register_default("Pathfinder", Pathfinder)
