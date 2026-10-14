from __future__ import annotations

import networkx

from angr.errors import AngrError
from angr.rustylib.automaton import (
    DeterministicFiniteAutomaton,
    Epsilon,
    EpsilonNFA,
    State,
    Symbol,
)

from .typevars import Subtype
from .variance import Variance

START_STATE = State("START")
END_STATE = State("END")


class EmptyEpsilonNFAError(AngrError):
    """
    A notification exception generated when the epsilon NFA is empty.
    """


class DFAConstraintSolver:
    """
    Implements a DFA-based graph solver.
    """

    @staticmethod
    def graph_to_epsilon_nfa(graph: networkx.DiGraph, starts: set, ends: set) -> EpsilonNFA:
        enfa = EpsilonNFA()

        # print("Converting graph to eNFA")

        for src, dst, data in graph.edges(data=True):
            if not data:
                symbol = Epsilon()
            else:
                assert "label" in data
                label, kind = data["label"]
                symbol = Symbol((label, kind))

            # print(src, "-----", symbol, "----->", dst)
            enfa.add_transition(State(src), symbol, State(dst))

        enfa.add_start_state(START_STATE)

        for start in starts:
            # print("Start transition", START_STATE, "----->", start)
            enfa.add_transition(START_STATE, Symbol(start), State(start))

        enfa.add_final_state(END_STATE)
        for end in ends:
            # print("End transition", end, "----->", END_STATE)
            enfa.add_transition(State(end), Symbol(end), END_STATE)

        # networkx.drawing.nx_pydot.write_dot(graph, "d:/enfa.dot")

        if enfa.is_empty():
            raise EmptyEpsilonNFAError
        return enfa

    def generate_constraints_between(self, graph: networkx.DiGraph, starts: set, ends: set) -> set:
        epsilon_nfa = self.graph_to_epsilon_nfa(graph, starts, ends)
        min_dfa: DeterministicFiniteAutomaton = epsilon_nfa.minimize()
        dfa_graph: networkx.MultiDiGraph = min_dfa.to_networkx()
        return self._constraints_from_simple_paths(dfa_graph, min_dfa.start_state, set(min_dfa.final_states))

    @staticmethod
    def _constraints_from_simple_paths(dfa_graph: networkx.MultiDiGraph, start, finals: set) -> set[Subtype]:
        """
        Collect a constraint for every simple path from the start state to a final state. A path reads a start node,
        then recall/forget labels, then an end node; its constraint is start.recall(recalls) <: end.recall(forgets
        reversed) when both sides are covariant and different.

        The number of simple paths can be exponential in the size of the DFA, so the paths are enumerated with a DFS
        that shares work between paths with a common prefix: the left-hand side is computed once per prefix, right-hand
        sides are cached, and prefixes whose left-hand side is fixed and contravariant are not extended.
        """

        succs = {
            node: [(dst, data["label"]) for _, dst, data in dfa_graph.out_edges(node, data=True)] for node in dfa_graph
        }
        # states from which a recall label can still be read
        can_recall = set()
        for node, edges in succs.items():
            if node not in can_recall and any(isinstance(lbl, tuple) and lbl[1] == "recall" for _, lbl in edges):
                can_recall.add(node)
                can_recall |= networkx.ancestors(dfa_graph, node)

        covariant = Variance.COVARIANT
        constraints = set()
        rhs_cache = {}
        seen_pairs = set()
        for first_dst, first in succs.get(start, ()):
            # single-label paths never produce a constraint
            if first_dst == start or not succs[first_dst]:
                continue
            visited = {start, first_dst}
            recalls = []
            # frame: node, next edge index, left-hand side (None until computed), forget labels, pushed a recall
            stack = [[first_dst, 0, None, (), False]]
            while stack:
                frame = stack[-1]
                node, idx, lhs, forgets, _ = frame
                edges = succs[node]
                if idx == len(edges):
                    stack.pop()
                    visited.discard(node)
                    if frame[4]:
                        recalls.pop()
                    continue
                frame[1] = idx + 1
                dst, label = edges[idx]
                if dst in visited:
                    continue

                if dst in finals:
                    if lhs is None:
                        lhs = frame[2] = first.recall_many(recalls)
                    if lhs.variance == covariant:
                        key = label, forgets
                        rhs = rhs_cache.get(key)
                        if rhs is None:
                            rhs = rhs_cache[key] = label.recall_many(forgets[::-1])
                        if rhs.variance == covariant:
                            pair = lhs.typevar, rhs.typevar
                            if pair not in seen_pairs:
                                seen_pairs.add(pair)
                                if pair[0] != pair[1]:
                                    constraints.add(Subtype(*pair))

                if not succs[dst]:
                    continue
                lbl, kind = label
                child_forgets = forgets
                if kind == "recall":
                    recalls.append(lbl)
                    child_lhs = None
                else:
                    if kind == "forget":
                        child_forgets = (*forgets, lbl)
                    child_lhs = lhs
                if dst not in can_recall:
                    # the left-hand side is fixed from here on
                    if child_lhs is None:
                        child_lhs = first.recall_many(recalls)
                    if child_lhs.variance != covariant:
                        if kind == "recall":
                            recalls.pop()
                        continue
                visited.add(dst)
                stack.append([dst, 0, child_lhs, child_forgets, kind == "recall"])

        return constraints
