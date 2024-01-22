from typing import Set, List, Tuple, Optional, TYPE_CHECKING

import networkx

# FIXME: Remove the dependency on pyformlang
from pyformlang.finite_automaton import Epsilon, EpsilonNFA, State, Symbol

from .typevars import BaseLabel, Subtype
from .variance import Variance

if TYPE_CHECKING:
    from pyformlang.finite_automaton import DeterministicFiniteAutomaton


START_STATE = State("START")
END_STATE = State("END")


class DFAConstraintSolver:
    """
    Implements a DFA-based graph solver.
    """

    def graph_to_epsilon_nfa(self, graph: networkx.DiGraph, starts: Set, ends: Set) -> EpsilonNFA:
        enfa = EpsilonNFA()

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
            enfa.add_transition(START_STATE, Symbol(start), State(start))

        enfa.add_final_state(END_STATE)
        for end in ends:
            enfa.add_transition(State(end), Symbol(end), END_STATE)

        assert not enfa.is_empty()
        return enfa

    def generate_constraints_between(self, graph: networkx.DiGraph, starts: Set, ends: Set) -> Set:
        epsilon_nfa = self.graph_to_epsilon_nfa(graph, starts, ends)
        min_dfa: "DeterministicFiniteAutomaton" = epsilon_nfa.minimize()
        dfa_graph: networkx.MultiDiGraph = min_dfa.to_networkx()

        constraints = set()

        for final_state in min_dfa.final_states:
            for path in networkx.all_simple_edge_paths(dfa_graph, min_dfa.start_state, final_state):
                path_labels = []
                for src, dst, index in path:
                    d = dfa_graph.get_edge_data(src, dst)[index]
                    path_labels.append(d["label"])

                start_node = path_labels[0]
                end_node = path_labels[-1]

                constraint = self._check_constraint(start_node, end_node, path_labels[1:-1])
                if constraint is not None:
                    constraints.add(constraint)

        return constraints

    def _check_constraint(self, src, dst, string: List[Tuple[BaseLabel, str]]) -> Optional[Subtype]:
        forgets = []
        recalls = []
        for label, kind in string:
            if kind == "forget":
                forgets.append(label)
            elif kind == "recall":
                recalls.append(label)

        lhs = src
        rhs = dst
        for recall in recalls:
            lhs = lhs.recall(recall)
        for forget in reversed(forgets):
            rhs = rhs.recall(forget)

        if lhs.variance == Variance.COVARIANT and rhs.variance == Variance.COVARIANT:
            if lhs.typevar != rhs.typevar:
                return Subtype(lhs.typevar, rhs.typevar)
        return None
