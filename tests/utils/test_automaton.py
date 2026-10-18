from __future__ import annotations

import unittest

from angr.rustylib.automaton import EpsilonNFA, State, Symbol


class _Collider:
    """
    Distinct under __eq__, but every instance shares one hash and one repr.
    """

    def __hash__(self):
        return 7

    def __repr__(self):
        return "<Collider>"

    def __eq__(self, other):
        return self is other


class TestAutomaton(unittest.TestCase):
    """
    Test the automaton bindings.
    """

    def test_states_sharing_hash_and_repr_stay_distinct(self):
        a, b = _Collider(), _Collider()
        nfa = EpsilonNFA()
        nfa.add_transition(State(a), Symbol("x"), State(b))
        nfa.add_start_state(State(a))
        nfa.add_final_state(State(b))

        dfa = nfa.minimize()
        # a is not accepting, so the empty string is not in the language
        assert dfa.start_state not in dfa.final_states
        graph = dfa.to_networkx()
        assert graph.number_of_nodes() == 2
        assert [label for _, _, label in graph.edges(data="label")] == ["x"]

    def test_symbols_sharing_hash_and_repr_stay_distinct(self):
        s1, s2 = _Collider(), _Collider()
        nfa = EpsilonNFA()
        nfa.add_transition(State(0), Symbol(s1), State(1))
        nfa.add_transition(State(1), Symbol(s2), State(2))
        nfa.add_start_state(State(0))
        nfa.add_final_state(State(2))

        graph = nfa.minimize().to_networkx()
        labels = [label for _, _, label in graph.edges(data="label")]
        assert len(labels) == 2
        assert {id(label) for label in labels} == {id(s1), id(s2)}

    def test_equal_states_are_merged(self):
        # 1 == 1.0 and they hash alike, so they are the same state even though their reprs differ
        nfa = EpsilonNFA()
        nfa.add_transition(State(1), Symbol("x"), State(2))
        nfa.add_start_state(State(1.0))
        nfa.add_final_state(State(2))

        assert not nfa.is_empty()

    def test_object_is_its_own_state_even_if_not_equal_to_itself(self):
        # nan != nan, but like a dict key the same object must still map to one state
        nan = float("nan")
        nfa = EpsilonNFA()
        nfa.add_transition(State(nan), Symbol("x"), State(nan))
        nfa.add_start_state(State(nan))
        nfa.add_final_state(State(nan))

        graph = nfa.minimize().to_networkx()
        assert graph.number_of_nodes() == 1

    def test_raising_eq_propagates(self):
        class Boom:
            def __hash__(self):
                return 3

            def __eq__(self, other):
                raise RuntimeError("nope")

        nfa = EpsilonNFA()
        nfa.add_start_state(State(Boom()))
        with self.assertRaises(RuntimeError):
            nfa.add_final_state(State(Boom()))


if __name__ == "__main__":
    unittest.main()
