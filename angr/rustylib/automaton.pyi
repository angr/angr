from typing import Any

import networkx

class State:
    """
    A State wrapper that holds any Python object.
    """

    def __init__(self, value: Any) -> None:
        """
        Initialize a State with the given value.

        :arg value: The value to wrap.
        """

    @property
    def value(self) -> Any:
        """
        Get the underlying value.

        :returns: The wrapped value.
        """

    def __repr__(self) -> str: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

class Symbol:
    """
    A Symbol wrapper that holds any Python object.
    """

    def __init__(self, value: Any) -> None:
        """
        Initialize a Symbol with the given value.

        :arg value: The value to wrap.
        """

    @property
    def value(self) -> Any:
        """
        Get the underlying value.

        :returns: The wrapped value.
        """

    def __repr__(self) -> str: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

class Epsilon:
    """
    Marker for epsilon (empty) transitions.
    """

    def __init__(self) -> None:
        """
        Initialize an Epsilon marker.
        """

    def __repr__(self) -> str: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

class EpsilonNFA:
    """
    An Epsilon Non-deterministic Finite Automaton.
    """

    def __init__(self) -> None:
        """
        Create a new empty epsilon-NFA.
        """

    def add_transition(self, source: State, symbol: Symbol | Epsilon, destination: State) -> None:
        """
        Add a transition from source to destination on the given symbol.

        :arg source: The source state.
        :arg symbol: The symbol (or Epsilon for epsilon transitions).
        :arg destination: The destination state.
        """

    def add_start_state(self, state: State) -> None:
        """
        Add a start state.

        :arg state: The state to add as a start state.
        """

    def add_final_state(self, state: State) -> None:
        """
        Add a final (accepting) state.

        :arg state: The state to add as a final state.
        """

    def is_empty(self) -> bool:
        """
        Check if the NFA's language is empty.

        :returns: True if the language is empty, False otherwise.
        """

    def minimize(self) -> DeterministicFiniteAutomaton:
        """
        Minimize the NFA by converting to DFA and minimizing.

        :returns: A minimized DeterministicFiniteAutomaton.
        """

class DeterministicFiniteAutomaton:
    """
    A Deterministic Finite Automaton.
    """

    @property
    def start_state(self) -> int | None:
        """
        Get the start state as an integer index.

        :returns: The start state index, or None if empty.
        """

    @property
    def final_states(self) -> set[int]:
        """
        Get the final states as a set of integer indices.

        :returns: Set of final state indices.
        """

    def is_empty(self) -> bool:
        """
        Check if the DFA's language is empty.

        :returns: True if the language is empty, False otherwise.
        """

    def to_networkx(self) -> networkx.MultiDiGraph:
        """
        Convert to a NetworkX MultiDiGraph.

        :returns: A networkx.MultiDiGraph with nodes as state indices and edges with 'label' attributes.
        """

    def minimize(self) -> DeterministicFiniteAutomaton:
        """
        Minimize the DFA.

        :returns: A new minimized DeterministicFiniteAutomaton.
        """

__all__ = ["State", "Symbol", "Epsilon", "EpsilonNFA", "DeterministicFiniteAutomaton"]
