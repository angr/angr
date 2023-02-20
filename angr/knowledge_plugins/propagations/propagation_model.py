from typing import Tuple, Dict, Set

from angr.serializable import Serializable


class PropagationModel(Serializable):
    """
    This class stores the propagation result that comes out of Propagator.
    """

    __slots__ = (
        "key",
        "node_iterations",
        "states",
        "block_initial_reg_values",
        "replacements",
        "equivalence",
        # internals of the function graph visitor
        "graph_visitor",
    )

    def __init__(
        self,
        prop_key: Tuple,
        node_iterations: Dict,
        states: Dict,
        block_initial_reg_values: Dict,
        replacements: Dict,
        equivalence: Set,
    ):
        self.key = prop_key
        self.node_iterations = node_iterations
        self.states = states
        self.block_initial_reg_values = block_initial_reg_values
        self.replacements = replacements
        self.equivalence = equivalence

        self.graph_visitor = None

    def downsize(self):
        self.node_iterations = None
        self.block_initial_reg_values = None
        self.states = None
        self.graph_visitor = None
