from typing import Tuple, Dict, Set, DefaultDict, Any, Optional
from collections import defaultdict

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
        node_iterations: Optional[DefaultDict[Any, int]] = None,
        states: Optional[Dict] = None,
        block_initial_reg_values: Optional[Dict] = None,
        replacements: Optional[DefaultDict[Any, Dict]] = None,
        equivalence: Optional[Set] = None,
    ):
        self.key = prop_key
        self.node_iterations = node_iterations if node_iterations is not None else defaultdict(int)
        self.states = states if states is not None else {}
        self.block_initial_reg_values = block_initial_reg_values if block_initial_reg_values is not None else {}
        self.replacements = replacements
        self.equivalence = equivalence if equivalence is not None else set()

        self.graph_visitor = None

    def downsize(self):
        self.node_iterations = None
        self.block_initial_reg_values = None
        self.states = None
        self.graph_visitor = None
