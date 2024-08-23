from __future__ import annotations
from typing import Any
from collections import defaultdict

import claripy
import ailment
from angr.serializable import Serializable
from angr.knowledge_plugins.functions.function import Function
from .states import PropagatorVEXState, PropagatorAILState, PropagatorState


class PropagationModel(Serializable):
    """
    This class stores the propagation result that comes out of Propagator.
    """

    __slots__ = (
        "key",
        "node_iterations",
        "states",
        "input_states",
        "block_initial_reg_values",
        "replacements",
        "equivalence",
        # internals of the function graph visitor
        "graph_visitor",
        "_initial_state",
        "_function",
    )

    def __init__(
        self,
        prop_key: tuple,
        node_iterations: defaultdict[Any, int] | None = None,
        states: dict | None = None,
        block_initial_reg_values: dict | None = None,
        replacements: defaultdict[Any, dict] | None = None,
        equivalence: set | None = None,
        function: Function | None = None,
        input_states: dict | None = None,
    ):
        self.key = prop_key
        self.node_iterations = node_iterations if node_iterations is not None else defaultdict(int)
        self.input_states = input_states if input_states is not None else {}
        self.states = states if states is not None else {}
        self.block_initial_reg_values = block_initial_reg_values if block_initial_reg_values is not None else {}
        self.replacements = replacements
        self.equivalence = equivalence if equivalence is not None else set()

        self.graph_visitor = None
        self._initial_state = None
        self._function = function

    def downsize(self):
        self.node_iterations = None
        self.block_initial_reg_values = None
        self.states = None
        self.input_states = None
        self.graph_visitor = None

    def block_beginning_state(self, block_addr) -> PropagatorState:
        if self._function is None:
            raise NotImplementedError

        node = self._function.get_node(block_addr)
        preds = [self.states[pnode.addr] for pnode in self._function.graph.predecessors(node)]
        if not preds:
            if isinstance(node, ailment.Block):
                state = PropagatorAILState.initial_state(self._function.project, func_addr=self._function.addr)
            else:
                state = PropagatorVEXState.initial_state(self._function.project, func_addr=self._function.addr)
                state.store_register(state.arch.ip_offset, state.arch.bytes, claripy.BVV(block_addr, state.arch.bits))
        else:
            state, _ = preds[0].merge(*preds[1:])
        return state
