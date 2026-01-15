from __future__ import annotations
import logging
from typing import TYPE_CHECKING
from collections.abc import Callable

import angr.ailment as ailment
from angr.analyses.decompiler.ailgraph_walker import traverse_in_order
from angr.utils.ssa import get_reg_offset_base_and_size
from .traversal_engine import SimEngineSSATraversal
from .traversal_state import TraversalState

if TYPE_CHECKING:
    import networkx
    from angr.knowledge_plugins.functions.function import Function
    from angr.project import Project


l = logging.getLogger(__name__)


class TraversalAnalysis:
    """
    TraversalAnalysis traverses the AIL graph and collects definitions.
    """

    def __init__(
        self,
        project: Project,
        func: Function,
        ail_graph: networkx.DiGraph[ailment.Block],
        sp_tracker,
        bp_as_gpr: bool,
        stackvars: bool,
        tmps: bool,
        func_args: set[ailment.Expr.VirtualVariable],
        functions: Callable[[int | str], Function | None] | None,
    ):
        self.project = project
        self._stackvars = stackvars
        self._tmps = tmps
        self._function = func
        self._ail_graph = ail_graph
        self._func_args = func_args
        self._pending_states: dict[ailment.Block, TraversalState | None] = {}

        self._engine_ail = SimEngineSSATraversal(
            self.project,
            self.project.simos,
            sp_tracker=sp_tracker,
            bp_as_gpr=bp_as_gpr,
            stackvars=self._stackvars,
            use_tmps=self._tmps,
            functions=functions,
        )

        self._analyze()

        self.def_info = self._engine_ail.def_info

    #
    # Main analysis routines

    def _analyze(self):
        entry_block = next((n for n in self._ail_graph if n.addr == self._function.addr), None)
        entry_blocks = {n for n in self._ail_graph if not self._ail_graph.pred[n]}
        if entry_block is not None:
            entry_blocks.add(entry_block)
        traverse_in_order(self._ail_graph, sorted(entry_blocks), self._run_on_node)
        self._engine_ail.finalize()

    def _initial_abstract_state(self) -> TraversalState:
        state = TraversalState(self.project.arch, self._function)
        # update it with function arguments
        if self._func_args:
            for func_arg in self._func_args:
                if func_arg.parameter_category == ailment.Expr.VirtualVariableCategory.REGISTER:
                    reg_offset = func_arg.parameter_reg_offset
                    assert reg_offset is not None
                    reg_size = func_arg.size
                    state.live_registers[reg_offset].update(())
                    # get the full register if needed
                    basereg_offset, basereg_size = get_reg_offset_base_and_size(
                        reg_offset, self.project.arch, size=reg_size
                    )
                    if basereg_size != reg_size or basereg_offset != reg_offset:
                        state.live_registers[basereg_offset].update(())
                elif func_arg.parameter_category == ailment.Expr.VirtualVariableCategory.STACK:
                    offset = func_arg.parameter_stack_offset
                    assert offset is not None
                    state.live_stackvars[offset].update(())
                    state.stackvar_unify(offset, func_arg.size)
        return state

    def _run_on_node(self, node: ailment.Block):
        """

        :param node:    The current node.
        :param state:   The analysis state.
        :return:        A tuple: (any changes occur, successor state)
        """

        state = self._pending_states.get(node, None)
        if state is None:
            state = self._initial_abstract_state()
        self._pending_states[node] = None
        self._engine_ail.process(state, block=node)

        succ_count = len(self._ail_graph.succ[node])
        for i, succ in enumerate(self._ail_graph.succ[node]):
            if succ not in self._pending_states:
                self._pending_states[succ] = state.copy() if i != succ_count - 1 else state
            else:
                existing = self._pending_states[succ]
                if existing is not None:
                    existing.merge(state)
