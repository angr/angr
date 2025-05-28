from __future__ import annotations
import logging

import angr.ailment as ailment

from angr.analyses import ForwardAnalysis
from angr.analyses.forward_analysis import FunctionGraphVisitor
from .traversal_engine import SimEngineSSATraversal
from .traversal_state import TraversalState


l = logging.getLogger(__name__)


class TraversalAnalysis(ForwardAnalysis[TraversalState, ailment.Block, object, tuple[int, int]]):
    """
    TraversalAnalysis traverses the AIL graph and collects definitions.
    """

    def __init__(
        self,
        project,
        func,
        ail_graph,
        sp_tracker,
        bp_as_gpr: bool,
        stackvars: bool,
        tmps: bool,
        func_args: set[ailment.Expr.VirtualVariable],
    ):

        self.project = project
        self._stackvars = stackvars
        self._tmps = tmps
        self._function = func
        self._graph_visitor = FunctionGraphVisitor(self._function, ail_graph)
        self._func_args = func_args

        ForwardAnalysis.__init__(
            self, order_jobs=True, allow_merging=True, allow_widening=False, graph_visitor=self._graph_visitor
        )
        self._engine_ail = SimEngineSSATraversal(
            self.project,
            self.project.simos,
            sp_tracker=sp_tracker,
            bp_as_gpr=bp_as_gpr,
            stackvars=self._stackvars,
            use_tmps=self._tmps,
        )

        self._visited_blocks: set[tuple[int, int]] = set()

        self._analyze()

        self.def_to_loc = self._engine_ail.def_to_loc
        self.loc_to_defs = self._engine_ail.loc_to_defs

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _initial_abstract_state(self, node: ailment.Block) -> TraversalState:
        state = TraversalState(self.project.arch, self._function)
        # update it with function arguments
        if self._func_args:
            for func_arg in self._func_args:
                if func_arg.oident[0] == ailment.Expr.VirtualVariableCategory.REGISTER:
                    reg_offset = func_arg.oident[1]
                    reg_size = func_arg.size
                    state.live_registers.add(reg_offset)
                    # get the full register if needed
                    basereg_offset, basereg_size = self.project.arch.get_base_register(reg_offset, size=reg_size)
                    if basereg_size != reg_size or basereg_offset != reg_offset:
                        state.live_registers.add(basereg_offset)
                elif func_arg.oident[0] == ailment.Expr.VirtualVariableCategory.STACK:
                    state.live_stackvars.add((func_arg.oident[1], func_arg.size))
        return state

    def _merge_states(self, node: ailment.Block, *states: TraversalState) -> tuple[TraversalState, bool]:
        merged_state = TraversalState(
            self.project.arch,
            self._function,
            live_registers=states[0].live_registers.copy(),
            live_stackvars=states[0].live_stackvars.copy(),
        )
        merge_occurred = merged_state.merge(*states[1:])
        return merged_state, not merge_occurred

    def _run_on_node(self, node, state: TraversalState):
        """

        :param node:    The current node.
        :param state:   The analysis state.
        :return:        A tuple: (any changes occur, successor state)
        """

        if isinstance(node, ailment.Block):
            block = node
            block_key = (node.addr, node.idx)
            engine = self._engine_ail
        else:
            l.warning("Unsupported node type %s.", node.__class__)
            return False, state

        if block_key in self._visited_blocks:
            # we visit each block exactly once
            return False, state

        engine: SimEngineSSATraversal

        state = state.copy()
        engine.process(state, block=block)

        self._visited_blocks.add(block_key)
        return True, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass
