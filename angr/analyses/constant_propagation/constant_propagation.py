
from collections import defaultdict

import ailment

from ...engines.light import SpOffset
from .. import register_analysis
from ..analysis import Analysis
from ..forward_analysis import ForwardAnalysis, FunctionGraphVisitor, SingleNodeGraphVisitor
from .values import TOP, BOTTOM
from .engine_vex import SimEngineCPVEX


class ConstantPropagationState:
    def __init__(self, arch=None, registers=None, local_variables=None, ):
        self.arch = arch
        self.registers = {} if registers is None else registers  # offset to values
        self.local_variables = {} if local_variables is None else local_variables  # offset to values

        self.gpr_size = arch.bits // arch.byte_width

    def copy(self):
        cp = ConstantPropagationState(
            arch=self.arch,
            registers=self.registers.copy(),
            local_variables=self.local_variables.copy(),
        )

        return cp

    def merge(self, *others):

        state = self.copy()
        for other in others:  # type: ConstantPropagationState
            for offset, value in other.registers.items():
                if offset not in state.registers:
                    state.registers[offset] = value
                else:
                    if state.registers[offset] != value:
                        state.registers[offset] = TOP

            for offset, value in other.local_variables.items():
                if offset not in state.local_variables:
                    state.local_variables[offset] = value
                else:
                    if state.local_variables[offset] != value:
                        state.local_variables[offset] = TOP

        return state

    def store_local_variable(self, offset, size, value):
        self.local_variables[offset] = value

    def load_local_variable(self, offset, size):
        try:
            return self.local_variables[offset]
        except KeyError:
            return BOTTOM

    def store_register(self, offset, size, value):
        if size != self.gpr_size:
            return

        self.registers[offset] = value

    def load_register(self, offset, size):

        if size != self.gpr_size:
            return BOTTOM

        try:
            return self.registers[offset]
        except KeyError:
            return BOTTOM


class ConstantPropagationAnalysis(ForwardAnalysis, Analysis):
    """
    ConstantPropagationAnalysis propagates values, either constants or variables, across a block or a function. It
    supports both VEX and AIL. It performs certain arithmetic operations between constants, including but are not
    limited to:
    - addition
    - subtraction
    - multiplication
    - division
    - xor
    It also performs the following memory operations, too:
    - Loading values from a known address
    - Writing values to a stack variable
    """

    def __init__(self, func=None, block=None, func_graph=None, base_state=None, max_iterations=3,
                 function_handler=None, load_callback=None, ):
        if func is not None:
            if block is not None:
                raise ValueError('You cannot specify both "func" and "block".')
            # traversing a function
            graph_visitor = FunctionGraphVisitor(func, func_graph)
        elif block is not None:
            # traversing a block
            graph_visitor = SingleNodeGraphVisitor(block)
        else:
            raise ValueError('Unsupported analysis target.')

        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=graph_visitor)

        self._base_state = base_state
        self._function = func
        self._max_iterations = max_iterations
        self._load_callback = load_callback

        self._node_iterations = defaultdict(int)

        self._engine_vex = SimEngineCPVEX()
        self._engine_ail = None

        self._analyze()

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _pre_job_handling(self, job):
        pass

    def _initial_abstract_state(self, node):
        state = ConstantPropagationState(arch=self.project.arch)
        state.store_register(self.project.arch.sp_offset,
                             self.project.arch.bytes,
                             SpOffset(self.project.arch.bits, 0)
                             )
        return state

    def _merge_states(self, node, *states):
        return states[0].merge(*states[1:])

    def _run_on_node(self, node, state):

        if isinstance(node, ailment.Block):
            raise NotImplementedError()
        else:
            block = self.project.factory.block(node.addr, node.size, opt_level=0)
            block_key = node.addr
            engine = self._engine_vex

        state = state.copy()
        state = engine.process(state, block=block, project=self.project, base_state=self._base_state,
                               load_callback=self._load_callback, fail_fast=self._fail_fast)

        self._node_iterations[block_key] += 1

        if self._node_iterations[block_key] < self._max_iterations:
            return True, state
        else:
            return False, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass


register_analysis(ConstantPropagationAnalysis, "ConstantPropagation")
