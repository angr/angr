from collections import defaultdict
import logging

from ...engines.light import SpOffset
from ...calling_conventions import DEFAULT_CC, SimRegArg, SimStackArg
from .. import register_analysis
from ..analysis import Analysis
from ..forward_analysis import ForwardAnalysis, FunctionGraphVisitor
from .engine_vex import SimEngineFunctionPrototypeVEX
from .base_state import FunctionPrototypeAnalysisState
from .domain import Parameter, ValuedVariable
from .solver import FuncProtoSolver

_l = logging.getLogger(name=__name__)


class FunctionPrototypeAnalysis(ForwardAnalysis, Analysis):  # pylint:disable=abstract-method
    def __init__(self, func=None, func_graph=None, base_state=None, max_iterations=3, stack_pointer_tracker=None):
        if func is not None:
            # traversing a function
            graph_visitor = FunctionGraphVisitor(func, func_graph)
        else:
            raise ValueError('Unsupported analysis target.')

        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=graph_visitor)

        self._base_state = base_state
        self._function = func
        self._max_iterations = max_iterations
        self._stack_pointer_tracker = stack_pointer_tracker  # only used when analyzing AIL functions

        self._node_iterations = defaultdict(int)
        self._states = {}

        self._engine_vex = SimEngineFunctionPrototypeVEX(project=self.project)

        self.param_descriptors = None

        self._analyze()

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _pre_job_handling(self, job):
        pass

    def _initial_abstract_state(self, node):
        # VEX
        arch = self.project.arch
        state = FunctionPrototypeAnalysisState(arch=arch)
        # create parameters
        if self._function.calling_convention is not None:
            cc = self._function.calling_convention
        else:
            _l.warning("Unknown calling convention for function %r. Assume tons of parameters.")
            cc = DEFAULT_CC[self.project.arch.name](self.project.arch)

        arch = self.project.arch
        if cc.args is not None:
            args = cc.args
        else:
            args = cc.arg_locs([False] * 10)

        for idx, arg in enumerate(args):
            param = Parameter(idx)
            if isinstance(arg, SimRegArg):
                offset = arch.registers[arg.reg_name][0]
                state.registers.set_object(offset, ValuedVariable(param, None), arg.size)
            elif isinstance(arg, SimStackArg):
                _l.warning("Stack arguments are not implemented yet.")

        # initialize sp
        state.registers.set_object(arch.sp_offset, ValuedVariable(None, SpOffset(arch.bits, 0)), arch.bytes)
        return state

    def _merge_states(self, node, *states):
        return states[0].merge(*states[1:])

    def _run_on_node(self, node, state):

        block = self.project.factory.block(node.addr, node.size, opt_level=1, cross_insn_opt=False)
        block_key = node.addr
        engine = self._engine_vex
        if block.size == 0:
            # maybe the block is not decodeable
            return False, state

        state = state.copy()
        state = engine.process(state, block=block, project=self.project,
                               fail_fast=self._fail_fast)

        self._node_iterations[block_key] += 1
        self._states[block_key] = state

        if self._node_iterations[block_key] < self._max_iterations:
            return True, state
        else:
            return False, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):

        # grab the last state
        retsite = next(iter(self._function._ret_sites))
        final_state = self._states[retsite.addr]

        # solve the constraints
        solver = FuncProtoSolver(final_state.constraints)
        self.param_descriptors = solver.param_descriptors


register_analysis(FunctionPrototypeAnalysis, "FunctionPrototype")
