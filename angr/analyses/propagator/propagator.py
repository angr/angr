
from collections import defaultdict

import ailment

from ...engines.light import SpOffset
from .. import register_analysis
from ..analysis import Analysis
from ..forward_analysis import ForwardAnalysis, FunctionGraphVisitor, SingleNodeGraphVisitor
from .values import TOP
from .engine_vex import SimEnginePropagatorVEX
from .engine_ail import SimEnginePropagatorAIL


# The base state

class PropagatorState:
    def __init__(self, arch, replacements=None):
        self.arch = arch
        self.gpr_size = arch.bits // arch.byte_width  # size of the general-purpose registers

        self._replacements = defaultdict(dict) if replacements is None else replacements

    def __repr__(self):
        return "<PropagatorState>"

    def copy(self):
        raise NotImplementedError()

    def merge(self, *others):

        state = self.copy()

        for o in others:
            for loc, vars_ in o._replacements.items():
                if loc not in state._replacements:
                    state._replacements[loc] = vars_.copy()
                else:
                    for var, repl in vars_.items():
                        if var not in state._replacements[loc]:
                            state._replacements[loc][var] = repl
                        else:
                            if state._replacements[loc][var] != repl:
                                state._replacements[loc][var] = TOP

        return state


    def add_replacement(self, codeloc, old, new):
        self._replacements[codeloc][old] = new

# VEX state

class PropagatorVEXState(PropagatorState):
    def __init__(self, arch, registers=None, local_variables=None, replacements=None):
        super().__init__(arch, replacements=replacements)
        self.registers = {} if registers is None else registers  # offset to values
        self.local_variables = {} if local_variables is None else local_variables  # offset to values

    def __repr__(self):
        return "<PropagatorVEXState>"

    def copy(self):
        cp = PropagatorVEXState(
            self.arch,
            registers=self.registers.copy(),
            local_variables=self.local_variables.copy(),
            replacements=self._replacements.copy(),
        )

        return cp

    def merge(self, *others):
        state = self.copy()
        for other in others:  # type: PropagatorVEXState
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

    def store_local_variable(self, offset, size, value):  # pylint:disable=unused-argument
        # TODO: Handle size
        self.local_variables[offset] = value

    def load_local_variable(self, offset, size):  # pylint:disable=unused-argument
        # TODO: Handle size
        try:
            return self.local_variables[offset]
        except KeyError:
            return TOP

    def store_register(self, offset, size, value):
        if size != self.gpr_size:
            return

        self.registers[offset] = value

    def load_register(self, offset, size):

        # TODO: Fix me
        if size != self.gpr_size:
            return TOP

        try:
            return self.registers[offset]
        except KeyError:
            return TOP

# AIL state

class PropagatorAILState(PropagatorState):
    def __init__(self, arch, replacements=None):
        super().__init__(arch, replacements=replacements)

        self._variables = { }  # variable to values

    def __repr__(self):
        return "<PropagatorAILState>"

    def copy(self):
        rd = PropagatorAILState(
            self.arch,
            replacements=self._replacements.copy(),
        )

        rd._variables = self._variables.copy()

        return rd

    def merge(self, *others):
        state = super().merge(*others)

        for o in others:
            for k, v in o._variables.items():
                if k not in state._variables:
                    state._variables[k] = v
                else:
                    if state._variables[k] != o._variables[k]:
                        # Go to TOP
                        state._variables[k] = TOP

        return state

    def store_variable(self, old, new):
        if new is not None:
            self._variables[old] = new

    def get_variable(self, old):
        return self._variables.get(old, None)

    def remove_variable(self, old):
        self._variables.pop(old, None)

    def filter_variables(self, atom):
        keys_to_remove = set()

        for k, v in self._variables.items():
            if isinstance(v, ailment.Expr.Expression) and (v == atom or v.has_atom(atom)):
                keys_to_remove.add(k)

        for k in keys_to_remove:
            self._variables.pop(k)


class PropagatorAnalysis(ForwardAnalysis, Analysis):  # pylint:disable=abstract-method
    """
    PropagatorAnalysis propagates values, either constants or variables, across a block or a function. It supports both
    VEX and AIL. It performs certain arithmetic operations between constants, including but are not limited to:

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
                 load_callback=None, stack_pointer_tracker=None):
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
        self._stack_pointer_tracker = stack_pointer_tracker  # only used when analyzing AIL functions

        self._node_iterations = defaultdict(int)
        self._states = { }
        self.replacements = None

        self._engine_vex = SimEnginePropagatorVEX(project=self.project)
        self._engine_ail = SimEnginePropagatorAIL(stack_pointer_tracker=self._stack_pointer_tracker)

        self._analyze()

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _pre_job_handling(self, job):
        pass

    def _initial_abstract_state(self, node):
        if isinstance(node, ailment.Block):
            # AIL
            state = PropagatorAILState(arch=self.project.arch)
        else:
            # VEX
            state = PropagatorVEXState(arch=self.project.arch)
            state.store_register(self.project.arch.sp_offset,
                                 self.project.arch.bytes,
                                 SpOffset(self.project.arch.bits, 0)
                                 )
        return state

    def _merge_states(self, node, *states):
        return states[0].merge(*states[1:])

    def _run_on_node(self, node, state):

        if isinstance(node, ailment.Block):
            block = node
            block_key = node.addr
            engine = self._engine_ail
        else:
            block = self.project.factory.block(node.addr, node.size, opt_level=0)
            block_key = node.addr
            engine = self._engine_vex

        state = state.copy()
        state = engine.process(state, block=block, project=self.project, base_state=self._base_state,
                               load_callback=self._load_callback, fail_fast=self._fail_fast)

        self._node_iterations[block_key] += 1
        self._states[block_key] = state
        self.replacements = state._replacements

        if self._node_iterations[block_key] < self._max_iterations:
            return True, state
        else:
            return False, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass


register_analysis(PropagatorAnalysis, "Propagator")
