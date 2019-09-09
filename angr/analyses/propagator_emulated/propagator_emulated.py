
from collections import defaultdict

import ailment

from ...engines.light import SpOffset
from .. import register_analysis
from ..analysis import Analysis
from ..forward_analysis import ForwardAnalysis, FunctionGraphVisitor, SingleNodeGraphVisitor, GraphVisitor
from .values import TOP
from .engines.vex.engine import SimEngineVEX
from ..cfg.cfg_utils import CFGUtils
from ...sim_state import SimState

class EmulatedCFGVisitor(GraphVisitor):
    def __init__(self, graph, start):
        super(EmulatedCFGVisitor, self).__init__()
        self._start = start
        self.graph=graph
        self.reset()
    def startpoints(self):

        return [self._start]

    def successors(self, node):

        return list(self.graph.successors(node))

    def predecessors(self, node):

        return list(self.graph.predecessors(node))

    def sort_nodes(self, nodes=None):

        sorted_nodes = CFGUtils.quasi_topological_sort_nodes(self.graph)

        if nodes is not None:
            sorted_nodes = [ n for n in sorted_nodes if n in set(nodes) ]

        return sorted_nodes



# The base state

class PropagatorState:
    def __init__(self, arch, replacements=None, concrete_states=None):
        self.arch = arch
        self.gpr_size = arch.bits // arch.byte_width  # size of the general-purpose registers

        self._replacements = defaultdict(dict) if replacements is None else replacements
        self._concrete_states = concrete_states

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

    @property
    def concrete_states(self):
        return self._concrete_states

    @concrete_states.setter
    def concrete_states(self, v):
        self._concrete_states = v

    def get_concrete_state(self, addr):
        """

        :param addr:
        :return:
        """

        for s in self.concrete_states:
            if s.ip._model_concrete.value == addr:
                return s

        return None

# VEX state

class PropagatorVEXState(PropagatorState):
    def __init__(self, arch, replacements=None, concrete_states=None):
        super().__init__(arch, replacements=replacements, concrete_states=concrete_states)

    def __repr__(self):
        return "<PropagatorVEXState>"

    def copy(self):
        cp = PropagatorVEXState(
            self.arch,
            replacements=self._replacements.copy(),
            concrete_states=self._concrete_states
        )
        return cp
    def add_replacement(self, codeloc, old, new):
        if old not in self._replacements[codeloc]:
            self._replacements[codeloc][old] = new
        elif self._replacements[codeloc][old] != new:
            self._replacements[codeloc][old] = TOP

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


class PropagatorEmulatedAnalysis(ForwardAnalysis, Analysis):  # pylint:disable=abstract-method
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
                 load_callback=None, stack_pointer_tracker=None, start=None, graph=None):

        # if func is not None:
        #     if block is not None:
        #         raise ValueError('You cannot specify both "func" and "block".')
        #     # traversing a function
        #     graph_visitor = FunctionGraphVisitor(func, func_graph)
        # elif block is not None:
        #     # traversing a block
        #     graph_visitor = SingleNodeGraphVisitor(block)
        # else:
        #     raise ValueError('Unsupported analysis target.')

        graph_visitor = EmulatedCFGVisitor(graph, self.project.entry if start is None else start)

        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=graph_visitor)

        self._base_state = base_state
        self._function = func
        self._max_iterations = max_iterations
        self._load_callback = load_callback
        self._stack_pointer_tracker = stack_pointer_tracker  # only used when analyzing AIL functions

        self._node_iterations = defaultdict(int)
        self._states = { }
        self.replacements = {}

        self._engine_vex = SimEngineVEX(project=self.project)
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
        if isinstance(node, ailment.Block):
            # AIL
            state = PropagatorAILState(arch=self.project.arch)
        else:
            # VEX
            #state = SimState(arch=self.projct.arch)
            state = PropagatorVEXState(arch=self.project.arch)
            state.concrete_states = [node.input_state]
        return state

    def _merge_states(self, node, *states):
        return states[0].merge(*states[1:])

    def _add_input_state(self, node, input_state):
        successors = self._graph_visitor.successors(node)

        for succ in successors:
            self._state_map[succ] = input_state

    def _run_on_node(self, node, abstract_state):
        concrete_state = abstract_state.get_concrete_state(node.addr)
        if concrete_state is None:
            # didn't find any state going to here
            print("_run_on_node(): cannot find any state for address ", hex(node.addr))
            return False, abstract_state

        if isinstance(node, ailment.Block):
            block = node
            block_key = node.addr
            engine = self._engine_ail
        else:
            block = self.project.factory.block(node.addr, node.size, opt_level=0)
            block_key = node.block_id
            engine = self._engine_vex

        #abstract_state = abstract_state.copy()
        if block_key in self._states:
            abstract_state = self._states[block_key]
        else:
            abstract_state = PropagatorVEXState(arch=self.project.arch)
        sim_successors = engine.process(concrete_state, abstract_state=abstract_state, block_key=block_key)
        abstract_state.concrete_states = sim_successors.all_successors
        self._node_iterations[block_key] += 1
        self._states[block_key] = abstract_state
        self.replacements[block_key] = abstract_state._replacements

        if self._node_iterations[block_key] < self._max_iterations:
            return True, abstract_state
        else:
            return False, abstract_state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass


register_analysis(PropagatorEmulatedAnalysis, "PropagatorEmulated")
