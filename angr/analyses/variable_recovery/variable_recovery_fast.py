
import logging
from collections import defaultdict
from itertools import count

from simuvex.s_variable import SimRegisterVariable, SimStackVariable

from ...analysis import Analysis, register_analysis
from ..forward_analysis import ForwardAnalysis, FunctionGraphVisitor
from ..code_location import CodeLocation
from .keyed_region import KeyedRegion


l = logging.getLogger('angr.analyses.variable_recovery_fast')


class VariableRecoveryFastState(object):
    """
    The abstract state of variable recovery analysis.
    """

    def __init__(self, variable_manager, arch, stack_variables=None, register_variables=None):
        self.variable_manager = variable_manager
        self.arch = arch

        self._state_per_instruction = { }
        if stack_variables is not None:
            self._stack_variables = stack_variables
        else:
            self._stack_variables = KeyedRegion()
        if register_variables is not None:
            self._register_variables = register_variables
        else:
            self._register_variables = KeyedRegion()

    def __repr__(self):
        return "<VRAbstractState: %d register variables, %d stack variables>" % (len(self._register_variables), len(self._stack_variables))

    def copy(self, copy_substates=True):

        state = VariableRecoveryFastState(
            self.variable_manager,
            self.arch,
            stack_variables=self._stack_variables.copy(),
            register_variables=self._register_variables.copy(),
        )

        if copy_substates:
            state._state_per_instruction = dict((k, v.copy()) for k, v in self._state_per_instruction.iteritems())

        return state

    def merge(self, other):
        """
        Merge two abstract states.

        :param VariableRecoveryState other: The other abstract state to merge.
        :return:                            The merged abstract state.
        :rtype:                             VariableRecoveryState
        """

        # TODO: finish it

        merged_concrete_states = self._merge_concrete_states(other)

        return VariableRecoveryFastState(self.variable_manager, self.arch, merged_concrete_states)

    #
    # Util methods
    #

    def _normalize_register_offset(self, offset):

        # TODO:

        return offset

    def _to_signed(self, n):

        if n >= 2 ** (self.arch.bits - 1):
            # convert it to a negative number
            return n - 2 ** self.arch.bits

        return n


class VariableRecoveryFast(ForwardAnalysis, Analysis):
    """
    Recover "variables" from a function by keeping track of stack pointer offsets and  pattern matching VEX statements.
    """

    def __init__(self, func):
        """

        :param knowledge.Function func:  The function to analyze.
        """

        function_graph_visitor = FunctionGraphVisitor(func)

        ForwardAnalysis.__init__(self, order_entries=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=function_graph_visitor)

        self.function = func
        self._node_to_state = { }

        self._variable_accesses = defaultdict(list)
        self._insn_to_variable = defaultdict(list)
        self._variable_counters = {
            'register': count(),
            'stack': count(),
            'argument': count(),
        }

        self._analyze()

    #
    # Variable Manager
    #

    def next_variable_name(self, sort):
        if sort not in self._variable_counters:
            raise ValueError('Unsupported variable sort %s' % sort)

        if sort == 'register':
            prefix = "regvar"
        elif sort == 'stack':
            prefix = "var"
        elif sort == 'argument':
            prefix = 'arg'
        else:
            prefix = "memvar"

        return "%s_%d" % (prefix, self._variable_counters[sort].next())

    def write_to(self, variable, offset, location):
        self._variable_accesses[variable].append(('write', location))
        self._insn_to_variable[location.ins_addr].append((variable, offset))

    def read_from(self, variable, offset, location):
        self._variable_accesses[variable].append(('read', location))
        self._insn_to_variable[location.ins_addr].append((variable, offset))

    def reference_at(self, variable, offset, location):
        self._variable_accesses[variable].append(('reference', location))
        self._insn_to_variable[location.ins_addr].append((variable, offset))

    def find_variable_by_insn(self, ins_addr):
        if ins_addr not in self._insn_to_variable:
            return None

        return self._insn_to_variable[ins_addr][0]

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _pre_entry_handling(self, job):
        pass

    def _get_initial_abstract_state(self, node):

        # annotate the stack pointer
        # concrete_state.regs.sp = concrete_state.regs.sp.annotate(StackLocationAnnotation(8))

        # give it enough stack space
        # concrete_state.regs.bp = concrete_state.regs.sp + 0x100000

        return VariableRecoveryFastState(self, self.project.arch)

    def _merge_states(self, *states):

        if len(states) == 1:
            return states[0]

        # FIXME: SimFastMemory doesn't support merge. We should do a merge here. Fix it later.
        return states[0]

        return reduce(lambda s_0, s_1: s_0.merge(s_1), states[1:], states[0])

    def _run_on_node(self, node, state):
        """


        :param angr.Block node:
        :param VariableRecoveryState state:
        :return:
        """

        block = self.project.factory.block(node.addr, node.size, opt_level=0)

        self._process_block(block)

        state = state.copy()

        self._node_to_state[node] = state

        return True, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass

    #
    # Private methods
    #

    def _process_block(self, block):

        statements = block.vex.statements

        for stmt in statements:
            print stmt.__str__(arch=self.project.arch, tyenv=block.vex.tyenv)


register_analysis(VariableRecoveryFast, 'VariableRecoveryFast')
