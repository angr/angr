
import logging
from collections import defaultdict

from ailment.expression import BinaryOp, StackBaseOffset

from ...keyed_region import KeyedRegion
from ..analysis import Analysis
from ..typehoon.typevars import TypeVariables

l = logging.getLogger(name=__name__)


def parse_stack_pointer(sp):
    """
    Convert multiple supported forms of stack pointer representations into stack offsets.

    :param sp:  A stack pointer representation.
    :return:    A stack pointer offset.
    :rtype:     int
    """
    if isinstance(sp, int):
        return sp

    if isinstance(sp, StackBaseOffset):
        return sp.offset

    if isinstance(sp, BinaryOp):
        op0, op1 = sp.operands
        off0 = parse_stack_pointer(op0)
        off1 = parse_stack_pointer(op1)
        if sp.op == "Sub":
            return off0 - off1
        elif sp.op == "Add":
            return off0 + off1

    raise NotImplementedError("Unsupported stack pointer representation type %s." % type(sp))


class VariableRecoveryBase(Analysis):
    """
    The base class for VariableRecovery and VariableRecoveryFast.
    """

    def __init__(self, func, max_iterations):

        self.function = func
        self.variable_manager = self.kb.variables

        self._max_iterations = max_iterations

        self._outstates = {}
        self._instates = {}
        self._dominance_frontiers = None

    #
    # Public methods
    #

    def get_variable_definitions(self, block_addr):
        """
        Get variables that are defined at the specified block.

        :param int block_addr:  Address of the block.
        :return:                A set of variables.
        """

        if block_addr in self._outstates:
            return self._outstates[block_addr].variables
        return set()

    #
    # Private methods
    #

    def initialize_dominance_frontiers(self):
        # Computer the dominance frontier for each node in the graph
        df = self.project.analyses.DominanceFrontier(self.function)
        self._dominance_frontiers = defaultdict(set)
        for b0, domfront in df.frontiers.items():
            for d in domfront:
                self._dominance_frontiers[d.addr].add(b0.addr)


class VariableRecoveryStateBase:
    """
    The base abstract state for variable recovery analysis.
    """

    def __init__(self, block_addr, analysis, arch, func, stack_region=None, register_region=None, typevars=None,
                 type_constraints=None, delayed_type_constraints=None):

        self.block_addr = block_addr
        self._analysis = analysis
        self.arch = arch
        self.function = func

        if stack_region is not None:
            self.stack_region = stack_region
        else:
            self.stack_region = KeyedRegion(phi_node_contains=self._phi_node_contains)
        if register_region is not None:
            self.register_region = register_region
        else:
            self.register_region = KeyedRegion(phi_node_contains=self._phi_node_contains)

        self.typevars = TypeVariables() if typevars is None else typevars
        self.type_constraints = set() if type_constraints is None else type_constraints
        self.delayed_type_constraints = defaultdict(set) \
            if delayed_type_constraints is None else delayed_type_constraints

    @property
    def func_addr(self):
        return self.function.addr

    @property
    def dominance_frontiers(self):
        return self._analysis._dominance_frontiers

    @property
    def variable_manager(self):
        return self._analysis.variable_manager

    @property
    def variables(self):
        for ro in self.stack_region:
            for var in ro.internal_objects:
                yield var
        for ro in self.register_region:
            for var in ro.internal_objects:
                yield var

    def get_variable_definitions(self, block_addr):
        """
        Get variables that are defined at the specified block.

        :param int block_addr:  Address of the block.
        :return:                A set of variables.
        """

        return self._analysis.get_variable_definitions(block_addr)

    def add_type_constraint(self, constraint):
        """
        Add a new type constraint.

        :param constraint:
        :return:
        """

        self.type_constraints.add(constraint)

    #
    # Private methods
    #

    def _make_phi_variables(self, successor, state0, state1):

        stack_variables = defaultdict(set)
        register_variables = defaultdict(set)

        for state in [ state0, state1 ]:
            stack_vardefs = state.stack_region.get_all_variables()
            reg_vardefs = state.register_region.get_all_variables()
            for var in stack_vardefs:
                stack_variables[(var.offset, var.size)].add(var)
            for var in reg_vardefs:
                register_variables[(var.reg, var.size)].add(var)

        replacements = {}

        for variable_dict in [stack_variables, register_variables]:
            for _, variables in variable_dict.items():
                if len(variables) > 1:
                    # Create a new phi variable
                    phi_node = self.variable_manager[self.function.addr].make_phi_node(successor, *variables)
                    # Fill the replacements dict
                    for var in variables:
                        if var is not phi_node:
                            replacements[var] = phi_node

        return replacements

    def _phi_node_contains(self, phi_variable, variable):
        """
        Checks if `phi_variable` is a phi variable, and if it contains `variable` as a sub-variable.

        :param phi_variable:
        :param variable:
        :return:
        """

        if self.variable_manager[self.function.addr].is_phi_variable(phi_variable):
            return variable in self.variable_manager[self.function.addr].get_phi_subvariables(phi_variable)
        return False
