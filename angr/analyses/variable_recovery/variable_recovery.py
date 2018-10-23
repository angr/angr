import logging
from collections import defaultdict
from functools import reduce

import angr # type annotations; pylint: disable=unused-import

from .. import Analysis

from .annotations import StackLocationAnnotation
from ..code_location import CodeLocation
from ..forward_analysis import ForwardAnalysis, FunctionGraphVisitor
from ... import BP, BP_AFTER
from ...keyed_region import KeyedRegion
from ...sim_variable import SimRegisterVariable, SimStackVariable, SimStackVariablePhi

l = logging.getLogger("angr.analyses.variable_recovery.variable_recovery")


class VariableRecoveryState:
    """
    The abstract state of variable recovery analysis.

    :ivar angr.knowledge.variable_manager.VariableManager variable_manager: The variable manager.
    """

    def __init__(self, variable_manager, arch, func_addr, concrete_states, stack_region=None, register_region=None):
        self.variable_manager = variable_manager  # type: angr.knowledge_plugins.variables.variable_manager.VariableManager
        self.arch = arch
        self.func_addr = func_addr
        self._concrete_states = concrete_states

        # self._state_per_instruction = { }
        if stack_region is not None:
            self.stack_region = stack_region
        else:
            self.stack_region = KeyedRegion()
        if register_region is not None:
            self.register_region = register_region
        else:
            self.register_region = KeyedRegion()

        # register callbacks
        self.register_callbacks(self.concrete_states)

    def __repr__(self):
        return "<VRAbstractState: %d register variables, %d stack variables>" % (len(self.register_region), len(self.stack_region))

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

    def copy(self):

        state = VariableRecoveryState(self.variable_manager,
                                      self.arch,
                                      self.func_addr,
                                      self._concrete_states,
                                      stack_region=self.stack_region.copy(),
                                      register_region=self.register_region.copy(),
                                      )

        return state

    def register_callbacks(self, concrete_states):
        """

        :param concrete_states:
        :return:
        """

        for concrete_state in concrete_states:
            # clear existing breakpoints
            # TODO: all breakpoints are removed. Fix this later by only removing breakpoints that we added
            for bp_type in ('reg_read', 'reg_write', 'mem_read', 'mem_write', 'instruction'):
                concrete_state.inspect._breakpoints[bp_type] = [ ]

            concrete_state.inspect.add_breakpoint('reg_read', BP(when=BP_AFTER, enabled=True,
                                                                 action=self._hook_register_read
                                                                 )
                                                  )
            concrete_state.inspect.add_breakpoint('reg_write', BP(enabled=True, action=self._hook_register_write))
            concrete_state.inspect.add_breakpoint('mem_read', BP(when=BP_AFTER, enabled=True,
                                                                 action=self._hook_memory_read
                                                                 )
                                                  )
            concrete_state.inspect.add_breakpoint('mem_write', BP(enabled=True, action=self._hook_memory_write))

    def merge(self, other):
        """
        Merge two abstract states.

        :param VariableRecoveryState other: The other abstract state to merge.
        :return:                            The merged abstract state.
        :rtype:                             VariableRecoveryState
        """

        # TODO: finish it

        merged_concrete_states =  [ self._concrete_states[0] ] # self._merge_concrete_states(other)

        new_stack_region = self.stack_region.copy()
        new_stack_region.merge(other.stack_region)

        new_register_region = self.register_region.copy()
        new_register_region.merge(other.register_region)

        return VariableRecoveryState(self.variable_manager, self.arch, self.func_addr, merged_concrete_states,
                                     stack_region=new_stack_region,
                                     register_region=new_register_region
                                     )

    def _merge_concrete_states(self, other):
        """

        :param VariableRecoveryState other:
        :return:
        :rtype:                             list
        """

        merged = [ ]

        for s in self.concrete_states:
            other_state = other.get_concrete_state(s.ip._model_concrete.value)
            if other_state is not None:
                s = s.merge(other_state)
            merged.append(s)

        return merged

    #
    # SimInspect callbacks
    #

    def _hook_register_read(self, state):

        reg_read_offset = state.inspect.reg_read_offset
        reg_read_length = state.inspect.reg_read_length

        if reg_read_offset == state.arch.sp_offset and reg_read_length == state.arch.bytes:
            # TODO: make sure the sp is not overwritten by something that we are not tracking
            return

        #if reg_read_offset == state.arch.bp_offset and reg_read_length == state.arch.bytes:
        #    # TODO:

        var_offset = self._normalize_register_offset(reg_read_offset)
        if var_offset not in self.register_region:
            # the variable being read doesn't exist before
            variable = SimRegisterVariable(reg_read_offset, reg_read_length,
                                           ident=self.variable_manager[self.func_addr].next_variable_ident('register'),
                                           region=self.func_addr,
                                           )
            self.register_region.add_variable(var_offset, variable)

            # record this variable in variable manager
            self.variable_manager[self.func_addr].add_variable('register', var_offset, variable)

    def _hook_register_write(self, state):

        reg_write_offset = state.inspect.reg_write_offset

        if reg_write_offset == state.arch.sp_offset:
            # it's updating stack pointer. skip
            return

        reg_write_expr = state.inspect.reg_write_expr
        reg_write_length = len(reg_write_expr) // 8

        # annotate it
        # reg_write_expr = reg_write_expr.annotate(VariableSourceAnnotation.from_state(state))

        state.inspect.reg_write_expr = reg_write_expr

        # create the variable
        variable = SimRegisterVariable(reg_write_offset, reg_write_length,
                                       ident=self.variable_manager[self.func_addr].next_variable_ident('register'),
                                       region=self.func_addr,
                                       )
        var_offset = self._normalize_register_offset(reg_write_offset)
        self.register_region.set_variable(var_offset, variable)
        # record this variable in variable manager
        self.variable_manager[self.func_addr].add_variable('register', var_offset, variable)

        # is it writing a pointer to a stack variable into the register?
        # e.g. lea eax, [ebp-0x40]
        stack_offset = self._addr_to_stack_offset(reg_write_expr)
        if stack_offset is not None:
            # it is!
            # unfortunately we don't know the size. We use size None for now.

            if stack_offset not in self.stack_region:
                new_var = SimStackVariable(stack_offset, None, base='bp',
                                            ident=self.variable_manager[self.func_addr].next_variable_ident('stack'),
                                            region=self.func_addr,
                                            )
                self.stack_region.add_variable(stack_offset, new_var)

                # record this variable in variable manager
                self.variable_manager[self.func_addr].add_variable('stack', stack_offset, new_var)

            base_offset = self.stack_region.get_base_addr(stack_offset)
            assert base_offset is not None
            for var in self.stack_region.get_variables_by_offset(stack_offset):
                self.variable_manager[self.func_addr].reference_at(var, stack_offset - base_offset,
                                                                   self._codeloc_from_state(state)
                                                                   )

    def _hook_memory_read(self, state):

        mem_read_address = state.inspect.mem_read_address
        mem_read_length = state.inspect.mem_read_length

        stack_offset = self._addr_to_stack_offset(mem_read_address)

        if stack_offset is None:
            # it's not a stack access
            # TODO:
            pass

        else:
            if stack_offset not in self.stack_region:
                # this stack offset is not covered by any existing stack variable
                ident_sort = 'argument' if stack_offset > 0 else 'stack'
                variable = SimStackVariable(stack_offset, mem_read_length, base='bp',
                                            ident=self.variable_manager[self.func_addr].next_variable_ident(ident_sort),
                                            region=self.func_addr,
                                            )
                self.stack_region.add_variable(stack_offset, variable)

                # record this variable in variable manager
                self.variable_manager[self.func_addr].add_variable('stack', stack_offset, variable)

            base_offset = self.stack_region.get_base_addr(stack_offset)
            assert base_offset is not None

            existing_variables = self.stack_region.get_variables_by_offset(stack_offset)

            if len(existing_variables) > 1:
                # create a phi node for all other variables
                ident_sort = 'argument' if stack_offset > 0 else 'stack'
                variable = SimStackVariablePhi(
                    ident=self.variable_manager[self.func_addr].next_variable_ident(ident_sort),
                    region=self.func_addr,
                    variables=existing_variables,
                )
                self.stack_region.set_variable(stack_offset, variable)

                self.variable_manager[self.func_addr].add_variable('stack', stack_offset, variable)

            for variable in self.stack_region.get_variables_by_offset(stack_offset):
                self.variable_manager[self.func_addr].read_from(variable, stack_offset - base_offset, self._codeloc_from_state(state))

    def _hook_memory_write(self, state):

        mem_write_address = state.inspect.mem_write_address
        mem_write_expr = state.inspect.mem_write_expr
        mem_write_length = len(mem_write_expr) // 8

        stack_offset = self._addr_to_stack_offset(mem_write_address)

        if stack_offset is None:
            # it's not a stack access
            # TODO:
            pass

        else:
            # we always add a new variable to keep it SSA
            variable = SimStackVariable(stack_offset, mem_write_length, base='bp',
                                        ident=self.variable_manager[self.func_addr].next_variable_ident('stack'),
                                        region=self.func_addr,
                                        )
            self.stack_region.set_variable(stack_offset, variable)

            # record this variable in variable manager
            self.variable_manager[self.func_addr].add_variable('stack', stack_offset, variable)

            base_offset = self.stack_region.get_base_addr(stack_offset)
            assert base_offset is not None
            for variable in self.stack_region.get_variables_by_offset(stack_offset):
                self.variable_manager[self.func_addr].write_to(variable, stack_offset - base_offset, self._codeloc_from_state(state))

    #
    # Util methods
    #

    def _normalize_register_offset(self, offset):  #pylint:disable=no-self-use

        # TODO:

        return offset

    @staticmethod
    def _codeloc_from_state(state):
        return CodeLocation(state.scratch.bbl_addr, state.scratch.stmt_idx, ins_addr=state.scratch.ins_addr)

    def _to_signed(self, n):

        if n >= 2 ** (self.arch.bits - 1):
            # convert it to a negative number
            return n - 2 ** self.arch.bits

        return n

    def _addr_to_stack_offset(self, addr):
        """
        Convert an address to a stack offset.

        :param claripy.ast.Base addr:  The address to convert from.
        :return:                       A stack offset if the addr comes from the stack pointer, or None if the address
                                       does not come from the stack pointer.
        """

        def _parse(addr):
            if addr.op == '__add__':
                # __add__ might have multiple arguments
                parsed = [ _parse(arg) for arg in addr.args ]
                annotated = [ True for annotated, _ in parsed if annotated is True ]
                if len(annotated) != 1:
                    # either nothing is annotated, or more than one element is annotated
                    raise ValueError()

                return True, sum([ offset for _, offset in parsed ])
            elif addr.op == '__sub__':
                # __sub__ might have multiple arguments

                parsed = [ _parse(arg) for arg in addr.args ]
                first_annotated, first_offset = parsed[0]
                if first_annotated is False:
                    # the first argument is not annotated. we don't support it.
                    raise ValueError()
                if any([ annotated for annotated, _ in parsed[1:] ]):
                    # more than one argument is annotated. we don't support it.
                    raise ValueError()

                return True, first_offset - sum([ offset for _, offset in parsed[1:] ])
            else:
                anno = next(iter(anno for anno in addr.annotations if isinstance(anno, StackLocationAnnotation)), None)
                if anno is None:
                    if addr.op == 'BVV':
                        return False, addr._model_concrete.value
                    raise ValueError()
                return True, anno.offset

        # find the annotated AST
        try: annotated, offset = _parse(addr)
        except ValueError: return None

        if not annotated:
            return None

        return self._to_signed(offset)


class VariableRecovery(ForwardAnalysis, Analysis):  #pylint:disable=abstract-method
    """
    Recover "variables" from a function using forced execution.

    While variables play a very important role in programming, it does not really exist after compiling. However, we can
    still identify and recovery their counterparts in binaries. It is worth noting that not every variable in source
    code can be identified in binaries, and not every recognized variable in binaries have a corresponding variable in
    the original source code. In short, there is no guarantee that the variables we identified/recognized in a binary
    are the same variables in its source code.

    This analysis uses heuristics to identify and recovers the following types of variables:
    - Register variables.
    - Stack variables.
    - Heap variables.
    - Global variables.

    This analysis takes a function as input, and performs a data-flow analysis on nodes. It runs concrete execution on
    every statement and hooks all register/memory accesses to discover all places that are accessing variables. It is
    slow, but has a more accurate analysis result. For a fast but inaccurate variable recovery, you may consider using
    VariableRecoveryFast.

    This analysis follows SSA, which means every write creates a new variable in registers or memory (statck, heap,
    etc.). Things may get tricky when overlapping variable (in memory, as you cannot really have overlapping accesses
    to registers) accesses exist, and in such cases, a new variable will be created, and this new variable will overlap
    with one or more existing varaibles. A decision procedure (which is pretty much TODO) is required at the end of this
    analysis to resolve the conflicts between overlapping variables.
    """

    def __init__(self, func, max_iterations=20):
        """

        :param knowledge.Function func:  The function to analyze.
        """

        function_graph_visitor = FunctionGraphVisitor(func)

        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=function_graph_visitor)

        self.function = func
        self._node_to_state = { }

        self.variable_manager = self.kb.variables

        self._max_iterations = max_iterations
        self._node_iterations = defaultdict(int)

        self._analyze()

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _pre_job_handling(self, job):
        pass

    def _initial_abstract_state(self, node):

        concrete_state = self.project.factory.blank_state(
            addr=node.addr,
            mode='fastpath'  # we don't want to do any solving
        )

        # annotate the stack pointer
        concrete_state.regs.sp = concrete_state.regs.sp.annotate(StackLocationAnnotation(8))

        # give it enough stack space
        concrete_state.regs.bp = concrete_state.regs.sp + 0x100000

        return VariableRecoveryState(self.variable_manager, self.project.arch, self.function.addr, [ concrete_state ])

    def _merge_states(self, node, *states):

        if len(states) == 1:
            return states[0]

        return reduce(lambda s_0, s_1: s_0.merge(s_1), states[1:], states[0])

    def _run_on_node(self, node, state):
        """


        :param angr.Block node:
        :param VariableRecoveryState state:
        :return:
        """

        l.debug('Analyzing block %#x, iteration %d.', node.addr, self._node_iterations[node])

        concrete_state = state.get_concrete_state(node.addr)

        if concrete_state is None:
            # didn't find any state going to here
            l.error("_run_on_node(): cannot find any state for address %#x.", node.addr)
            return False, state

        state = state.copy()

        if self._node_iterations[node] >= self._max_iterations:
            l.debug('Skip node %s as we have iterated %d times on it.', node, self._node_iterations[node])
            return False, state

        state.register_callbacks([ concrete_state ])

        successors = self.project.factory.successors(concrete_state,
                                                     addr=node.addr,
                                                     size=node.size,
                                                     opt_level=0  # disable the optimization in order to have
                                                                  # instruction-level analysis results
                                                     )
        output_states = successors.all_successors

        state.concrete_states = [ state for state in output_states if not state.ip.symbolic ]

        self._node_to_state[node.addr] = state

        self._node_iterations[node] += 1

        return True, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        # TODO: only re-assign variable names to those that are newly changed
        self.variable_manager.initialize_variable_names()

        for addr, state in self._node_to_state.items():
            self.variable_manager[self.function.addr].set_live_variables(addr,
                                                                         state.register_region,
                                                                         state.stack_region
                                                                         )


from angr.analyses import AnalysesHub
AnalysesHub.register_default('VariableRecovery', VariableRecovery)
