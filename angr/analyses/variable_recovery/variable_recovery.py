import logging
from collections import defaultdict
from typing import Tuple

import claripy

from ...errors import SimMemoryMissingError
from ...storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from ... import BP, BP_AFTER
from ...sim_variable import SimRegisterVariable, SimStackVariable
from ...code_location import CodeLocation
from ..forward_analysis import ForwardAnalysis, FunctionGraphVisitor
from .variable_recovery_base import VariableRecoveryBase, VariableRecoveryStateBase
from .annotations import StackLocationAnnotation

l = logging.getLogger(name=__name__)


class VariableRecoveryState(VariableRecoveryStateBase):
    """
    The abstract state of variable recovery analysis.

    :ivar angr.knowledge.variable_manager.VariableManager variable_manager: The variable manager.
    """

    def __init__(self, block_addr, analysis, arch, func, concrete_states, stack_region=None, register_region=None):
        super().__init__(block_addr, analysis, arch, func, stack_region=stack_region, register_region=register_region)

        self._concrete_states = concrete_states
        # register callbacks
        self.register_callbacks(self.concrete_states)

    def __repr__(self):
        return "<VRAbstractState>"

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
        state = VariableRecoveryState(
            self.block_addr,
            self._analysis,
            self.arch,
            self.function,
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
            for bp_type in ("reg_read", "reg_write", "mem_read", "mem_write", "instruction"):
                concrete_state.inspect._breakpoints[bp_type] = []

            concrete_state.inspect.add_breakpoint(
                "reg_read", BP(when=BP_AFTER, enabled=True, action=self._hook_register_read)
            )
            concrete_state.inspect.add_breakpoint("reg_write", BP(enabled=True, action=self._hook_register_write))
            concrete_state.inspect.add_breakpoint(
                "mem_read", BP(when=BP_AFTER, enabled=True, action=self._hook_memory_read)
            )
            concrete_state.inspect.add_breakpoint("mem_write", BP(enabled=True, action=self._hook_memory_write))

    def merge(self, others: Tuple["VariableRecoveryState"], successor=None) -> Tuple["VariableRecoveryState", bool]:
        """
        Merge two abstract states.

        :param others:  Other abstract states to merge.
        :return:        The merged abstract state.
        :rtype:         VariableRecoveryState, and a boolean that indicates if any merge has happened.
        """

        self.phi_variables = {}
        self.successor_block_addr = successor

        merged_concrete_states = [self._concrete_states[0]]  # self._merge_concrete_states(other)

        new_stack_region = self.stack_region.copy()
        new_stack_region.set_state(self)
        merge_occurred = new_stack_region.merge([other.stack_region for other in others], None)

        new_register_region = self.register_region.copy()
        new_register_region.set_state(self)
        merge_occurred |= new_register_region.merge([other.register_region for other in others], None)

        self.phi_variables = {}
        self.successor_block_addr = None

        return (
            VariableRecoveryState(
                successor,
                self._analysis,
                self.arch,
                self.function,
                merged_concrete_states,
                stack_region=new_stack_region,
                register_region=new_register_region,
            ),
            merge_occurred,
        )

    def _merge_concrete_states(self, other):
        """

        :param VariableRecoveryState other:
        :return:
        :rtype:                             list
        """

        merged = []

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
        if isinstance(reg_read_offset, claripy.ast.BV):
            if reg_read_offset.multivalued:
                # Multi-valued register offsets are not supported
                l.warning("Multi-valued register offsets are not supported.")
                return
            reg_read_offset = state.solver.eval(reg_read_offset)
        reg_read_length = state.inspect.reg_read_length
        reg_read_expr = state.inspect.reg_read_expr

        if reg_read_offset == state.arch.sp_offset and reg_read_length == state.arch.bytes:
            # TODO: make sure the sp is not overwritten by something that we are not tracking
            return

        var_offset = reg_read_offset
        try:
            _: MultiValues = self.register_region.load(reg_read_offset, reg_read_length)
        except SimMemoryMissingError:
            # the variable being read doesn't exist before
            variable = SimRegisterVariable(
                reg_read_offset,
                reg_read_length,
                ident=self.variable_manager[self.func_addr].next_variable_ident("register"),
                region=self.func_addr,
            )
            data = self.annotate_with_variables(reg_read_expr, [(0, variable)])
            self.register_region.store(var_offset, data)

            # record this variable in variable manager
            self.variable_manager[self.func_addr].add_variable("register", var_offset, variable)

    def _hook_register_write(self, state):
        reg_write_offset = state.inspect.reg_write_offset
        if isinstance(reg_write_offset, claripy.ast.BV):
            if reg_write_offset.multivalued:
                # Multi-valued register offsets are not supported
                l.warning("Multi-valued register offsets are not supported.")
                return
            reg_write_offset = state.solver.eval(reg_write_offset)

        if reg_write_offset == state.arch.sp_offset:
            # it's updating stack pointer. skip
            return

        reg_write_expr = state.inspect.reg_write_expr
        reg_write_length = len(reg_write_expr) // 8

        # annotate it
        # reg_write_expr = reg_write_expr.annotate(VariableSourceAnnotation.from_state(state))

        state.inspect.reg_write_expr = reg_write_expr

        existing_vars = self.variable_manager[self.func_addr].find_variables_by_stmt(
            state.scratch.bbl_addr, state.scratch.stmt_idx, "register"
        )
        if not existing_vars:
            # create the variable
            variable = SimRegisterVariable(
                reg_write_offset,
                reg_write_length,
                ident=self.variable_manager[self.func_addr].next_variable_ident("register"),
                region=self.func_addr,
            )
            var_offset = reg_write_offset
            data = self.top(reg_write_length * self.arch.byte_width)
            data = self.annotate_with_variables(data, [(0, variable)])
            self.register_region.store(var_offset, data)

            # record this variable in variable manager
            self.variable_manager[self.func_addr].set_variable("register", var_offset, variable)
            self.variable_manager[self.func_addr].write_to(variable, 0, self._codeloc_from_state(state))

        # is it writing a pointer to a stack variable into the register?
        # e.g. lea eax, [ebp-0x40]
        stack_offset = self._addr_to_stack_offset(reg_write_expr)
        if stack_offset is not None:
            # it is!
            # unfortunately we don't know the size. We use size None for now.

            if stack_offset not in self.stack_region:
                lea_size = 1
                new_var = SimStackVariable(
                    stack_offset,
                    lea_size,
                    base="bp",
                    ident=self.variable_manager[self.func_addr].next_variable_ident("stack"),
                    region=self.func_addr,
                )
                reg_write_expr = self.annotate_with_variables(reg_write_expr, [(0, new_var)])
                self.stack_region.store(
                    self.stack_addr_from_offset(stack_offset), reg_write_expr, endness=self.arch.memory_endness
                )

                # record this variable in variable manager
                self.variable_manager[self.func_addr].add_variable("stack", stack_offset, new_var)

            existing_vars = set()
            try:
                vs: MultiValues = self.stack_region.load(self.stack_addr_from_offset(stack_offset), size=1)
                for values in vs.values():
                    for v in values:
                        for offset, var in self.extract_variables(v):
                            existing_vars.add((offset, var))
            except SimMemoryMissingError:
                pass

            for offset, var in existing_vars:
                self.variable_manager[self.func_addr].reference_at(var, offset, self._codeloc_from_state(state))

    def _hook_memory_read(self, state):
        mem_read_address = state.inspect.mem_read_address
        mem_read_expr = state.inspect.mem_read_expr
        mem_read_length = state.inspect.mem_read_length
        endness = state.inspect.mem_read_endness

        stack_offset = self._addr_to_stack_offset(mem_read_address)

        if stack_offset is None:
            # it's not a stack access
            # TODO:
            pass

        else:
            if stack_offset not in self.stack_region:
                # this stack offset is not covered by any existing stack variable
                ident_sort = "argument" if stack_offset > 0 else "stack"
                variable = SimStackVariable(
                    stack_offset,
                    mem_read_length,
                    base="bp",
                    ident=self.variable_manager[self.func_addr].next_variable_ident(ident_sort),
                    region=self.func_addr,
                )
                mem_read_expr = self.annotate_with_variables(mem_read_expr, [(0, variable)])
                self.stack_region.store(self.stack_addr_from_offset(stack_offset), mem_read_expr, endness=endness)

                # record this variable in variable manager
                self.variable_manager[self.func_addr].add_variable("stack", stack_offset, variable)

            # load existing variables
            existing_variables = set()
            try:
                vs: MultiValues = self.stack_region.load(
                    self.stack_addr_from_offset(stack_offset), size=mem_read_length, endness=endness
                )
                for values in vs.values():
                    for v in values:
                        for offset, var in self.extract_variables(v):
                            existing_variables.add((offset, var))
            except SimMemoryMissingError:
                pass

            if len(existing_variables) > 1:
                # create a phi node for all other variables
                l.warning(
                    "Reading memory with overlapping variables: %s. Ignoring all but the first one.", existing_variables
                )

            if existing_variables:
                offset, variable = next(iter(existing_variables))
                self.variable_manager[self.func_addr].read_from(variable, offset, self._codeloc_from_state(state))

    def _hook_memory_write(self, state):
        mem_write_address = state.inspect.mem_write_address
        mem_write_expr = state.inspect.mem_write_expr
        mem_write_length = len(mem_write_expr) // 8
        endness = state.inspect.mem_write_endness

        stack_offset = self._addr_to_stack_offset(mem_write_address)

        if stack_offset is None:
            # it's not a stack access
            # TODO:
            pass

        else:
            # we always add a new variable to keep it SSA
            variable = SimStackVariable(
                stack_offset,
                mem_write_length,
                base="bp",
                ident=self.variable_manager[self.func_addr].next_variable_ident("stack"),
                region=self.func_addr,
            )
            mem_write_expr = self.annotate_with_variables(mem_write_expr, [(0, variable)])
            self.stack_region.store(self.stack_addr_from_offset(stack_offset), mem_write_expr, endness=endness)

            # record this variable in variable manager
            self.variable_manager[self.func_addr].add_variable("stack", stack_offset, variable)
            self.variable_manager[self.func_addr].write_to(variable, 0, self._codeloc_from_state(state))

    #
    # Util methods
    #

    def _normalize_register_offset(self, offset):  # pylint:disable=no-self-use
        # TODO:

        return offset

    @staticmethod
    def _codeloc_from_state(state):
        return CodeLocation(state.scratch.bbl_addr, state.scratch.stmt_idx, ins_addr=state.scratch.ins_addr)

    def _to_signed(self, n):
        if n >= 2 ** (self.arch.bits - 1):
            # convert it to a negative number
            return n - 2**self.arch.bits

        return n

    def _addr_to_stack_offset(self, addr):
        """
        Convert an address to a stack offset.

        :param claripy.ast.Base addr:  The address to convert from.
        :return:                       A stack offset if the addr comes from the stack pointer, or None if the address
                                       does not come from the stack pointer.
        """

        def _parse(addr):
            if addr.op == "__add__":
                # __add__ might have multiple arguments
                parsed = [_parse(arg) for arg in addr.args]
                annotated = [True for annotated, _ in parsed if annotated is True]
                if len(annotated) != 1:
                    # either nothing is annotated, or more than one element is annotated
                    raise ValueError()

                return True, sum(off for _, off in parsed)
            elif addr.op == "__sub__":
                # __sub__ might have multiple arguments

                parsed = [_parse(arg) for arg in addr.args]
                first_annotated, first_offset = parsed[0]
                if first_annotated is False:
                    # the first argument is not annotated. we don't support it.
                    raise ValueError()
                if any(annotated for annotated, _ in parsed[1:]):
                    # more than one argument is annotated. we don't support it.
                    raise ValueError()

                return True, first_offset - sum(off for _, off in parsed[1:])
            else:
                anno = next(iter(anno for anno in addr.annotations if isinstance(anno, StackLocationAnnotation)), None)
                if anno is None:
                    if addr.op == "BVV":
                        return False, addr._model_concrete.value
                    raise ValueError()
                return True, anno.offset

        # find the annotated AST
        try:
            annotated, offset = _parse(addr)
        except ValueError:
            return None

        if not annotated:
            return None

        return self._to_signed(offset)


class VariableRecovery(ForwardAnalysis, VariableRecoveryBase):  # pylint:disable=abstract-method
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
    - Heap variables.  (not implemented yet)
    - Global variables.  (not implemented yet)

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

    def __init__(self, func, max_iterations=20, store_live_variables=False):
        """

        :param knowledge.Function func:  The function to analyze.
        """

        function_graph_visitor = FunctionGraphVisitor(func)

        VariableRecoveryBase.__init__(self, func, max_iterations, store_live_variables)
        ForwardAnalysis.__init__(
            self, order_jobs=True, allow_merging=True, allow_widening=False, graph_visitor=function_graph_visitor
        )

        self._node_iterations = defaultdict(int)

        self._analyze()

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        self.initialize_dominance_frontiers()

    def _pre_job_handling(self, job):
        pass

    def _initial_abstract_state(self, node):
        concrete_state = self.project.factory.blank_state(
            addr=node.addr, mode="fastpath"  # we don't want to do any solving
        )

        # annotate the stack pointer
        concrete_state.regs.sp = concrete_state.regs.sp.annotate(StackLocationAnnotation(8))

        # give it enough stack space
        concrete_state.regs.bp = concrete_state.regs.sp + 0x100000

        return VariableRecoveryState(node.addr, self, self.project.arch, self.function, [concrete_state])

    def _merge_states(self, node, *states: VariableRecoveryState):
        if len(states) == 1:
            return states[0], True

        merged_state, merge_occurred = states[0].merge(states[1:], successor=node.addr)
        return merged_state, not merge_occurred

    def _run_on_node(self, node, state):
        """
        Take an input abstract state, execute the node, and derive an output state.

        :param angr.Block node:             The node to work on.
        :param VariableRecoveryState state: The input state.
        :return:                            A tuple of (changed, new output state).
        :rtype:                             tuple
        """

        l.debug("Analyzing block %#x, iteration %d.", node.addr, self._node_iterations[node])

        concrete_state = state.get_concrete_state(node.addr)

        if concrete_state is None:
            # didn't find any state going to here
            l.error("_run_on_node(): cannot find any state for address %#x.", node.addr)
            return False, state

        state = state.copy()
        self._instates[node.addr] = state

        if self._node_iterations[node] >= self._max_iterations:
            l.debug("Skip node %s as we have iterated %d times on it.", node, self._node_iterations[node])
            return False, state

        state.register_callbacks([concrete_state])

        successors = self.project.factory.successors(
            concrete_state,
            addr=node.addr,
            size=node.size,
            opt_level=1,
            cross_insn_opt=False,
        )
        output_states = successors.all_successors

        state.concrete_states = [state for state in output_states if not state.ip.symbolic]

        self._outstates[node.addr] = state

        self._node_iterations[node] += 1

        return True, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        # TODO: only re-assign variable names to those that are newly changed
        self.variable_manager.initialize_variable_names()

        if self._store_live_variables:
            for addr, state in self._outstates.items():
                self.variable_manager[self.function.addr].set_live_variables(
                    addr,
                    state.downsize_region(state.register_region),
                    state.downsize_region(state.stack_region),
                )


from angr.analyses import AnalysesHub

AnalysesHub.register_default("VariableRecovery", VariableRecovery)
