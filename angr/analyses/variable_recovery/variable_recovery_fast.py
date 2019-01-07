
import logging
from collections import defaultdict

import ailment

from ...engines.light import SpOffset, SimEngineLightVEX, SimEngineLightAIL
from ...errors import SimEngineError
from ...knowledge_plugins import Function
from ...sim_variable import SimStackVariable, SimRegisterVariable
from ..calling_convention import CallingConventionAnalysis
from ..code_location import CodeLocation
from ..forward_analysis import ForwardAnalysis, FunctionGraphVisitor
from .variable_recovery_base import VariableRecoveryBase, VariableRecoveryStateBase

l = logging.getLogger(name=__name__)


class ProcessorState:

    __slots__ = ['_arch', 'sp_adjusted', 'sp_adjustment', 'bp_as_base', 'bp']

    def __init__(self, arch):
        self._arch = arch
        # whether we have met the initial stack pointer adjustment
        self.sp_adjusted = None
        # how many bytes are subtracted from the stack pointer
        self.sp_adjustment = arch.bytes if arch.call_pushes_ret else 0
        # whether the base pointer is used as the stack base of the stack frame or not
        self.bp_as_base = None
        # content of the base pointer
        self.bp = None

    def copy(self):
        s = ProcessorState(self._arch)
        s.sp_adjusted = self.sp_adjusted
        s.sp_adjustment = self.sp_adjustment
        s.bp_as_base = self.bp_as_base
        s.bp = self.bp
        return s

    def merge(self, other):
        if not self == other:
            l.warning("Inconsistent merge: %s %s ", self, other)

        # FIXME: none of the following logic makes any sense...
        if other.sp_adjusted is True:
            self.sp_adjusted = True
        self.sp_adjustment = max(self.sp_adjustment, other.sp_adjustment)
        if other.bp_as_base is True:
            self.bp_as_base = True
        if self.bp is None:
            self.bp = other.bp
        elif other.bp is not None:  # and self.bp is not None
            self.bp = max(self.bp, other.bp)
        return self

    def __eq__(self, other):
        if not isinstance(other, ProcessorState):
            return False
        return (self.sp_adjusted == other.sp_adjusted and
                self.sp_adjustment == other.sp_adjustment and
                self.bp == other.bp and
                self.bp_as_base == other.bp_as_base)

    def __repr__(self):
        return "<ProcessorState %s%#x%s %s>" % (self.bp, self.sp_adjustment,
            " adjusted" if self.sp_adjusted else "", self.bp_as_base)


def get_engine(base_engine):
    class SimEngineVR(base_engine):
        def __init__(self):
            super(SimEngineVR, self).__init__()

            self.processor_state = None
            self.variable_manager = None

        @property
        def func_addr(self):
            if self.state is None:
                return None
            return self.state.function.addr

        def process(self, state, *args, **kwargs):  # pylint:disable=unused-argument
            # we are using a completely different state. Therefore, we directly call our _process() method before
            # SimEngine becomes flexible enough.
            try:
                self._process(state, None, block=kwargs.pop('block', None))
            except SimEngineError as e:
                if kwargs.pop('fail_fast', False) is True:
                    raise e

        def _process(self, state, successors, block=None, func_addr=None):  # pylint:disable=unused-argument

            self.processor_state = state.processor_state
            self.variable_manager = state.variable_manager

            super(SimEngineVR, self)._process(state, successors, block=block)

        #
        # VEX
        #

        # Statement handlers

        def _handle_Put(self, stmt):
            offset = stmt.offset
            data = self._expr(stmt.data)
            size = stmt.data.result_size(self.tyenv) // 8

            if offset == self.arch.ip_offset:
                return
            self._assign_to_register(offset, data, size)

        def _handle_Store(self, stmt):
            addr = self._expr(stmt.addr)
            size = stmt.data.result_size(self.tyenv) // 8
            data = self._expr(stmt.data)

            self._store(addr, data, size)


        # Expression handlers

        def _handle_Get(self, expr):
            reg_offset = expr.offset
            reg_size = expr.result_size(self.tyenv) // 8

            return self._read_from_register(reg_offset, reg_size)


        def _handle_Load(self, expr):
            addr = self._expr(expr.addr)
            size = expr.result_size(self.tyenv) // 8

            return self._load(addr, size)

        #
        # AIL
        #

        # Statement handlers

        def _ail_handle_Assignment(self, stmt):
            dst_type = type(stmt.dst)

            if dst_type is ailment.Expr.Register:
                offset = stmt.dst.reg_offset
                data = self._expr(stmt.src)
                size = stmt.src.bits // 8

                self._assign_to_register(offset, data, size)

            elif dst_type is ailment.Expr.Tmp:
                # simply write to self.tmps
                data = self._expr(stmt.src)
                if data is None:
                    return

                self.tmps[stmt.dst.tmp_idx] = data

            else:
                l.warning('Unsupported dst type %s.', dst_type)

        def _ail_handle_Store(self, stmt):
            addr = self._expr(stmt.addr)
            data = self._expr(stmt.data)
            size = stmt.data.bits // 8

            self._store(addr, data, size)

        def _ail_handle_Jump(self, stmt):
            pass

        def _ail_handle_ConditionalJump(self, stmt):
            self._expr(stmt.condition)

        def _ail_handle_Call(self, stmt):
            pass

        # Expression handlers

        def _ail_handle_Register(self, expr):
            offset = expr.reg_offset
            size = expr.bits // 8

            return self._read_from_register(offset, size)

        def _ail_handle_Load(self, expr):
            addr = self._expr(expr.addr)
            size = expr.size

            return self._load(addr, size)

        def _ail_handle_BinaryOp(self, expr):
            r = super()._ail_handle_BinaryOp(expr)
            if r is None:
                # Treat it as a normal binaryop expression
                self._expr(expr.operands[0])
                self._expr(expr.operands[1])
            return r

        def _ail_handle_Convert(self, expr):
            return self._expr(expr.operand)

        def _ail_handle_StackBaseOffset(self, expr):
            return SpOffset(self.arch.bits, expr.offset, is_base=False)

        #
        # Logic
        #

        def _assign_to_register(self, offset, data, size):
            """

            :param int offset:
            :param data:
            :param int size:
            :return:
            """

            codeloc = self._codeloc()

            if offset == self.arch.sp_offset:
                if type(data) is SpOffset:
                    sp_offset = data.offset
                    self.processor_state.sp_adjusted = True
                    self.processor_state.sp_adjustment = sp_offset
                    l.debug('Adjusting stack pointer at %#x with offset %+#x.', self.ins_addr, sp_offset)
                return

            if offset == self.arch.bp_offset:
                if data is not None:
                    self.processor_state.bp = data
                else:
                    self.processor_state.bp = None
                return

            # handle register writes
            if type(data) is SpOffset:
                # lea
                stack_offset = data.offset
                existing_vars = self.variable_manager[self.func_addr].find_variables_by_stmt(self.block.addr,
                                                                                             self.stmt_idx,
                                                                                             'memory')

                if not existing_vars:
                    # TODO: how to determine the size for a lea?
                    existing_vars = self.state.stack_region.get_variables_by_offset(stack_offset)
                    if not existing_vars:
                        lea_size = 1
                        variable = SimStackVariable(stack_offset, lea_size, base='bp',
                                                    ident=self.variable_manager[self.func_addr].next_variable_ident(
                                                        'stack'),
                                                    region=self.func_addr,
                                                    )

                        self.variable_manager[self.func_addr].add_variable('stack', stack_offset, variable)
                        l.debug('Identified a new stack variable %s at %#x.', variable, self.ins_addr)
                    else:
                        variable = next(iter(existing_vars))

                else:
                    variable, _ = existing_vars[0]

                self.state.stack_region.add_variable(stack_offset, variable)
                base_offset = self.state.stack_region.get_base_addr(stack_offset)
                for var in self.state.stack_region.get_variables_by_offset(base_offset):
                    self.variable_manager[self.func_addr].reference_at(var, stack_offset - base_offset, codeloc)

            else:
                pass

            # register writes

            existing_vars = self.variable_manager[self.func_addr].find_variables_by_stmt(self.block.addr, self.stmt_idx,
                                                                                         'register'
                                                                                         )
            if not existing_vars:
                variable = SimRegisterVariable(offset, size,
                                               ident=self.variable_manager[self.func_addr].next_variable_ident(
                                                   'register'),
                                               region=self.func_addr
                                               )
                self.variable_manager[self.func_addr].set_variable('register', offset, variable)
            else:
                variable, _ = existing_vars[0]

            self.state.register_region.set_variable(offset, variable)
            self.variable_manager[self.func_addr].write_to(variable, 0, codeloc)

        def _store(self, addr, data, size):  # pylint:disable=unused-argument
            """

            :param addr:
            :param data:
            :param int size:
            :return:
            """

            if type(addr) is SpOffset:
                # Storing data to stack
                stack_offset = addr.offset

                existing_vars = self.variable_manager[self.func_addr].find_variables_by_stmt(self.block.addr, self.stmt_idx,
                                                                                             'memory')
                if not existing_vars:
                    variable = SimStackVariable(stack_offset, size, base='bp',
                                                ident=self.variable_manager[self.func_addr].next_variable_ident('stack'),
                                                region=self.func_addr,
                                                )
                    self.variable_manager[self.func_addr].set_variable('stack', stack_offset, variable)
                    l.debug('Identified a new stack variable %s at %#x.', variable, self.ins_addr)

                else:
                    variable, _ = existing_vars[0]

                self.state.stack_region.set_variable(stack_offset, variable)

                base_offset = self.state.stack_region.get_base_addr(stack_offset)
                codeloc = CodeLocation(self.block.addr, self.stmt_idx, ins_addr=self.ins_addr)
                for var in self.state.stack_region.get_variables_by_offset(stack_offset):
                    self.variable_manager[self.func_addr].write_to(var,
                                                                   stack_offset - base_offset,
                                                                   codeloc
                                                                   )

        def _load(self, addr, size):
            """

            :param addr:
            :param size:
            :return:
            """

            if type(addr) is SpOffset:
                # Loading data from stack
                stack_offset = addr.offset

                if stack_offset not in self.state.stack_region:
                    variable = SimStackVariable(stack_offset, size, base='bp',
                                                ident=self.variable_manager[self.func_addr].next_variable_ident('stack'),
                                                region=self.func_addr,
                                                )
                    self.state.stack_region.add_variable(stack_offset, variable)

                    self.variable_manager[self.func_addr].add_variable('stack', stack_offset, variable)

                    l.debug('Identified a new stack variable %s at %#x.', variable, self.ins_addr)

                base_offset = self.state.stack_region.get_base_addr(stack_offset)

                codeloc = CodeLocation(self.block.addr, self.stmt_idx, ins_addr=self.ins_addr)

                all_vars = self.state.stack_region.get_variables_by_offset(base_offset)

                if len(all_vars) > 1:
                    # overlapping variables
                    l.warning("Reading memory with overlapping variables: %s. Ignoring all but the first one.",
                              all_vars)

                var = next(iter(all_vars))
                self.variable_manager[self.func_addr].read_from(var,
                                                                stack_offset - base_offset,
                                                                codeloc,
                                                                # overwrite=True
                                                                )


        def _read_from_register(self, offset, size):
            """

            :param offset:
            :param size:
            :return:
            """

            codeloc = self._codeloc()

            if offset == self.arch.sp_offset:
                # loading from stack pointer
                return SpOffset(self.arch.bits, self.processor_state.sp_adjustment, is_base=False)
            elif offset == self.arch.bp_offset:
                return self.processor_state.bp

            if offset not in self.state.register_region:
                variable = SimRegisterVariable(offset, size,
                                               ident=self.variable_manager[self.func_addr].next_variable_ident('register'),
                                               region=self.func_addr,
                                               )
                self.state.register_region.add_variable(offset, variable)
                self.variable_manager[self.func_addr].add_variable('register', offset, variable)

            for var in self.state.register_region.get_variables_by_offset(offset):
                self.variable_manager[self.func_addr].read_from(var, 0, codeloc)

            return None


    return SimEngineVR


class VariableRecoveryFastState(VariableRecoveryStateBase):
    """
    The abstract state of variable recovery analysis.

    :ivar KeyedRegion stack_region: The stack store.
    :ivar KeyedRegion register_region:  The register store.
    """

    def __init__(self, block_addr, analysis, arch, func, stack_region=None, register_region=None,
                 processor_state=None):

        super().__init__(block_addr, analysis, arch, func, stack_region=stack_region, register_region=register_region)

        self.processor_state = ProcessorState(self.arch) if processor_state is None else processor_state

    def __repr__(self):
        return "<VRAbstractState: %d register variables, %d stack variables>" % (len(self.register_region), len(self.stack_region))

    def __eq__(self, other):
        if type(other) is not VariableRecoveryFastState:
            return False
        return self.stack_region == other.stack_region and self.register_region == other.register_region

    def copy(self):

        state = VariableRecoveryFastState(
            self.block_addr,
            self._analysis,
            self.arch,
            self.function,
            stack_region=self.stack_region.copy(),
            register_region=self.register_region.copy(),
            processor_state=self.processor_state.copy(),
        )

        return state

    def merge(self, other, successor=None):
        """
        Merge two abstract states.

        For any node A whose dominance frontier that the current node (at the current program location) belongs to, we
        create a phi variable V' for each variable V that is defined in A, and then replace all existence of V with V'
        in the merged abstract state.

        :param VariableRecoveryState other: The other abstract state to merge.
        :return:                            The merged abstract state.
        :rtype:                             VariableRecoveryState
        """

        replacements = {}
        if successor in self.dominance_frontiers:
            replacements = self._make_phi_variables(successor, self, other)

        merged_stack_region = self.stack_region.copy().replace(replacements).merge(other.stack_region,
                                                                                   replacements=replacements)
        merged_register_region = self.register_region.copy().replace(replacements).merge(other.register_region,
                                                                                         replacements=replacements)

        state = VariableRecoveryFastState(
            successor,
            self._analysis,
            self.arch,
            self.function,
            stack_region=merged_stack_region,
            register_region=merged_register_region,
            processor_state=self.processor_state.copy().merge(other.processor_state),
        )

        return state

    #
    # Util methods
    #

    def _normalize_register_offset(self, offset):  #pylint:disable=no-self-use

        # TODO:

        return offset

    def _to_signed(self, n):

        if n >= 2 ** (self.arch.bits - 1):
            # convert it to a negative number
            return n - 2 ** self.arch.bits

        return n


class VariableRecoveryFast(ForwardAnalysis, VariableRecoveryBase):  #pylint:disable=abstract-method
    """
    Recover "variables" from a function by keeping track of stack pointer offsets and  pattern matching VEX statements.
    """

    def __init__(self, func, max_iterations=3, clinic=None):
        """

        :param knowledge.Function func:  The function to analyze.
        :param int max_iterations:
        :param clinic:
        """

        function_graph_visitor = FunctionGraphVisitor(func)

        VariableRecoveryBase.__init__(self, func, max_iterations)
        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=function_graph_visitor)

        self._clinic = clinic

        self._ail_engine = get_engine(SimEngineLightAIL)()
        self._vex_engine = get_engine(SimEngineLightVEX)()

        self._node_iterations = defaultdict(int)

        self._node_to_cc = { }

        self._analyze()

    #
    # Main analysis routines
    #

    def _pre_analysis(self):

        self.initialize_dominance_frontiers()

        CallingConventionAnalysis.recover_calling_conventions(self.project)

        # initialize node_to_cc map
        function_nodes = [n for n in self.function.transition_graph.nodes() if isinstance(n, Function)]
        for func_node in function_nodes:
            for callsite_node in self.function.transition_graph.predecessors(func_node):
                self._node_to_cc[callsite_node.addr] = func_node.calling_convention

    def _pre_job_handling(self, job):
        pass

    def _initial_abstract_state(self, node):

        # annotate the stack pointer
        # concrete_state.regs.sp = concrete_state.regs.sp.annotate(StackLocationAnnotation(8))

        # give it enough stack space
        # concrete_state.regs.bp = concrete_state.regs.sp + 0x100000

        state = VariableRecoveryFastState(node.addr, self, self.project.arch, self.function,
                                          )
        # put a return address on the stack if necessary
        if self.project.arch.call_pushes_ret:
            ret_addr_offset = self.project.arch.bytes
            ret_addr_var = SimStackVariable(ret_addr_offset, self.project.arch.bytes, base='bp', name='ret_addr',
                                            region=self.function.addr, category='return_address',
                                            )
            state.stack_region.add_variable(ret_addr_offset, ret_addr_var)

        return state

    def _merge_states(self, node, *states):

        return states[0].merge(states[1], successor=node.addr)

    def _run_on_node(self, node, state):
        """


        :param angr.Block node:
        :param VariableRecoveryState state:
        :return:
        """

        input_state = state  # make it more meaningful

        if self._clinic:
            # AIL mode
            block = self._clinic.block(node.addr, node.size)
        else:
            # VEX mode
            block = self.project.factory.block(node.addr, node.size, opt_level=0)

        if node.addr in self._instates:
            prev_state = self._instates[node.addr]
            if input_state == prev_state:
                l.debug('Skip node %#x as we have reached a fixed-point', node.addr)
                return False, input_state
            else:
                l.debug('Merging input state of node %#x with the previous state.', node.addr)
                input_state = prev_state.merge(input_state, successor=node.addr)

        state = input_state.copy()
        state.block_addr = node.addr
        self._instates[node.addr] = input_state

        if self._node_iterations[node.addr] >= self._max_iterations:
            l.debug('Skip node %#x as we have iterated %d times on it.', node.addr, self._node_iterations[node.addr])
            return False, state

        self._process_block(state, block)

        self._outstates[node.addr] = state

        self._node_iterations[node.addr] += 1

        return True, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        self.variable_manager.initialize_variable_names()

        for addr, state in self._outstates.items():
            self.variable_manager[self.function.addr].set_live_variables(addr,
                                                                         state.register_region,
                                                                         state.stack_region
                                                                         )

    #
    # Private methods
    #

    def _process_block(self, state, block):  # pylint:disable=no-self-use
        """
        Scan through all statements and perform the following tasks:
        - Find stack pointers and the VEX temporary variable storing stack pointers
        - Selectively calculate VEX statements
        - Track memory loading and mark stack and global variables accordingly

        :param angr.Block block:
        :return:
        """

        l.debug('Processing block %#x.', block.addr)

        processor = self._ail_engine if isinstance(block, ailment.Block) else self._vex_engine
        processor.process(state, block=block, fail_fast=self._fail_fast)

        # readjusting sp at the end for blocks that end in a call
        if block.addr in self._node_to_cc:
            cc = self._node_to_cc[block.addr]
            if cc is not None:
                state.processor_state.sp_adjustment += cc.sp_delta
                state.processor_state.sp_adjusted = True
                l.debug('Adjusting stack pointer at end of block %#x with offset %+#x.',
                        block.addr, state.processor_state.sp_adjustment)


from angr.analyses import AnalysesHub
AnalysesHub.register_default('VariableRecoveryFast', VariableRecoveryFast)
