
import logging
from collections import defaultdict
from itertools import count

import pyvex
from simuvex.s_variable import SimRegisterVariable, SimStackVariable

from ...analysis import Analysis, register_analysis
from ..forward_analysis import ForwardAnalysis, FunctionGraphVisitor
from ..code_location import CodeLocation
from .keyed_region import KeyedRegion
from .variable_manager import VariableManager


l = logging.getLogger('angr.analyses.variable_recovery_fast')


class RegAndOffset(object):
    def __init__(self, reg, offset):
        self.reg = reg
        self.offset = offset

    def __repr__(self):
        return "%s%s" % (self.reg, '' if self.offset == 0 else '%+x' % self.offset)

    def __add__(self, other):
        if type(other) in (int, long):
            return RegAndOffset(self.reg, self.offset + other)
        raise TypeError()

    def __sub__(self, other):
        if type(other) in (int, long):
            return RegAndOffset(self.reg, self.offset - other)
        raise TypeError()


class SpAndOffset(RegAndOffset):
    def __init__(self, offset, is_base=False):
        super(SpAndOffset, self).__init__('sp', offset)
        self.is_base = is_base

    def __repr__(self):
        return "%s%s" % ('BP' if self.is_base else 'SP', '' if self.offset == 0 else '%+x' % self.offset)

    def __add__(self, other):
        if type(other) in (int, long):
            return SpAndOffset(self.offset + other)
        raise TypeError()

    def __sub__(self, other):
        if type(other) in (int, long):
            return SpAndOffset(self.offset - other)
        raise TypeError()


class ProcessorState(object):

    __slots__ = ['sp_adjusted', 'sp_adjustment', 'bp_as_base', 'bp']

    def __init__(self):
        # whether we have met the initial stack pointer adjustment
        self.sp_adjusted = None
        # how many bytes are subtracted from the stack pointer
        self.sp_adjustment = 0
        # whether the base pointer is used as the stack base of the stack frame or not
        self.bp_as_base = None
        # content of the base pointer
        self.bp = None

    def copy(self):
        s = ProcessorState()
        s.sp_adjusted = self.sp_adjusted
        s.sp_adjustment = self.sp_adjustment
        s.bp_as_base = self.bp_as_base
        s.bp = self.bp
        return s


class BlockProcessor(object):
    def __init__(self, state, block):

        self.state = state
        self.processor_state = state.processor_state
        self.arch = state.arch
        self.func_addr = state.function.addr
        self.variable_manager = state.variable_manager
        self.block = block
        self.vex_block = block.vex
        self.tyenv = self.vex_block.tyenv

        self.stmt_idx = None
        self.ins_addr = None
        self.tmps = { }

    def process(self):

        for stmt_idx, stmt in enumerate(self.vex_block.statements):
            # print stmt.__str__(arch=self.arch, tyenv=self.vex_block.tyenv)

            if type(stmt) is pyvex.IRStmt.IMark:
                self.stmt_idx = stmt_idx
                self.ins_addr = stmt.addr + stmt.delta
                continue

            handler = "_handle_%s" % type(stmt).__name__
            if hasattr(self, handler):
                getattr(self, handler)(stmt)

        #print ""
        #print self.tmps
        #print ""

        self.stmt_idx = None
        self.ins_addr = None

    #
    # Statement handlers
    #

    def _handle_WrTmp(self, stmt):
        data = self._expr(stmt.data)
        if data is None:
            return

        self.tmps[stmt.tmp] = data

    def _handle_Put(self, stmt):
        offset = stmt.offset
        if offset == self.arch.sp_offset:
            if self.processor_state.sp_adjusted is None:
                data = self._expr(stmt.data)
                if type(data) is SpAndOffset:
                    sp_offset = data.offset
                    self.processor_state.sp_adjusted = True
                    self.processor_state.sp_adjustment = sp_offset

                    l.debug('Adjusting stack pointer at %#x with offset %+#x.', self.ins_addr, sp_offset)

            return

        if offset == self.arch.bp_offset:
            data = self._expr(stmt.data)
            if data is not None:
                self.processor_state.bp = data
            else:
                self.processor_state.bp = None
            return

        # handle lea
        data = self._expr(stmt.data)
        if type(data) is SpAndOffset:
            stack_offset = data.offset
            if stack_offset not in self.state.stack_region:
                variable = SimStackVariable(stack_offset, None, base='bp',
                                            ident=self.variable_manager[self.func_addr].next_variable_ident('stack'),
                                            region=self.func_addr,
                                            )
                self.state.stack_region.add_variable(stack_offset, variable)
                self.variable_manager[self.func_addr].add_variable('stack', stack_offset, variable)

                l.debug('Identified a new stack variable %s at %#x.', variable, self.ins_addr)

            base_offset = self.state.stack_region.get_base_addr(stack_offset)
            codeloc = CodeLocation(self.block.addr, self.stmt_idx, ins_addr=self.ins_addr)
            for var in self.state.stack_region.get_variables_by_offset(base_offset):
                self.variable_manager[self.func_addr].reference_at(var, stack_offset - base_offset, codeloc)


    def _handle_Store(self, stmt):
        addr = self._expr(stmt.addr)

        if type(addr) is SpAndOffset:
            # Storing data to stack
            size = stmt.data.result_size(self.tyenv) / 8
            stack_offset = addr.offset
            variable = SimStackVariable(stack_offset, size, base='bp',
                                        ident=self.variable_manager[self.func_addr].next_variable_ident('stack'),
                                        region=self.func_addr,
                                        )

            self.state.stack_region.set_variable(stack_offset, variable)

            self.variable_manager[self.func_addr].add_variable('stack', stack_offset, variable)

            base_offset = self.state.stack_region.get_base_addr(stack_offset)
            codeloc = CodeLocation(self.block.addr, self.stmt_idx, ins_addr=self.ins_addr)
            for var in self.state.stack_region.get_variables_by_offset(stack_offset):
                self.variable_manager[self.func_addr].write_to(var,
                                                               stack_offset - base_offset,
                                                               codeloc
                                                               )

            l.debug('Identified a new stack variable %s at %#x.', variable, self.ins_addr)

    #
    # Expression handlers
    #

    def _expr(self, expr):

        handler = "_handle_%s" % type(expr).__name__
        if hasattr(self, handler):
            return getattr(self, handler)(expr)
        return None

    def _handle_RdTmp(self, expr):
        tmp = expr.tmp

        if tmp in self.tmps:
            return self.tmps[tmp]
        return None

    def _handle_Get(self, expr):
        if expr.offset == self.arch.sp_offset:
            # loading from stack pointer
            return SpAndOffset(self.processor_state.sp_adjustment, is_base=False)
        elif expr.offset == self.arch.bp_offset:
            return self.processor_state.bp

        return None

    def _handle_Load(self, expr):
        addr = self._expr(expr.addr)

        if type(addr) is SpAndOffset:
            # Loading data from stack
            size = expr.result_size(self.tyenv) / 8
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
            for var in self.state.stack_region.get_variables_by_offset(base_offset):
                self.variable_manager[self.func_addr].read_from(var,
                                                                stack_offset - base_offset,
                                                                codeloc
                                                                )

    def _handle_Binop(self, expr):
        if expr.op.startswith('Iop_Add'):
            return self._handle_Add(*expr.args)
        elif expr.op.startswith('Iop_Sub'):
            return self._handle_Sub(*expr.args)
        elif expr.op.startswith('Const'):
            return self._handle_Const(*expr.args)

        return None

    #
    # Binary operation handlers
    #

    def _handle_Add(self, arg0, arg1):
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            return expr_0 + expr_1
        except TypeError:
            return None

    def _handle_Sub(self, arg0, arg1):
        expr_0 = self._expr(arg0)
        if expr_0 is None:
            return None
        expr_1 = self._expr(arg1)
        if expr_1 is None:
            return None

        try:
            return expr_0 - expr_1
        except TypeError:
            return None

    def _handle_Const(self, arg):
        return arg.con.value


class VariableRecoveryFastState(object):
    """
    The abstract state of variable recovery analysis.
    """

    def __init__(self, variable_manager, arch, func, stack_region=None, register_region=None, processor_state=None):
        self.variable_manager = variable_manager
        self.arch = arch
        self.function = func

        if stack_region is not None:
            self.stack_region = stack_region
        else:
            self.stack_region = KeyedRegion()
        if register_region is not None:
            self.register_region = register_region
        else:
            self.register_region = KeyedRegion()

        self.processor_state = ProcessorState() if processor_state is None else processor_state

    def __repr__(self):
        return "<VRAbstractState: %d register variables, %d stack variables>" % (len(self.register_region), len(self.stack_region))

    def copy(self):

        state = VariableRecoveryFastState(
            self.variable_manager,
            self.arch,
            self.function,
            stack_region=self.stack_region.copy(),
            register_region=self.register_region.copy(),
            processor_state=self.processor_state.copy(),
        )

        return state

    def merge(self, other):
        """
        Merge two abstract states.

        :param VariableRecoveryState other: The other abstract state to merge.
        :return:                            The merged abstract state.
        :rtype:                             VariableRecoveryState
        """

        # TODO: finish it

        return VariableRecoveryFastState(self.variable_manager, self.arch, self.function)

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

    def __init__(self, func, max_iterations=1):
        """

        :param knowledge.Function func:  The function to analyze.
        """

        function_graph_visitor = FunctionGraphVisitor(func)

        ForwardAnalysis.__init__(self, order_entries=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=function_graph_visitor)

        self.function = func
        self._node_to_state = { }

        # TODO: load variable manager from KB
        self.variable_manager = VariableManager()

        self._max_iterations = max_iterations
        self._node_iterations = defaultdict(int)

        self._analyze()

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

        return VariableRecoveryFastState(self.variable_manager, self.project.arch, self.function)

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

        state = state.copy()

        if self._node_iterations[node.addr] >= self._max_iterations:
            l.debug('Skip node %#x as we have iterated %d times on it.', node.addr, self._node_iterations[node.addr])
            return False, state

        self._process_block(state, block)

        self._node_to_state[node] = state

        self._node_iterations[node.addr] += 1

        return True, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass

    #
    # Private methods
    #

    def _process_block(self, state, block):
        """
        Scan through all statements and perform the following tasks:
        - Find stack pointers and the VEX temporary variable storing stack pointers
        - Selectively calculate VEX statements
        - Track memory loading and mark stack and global variables accordingly

        :param angr.Block block:
        :return:
        """

        statements = block.vex.statements

        l.debug('Processing block %#x.', block.addr)

        processor = BlockProcessor(state, block)
        processor.process()


register_analysis(VariableRecoveryFast, 'VariableRecoveryFast')
