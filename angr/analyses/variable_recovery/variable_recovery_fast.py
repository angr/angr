
import logging
from collections import defaultdict

import pyvex
from simuvex.s_variable import SimStackVariable, SimRegisterVariable

from ...knowledge.keyed_region import KeyedRegion
from ..code_location import CodeLocation
from ..forward_analysis import ForwardAnalysis, FunctionGraphVisitor
from ...analysis import Analysis, register_analysis

l = logging.getLogger('angr.analyses.variable_recovery_fast')


class RegAndOffset(object):
    def __init__(self, bits, reg, offset):
        self._bits = bits
        self.reg = reg
        self.offset = offset

    def __repr__(self):
        return "%s%s" % (self.reg, '' if self.offset == 0 else '%+x' % self.offset)

    def __add__(self, other):
        if type(other) in (int, long):
            return RegAndOffset(self._bits, self.reg, self._to_signed(self.offset + other))
        raise TypeError()

    def __sub__(self, other):
        if type(other) in (int, long):
            return RegAndOffset(self._bits, self.reg, self._to_signed(self.offset - other))
        raise TypeError()

    def _to_signed(self, n):
        if n >= 2 ** (self._bits - 1):
            return n - 2 ** self._bits
        return n


class SpAndOffset(RegAndOffset):
    def __init__(self, bits, offset, is_base=False):
        super(SpAndOffset, self).__init__(bits, 'sp', offset)
        self.is_base = is_base

    def __repr__(self):
        return "%s%s" % ('BP' if self.is_base else 'SP', '' if self.offset == 0 else '%+x' % self.offset)

    def __add__(self, other):
        if type(other) in (int, long):
            return SpAndOffset(self._bits, self._to_signed(self.offset + other))
        raise TypeError()

    def __sub__(self, other):
        if type(other) in (int, long):
            return SpAndOffset(self._bits, self._to_signed(self.offset - other))
        raise TypeError()


class ProcessorState(object):

    __slots__ = ['_arch', 'sp_adjusted', 'sp_adjustment', 'bp_as_base', 'bp']

    def __init__(self, arch):
        self._arch = arch
        # whether we have met the initial stack pointer adjustment
        self.sp_adjusted = None
        # how many bytes are subtracted from the stack pointer
        self.sp_adjustment = arch.bits / 8 if arch.call_pushes_ret else 0
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
        # FIXME: none of the following logic makes any sense...
        if other.sp_adjusted is True:
            self.sp_adjusted = True
        self.sp_adjustment = max(self.sp_adjustment, other.sp_adjustment)
        if other.bp_as_base is True:
            self.bp_as_base = True
        self.bp = max(self.bp, other.bp)
        return self


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

            self.stmt_idx = stmt_idx
            if type(stmt) is pyvex.IRStmt.IMark:
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
        codeloc = CodeLocation(self.block.addr, self.stmt_idx, ins_addr=self.ins_addr)

        if offset == self.arch.sp_offset:
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

        # handle register writes
        data = self._expr(stmt.data)
        if type(data) is SpAndOffset:
            # lea
            stack_offset = data.offset
            existing_vars = self.variable_manager[self.func_addr].find_variables_by_stmt(self.block.addr, self.stmt_idx,
                                                                                         'memory')

            if not existing_vars:
                # TODO: how to determine the size for a lea?
                existing_vars = self.state.stack_region.get_variables_by_offset(stack_offset)
                if not existing_vars:
                    size = 1
                    variable = SimStackVariable(stack_offset, size, base='bp',
                                                ident=self.variable_manager[self.func_addr].next_variable_ident('stack'),
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
            reg_size = stmt.data.result_size(self.tyenv) / 8
            variable = SimRegisterVariable(offset, reg_size,
                                           ident=self.variable_manager[self.func_addr].next_variable_ident('register'),
                                           region=self.func_addr
                                           )
            self.variable_manager[self.func_addr].add_variable('register', offset, variable)
        else:
            variable, _ = existing_vars[0]

        self.state.register_region.set_variable(offset, variable)
        self.variable_manager[self.func_addr].write_to(variable, 0, codeloc)


    def _handle_Store(self, stmt):
        addr = self._expr(stmt.addr)

        if type(addr) is SpAndOffset:
            # Storing data to stack
            size = stmt.data.result_size(self.tyenv) / 8
            stack_offset = addr.offset

            existing_vars = self.variable_manager[self.func_addr].find_variables_by_stmt(self.block.addr, self.stmt_idx,
                                                                                         'memory')
            if not existing_vars:
                variable = SimStackVariable(stack_offset, size, base='bp',
                                            ident=self.variable_manager[self.func_addr].next_variable_ident('stack'),
                                            region=self.func_addr,
                                            )
                self.variable_manager[self.func_addr].add_variable('stack', stack_offset, variable)
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
        reg_offset = expr.offset
        reg_size = expr.result_size(self.tyenv) / 8
        codeloc = CodeLocation(self.block.addr, self.stmt_idx, ins_addr=self.ins_addr)

        if reg_offset == self.arch.sp_offset:
            # loading from stack pointer
            return SpAndOffset(self.arch.bits, self.processor_state.sp_adjustment, is_base=False)
        elif reg_offset == self.arch.bp_offset:
            return self.processor_state.bp

        if reg_offset not in self.state.register_region:
            variable = SimRegisterVariable(reg_offset, reg_size,
                                           ident=self.variable_manager[self.func_addr].next_variable_ident('register'),
                                           region=self.func_addr,
                                           )
            self.state.register_region.add_variable(reg_offset, variable)
            self.variable_manager[self.func_addr].add_variable('register', reg_offset, variable)

        for var in self.state.register_region.get_variables_by_offset(reg_offset):
            self.variable_manager[self.func_addr].read_from(var, 0, codeloc)

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

            all_vars = self.state.stack_region.get_variables_by_offset(base_offset)
            assert len(all_vars) == 1  # we enabled phi nodes

            var = next(iter(all_vars))
            self.variable_manager[self.func_addr].read_from(var,
                                                            stack_offset - base_offset,
                                                            codeloc,
                                                            # overwrite=True
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

    def _handle_Const(self, arg):  #pylint:disable=no-self-use
        return arg.con.value


class VariableRecoveryFastState(object):
    """
    The abstract state of variable recovery analysis.
    """

    def __init__(self, variable_manager, arch, func, stack_region=None, register_region=None, processor_state=None,
                 make_phi=None):
        self.variable_manager = variable_manager
        self.arch = arch
        self.function = func
        self._make_phi = make_phi

        if stack_region is not None:
            self.stack_region = stack_region
        else:
            self.stack_region = KeyedRegion()
        if register_region is not None:
            self.register_region = register_region
        else:
            self.register_region = KeyedRegion()

        self.processor_state = ProcessorState(self.arch) if processor_state is None else processor_state

    def __repr__(self):
        return "<VRAbstractState: %d register variables, %d stack variables>" % (len(self.register_region), len(self.stack_region))

    def __eq__(self, other):
        if type(other) is not VariableRecoveryFastState:
            return False

        return self.stack_region == other.stack_region and self.register_region == other.register_region

    def copy(self):

        state = VariableRecoveryFastState(
            self.variable_manager,
            self.arch,
            self.function,
            stack_region=self.stack_region.copy(),
            register_region=self.register_region.copy(),
            processor_state=self.processor_state.copy(),
            make_phi=self._make_phi,
        )

        return state

    def merge(self, other, successor=None):
        """
        Merge two abstract states.

        :param VariableRecoveryState other: The other abstract state to merge.
        :return:                            The merged abstract state.
        :rtype:                             VariableRecoveryState
        """

        def _make_phi(*variables):
            return self._make_phi(successor, *variables)

        merged_stack_region = self.stack_region.copy().merge(other.stack_region, make_phi_func=_make_phi)
        merged_register_region = self.register_region.copy().merge(other.register_region, make_phi_func=_make_phi)

        state = VariableRecoveryFastState(
            self.variable_manager,
            self.arch,
            self.function,
            stack_region=merged_stack_region,
            register_region=merged_register_region,
            processor_state=self.processor_state.copy().merge(other.processor_state),
            make_phi=self._make_phi,
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


class VariableRecoveryFast(ForwardAnalysis, Analysis):  #pylint:disable=abstract-method
    """
    Recover "variables" from a function by keeping track of stack pointer offsets and  pattern matching VEX statements.
    """

    def __init__(self, func, max_iterations=3):
        """

        :param knowledge.Function func:  The function to analyze.
        """

        function_graph_visitor = FunctionGraphVisitor(func)

        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=function_graph_visitor)

        self.function = func
        self._node_to_state = { }
        self._node_to_input_state = { }

        self.variable_manager = self.kb.variables

        self._max_iterations = max_iterations
        self._node_iterations = defaultdict(int)

        # phi nodes dict
        self._cached_phi_nodes = { }

        self._analyze()

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _pre_job_handling(self, job):
        pass

    def _initial_abstract_state(self, node):

        # annotate the stack pointer
        # concrete_state.regs.sp = concrete_state.regs.sp.annotate(StackLocationAnnotation(8))

        # give it enough stack space
        # concrete_state.regs.bp = concrete_state.regs.sp + 0x100000

        return VariableRecoveryFastState(self.variable_manager, self.project.arch, self.function,
                                         make_phi=self._make_phi_node
                                         )

    def _merge_states(self, node, *states):

        return states[0].merge(states[1], successor=node.addr)

    def _run_on_node(self, node, state):
        """


        :param angr.Block node:
        :param VariableRecoveryState state:
        :return:
        """

        input_state = state  # make it more meaningful

        block = self.project.factory.block(node.addr, node.size, opt_level=0)

        if node.addr in self._node_to_input_state:
            prev_state = self._node_to_input_state[node.addr]
            #if node.addr == 0x804824f:
            #    print "###\n### STACK\n###"
            #    print input_state.stack_region.dbg_repr()
            #    print ""
            #    print prev_state.stack_region.dbg_repr()
            #    print "###\nREGISTER\n###"
            #    print input_state.register_region.dbg_repr()
            #    print ""
            #    print prev_state.register_region.dbg_repr()
            #    # import ipdb; ipdb.set_trace()
            if input_state == prev_state:
                l.debug('Skip node %#x as we have reached a fixed-point', node.addr)
                return False, input_state
            else:
                l.debug('Merging input state of node %#x with the previous state.', node.addr)
                input_state = prev_state.merge(input_state, successor=node.addr)

        state = input_state.copy()
        self._node_to_input_state[node.addr] = input_state

        if self._node_iterations[node.addr] >= self._max_iterations:
            l.debug('Skip node %#x as we have iterated %d times on it.', node.addr, self._node_iterations[node.addr])
            return False, state

        self._process_block(state, block)

        self._node_to_state[node.addr] = state

        self._node_iterations[node.addr] += 1

        return True, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        self.variable_manager.initialize_variable_names()

        for addr, state in self._node_to_state.iteritems():
            self.variable_manager[self.function.addr].set_live_variables(addr,
                                                                         state.register_region,
                                                                         state.stack_region
                                                                         )

    #
    # Private methods
    #

    def _process_block(self, state, block):  #pylint:disable=no-self-use
        """
        Scan through all statements and perform the following tasks:
        - Find stack pointers and the VEX temporary variable storing stack pointers
        - Selectively calculate VEX statements
        - Track memory loading and mark stack and global variables accordingly

        :param angr.Block block:
        :return:
        """

        l.debug('Processing block %#x.', block.addr)

        processor = BlockProcessor(state, block)
        processor.process()

    def _make_phi_node(self, block_addr, *variables):

        key = tuple(sorted(variables, key=lambda v: v.ident))

        if block_addr not in self._cached_phi_nodes:
            self._cached_phi_nodes[block_addr] = { }

        if key in self._cached_phi_nodes[block_addr]:
            return self._cached_phi_nodes[block_addr][key]

        phi_node = self.variable_manager[self.function.addr].make_phi_node(*variables)
        self._cached_phi_nodes[block_addr][key] = phi_node
        return phi_node


register_analysis(VariableRecoveryFast, 'VariableRecoveryFast')
