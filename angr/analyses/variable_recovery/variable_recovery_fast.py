from typing import Optional, List
import logging
from collections import defaultdict

import pyvex
import ailment

from ...block import Block
from ...errors import AngrVariableRecoveryError, SimEngineError
from ...knowledge_plugins import Function
from ...sim_variable import SimStackVariable, SimRegisterVariable, SimVariable
from ...engines.vex.claripy.irop import vexop_to_simop
from ..forward_analysis import ForwardAnalysis, FunctionGraphVisitor
from ..typehoon.typevars import Equivalence, TypeVariable
from .variable_recovery_base import VariableRecoveryBase, VariableRecoveryStateBase
from .engine_vex import SimEngineVRVEX
from .engine_ail import SimEngineVRAIL

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
            if self.bp == other.bp:
                pass
            else:
                if type(self.bp) is int and type(other.bp) is int:
                    self.bp = max(self.bp, other.bp)
                else:
                    self.bp = None
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


class VariableRecoveryFastState(VariableRecoveryStateBase):
    """
    The abstract state of variable recovery analysis.

    :ivar KeyedRegion stack_region: The stack store.
    :ivar KeyedRegion register_region:  The register store.
    """
    def __init__(self, block_addr, analysis, arch, func, stack_region=None, register_region=None,
                 typevars=None, type_constraints=None, delayed_type_constraints=None, processor_state=None):

        super().__init__(block_addr, analysis, arch, func, stack_region=stack_region, register_region=register_region,
                         typevars=typevars, type_constraints=type_constraints,
                         delayed_type_constraints=delayed_type_constraints)

        self.processor_state = ProcessorState(self.arch) if processor_state is None else processor_state

    def __repr__(self):
        return "<VRAbstractState@%#x: %d register variables, %d stack variables>" % (
            self.block_addr, len(self.register_region), len(self.stack_region))

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
            typevars=self.typevars.copy(),
            type_constraints=self.type_constraints.copy(),
            processor_state=self.processor_state.copy(),
            delayed_type_constraints=self.delayed_type_constraints.copy(),
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
        merged_typevars = self.typevars.merge(other.typevars)
        merged_typeconstraints = self.type_constraints.copy() | other.type_constraints
        delayed_typeconstraints = self.delayed_type_constraints.copy()
        for v, cons in other.delayed_type_constraints.items():
            delayed_typeconstraints[v] |= cons
        # add subtype constraints for all replacements
        for v0, v1 in replacements.items():
            # v0 will be replaced by v1
            if not merged_typevars.has_type_variable_for(v1, None):
                merged_typevars.add_type_variable(v1, None, TypeVariable())
            if not merged_typevars.has_type_variable_for(v0, None):
                merged_typevars.add_type_variable(v0, None, TypeVariable())
            # Assuming v2 = phi(v0, v1), then we know that v0_typevar == v1_typevar == v2_typevar
            # However, it's possible that neither v0 nor v1 will ever be used in future blocks, which not only makes
            # this phi function useless, but also leads to the incorrect assumption that v1_typevar == v2_typevar.
            # Hence, we delay the addition of the equivalence relationship into the type constraints. It is only added
            # when v1 (the new variable that will end up in the state) is ever used in the future.

            # create an equivalence relationship
            equivalence = Equivalence(merged_typevars.get_type_variable(v1, None),
                                      merged_typevars.get_type_variable(v0, None)
                                      )
            delayed_typeconstraints[v1].add(equivalence)

        state = VariableRecoveryFastState(
            successor,
            self._analysis,
            self.arch,
            self.function,
            stack_region=merged_stack_region,
            register_region=merged_register_region,
            typevars=merged_typevars,
            type_constraints=merged_typeconstraints,
            delayed_type_constraints=delayed_typeconstraints,
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
    Recover "variables" from a function by keeping track of stack pointer offsets and pattern matching VEX statements.

    If calling conventions are recovered prior to running VariableRecoveryFast, variables can be recognized more
    accurately. However, it is not a requirement.
    """

    def __init__(self, func, func_graph=None, max_iterations=1, low_priority=False, track_sp=True,
                 func_args: Optional[List[SimVariable]]=None):
        """

        :param knowledge.Function func:  The function to analyze.
        :param int max_iterations:
        :param clinic:
        """

        function_graph_visitor = FunctionGraphVisitor(func, graph=func_graph)

        # Make sure the function is not empty
        if not func.block_addrs_set or func.startpoint is None:
            raise AngrVariableRecoveryError("Function %s is empty." % repr(func))

        VariableRecoveryBase.__init__(self, func, max_iterations)
        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=function_graph_visitor)

        self._low_priority = low_priority
        self._job_ctr = 0
        self._track_sp = track_sp
        self._func_args = func_args

        self._ail_engine = SimEngineVRAIL(self.project, self.kb)
        self._vex_engine = SimEngineVRVEX(self.project, self.kb)

        self._node_iterations = defaultdict(int)

        self._node_to_cc = { }
        self.var_to_typevar = { }
        self.type_constraints = None

        self._analyze()

        # cleanup (for cpython pickle)
        self._ail_engine = None
        self._vex_engine = None

    #
    # Main analysis routines
    #

    def _pre_analysis(self):

        self.type_constraints = set()

        self.initialize_dominance_frontiers()

        if self._track_sp:
            # initialize node_to_cc map
            function_nodes = [n for n in self.function.transition_graph.nodes() if isinstance(n, Function)]
            # all nodes that end with a call must be in the _node_to_cc dict
            for func_node in function_nodes:
                for callsite_node in self.function.transition_graph.predecessors(func_node):
                    if func_node.calling_convention is None:
                        l.warning("Unknown calling convention for %r.", func_node)
                        self._node_to_cc[callsite_node.addr] = None
                    else:
                        self._node_to_cc[callsite_node.addr] = func_node.calling_convention

    def _pre_job_handling(self, job):
        self._job_ctr += 1
        if self._low_priority:
            self._release_gil(self._job_ctr, 5, 0.0001)

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

        if self._func_args:
            for arg in self._func_args:
                if isinstance(arg, SimRegisterVariable):
                    state.register_region.set_variable(arg.reg, arg)
                    self.variable_manager[self.function.addr].add_variable('register', arg.reg, arg)
                elif isinstance(arg, SimStackVariable):
                    state.stack_region.set_variable(arg.offset, arg)
                    self.variable_manager[self.function.addr].add_variable('stack', arg.offset, arg)
                else:
                    raise TypeError("Unsupported function argument type %s." % type(arg))

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

        if type(node) is ailment.Block:
            # AIL mode
            block = node
        else:
            # VEX mode, get the block again
            block = self.project.factory.block(node.addr, node.size, opt_level=1, cross_insn_opt=False)

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
        self.type_constraints |= state.type_constraints
        self.var_to_typevar.update(state.typevars._typevars)

        return True, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        self.variable_manager[self.function.addr].assign_variable_names()

        for addr, state in self._outstates.items():
            self.variable_manager[self.function.addr].set_live_variables(addr,
                                                                         state.register_region,
                                                                         state.stack_region
                                                                         )

    #
    # Private methods
    #

    @staticmethod
    def _get_irconst(value, size):
        mapping = {
            1: pyvex.const.U1,
            8: pyvex.const.U8,
            16: pyvex.const.U16,
            32: pyvex.const.U32,
            64: pyvex.const.U64,
            128: pyvex.const.V128,
            256: pyvex.const.V256,
        }
        if size not in mapping:
            raise TypeError("Unsupported size %d." % size)
        return mapping.get(size)(value)

    def _peephole_optimize(self, block: Block):

        # find regN = xor(regN, regN) and replace it with PUT(regN) = 0
        i = 0
        while i < len(block.vex.statements) - 3:
            stmt0 = block.vex.statements[i]
            next_i = i + 1
            if isinstance(stmt0, pyvex.IRStmt.WrTmp) and isinstance(stmt0.data, pyvex.IRStmt.Get):
                stmt1 = block.vex.statements[i + 1]
                if isinstance(stmt1, pyvex.IRStmt.WrTmp) and isinstance(stmt1.data, pyvex.IRStmt.Get):
                    next_i = i + 2
                    if stmt0.data.offset == stmt1.data.offset and stmt0.data.ty == stmt1.data.ty:
                        next_i = i + 3
                        reg_offset = stmt0.data.offset
                        tmp0 = stmt0.tmp
                        tmp1 = stmt1.tmp
                        stmt2 = block.vex.statements[i + 2]
                        if isinstance(stmt2, pyvex.IRStmt.WrTmp) and isinstance(stmt2.data, pyvex.IRExpr.Binop):
                            if isinstance(stmt2.data.args[0], pyvex.IRExpr.RdTmp) \
                                    and isinstance(stmt2.data.args[1], pyvex.IRExpr.RdTmp) \
                                    and {stmt2.data.args[0].tmp, stmt2.data.args[1].tmp} == {tmp0, tmp1}\
                                    and vexop_to_simop(stmt2.data.op)._generic_name == 'Xor':
                                # found it!
                                # make a copy so we don't trash the cached VEX IRSB
                                block._vex = block.vex.copy()
                                block.vex.statements[i] = pyvex.IRStmt.NoOp()
                                block.vex.statements[i + 1] = pyvex.IRStmt.NoOp()
                                zero = pyvex.IRExpr.Const(self._get_irconst(0, block.vex.tyenv.sizeof(tmp0)))
                                block.vex.statements[i + 2] = pyvex.IRStmt.Put(zero, reg_offset)
            i = next_i
        return block

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

        if isinstance(block, Block):
            try:
                _ = block.vex
            except SimEngineError:
                # the block does not exist or lifting failed
                return
            block = self._peephole_optimize(block)

        processor = self._ail_engine if isinstance(block, ailment.Block) else self._vex_engine
        processor.process(state, block=block, fail_fast=self._fail_fast)

        if self._track_sp and block.addr in self._node_to_cc:
            # readjusting sp at the end for blocks that end in a call
            adjusted = False
            if state.processor_state.sp_adjustment is None:
                state.processor_state.sp_adjustment = 0
            cc = self._node_to_cc[block.addr]
            if cc is not None and cc.sp_delta is not None:
                state.processor_state.sp_adjustment += cc.sp_delta
                state.processor_state.sp_adjusted = True
                adjusted = True
                l.debug('Adjusting stack pointer at end of block %#x with offset %+#x.',
                        block.addr, state.processor_state.sp_adjustment)

            if not adjusted:
                # make a guess
                # of course, this will fail miserably if the function called is not cdecl
                if self.project.arch.call_pushes_ret:
                    state.processor_state.sp_adjustment += self.project.arch.bytes
                    state.processor_state.sp_adjusted = True


from angr.analyses import AnalysesHub
AnalysesHub.register_default('VariableRecoveryFast', VariableRecoveryFast)
