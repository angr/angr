
# pylint:disable=abstract-method

from collections import defaultdict
import logging

import pyvex

from ..knowledge_plugins import Function
from ..block import BlockNode
from .analysis import Analysis
from .forward_analysis import ForwardAnalysis, FunctionGraphVisitor


_l = logging.getLogger(name=__name__)


LOC_BEFORE = 0
LOC_AFTER = 1


class StackPointerState:

    __slots__ = ('block_addr', 'sp_offset_in', 'sp_offset_out', 'bp_offset_in', 'bp_offset_out', )

    def __init__(self, block_addr : int, sp_offset_in : int=0, sp_offset_out : int=0, bp_offset_in : int=None,
                 bp_offset_out : int=None):
        self.block_addr = block_addr
        self.sp_offset_in = sp_offset_in
        self.sp_offset_out = sp_offset_out
        self.bp_offset_in = bp_offset_in
        self.bp_offset_out = bp_offset_out

    def __eq__(self, other):
        return isinstance(other, StackPointerState) and \
            self.block_addr == other.block_addr and \
            self.sp_offset_in == other.sp_offset_in and \
            self.sp_offset_out == other.sp_offset_out and \
            self.bp_offset_in == other.bp_offset_in and \
            self.bp_offset_out == other.bp_offset_out

    def copy(self):
        return StackPointerState(self.block_addr, sp_offset_in=self.sp_offset_in, sp_offset_out=self.sp_offset_out,
                                 bp_offset_in=self.bp_offset_in, bp_offset_out=self.bp_offset_out)


class StackPointerTracker(Analysis, ForwardAnalysis):
    """
    Track the offset of stack pointer at the end of each basic block of a function.
    """

    def __init__(self, func : Function):

        super(StackPointerTracker, self).__init__(
            order_jobs=False,
            allow_merging=True,
            allow_widening=False,
            graph_visitor=FunctionGraphVisitor(func)
        )

        if not func.normalized:
            # Make a copy before normalizing the function
            func = func.copy()
            func.normalize()

        self._func = func
        self._states = { }
        self._insn_to_sp_offset = defaultdict(dict)
        self._insn_to_bp_offset = defaultdict(dict)
        self.sp_inconsistent = False

        self._analyze()

    def sp_offset_out(self, block_addr):
        if block_addr not in self._states:
            return None
        return self._states[block_addr].sp_offset_out

    def sp_offset_in(self, block_addr):
        if block_addr not in self._states:
            return None
        return self._states[block_addr].sp_offset_in

    def bp_offset_out(self, block_addr):
        if block_addr not in self._states:
            return None
        return self._states[block_addr].bp_offset_out

    def bp_offset_in(self, block_addr):
        if block_addr not in self._states:
            return None
        return self._states[block_addr].bp_offset_in

    def insn_sp_offset_in(self, insn_addr):
        if insn_addr not in self._insn_to_sp_offset:
            return None
        if LOC_BEFORE not in self._insn_to_sp_offset[insn_addr]:
            return None
        return self._insn_to_sp_offset[insn_addr][LOC_BEFORE]

    def insn_sp_offset_out(self, insn_addr):
        if insn_addr not in self._insn_to_sp_offset:
            return None
        if LOC_AFTER not in self._insn_to_sp_offset[insn_addr]:
            return None
        return self._insn_to_sp_offset[insn_addr][LOC_AFTER]

    def insn_bp_offset_in(self, insn_addr):
        if insn_addr not in self._insn_to_bp_offset:
            return None
        if LOC_BEFORE not in self._insn_to_bp_offset[insn_addr]:
            return None
        return self._insn_to_bp_offset[insn_addr][LOC_BEFORE]

    def insn_bp_offset_out(self, insn_addr):
        if insn_addr not in self._insn_to_bp_offset:
            return None
        if LOC_AFTER not in self._insn_to_bp_offset[insn_addr]:
            return None
        return self._insn_to_bp_offset[insn_addr][LOC_AFTER]

    #
    # Overridable methods
    #

    def _pre_analysis(self):
        pass

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass

    def _initial_abstract_state(self, node : BlockNode):
        return StackPointerState(node.addr)

    def _run_on_node(self, node : BlockNode, state : StackPointerState):

        block = self.project.factory.block(node.addr, size=node.size)

        sp_offset = self.project.arch.get_register_offset('sp')
        bp_offset = self.project.arch.get_register_offset('bp')
        state = StackPointerState(node.addr, sp_offset_in=state.sp_offset_out, sp_offset_out=0,
                                  bp_offset_in=state.bp_offset_out, bp_offset_out=0)

        tmps = { }
        sp = state.sp_offset_in
        bp = state.bp_offset_in
        ins_addr = None

        for stmt in block.vex.statements:
            if type(stmt) is pyvex.IRStmt.IMark:
                if ins_addr is not None:
                    self._insn_to_sp_offset[ins_addr][LOC_AFTER] = sp
                    self._insn_to_bp_offset[ins_addr][LOC_AFTER] = bp
                ins_addr = stmt.addr + stmt.delta
                self._insn_to_sp_offset[ins_addr][LOC_BEFORE] = sp
                self._insn_to_bp_offset[ins_addr][LOC_BEFORE] = bp

            elif type(stmt) is pyvex.IRStmt.WrTmp:
                if type(stmt.data) is pyvex.IRExpr.Get:
                    if stmt.data.offset == sp_offset:
                        # writing SP to tmp
                        tmps[stmt.tmp] = sp
                    elif stmt.data.offset == bp_offset:
                        # writing BP to tmp
                        tmps[stmt.tmp] = bp

                elif type(stmt.data) is pyvex.IRExpr.Binop:
                    arg0, arg1 = stmt.data.args
                    if type(arg0) is pyvex.IRExpr.RdTmp and arg0.tmp in tmps and \
                            type(arg1) is pyvex.IRExpr.Const:
                        if stmt.data.op.startswith('Iop_Add') and tmps[arg0.tmp] is not None:
                            tmps[stmt.tmp] = tmps[arg0.tmp] + arg1.con.value
                        elif stmt.data.op.startswith('Iop_Sub') and tmps[arg0.tmp] is not None:
                            tmps[stmt.tmp] = tmps[arg0.tmp] - arg1.con.value
                        elif stmt.data.op.startswith('Iop_And') and tmps[arg0.tmp] is not None:
                            tmps[stmt.tmp] = tmps[arg0.tmp] & arg1.con.value

            elif type(stmt) is pyvex.IRStmt.Put:
                if stmt.offset == sp_offset:
                    if type(stmt.data) is pyvex.IRExpr.RdTmp and stmt.data.tmp in tmps:
                        sp = tmps[stmt.data.tmp]
                        # if ins_addr not in self._insn_to_sp_offset:
                        #    self._insn_to_sp_offset[ins_addr] = sp
                        if ins_addr in self._insn_to_sp_offset and \
                                LOC_AFTER in self._insn_to_sp_offset and \
                                sp != self._insn_to_sp_offset[ins_addr][LOC_AFTER]:
                            _l.warning("Inconsistent stack pointers (original=%#x, new%#x) at instruction %#x.",
                                       self._insn_to_sp_offset[ins_addr],
                                       sp,
                                       ins_addr
                                       )
                            # do not update it. instead, abort
                            self.sp_inconsistent = True
                            self.abort()
                elif stmt.offset == bp_offset:
                    if type(stmt.data) is pyvex.IRExpr.RdTmp and stmt.data.tmp in tmps:
                        bp = tmps[stmt.data.tmp]
                        # if ins_addr not in self._insn_to_sp_offset:
                        #    self._insn_to_sp_offset[ins_addr] = sp
                        if ins_addr in self._insn_to_bp_offset and \
                                LOC_AFTER in self._insn_to_bp_offset and \
                                bp != self._insn_to_bp_offset[ins_addr][LOC_AFTER]:
                            _l.warning("Inconsistent stack base pointers (original=%#x, new%#x) at instruction %#x.",
                                       self._insn_to_bp_offset[ins_addr],
                                       bp,
                                       ins_addr
                                       )
                            # do not update it. instead, abort
                            self.sp_inconsistent = True
                            self.abort()

        # stack pointer adjustment
        if block.vex.jumpkind == 'Ijk_Call' and self.project.arch.call_pushes_ret:
            sp += self.project.arch.bytes

        if ins_addr is not None:
            self._insn_to_sp_offset[ins_addr][LOC_AFTER] = sp
            self._insn_to_bp_offset[ins_addr][LOC_AFTER] = bp

        state.sp_offset_out = sp
        state.bp_offset_out = bp

        if node.addr not in self._states:
            self._states[node.addr] = state
            return True, state
        else:
            return state != self._states[node.addr], state

    def _merge_states(self, node, *states):

        assert len(states) == 2

        if states[0].sp_offset_out == states[1].sp_offset_out:
            return states[0].copy()

        # umm... this is pretty bad, but this should be rare, too
        _l.warning("Inconsistent stack pointers (%#x, %#x) at block %#x.",
                   states[0].sp_offset_out,
                   states[1].sp_offset_out,
                   node.addr
                   )

        # We... abort
        self.abort()
        # return the first one. It's aborting anyway.
        return states[0].copy()


from ..analyses import AnalysesHub
AnalysesHub.register_default('StackPointerTracker', StackPointerTracker)
