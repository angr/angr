
import logging

import pyvex

from ..knowledge_plugins import Function
from ..block import BlockNode
from .analysis import Analysis
from .forward_analysis import ForwardAnalysis, FunctionGraphVisitor


_l = logging.getLogger(name=__name__)


class StackPointerState:

    __slots__ = ['block_addr', 'sp_offset_in', 'sp_offset_out']

    def __init__(self, block_addr : int, sp_offset_in : int=0, sp_offset_out : int=0):
        self.block_addr = block_addr
        self.sp_offset_in = sp_offset_in
        self.sp_offset_out = sp_offset_out

    def __eq__(self, other):
        return isinstance(other, StackPointerState) and \
            self.block_addr == other.block_addr and \
            self.sp_offset_in == other.sp_offset_in and \
            self.sp_offset_out == other.sp_offset_out

    def copy(self):
        return StackPointerState(self.block_addr, self.sp_offset_in, self.sp_offset_out)


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
            _l.warning("The provided function is not normalized. It will be normalized now.")
            func = func.copy()
            func.normalize()

        self._func = func
        self._states = { }
        self._insn_to_sp_offset = { }

        self._analyze()

    def sp_offset_out(self, block_addr):
        if block_addr not in self._states:
            return None
        return self._states[block_addr].sp_offset_out

    def sp_offset_in(self, block_addr):
        if block_addr not in self._states:
            return None
        return self._states[block_addr].sp_offset_in

    def insn_sp_offset_out(self, insn_addr):
        if insn_addr not in self._insn_to_sp_offset:
            return None
        return self._insn_to_sp_offset[insn_addr]

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
        state = StackPointerState(node.addr, sp_offset_in=state.sp_offset_out, sp_offset_out=0)

        tmps = { }
        sp = state.sp_offset_in
        ins_addr = None

        for stmt in block.vex.statements:
            if type(stmt) is pyvex.IRStmt.IMark:
                ins_addr = stmt.addr + stmt.delta
            elif type(stmt) is pyvex.IRStmt.WrTmp:
                if type(stmt.data) is pyvex.IRExpr.Get and stmt.data.offset == sp_offset:
                    # writing to tmp
                    tmps[stmt.tmp] = sp
                elif type(stmt.data) is pyvex.IRExpr.Binop:
                    arg0, arg1 = stmt.data.args
                    if type(arg0) is pyvex.IRExpr.RdTmp and arg0.tmp in tmps and \
                            type(arg1) is pyvex.IRExpr.Const:
                        if stmt.data.op.startswith('Iop_Add'):
                            tmps[stmt.tmp] = tmps[arg0.tmp] + arg1.con.value
                        elif stmt.data.op.startswith('Iop_Sub'):
                            tmps[stmt.tmp] = tmps[arg0.tmp] - arg1.con.value
            elif type(stmt) is pyvex.IRStmt.Put and stmt.offset == sp_offset:
                if type(stmt.data) is pyvex.IRExpr.RdTmp and stmt.data.tmp in tmps:
                    sp = tmps[stmt.data.tmp]
                    if ins_addr not in self._insn_to_sp_offset:
                        self._insn_to_sp_offset[ins_addr] = sp
                    elif sp != self._insn_to_sp_offset[ins_addr]:
                        _l.warning("Inconsistent stack pointers (original=%#x, new%#x) at instruction %#x.",
                                   self._insn_to_sp_offset[ins_addr],
                                   sp,
                                   ins_addr
                                   )
                        # do not update it. instead, abort
                        self.abort()

        state.sp_offset_out = sp

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
