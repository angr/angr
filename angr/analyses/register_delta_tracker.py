
# pylint:disable=abstract-method

import logging

import pyvex

from ..knowledge_plugins import Function
from ..block import BlockNode
from .analysis import Analysis
from .forward_analysis import ForwardAnalysis, FunctionGraphVisitor


_l = logging.getLogger(name=__name__)


class RegisterDeltaTracker(Analysis, ForwardAnalysis):
    """
    Track the offset of stack pointer at the end of each basic block of a function.
    """

    def __init__(self, func : Function, regOffset : int):

        super().__init__(
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
        self.regOffset = regOffset
        self.states = { }
        self.inconsistent = False

        self._analyze()

    def _offset_for(self, addr, pre_or_post):
        if addr not in self.states:
            return None

        addr_map = self.states[addr]
        if pre_or_post not in addr_map:
            return None

        return addr_map[pre_or_post]

    def offset_after(self, addr):
        return self._offset_for(addr, 'post')

    def offset_before(self, addr):
        return self._offset_for(addr, 'pre')


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
        return 0

    def _set_state(self, addr, new_val, pre_or_post):
        previous_val = self._offset_for(addr, pre_or_post)
        does_change = previous_val is not None and previous_val != new_val
        if previous_val is not None and previous_val != new_val:
            self.inconsistent = True
            _l.warning("Inconsistent stack pointers (original=%#x, new%#x) at instruction %#x.",
                       previous_val,
                       new_val,
                       addr
                       )
            self.abort()
        if addr not in self.states:
            self.states[addr] = { }
        self.states[addr][pre_or_post] = new_val
        return does_change

    def _set_post_state(self, addr, new_val):
        return self._set_state(addr, new_val, 'post')

    def _set_pre_state(self, addr, new_val):
        return self._set_state(addr, new_val, 'pre')

    def _run_on_node(self, node : BlockNode, state):
        input_state = state

        block = self.project.factory.block(node.addr, size=node.size)

        tmps = { }
        deltaVal = input_state
        curr_stmt_start_addr = None

        didChange = False

        for stmt in block.vex.statements:
            if type(stmt) is pyvex.IRStmt.IMark:
                if curr_stmt_start_addr is not None:
                    # we've reached a new instruction. Time to store the post state
                    didChange |= self._set_post_state(curr_stmt_start_addr, deltaVal)
                curr_stmt_start_addr = stmt.addr
                didChange |= self._set_pre_state(curr_stmt_start_addr, deltaVal)

            elif type(stmt) is pyvex.IRStmt.WrTmp:
                if type(stmt.data) is pyvex.IRExpr.Get:
                    if stmt.data.offset == self.regOffset:
                        tmps[stmt.tmp] = deltaVal

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
                if stmt.offset == self.regOffset:
                    if type(stmt.data) is pyvex.IRExpr.RdTmp and stmt.data.tmp in tmps:
                        deltaVal = tmps[stmt.data.tmp]

        # stack pointer adjustment
        if self.regOffset == self.project.arch.sp_offset \
                and block.vex.jumpkind == 'Ijk_Call' \
                and self.project.arch.call_pushes_ret:
            deltaVal += self.project.arch.bytes

        if curr_stmt_start_addr is not None:
            didChange |= self._set_post_state(curr_stmt_start_addr, deltaVal)

        return didChange, deltaVal

    def _merge_states(self, node, *states):

        assert len(states) == 2
        if states[0] == states[1]:
            return states[0]

        # umm... this is pretty bad, but this should be rare, too
        _l.warning("Inconsistent stack pointers (%#x, %#x) at block %#x.",
                   states[0].sp_offset_out,
                   states[1].sp_offset_out,
                   node.addr
                   )

        # We... abort
        self.abort()
        # return the first one. It's aborting anyway.
        return states[0]


from ..analyses import AnalysesHub
AnalysesHub.register_default('RegisterDeltaTracker', RegisterDeltaTracker)
