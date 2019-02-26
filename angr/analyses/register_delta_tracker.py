
# pylint:disable=abstract-method

import logging

import pyvex

from ..knowledge_plugins import Function
from ..block import BlockNode
from .analysis import Analysis
from .forward_analysis import ForwardAnalysis, FunctionGraphVisitor


_l = logging.getLogger(name=__name__)

TOP = None


class Constant:

    __slots__ = ( 'val', )

    def __init__(self, val):
        self.val = val

    def __eq__(self, other):
        if type(other) is not type(self):
            return False
        return self.val == other.val

    def __hash__(self):
        return hash((type(self), self.val))

    def __repr__(self):
        return repr(self.val)

    def __add__(self, other):
        if type(self) is type(other):
            return Constant(self.val + other.val)
        else:
            return other + self

    def __sub__(self, other):
        if type(self) is type(other):
            return Constant(self.val + other.val)
        else:
            raise CouldNotResolveException


class OffsetVal:

    __slots__ = ( '_reg', '_offset', )

    def __init__(self, reg, offset):
        self._reg = reg
        self._offset = offset

    @property
    def reg(self):
        return self._reg

    @property
    def offset(self):
        return self._offset

    def __add__(self, other):
        if type(other) is Constant:
            return OffsetVal(self._reg, self._offset + other.val)
        else:
            raise CouldNotResolveException

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        if type(other) is Constant:
            return OffsetVal(self._reg, self._offset - other.val)
        else:
            raise CouldNotResolveException

    def __rsub__(self, other):
        raise CouldNotResolveException

    def __eq__(self, other):
        if type(other) is not type(self):
            return False
        return self.reg == other.reg and self.offset == other.offset

    def __hash__(self):
        return hash((type(self), self._reg, self._offset))

    def __repr__(self):
        return 'reg({})+{}'.format(self.reg, self.offset)

class FrozenRegisterDeltaTrackerState:

    __slots__ = 'regs', 'memory'

    def __init__(self, regs, memory):
        self.regs = regs
        self.memory = memory

    def unfreeze(self):
        return RegisterDeltaTrackerState(dict(self.regs), dict(self.memory))

    def __hash__(self):
        return hash((type(self), self.regs, self.memory))

    def merge(self, other):
        return self.unfreeze().merge(other.unfreeze()).freeze()


class RegisterDeltaTrackerState:

    __slots__ = 'regs', 'memory'

    def __init__(self, regs, memory):
        self.regs = regs
        self.memory = memory

    def store(self, addr, val):
        self.memory[addr] = val

    def load(self, addr):
        try:
            val = self.memory[addr]
            if val is not TOP:
                return val
        except KeyError:
            pass
        raise CouldNotResolveException

    def get(self, reg):
        try:
            val = self.regs[reg]
            if val is not TOP:
                return val
        except KeyError:
            pass
        raise CouldNotResolveException

    def put(self, reg, val):
        if reg in self.regs:
            self.regs[reg] = val

    def copy(self):
        return RegisterDeltaTrackerState(self.regs.copy(), self.memory.copy())

    def freeze(self):
        return FrozenRegisterDeltaTrackerState(list(self.regs.items()), list(self.memory.items()))

    def __eq__(self, other):
        return type(self) == type(other) and \
                self.regs == other.regs and \
                self.memory == other.memory

    def __hash__(self):
        return hash(type(self), (self.regs, self.memory))

    def merge(self, other):
        return RegisterDeltaTrackerState(regs=_dict_merge(self.regs, other.regs),
                                         memory=_dict_merge(self.memory, other.memory))


class MergeException(Exception):
    pass


def _dict_merge(d1, d2):
    all_keys = set(d1.keys()) | set(d2.keys())
    merged = {}
    for k in all_keys:
        if k in d1 and (k not in d2 or d2[k] is None):
            merged[k] = d1[k]
        elif k in d2 and (k not in d1 or d1[k] is None):
            merged[k] = d2[k]
        elif d1[k] == d2[k]:
            merged[k] = d1[k]
        else:
            raise MergeException
    return merged


class CouldNotResolveException(Exception):
    pass


class RegisterDeltaTracker(Analysis, ForwardAnalysis):
    """
    Track the offset of stack pointer at the end of each basic block of a function.
    """

    def __init__(self, func : Function, regOffsets : set):

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
        self.regOffsets = regOffsets
        self.states = { }
        self.inconsistent = False

        self._analyze()

    def _state_for(self, addr, pre_or_post):
        if addr not in self.states:
            return None

        addr_map = self.states[addr]
        if pre_or_post not in addr_map:
            return None

        return addr_map[pre_or_post]

    def _offset_for(self, addr, pre_or_post, reg):
        regval = dict(self._state_for(addr, pre_or_post).regs)[reg]
        if regval is TOP or type(regval) is Constant:
            return TOP
        else:
            return regval.offset


    def offset_after(self, addr, reg):
        return self._offset_for(addr, 'post', reg)

    def offset_before(self, addr, reg):
        return self._offset_for(addr, 'pre', reg)

    def offset_after_block(self, block_addr, reg):
        instr_addrs = self.project.factory.block(block_addr).instruction_addrs
        if len(instr_addrs) == 0:
            return TOP
        else:
            return self.offset_after(instr_addrs[-1], reg)

    def offset_before_block(self, block_addr, reg):
        instr_addrs = self.project.factory.block(block_addr).instruction_addrs
        if len(instr_addrs) == 0:
            return TOP
        else:
            return self.offset_before(instr_addrs[0], reg)

    def inconsistent_for(self, reg):
        for endpoint in self._func.endpoints:
            if self.offset_after_block(endpoint.addr, reg) is TOP:
                return True
        return False

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
        return RegisterDeltaTrackerState(regs={r : OffsetVal(r, 0) for r in self.regOffsets},
                                         memory={}).freeze()

    def _set_state(self, addr, new_val, pre_or_post):
        previous_val = self._state_for(addr, pre_or_post)
        does_change = previous_val is not None and previous_val != new_val
        if does_change:
            self.inconsistent = True
            _l.warning("Inconsistent stack pointers (original=%s, new=%s) at instruction %#x.",
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

        state = state.unfreeze()
        tmps = { }
        curr_stmt_start_addr = None

        def _resolve_expr(expr):
            if type(expr) is pyvex.IRExpr.Binop:
                arg0, arg1 = expr.args
                if expr.op.startswith('Iop_Add'):
                    return _resolve_expr(arg0) + _resolve_expr(arg1)
                elif expr.op.startswith('Iop_Sub'):
                    return _resolve_expr(arg0) - _resolve_expr(arg1)
            elif type(expr) is pyvex.IRExpr.RdTmp and expr.tmp in tmps and tmps[expr.tmp] is not None:
                return tmps[expr.tmp]
            elif type(expr) is pyvex.IRExpr.Const:
                return Constant(expr.con.value)
            elif type(expr) is pyvex.IRExpr.Get:
                return state.get(expr.offset)
            elif type(expr) is pyvex.IRExpr.Load:
                return state.load(_resolve_expr(expr.addr))
            else:
                raise CouldNotResolveException

        def resolve_expr(expr):
            try:
                return _resolve_expr(expr)
            except CouldNotResolveException:
                return TOP

        def resolve_stmt(stmt):
            if type(stmt) is pyvex.IRStmt.WrTmp:
                tmps[stmt.tmp] = resolve_expr(stmt.data)
            elif type(stmt) is pyvex.IRStmt.Store:
                state.store(resolve_expr(stmt.addr), resolve_expr(stmt.data))
            elif type(stmt) is pyvex.IRStmt.Put:
                state.put(stmt.offset, resolve_expr(stmt.data))
            else:
                raise CouldNotResolveException


        for stmt in block.vex.statements:
            if type(stmt) is pyvex.IRStmt.IMark:
                if curr_stmt_start_addr is not None:
                    # we've reached a new instruction. Time to store the post state
                    self._set_post_state(curr_stmt_start_addr, state.freeze())
                curr_stmt_start_addr = stmt.addr
                self._set_pre_state(curr_stmt_start_addr, state.freeze())
            else:
                try:
                    resolve_stmt(stmt)
                except CouldNotResolveException:
                    pass

        # stack pointer adjustment
        if self.project.arch.sp_offset in self.regOffsets \
                and block.vex.jumpkind == 'Ijk_Call' \
                and self.project.arch.call_pushes_ret:
            try:
                incremented = state.get(self.project.arch.sp_offset) + Constant(self.project.arch.bytes)
                state.put(self.project.arch.sp_offset, incremented)
            except CouldNotResolveException:
                pass

        if curr_stmt_start_addr is not None:
            self._set_post_state(curr_stmt_start_addr, state.freeze())

        output_state = state.freeze()
        return output_state != input_state, output_state

    def _merge_states(self, node, *states):

        assert len(states) == 2
        try:
            return states[0].merge(states[1])
        except MergeException:
            _l.warning('Failed to merge stack pointer tracking states')
            self.abort()

        # return the first one. It's aborting anyway.
        return states[0]


from ..analyses import AnalysesHub
AnalysesHub.register_default('RegisterDeltaTracker', RegisterDeltaTracker)
