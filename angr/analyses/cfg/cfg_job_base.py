
import logging

from archinfo.arch_soot import SootAddressDescriptor

from ...errors import SimValueError, SimSolverModeError
from ...state_plugins.callstack import CallStack

l = logging.getLogger(name=__name__)

# TODO: Make callsite an object and use it in BlockID and FunctionKey


class BlockID(object):
    """
    A context-sensitive key for a SimRun object.
    """

    def __init__(self, addr, callsite_tuples, jump_type):
        self.addr = addr
        self.callsite_tuples = callsite_tuples
        self.jump_type = jump_type

        self._hash = None

    def callsite_repr(self):

        if self.callsite_tuples is None:
            return "None"

        s = [ ]
        format_addr = lambda addr: 'None' if addr is None else hex(addr)
        for i in range(0, len(self.callsite_tuples), 2):
            s.append('@'.join(map(format_addr, self.callsite_tuples[i:i+2])))
        return " -> ".join(s)

    def __repr__(self):
        return "<BlockID %#08x (%s) %% %s>" % (self.addr, self.callsite_repr(), self.jump_type)

    def __hash__(self):
        if self._hash is None:
            self._hash = hash((self.callsite_tuples,) + (self.addr, self.jump_type))
        return self._hash

    def __eq__(self, other):
        return isinstance(other, BlockID) and \
               self.addr == other.addr and self.callsite_tuples == other.callsite_tuples and \
               self.jump_type == other.jump_type

    def __ne__(self, other):
        return not self == other

    @staticmethod
    def new(addr, callstack_suffix, jumpkind):
        if jumpkind.startswith('Ijk_Sys') or jumpkind == 'syscall':
            jump_type = 'syscall'
        elif jumpkind in ('Ijk_Exit', 'exit'):
            jump_type = 'exit'
        else:
            jump_type = "normal"
        return BlockID(addr, callstack_suffix, jump_type)

    @property
    def func_addr(self):
        if self.callsite_tuples:
            return self.callsite_tuples[-1]
        return None


class FunctionKey(object):
    """
    A context-sensitive key for a function.
    """

    def __init__(self, addr, callsite_tuples):
        self.addr = addr
        self.callsite_tuples = callsite_tuples

        self._hash = None

    def callsite_repr(self):

        if self.callsite_tuples is None:
            return "None"

        s = []
        format_addr = lambda addr: 'None' if addr is None else hex(addr)
        for i in range(0, len(self.callsite_tuples), 2):
            s.append('@'.join(map(format_addr, self.callsite_tuples[i:i + 2])))
        return " -> ".join(s)

    def __repr__(self):
        s = "<FuncKey %#08x (%s)>" % (self.addr, self.callsite_repr())
        return s

    def __hash__(self):
        if self._hash is None:
            self._hash = hash((self.callsite_tuples, ) + (self.addr, ))
        return self._hash

    def __eq__(self, other):
        return isinstance(other, FunctionKey) and \
                self.addr == other.addr and self.callsite_tuples == other.callsite_tuples

    @staticmethod
    def new(addr, callsite_tuples):
        return FunctionKey(addr, callsite_tuples)


class CFGJobBase(object):
    """
    Describes an entry in CFG or VFG. Only used internally by the analysis.
    """
    def __init__(self, addr, state, context_sensitivity_level, block_id=None, src_block_id=None,
                 src_exit_stmt_idx=None, src_ins_addr=None, jumpkind=None, call_stack=None, is_narrowing=False,
                 skip=False, final_return_address=None):
        self.addr = addr  # Note that addr may not always be equal to self.state.ip (for syscalls, for example)
        self.state = state
        self.jumpkind = jumpkind
        self.src_block_id = src_block_id
        self.src_exit_stmt_idx = src_exit_stmt_idx
        self.src_ins_addr = src_ins_addr
        self.skip = skip
        self._block_id = block_id

        # Other parameters
        self._context_sensitivity_level = context_sensitivity_level
        self.is_narrowing = is_narrowing

        if call_stack is None:
            self._call_stack = CallStack()

            # Added the function address of the current exit to callstack
            se = self.state.solver
            sp_expr = self.state.regs.sp

            # If the sp_expr cannot be concretized, the stack pointer cannot be traced anymore.
            try:
                sp = se.eval_one(sp_expr)
            except (SimValueError, SimSolverModeError):
                l.warning("Stack pointer cannot be concretized. CallStack cannot track the stack pointer changes.")

                # Set the stack pointer to None
                sp = None

            self._call_stack = self._call_stack.call(None, self.addr, retn_target=final_return_address, stack_pointer=sp)

        else:
            self._call_stack = call_stack

    @property
    def call_stack(self):
        return self._call_stack

    def call_stack_copy(self):
        return self._call_stack.copy()

    def get_call_stack_suffix(self):
        return self._call_stack.stack_suffix(self._context_sensitivity_level)

    @property
    def func_addr(self):
        return self._call_stack.current_function_address

    @func_addr.setter
    def func_addr(self, v):
        # Make a copy because we might be sharing it with other CFGJobs
        self._call_stack = self._call_stack.copy()
        self._call_stack.current_function_address = v

    @property
    def current_stack_pointer(self):
        return self._call_stack.current_stack_pointer

    def __repr__(self):
        if isinstance(self.addr, SootAddressDescriptor):
            return "<Entry {} {}>".format(self.addr, self.jumpkind)
        else:
            return "<Entry %#08x %% %s>" % (self.addr, self.jumpkind)
