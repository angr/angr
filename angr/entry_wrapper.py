
import logging

import simuvex

from .call_stack import CallStack

l = logging.getLogger(name="angr.entry_wrapper")

# TODO: Make callsite an object and use it in SimRunKey and FunctionKey


class SimRunKey(object):
    """
    A context-sensitive key for a SimRun object.
    """

    def __init__(self, addr, callsite_tuples, jump_type, continue_at=None):
        self.addr = addr
        self.callsite_tuples = callsite_tuples
        self.jump_type = jump_type
        self.continue_at = continue_at

        self._hash = None

    def callsite_repr(self):

        if self.callsite_tuples is None:
            return "None"

        s = [ ]
        format_addr = lambda addr: 'None' if addr is None else hex(addr)
        for i in xrange(0, len(self.callsite_tuples), 2):
            s.append('@'.join(map(format_addr, self.callsite_tuples[i:i+2])))
        return " -> ".join(s)

    def __repr__(self):
        return "<SRKey %#08x (%s) %% %s%s>" % (self.addr, self.callsite_repr(), self.jump_type,
                                               "" if self.continue_at is None else "-" + self.continue_at
                                               )

    def __hash__(self):
        if self._hash is None:
            self._hash = hash((self.callsite_tuples,) + (self.addr, self.jump_type, self.continue_at, ))
        return self._hash

    def __eq__(self, other):
        return isinstance(other, SimRunKey) and \
               self.addr == other.addr and self.callsite_tuples == other.callsite_tuples and \
               self.jump_type == other.jump_type and \
               self.continue_at == other.continue_at

    def __ne__(self, other):
        return not self == other

    @staticmethod
    def new(addr, callstack_suffix, jumpkind, continue_at=None):
        if jumpkind.startswith('Ijk_Sys') or jumpkind == 'syscall':
            jump_type = 'syscall'
        elif jumpkind in ('Ijk_Exit', 'exit'):
            jump_type = 'exit'
        else:
            jump_type = "normal"
        return SimRunKey(addr, callstack_suffix, jump_type, continue_at=continue_at)

    @property
    def func_addr(self):
        if self.callsite_tuples:
            return self.callsite_tuples[-1]
        else:
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
        for i in xrange(0, len(self.callsite_tuples), 2):
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


class EntryWrapper(object):
    """
    Describes an entry in CFG or VFG. Only used internally by the analysis.
    """
    def __init__(self, addr, path, context_sensitivity_level, simrun_key=None, src_simrun_key=None,
                 src_exit_stmt_idx=None, jumpkind=None, call_stack=None, is_narrowing=False,
                 skip=False, final_return_address=None, continue_at=None):
        self.addr = addr  # Note that addr may not always be equal to self.path.addr (for syscalls, for example)
        self._path = path
        self.jumpkind = jumpkind
        self.src_simrun_key = src_simrun_key
        self.src_exit_stmt_idx = src_exit_stmt_idx
        self.skip = skip
        self._simrun_key = simrun_key
        self.continue_at = continue_at

        # Other parameters
        self._context_sensitivity_level = context_sensitivity_level
        self.is_narrowing = is_narrowing

        if call_stack is None:
            self._call_stack = CallStack()

            # Added the function address of the current exit to callstack
            se = self._path.state.se
            sp_expr = self._path.state.regs.sp

            # If the sp_expr cannot be concretized, the stack pointer cannot be traced anymore.
            try:
                sp = se.exactly_n_int(sp_expr, 1)[0]
            except (simuvex.SimValueError, simuvex.SimSolverModeError):
                l.warning("Stack pointer cannot be concretized. CallStack cannot track the stack pointer changes.")

                # Set the stack pointer to None
                sp = None

            self._call_stack.call(None, self._path.addr, retn_target=final_return_address, stack_pointer=sp)

        else:
            self._call_stack = call_stack

    @property
    def path(self):
        return self._path

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

    @property
    def current_stack_pointer(self):
        return self._call_stack.current_stack_pointer

    def __repr__(self):
        return "<Entry %#08x %% %s>" % (self.addr, self.jumpkind)
