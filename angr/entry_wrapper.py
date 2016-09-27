import copy
import logging

import simuvex

from .call_stack import CallFrame as BaseCallFrame, CallStack as BaseCallStack

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
                                               "" if self.continue_at is None else self.continue_at
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


class CallStackFrame(BaseCallFrame):
    """
    CallStackFrame represents a stack frame in the call stack.
    """
    def __init__(self, call_site, call_target, caller_func_addr, return_target, stack_pointer=None,
                 accessed_registers=None):
        """
        Constructor.

        :param int call_site: Address of the call site.
        :param int call_target: Target of the call. Usually it is the address of a function.
        :param int caller_func_addr: Address of the current function. Note that it may not always be the same as
                                     call_target (consider situations like PLT entries and tail-call optimization).
        :param int return_target: Target address of returning.
        :param int stack_pointer: Value of the stack pointer.
        :param set accessed_registers: A set of registers that are accessed.
        :return: None
        """

        super(CallStackFrame, self).__init__(call_site_addr=call_site, func_addr=call_target, stack_ptr=stack_pointer, ret_addr=return_target, jumpkind='Ijk_Call')

        # extra properties
        self.caller_func_addr = caller_func_addr
        self.accessed_registers = set() if accessed_registers is None else accessed_registers

    def __repr__(self):
        """
        Get a string representation.

        :return: A printable representation of the CallStackFrame object.
        :rtype: str
        """
        return "CallStackFrame (calling %s from %s, returning to %s, function %s)" % (
            ("%#x" % self.call_target) if self.call_target is not None else "None",
            ("%#x" % self.call_site_addr) if self.call_site_addr is not None else "None",
            ("%#x" % self.return_target) if self.return_target is not None else "None",
            ("%#x" % self.caller_func_addr) if self.caller_func_addr is not None else "None",
        )

    def copy(self):
        """
        Make a copy of the call stack frame.

        :return: A new stack frame
        :rtype: CallStackFrame
        """

        return CallStackFrame(self.call_site_addr,
                              self.call_target,
                              self.caller_func_addr,
                              self.return_target,
                              stack_pointer=self.stack_pointer,
                              accessed_registers=self.accessed_registers.copy()
                              )


class CallStack(BaseCallStack):
    """
    CallStack is a representation of a call stack along a specific execution path.
    """
    def __init__(self, stack=None):
        """
        Constructor.

        :param list stack: A list representing the stack, where each element is a CallStackFrame instance.
        :return: None
        """

        super(CallStack, self).__init__(stack=stack)

    #
    # Properties
    #

    @property
    def current_function_address(self):
        """
        Address of the current function.

        :return: the address of the function
        :rtype: int
        """

        if len(self._callstack) == 0:
            return 0  # This is the root level
        else:
            frame = self._callstack[-1]
            return frame.caller_func_addr

    @current_function_address.setter
    def current_function_address(self, caller_func_addr):
        """
        Set the address of the current function. Note that we must make a copy of the CallStackFrame as CallStackFrame
        is considered to be immutable.

        :param int caller_func_addr: The function address.
        :return: None
        """

        frame = self._callstack[-1].copy()
        frame.caller_func_addr = caller_func_addr
        self._callstack[-1] = frame

    @property
    def all_function_addresses(self):
        """
        Get all function addresses called in the path, from the earliest one to the most recent one

        :return: a list of function addresses
        :rtype: list
        """
        return [ frame.caller_func_addr for frame in self._callstack ]

    @property
    def current_function_accessed_registers(self):
        """
        Get all accessed registers of the function.

        :return: A set of register offsets
        :rtype: set
        """
        if len(self._callstack) == 0:
            return set()
        else:
            frame = self._callstack[-1]
            return frame.accessed_registers

    #
    # Private methods
    #

    def _rfind_return_target(self, target):
        """
        Check if the return target exists in the stack, and return the index if exists. We always search from the most
        recent call stack frame since the most recent frame has a higher chance to be hit in normal CFG recovery.

        :param int target: Target of the return.
        :return: The index of the object
        :rtype: int
        """

        for i in xrange(len(self._callstack) - 1, -1, -1):
            frame = self._callstack[i]
            if frame.return_target == target:
                return i
        return None

    #
    # Public methods
    #

    def call(self, callsite_addr, addr, retn_target=None, stack_pointer=None):
        """
        Push a stack frame into the call stack. This method is called when calling a function in CFG recovery.

        :param int callsite_addr: Address of the call site
        :param int addr: Address of the call target
        :param int retn_target: Address of the return target
        :param int stack_pointer: Value of the stack pointer
        :return: None
        """

        frame = CallStackFrame(callsite_addr, addr, addr, retn_target, stack_pointer=stack_pointer)
        self._callstack.append(frame)

    def ret(self, retn_target):
        """
        Pop one or many call frames from the stack. This method is called when returning from a function in CFG
        recovery.

        :param int retn_target: The target to return to.
        :return: None
        """

        return_target_index = self._rfind_return_target(retn_target)

        if return_target_index is not None:
            # We may want to return to several levels up there, not only a
            # single stack frame
            levels = return_target_index

            # Remove all frames higher than the level
            self._callstack = self._callstack[ : levels]

        else:
            l.warning("Returning to an unexpected address %#x", retn_target)

            # For Debugging
            # raise Exception()
            # There are cases especially in ARM where return is used as a jump
            # So we don't pop anything out

    def copy(self):
        """
        Make a copy of this CallStack object.
        Note that although the stack is copied, each stack frame inside the stack is not duplicated.

        :return: A new copy
        :rtype: CallStack
        """

        return CallStack(stack=self._callstack[::])


class BBLStack(object):
    def __init__(self, stack_dict=None):
        if stack_dict is None:
            self._stack_dict = { }
        else:
            self._stack_dict = stack_dict

    @staticmethod
    def _get_key(callstack_suffix, func_addr):
        if len(callstack_suffix) > 0:
            key = callstack_suffix
        else:
            key = func_addr

        return key

    def copy(self):
        return BBLStack(copy.deepcopy(self._stack_dict))

    def call(self, callstack_suffix, func_addr):
        key = self._get_key(callstack_suffix, func_addr)

        # Create a stack with respect to that function
        self._stack_dict[key] = []

    def ret(self, callstack_suffix, func_addr):
        key = self._get_key(callstack_suffix, func_addr)

        if key in self._stack_dict:
            # Return from a function. Remove the corresponding stack
            del self._stack_dict[key]
        else:
            l.warning("Attempting to ret from a non-existing stack frame %s.", hex(key) if isinstance(key, (int, long)) else key)

    def push(self, callstack_suffix, func_addr, bbl):
        key = self._get_key(callstack_suffix, func_addr)

        if key not in self._stack_dict:
            l.warning("Key %s is not in stack dict. It might be caused by " +
                      "an unexpected exit target.", hex(key) if isinstance(key, (int, long)) else key)
            self.call(callstack_suffix, func_addr)
        self._stack_dict[key].append(bbl)

    def in_stack(self, callstack_suffix, func_addr, bbl):
        key = self._get_key(callstack_suffix, func_addr)

        if key in self._stack_dict:
            return bbl in self._stack_dict[key]
        return False

    def __repr__(self):
        s = [ ]
        for key, stack in self._stack_dict.iteritems():
            s_ = ", ".join([ (hex(k) if k is not None else "None") for k in key ])
            s_ = "[" + s_ + "]:\n  "
            s_ += " -> ".join([ hex(k) for k in stack ])

            s.append(s_)

        return "\n".join(s)


class EntryWrapper(object):
    """
    Describes an entry in CFG or VFG. Only used internally by the analysis.
    """
    def __init__(self, addr, path, context_sensitivity_level, simrun_key=None, src_simrun_key=None,
                 src_exit_stmt_idx=None, jumpkind=None, call_stack=None, bbl_stack=None, is_narrowing=False,
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

        if bbl_stack is None:
            self._bbl_stack = BBLStack()
            # Initialize the BBL stack
            self._bbl_stack.call(self._call_stack.stack_suffix(self._context_sensitivity_level), path.addr)
        else:
            self._bbl_stack = bbl_stack

        assert self._call_stack is not None and self._bbl_stack is not None

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

    def bbl_stack_push(self, call_stack_suffix, function_addr, bbl_addr):
        self._bbl_stack.push(call_stack_suffix, function_addr, bbl_addr)

    def bbl_in_stack(self, call_stack_suffix, function_addr, bbl_addr):
        return self._bbl_stack.in_stack(call_stack_suffix, function_addr, bbl_addr)

    def bbl_stack(self):
        return self._bbl_stack

    def bbl_stack_copy(self):
        return self._bbl_stack.copy()

    @property
    def func_addr(self):
        return self._call_stack.current_function_address

    @property
    def current_stack_pointer(self):
        return self._call_stack.current_stack_pointer

    @property
    def accessed_registers_in_function(self):
        return self._call_stack.current_function_accessed_registers

    def __repr__(self):
        return "<Entry %#08x %% %s>" % (self.addr, self.jumpkind)
