import copy
import logging
from itertools import dropwhile

import simuvex

l = logging.getLogger(name="angr.entry_wrapper")

class CallStackFrame(object):
    """
    CallStackFrame represents a stack frame in the call stack.
    """
    def __init__(self, call_site, call_target, function_address, return_target, stack_pointer=None, accessed_registers=None):
        """
        Constructor.

        :param int call_site: Address of the call site.
        :param int call_target: Target of the call. Usually it is the address of a function.
        :param int function_address: Address of the current function. Note that it may not always be the same as
                                     call_target (consider situations like PLT entries and tail-call optimization).
        :param int return_target: Target address of returning.
        :param int stack_pointer: Value of the stack pointer.
        :param set accessed_registers: A set of registers that are accessed.
        :return: None
        """

        self.call_site = call_site
        self.call_target = call_target
        self.function_address = function_address
        self.return_target = return_target
        self.stack_pointer = stack_pointer
        self.accessed_registers = set() if accessed_registers is None else accessed_registers

    def __repr__(self):
        """
        Get a string representation.

        :return: A printable representation of the CallStackFrame object.
        :rtype: str
        """
        return "CallStackFrame (calling %s from %s, returning to %s, function %s)" % (
            ("%#x" % self.call_target) if self.call_target is not None else "None",
            ("%#x" % self.call_site) if self.call_site is not None else "None",
            ("%#x" % self.return_target) if self.return_target is not None else "None",
            ("%#x" % self.function_address) if self.function_address is not None else "None",
        )

    def copy(self):
        """
        Make a copy of the call stack frame.

        :return: A new stack frame
        :rtype: CallStackFrame
        """

        return CallStackFrame(self.call_site,
                              self.call_target,
                              self.function_address,
                              self.return_target,
                              stack_pointer=self.stack_pointer,
                              accessed_registers=self.accessed_registers.copy()
                              )

class CallStack(object):
    """
    CallStack is a representation of a call stack along a specific execution path.
    """
    def __init__(self, stack=None):
        """
        Constructor.

        :param list stack: A list representing the stack, where each element is a CallStackFrame instance.
        :return: None
        """
        self._stack = [ ] if stack is None else stack

    #
    # Static methods
    #

    @staticmethod
    def stack_suffix_to_string(stack_suffix):
        """
        Convert a stack suffix to a human-readable string representation.
        :param tuple stack_suffix: The stack suffix.
        :return: A string representation
        :rtype: str
        """
        s = "[" + ",".join([("0x%x" % i) if i is not None else "Unspecified" for i in stack_suffix]) + "]"
        return s

    @staticmethod
    def _rfind(lst, item):
        """
        Reverse look-up.

        :param list lst: The list to look up in.
        :param item: The item to look for.
        :return: Offset of the item if found. A ValueError is raised if the item is not in the list.
        :rtype: int
        """

        try:
            return dropwhile(lambda x: lst[x] != item,
                             reversed(xrange(len(lst)))).next()
        except Exception:
            raise ValueError("%s not in the list" % item)

    #
    # Overriden properties
    #

    def __len__(self):
        """
        Get how many frames there are in the current stack

        :return: Number of frames
        :rtype: int
        """

        return len(self._stack)

    def __repr__(self):
        """
        Get a string representation.

        :return: A printable representation of the CallStack object
        :rtype: str
        """
        return "<CallStack of %d frames>" % len(self._stack)

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

        if len(self._stack) == 0:
            return 0 # This is the root level
        else:
            frame =  self._stack[-1]
            return frame.function_address

    @current_function_address.setter
    def current_function_address(self, function_address):
        """
        Set the address of the current function. Note that we must make a copy of the CallStackFrame as CallStackFrame
        is considered to be immutable.

        :param int function_address: The function address.
        :return: None
        """

        frame = self._stack[-1].copy()
        frame.function_address = function_address
        self._stack[-1] = frame

    @property
    def all_function_addresses(self):
        """
        Get all function addresses called in the path, from the earliest one to the most recent one

        :return: a list of function addresses
        :rtype: list
        """
        return [ frame.function_address for frame in self._stack ]

    @property
    def current_stack_pointer(self):
        """
        Get the value of the stack pointer.

        :return: Value of the stack pointer
        :rtype: int
        """
        if len(self._stack) == 0:
            return None
        else:
            frame = self._stack[-1]
            return frame.stack_pointer

    @property
    def current_function_accessed_registers(self):
        """
        Get all accessed registers of the function.

        :return: A set of register offsets
        :rtype: set
        """
        if len(self._stack) == 0:
            return set()
        else:
            frame = self._stack[-1]
            return frame.accessed_registers

    @property
    def current_return_target(self):
        """
        Get the return target.

        :return: The address of return target.
        :rtype: int
        """

        if len(self._stack) == 0:
            return None
        return self._stack[-1].return_target

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

        for i in xrange(len(self._stack) - 1, -1, -1):
            frame = self._stack[i]
            if frame.return_target == target:
                return i
        return None

    #
    # Public methods
    #

    def dbg_repr(self):
        """
        Debugging representation of this CallStack object.

        :return: Details of this CalLStack
        :rtype: str
        """

        stack = [ ]
        for i, frame in enumerate(reversed(self._stack)):
            s = "%d | %s -> %s, returning to %s" % (
                i,
                "None" if frame.call_site is None else "%#x" % (frame.call_site),
                "None" if frame.function_address is None else "%#x" % (frame.function_address),
                "None" if frame.return_target is None else "%#x" % (frame.return_target)
            )
            stack.append(s)

        return "\n".join(stack)

    def clear(self):
        """
        Clear the call stack.

        :return: None
        """
        self._stack = [ ]

    def stack_suffix(self, context_sensitivity_level):
        """
        Generate the stack suffix. A stack suffix can be used as the key to a SimRun in CFG recovery.

        :param int context_sensitivity_level: Level of context sensitivity.
        :return: A tuple of stack suffix.
        :rtype: tuple
        """

        length = len(self._stack)

        ret = ()
        for i in xrange(context_sensitivity_level):
            index = length - i - 1
            if index < 0:
                ret = (None, None) + ret
            else:
                frame = self._stack[index]
                ret = (frame.call_site, frame.call_target) + ret
        return ret

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
        self._stack.append(frame)

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
            self._stack = self._stack[ : levels]

        else:
            l.warning("Returning to an unexpected address %#x", retn_target)\

            # For Debugging
            # raise Exception()
            # There are cases especially in ARM where return is used as a jump
            # So we don't pop anything out
            pass

    def copy(self):
        """
        Make a copy of this CallStack object.
        Note that although the stack is copied, each stack frame inside the stack is not duplicated.

        :return: A new copy
        :rtype: CallStack
        """

        return CallStack(stack=self._stack[::])

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
            l.warning("Key %s is not in stack dict. It might be caused by " + \
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
    def __init__(self, path, context_sensitivity_level, src_simrun_key=None, src_exit_stmt_idx=None, jumpkind=None,
                 call_stack=None, bbl_stack=None, is_narrowing=False, skip=False, cancelled_pending_entry=None):
        self._path = path
        self.jumpkind = jumpkind
        self.src_simrun_key = src_simrun_key
        self.src_exit_stmt_idx = src_exit_stmt_idx
        self.skip = skip
        self.cancelled_pending_entry = cancelled_pending_entry

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

            self._call_stack.call(None, self._path.addr, stack_pointer=sp)

            self._bbl_stack = BBLStack()
            # Initialize the BBL stack
            self._bbl_stack.call(self._call_stack.stack_suffix(self._context_sensitivity_level), path.addr)
        else:
            self._call_stack = call_stack
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

    def call_stack_suffix(self):
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
    def current_function_address(self):
        return self._call_stack.current_function_address

    @property
    def current_stack_pointer(self):
        return self._call_stack.current_stack_pointer

    @property
    def current_function_accessed_registers(self):
        return self._call_stack.current_function_accessed_registers
