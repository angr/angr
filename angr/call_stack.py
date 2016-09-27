
import collections
from itertools import dropwhile

import simuvex


class CallFrame(object):
    """
    Stores the address of the function you're in and the value of SP
    at the VERY BOTTOM of the stack, i.e. points to the return address.
    """
    def __init__(self, state=None, call_site_addr=None, func_addr=None, stack_ptr=None, ret_addr=None, jumpkind=None):
        """
        Initialize with either a state or the function address,
        stack pointer, and return address
        """

        self.jumpkind = jumpkind if jumpkind is not None else (state.scratch.jumpkind if state is not None else None)
        self.call_site_addr = call_site_addr

        if state is not None:
            try:
                self.func_addr = state.se.any_int(state.ip)
                self.stack_ptr = state.se.any_int(state.regs.sp)
            except (simuvex.SimUnsatError, simuvex.SimSolverModeError):
                self.func_addr = None
                self.stack_ptr = None

            if self.jumpkind and self.jumpkind.startswith('Ijk_Sys'):
                # syscalls
                self.ret_addr = state.regs.ip_at_syscall
            else:
                # calls
                if state.arch.call_pushes_ret:
                    self.ret_addr = state.memory.load(state.regs.sp, state.arch.bits / 8,
                                                      endness=state.arch.memory_endness, inspect=False
                                                      )
                else:
                    self.ret_addr = state.regs.lr

            # Try to convert the ret_addr to an integer
            try:
                self.ret_addr = state.se.any_int(self.ret_addr)
            except (simuvex.SimUnsatError, simuvex.SimSolverModeError):
                self.ret_addr = None
        else:
            self.func_addr = func_addr
            self.stack_ptr = stack_ptr
            self.ret_addr = ret_addr

        self.block_counter = collections.Counter()

    def __str__(self):
        return "Func %#x, sp=%#x, ret=%#x" % (self.func_addr, self.stack_ptr, self.ret_addr)

    def __repr__(self):
        return '<CallFrame (Func %#x)>' % self.func_addr

    #
    # Properties
    #

    @property
    def call_target(self):
        return self.func_addr

    @property
    def return_target(self):
        return self.ret_addr

    @property
    def stack_pointer(self):
        return self.stack_ptr

    #
    # Public methods
    #

    def copy(self):
        c = CallFrame(state=None, call_site_addr=self.call_site_addr, func_addr=self.func_addr,
                      stack_ptr=self.stack_ptr, ret_addr=self.ret_addr, jumpkind=self.jumpkind
                      )
        c.block_counter = collections.Counter(self.block_counter)
        return c


class CallStack(object):
    """
    Represents a call stack.
    """
    def __init__(self, stack=None):

        if stack is None:
            self._callstack = [ ]
        else:
            self._callstack = stack

    #
    # Overriden methods
    #

    def __iter__(self):
        """
        Iterate through the callstack, from top to bottom
        (most recent first).
        """
        for cf in reversed(self._callstack):
            yield cf

    def __getitem__(self, k):
        """
        Returns the CallFrame at index k, indexing from the top of the stack.
        """
        k = -1 - k
        return self._callstack[k]

    def __len__(self):
        """
        Get how many frames there are in the current call stack.

        :return: Number of frames
        :rtype: int
        """

        return len(self._callstack)

    def __repr__(self):
        """
        Get a string representation.

        :return: A printable representation of the CallStack object
        :rtype: str
        """
        return "<CallStack (depth %d)>" % len(self._callstack)

    def __str__(self):
        return "Backtrace:\n%s" % "\n".join(str(f) for f in self)

    def __eq__(self, other):
        if not isinstance(other, CallStack):
            return False

        if len(self) != len(other):
            return False

        for c1, c2 in zip(self._callstack, other._callstack):
            if c1.func_addr != c2.func_addr or c1.stack_ptr != c2.stack_ptr or c1.ret_addr != c2.ret_addr:
                return False

        return True

    def __ne__(self, other):
        return self != other

    def __hash__(self):
        return hash(tuple((c.func_addr, c.stack_ptr, c.ret_addr) for c in self._callstack))

    #
    # Properties
    #

    @property
    def current_stack_pointer(self):
        """
        Get the value of the stack pointer.

        :return: Value of the stack pointer
        :rtype: int
        """
        if len(self._callstack) == 0:
            return None
        else:
            frame = self._callstack[-1]
            return frame.stack_pointer

    @property
    def current_return_target(self):
        """
        Get the return target.

        :return: The address of return target.
        :rtype: int
        """

        if len(self._callstack) == 0:
            return None
        return self._callstack[-1].return_target

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

    @property
    def top(self):
        """
        Returns the element at the top of the callstack without removing it.

        :return: A CallFrame.
        """
        try:
            return self._callstack[-1]
        except IndexError:
            raise ValueError("Empty CallStack")

    #
    # Public methods
    #

    def push(self, cf):
        """
        Push the :class:`CallFrame` `cf` on the callstack.
        """
        self._callstack.append(cf)

    def pop(self):
        """
        Pops one :class:`CallFrame` from the callstack.

        :return: A CallFrame.
        """
        try:
            return self._callstack.pop(-1)
        except IndexError:
            raise ValueError("Empty CallStack")

    def dbg_repr(self):
        """
        Debugging representation of this CallStack object.

        :return: Details of this CalLStack
        :rtype: str
        """

        stack = [ ]
        for i, frame in enumerate(reversed(self._callstack)):
            s = "%d | %s -> %s, returning to %s" % (
                i,
                "None" if frame.call_site is None else "%#x" % frame.call_site,
                "None" if frame.function_address is None else "%#x" % frame.function_address,
                "None" if frame.return_target is None else "%#x" % frame.return_target,
            )
            stack.append(s)

        return "\n".join(stack)

    def clear(self):
        """
        Clear the call stack.

        :return: None
        """
        self._callstack = [ ]

    def stack_suffix(self, context_sensitivity_level):
        """
        Generate the stack suffix. A stack suffix can be used as the key to a SimRun in CFG recovery.

        :param int context_sensitivity_level: Level of context sensitivity.
        :return: A tuple of stack suffix.
        :rtype: tuple
        """

        length = len(self._callstack)

        ret = ()
        for i in xrange(context_sensitivity_level):
            index = length - i - 1
            if index < 0:
                ret = (None, None) + ret
            else:
                frame = self._callstack[index]
                ret = (frame.call_site_addr, frame.call_target) + ret
        return ret

    def copy(self):
        c = CallStack()
        c._callstack = [cf.copy() for cf in self._callstack]
        return c
