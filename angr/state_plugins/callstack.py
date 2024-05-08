import collections
from itertools import dropwhile
import logging
from typing import Optional
from collections.abc import Iterator

from .plugin import SimStatePlugin
from ..errors import AngrError, SimEmptyCallStackError

l = logging.getLogger(name=__name__)


class CallStack(SimStatePlugin):
    """
    Stores the address of the function you're in and the value of SP
    at the VERY BOTTOM of the stack, i.e. points to the return address.
    """

    def __init__(
        self,
        call_site_addr=0,
        func_addr=0,
        stack_ptr=0,
        ret_addr=0,
        jumpkind="Ijk_Call",
        next_frame: Optional["CallStack"] = None,
        invoke_return_variable=None,
    ):
        super().__init__()
        self.state = None
        self.call_site_addr = call_site_addr
        self.func_addr = func_addr
        self.stack_ptr = stack_ptr
        self.ret_addr = ret_addr
        self.jumpkind = jumpkind
        self.next = next_frame
        self.invoke_return_variable = invoke_return_variable

        self.block_counter = collections.Counter()
        self.procedure_data = None
        self.locals = {}

    #
    # Public methods
    #

    @SimStatePlugin.memo
    def copy(self, memo, with_tail=True):  # pylint: disable=unused-argument,arguments-differ
        o = super().copy(memo)
        o.call_site_addr = self.call_site_addr
        o.func_addr = self.func_addr
        o.stack_ptr = self.stack_ptr
        o.ret_addr = self.ret_addr
        o.jumpkind = self.jumpkind
        o.next = self.next if with_tail else None
        o.invoke_return_variable = self.invoke_return_variable

        o.block_counter = collections.Counter(self.block_counter)
        o.procedure_data = self.procedure_data
        o.locals = dict(self.locals)
        return o

    def set_state(self, state):
        super().set_state(state)
        # make the stack pointer as large as possible as soon as we know how large that actually is
        if self.stack_ptr == 0:
            try:
                bits = state.arch.registers["sp"][1] * state.arch.byte_width
            except KeyError:
                bits = state.arch.bits
            self.stack_ptr = 2**bits - 1

    def merge(self, others, merge_conditions, common_ancestor=None):  # pylint: disable=unused-argument
        for o in others:
            if o != self:
                l.error("Trying to merge states with disparate callstacks!")

    def widen(self, others):  # pylint: disable=unused-argument
        l.warning("Widening not implemented for callstacks")

    def __iter__(self) -> Iterator["CallStack"]:
        """
        Iterate through the callstack, from top to bottom
        (most recent first).
        """
        i = self
        while i is not None:
            yield i
            i = i.next

    def __getitem__(self, k):
        """
        Returns the CallStack at index k, indexing from the top of the stack.
        """
        orig_k = k
        for i in self:
            if k == 0:
                return i
            k -= 1
        raise IndexError(orig_k)

    def __len__(self):
        """
        Get how many frames there are in the current call stack.

        :return: Number of frames
        :rtype: int
        """

        o = 0
        for _ in self:
            o += 1
        return o

    def __repr__(self):
        """
        Get a string representation.

        :return: A printable representation of the CallStack object
        :rtype: str
        """
        return "<CallStack (depth %d)>" % len(self)

    def __str__(self):
        return "Backtrace:\n%s" % "\n".join(
            "Frame %d: %#x => %#x, sp = %#x" % (i, f.call_site_addr, f.func_addr, f.stack_ptr)
            for i, f in enumerate(self)
        )

    def __eq__(self, other):
        if not isinstance(other, CallStack):
            return False

        if self.func_addr != other.func_addr or self.stack_ptr != other.stack_ptr or self.ret_addr != other.ret_addr:
            return False

        return self.next == other.next

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash(tuple((c.func_addr, c.stack_ptr, c.ret_addr) for c in self))

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

        return self.func_addr

    @current_function_address.setter
    def current_function_address(self, func_addr):
        """
        Set the address of the current function. Note that we must make a copy of the CallStackFrame as CallStackFrame
        is considered to be immutable.

        :param int func_addr: The function address.
        :return: None
        """

        self.func_addr = func_addr

    @property
    def current_stack_pointer(self):
        """
        Get the value of the stack pointer.

        :return: Value of the stack pointer
        :rtype: int
        """
        return self.stack_ptr

    @property
    def current_return_target(self):
        """
        Get the return target.

        :return: The address of return target.
        :rtype: int
        """

        return self.ret_addr

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
            return dropwhile(lambda x: lst[x] != item, next(reversed(range(len(lst)))))
        except Exception as e:
            raise ValueError("%s not in the list" % item) from e

    @property
    def top(self):
        """
        Returns the element at the top of the callstack without removing it.

        :return: A CallStack.
        """
        return self

    #
    # Public methods
    #

    def push(self, cf):
        """
        Push the frame cf onto the stack. Return the new stack.
        """
        cf.next = self
        if self.state is not None:
            self.state.register_plugin("callstack", cf)
            self.state.history.recent_stack_actions.append(
                CallStackAction(hash(cf), len(cf), "push", callframe=cf.copy({}, with_tail=False))
            )

        return cf

    def pop(self):
        """
        Pop the top frame from the stack. Return the new stack.
        """
        if self.next is None:
            raise SimEmptyCallStackError("Cannot pop a frame from an empty call stack.")
        new_list = self.next.copy({})

        if self.state is not None:
            self.state.register_plugin("callstack", new_list)
            self.state.history.recent_stack_actions.append(
                CallStackAction(hash(new_list), len(new_list), "pop", ret_site_addr=self.ret_addr)
            )

        return new_list

    def call(self, callsite_addr, addr, retn_target=None, stack_pointer=None):
        """
        Push a stack frame into the call stack. This method is called when calling a function in CFG recovery.

        :param int callsite_addr: Address of the call site
        :param int addr: Address of the call target
        :param int or None retn_target: Address of the return target
        :param int stack_pointer: Value of the stack pointer
        :return: None
        """

        frame = CallStack(call_site_addr=callsite_addr, func_addr=addr, ret_addr=retn_target, stack_ptr=stack_pointer)
        return self.push(frame)

    def ret(self, retn_target=None):
        """
        Pop one or many call frames from the stack. This method is called when returning from a function in CFG
        recovery.

        :param int retn_target: The target to return to.
        :return: None
        """

        if retn_target is None:
            return self.pop()

        # We may want to return to several levels up there, not only a
        # single stack frame
        return_target_index = self._find_return_target(retn_target)

        if return_target_index is not None:
            o = self
            while return_target_index >= 0:
                o = o.pop()
                return_target_index -= 1
            return o

        l.warning("Returning to an unexpected address %#x", retn_target)
        return self

        # For Debugging
        # raise Exception()
        # There are cases especially in ARM where return is used as a jump
        # So we don't pop anything out

    def dbg_repr(self):
        """
        Debugging representation of this CallStack object.

        :return: Details of this CalLStack
        :rtype: str
        """

        stack = []
        for i, frame in enumerate(self):
            s = "%d | %s -> %s, returning to %s" % (
                i,
                "None" if frame.call_site_addr is None else "%#x" % frame.call_site_addr,
                "None" if frame.func_addr is None else "%#x" % frame.func_addr,
                "None" if frame.current_return_target is None else "%#x" % frame.current_return_target,
            )
            stack.append(s)

        return "\n".join(stack)

    def stack_suffix(self, context_sensitivity_level) -> tuple[int | None, ...]:
        """
        Generate the stack suffix. A stack suffix can be used as the key to a SimRun in CFG recovery.

        :param int context_sensitivity_level: Level of context sensitivity.
        :return: A tuple of stack suffix.
        :rtype: tuple
        """

        ret = ()

        for frame in self:
            if len(ret) >= context_sensitivity_level * 2:
                break
            ret = (frame.call_site_addr, frame.func_addr) + ret

        while len(ret) < context_sensitivity_level * 2:
            ret = (None, None) + ret

        return ret

    #
    # Private methods
    #

    def _find_return_target(self, target):
        """
        Check if the return target exists in the stack, and return the index if exists. We always search from the most
        recent call stack frame since the most recent frame has a higher chance to be hit in normal CFG recovery.

        :param int target: Target of the return.
        :return: The index of the object
        :rtype: int
        """

        for i, frame in enumerate(self):
            if frame.ret_addr == target:
                return i
        return None


class CallStackAction:
    """
    Used in callstack backtrace, which is a history of callstacks along a path, to record individual actions occurred
    each time the callstack is changed.
    """

    def __init__(self, callstack_hash, callstack_depth, action, callframe=None, ret_site_addr=None):
        self.callstack_hash = callstack_hash
        self.callstack_depth = callstack_depth
        self.action = action

        if action not in ("push", "pop"):
            raise AngrError('Unsupported action string "%s".' % action)

        self.callframe = callframe
        self.ret_site_addr = ret_site_addr

        if action == "push" and self.callframe is None:
            raise AngrError('callframe must be specified when action is "push".')

        if action == "pop" and self.callframe is not None:
            raise AngrError('callframe must not be specified when action is "pop".')

    def __repr__(self):
        if self.action == "push":
            return "<CallStackAction push with %s>" % self.callframe
        else:  # pop
            return "<CallStackAction pop, ret site %#x>" % self.ret_site_addr


from angr.sim_state import SimState

SimState.register_default("callstack", CallStack)
