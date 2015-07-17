import copy
import logging
from itertools import dropwhile

import simuvex

l = logging.getLogger(name="angr.entry_wrapper")

class CallStack(object):
    def __init__(self, stack=None, retn_targets=None, stack_pointers=None, accessed_registers=None):
        self._stack = [ ] if stack is None else stack
        self._retn_targets = [ ] if retn_targets is None else retn_targets
        self._stack_pointers = [ ] if stack_pointers is None else stack_pointers
        self._accessed_registers = [ ] if accessed_registers is None else accessed_registers

    def __len__(self):
        """
        Get how many functions calls there are in the current stack
        :return:
        """

        return len(self._stack)

    def __repr__(self):
        """
        :return: A proper representation of the CallStack object
        """
        return "<CallStack of %d frames>" % len(self._stack)

    def dbg_print(self):
        """
        :return: Details of this CalLStack
        """

        stack = [ ]
        for i, (st, return_target) in enumerate(reversed(zip(self._stack, self._retn_targets))):
            # Unpack the tuple
            callsite_irsb_addr, func_addr = st

            s = "%d | %s -> %s, returning to %s" % (
                i,
                "None" if callsite_irsb_addr is None else hex(callsite_irsb_addr),
                "None" if func_addr is None else hex(func_addr),
                "None" if return_target is None else hex(return_target)
            )
            stack.append(s)

        return "\n".join(stack)

    def clear(self):
        self._stack = [ ]
        self._retn_targets = [ ]
        self._stack_pointers = [ ]

    @staticmethod
    def stack_suffix_to_string(stack_suffix):
        '''
        Convert a stack suffix to a human-readable string representation.
        :param stack_suffix:
        :return: A string
        '''
        s = "[" + ",".join([("0x%x" % i) if i is not None else "Unspecified" for i in stack_suffix]) + "]"
        return s

    def stack_suffix(self, context_sensitivity_level):
        length = len(self._stack)

        ret = ()
        for i in xrange(context_sensitivity_level):
            index = length - i - 1
            if index < 0:
                ret = (None, ) + ret
            else:
                ret = self._stack[index] + ret
        return ret

    def call(self, callsite_addr, addr, retn_target=None, stack_pointer=None):
        self._stack.append((callsite_addr, addr))
        self._retn_targets.append(retn_target)
        self._stack_pointers.append(stack_pointer)
        self._accessed_registers.append(set())

    @property
    def current_function_address(self):
        if len(self._stack) == 0:
            return 0 # This is the root level
        else:
            return self._stack[-1][-1]

    @property
    def all_function_addresses(self):
        """
        Get all function addresses called in the path, from the earliest one to the most recent one
        :return: a list of function addresses
        """
        return [ s[-1] for s in self._stack ]

    @property
    def current_stack_pointer(self):
        if len(self._stack) == 0:
            return None
        else:
            return self._stack_pointers[-1]

    @property
    def current_function_accessed_registers(self):
        if len(self._accessed_registers) == 0:
            return set()
        else:
            return self._accessed_registers[-1]

    @staticmethod
    def _rfind(lst, item):
        try:
            return dropwhile(lambda x: lst[x] != item,
                             reversed(xrange(len(lst)))).next()
        except Exception:
            raise ValueError("%s not in the list" % item)

    def ret(self, retn_target):
        if retn_target in self._retn_targets:
            # We may want to return to several levels up there, not only a
            # single stack frame
            levels = len(self._retn_targets) - \
                self._rfind(self._retn_targets, retn_target)
        else:
            l.warning("Returning to unexpected address 0x%08x", retn_target)
            # For Debugging
            # raise Exception()
            # There are cases especially in ARM where return is used as a jump
            # So we don't pop anything out
            levels = 0
        while levels > 0:
            if len(self._stack) > 0:
                self._stack.pop()
            if len(self._retn_targets) > 0:
                self._retn_targets.pop()
            if len(self._stack_pointers) > 0:
                self._stack_pointers.pop()
            if len(self._accessed_registers) > 0:
                self._accessed_registers.pop()
            levels -= 1

    def get_ret_target(self):
        if len(self._retn_targets) == 0:
            return None
        return self._retn_targets[-1]

    def copy(self):
        return CallStack(self._stack[::], self._retn_targets[::], self._stack_pointers[::], self._accessed_registers[::])

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
    def __init__(self, path, context_sensitivity_level, call_stack=None, bbl_stack=None, is_narrowing=False):
        self._path = path

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
