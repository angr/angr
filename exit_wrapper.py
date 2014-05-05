from itertools import dropwhile

import logging

l = logging.getLogger(name="angr.exit_wrapper")

class Stack(object):
    def __init__(self, stack=None, retn_targets=None):
        if stack is None:
            self._stack = []
        else:
            self._stack = stack

        if retn_targets is None:
            self._retn_targets = []
        else:
            self._retn_targets = retn_targets

    def stack_suffix(self):
        length = len(self._stack)
        if length == 0:
            return (None, None)
        elif length == 1:
            return (None, self._stack[length - 1])
        return (self._stack[length - 2], self._stack[length - 1])

    def call(self, callsite_addr, addr, retn_target=None):
        self._stack.append(callsite_addr)
        self._stack.append(addr)
        self._retn_targets.append(retn_target)

    def _rfind(self, lst, item):
        try:
            return dropwhile(lambda x: lst[x] != item, \
                             reversed(xrange(len(lst)))).next()
        except:
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
                self._stack.pop()
            if len(self._retn_targets) > 0:
                self._retn_targets.pop()
            levels -= 1

    def get_ret_target(self):
        if len(self._retn_targets) == 0:
            return None
        return self._retn_targets[len(self._retn_targets) - 1]

    def copy(self):
        return Stack(self._stack[::], self._retn_targets[::])

class SimExitWrapper(object):
    def __init__(self, ex, stack=None):
        self._exit = ex
        if stack == None:
            self._stack = Stack()
        else:
            self._stack = stack

    def sim_exit(self):
        return self._exit

    def stack(self):
        return self._stack

    def stack_copy(self):
        return self._stack.copy()

    def stack_suffix(self):
        return self._stack.stack_suffix()

