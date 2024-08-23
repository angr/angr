from __future__ import annotations
import claripy

import angr


class UserHook(angr.SimProcedure):
    NO_RET = True

    # pylint: disable=arguments-differ
    def run(self, user_func=None, length=None):
        result = user_func(self.state)
        if result is None:
            jumpkind = "Ijk_NoHook" if length == 0 else "Ijk_Boring"
            self.successors.add_successor(self.state, self.state.addr + length, claripy.true, jumpkind)
        else:
            for state in result:
                self.successors.add_successor(state, state.addr, state.scratch.guard, state.history.jumpkind)
