from __future__ import annotations

import logging

import claripy

import angr

l = logging.getLogger(name=__name__)


class strtok(angr.SimProcedure):
    # pylint:disable=arguments-differ

    KEY = "strtok_save_ptr"

    def run(self, s, delim):
        strtok_r = angr.SIM_PROCEDURES["posix"]["strtok_r"]
        malloc = angr.SIM_PROCEDURES["libc"]["malloc"]

        # Allocate the static save pointer on first use
        if self.KEY not in self.state.globals:
            l.debug("strtok: allocating static save pointer")
            save_ptr = self.inline_call(malloc, self.state.arch.bytes).ret_expr
            self.state.memory.store(
                save_ptr,
                claripy.BVV(0, self.state.arch.bits),
                endness=self.state.arch.memory_endness,
            )
            self.state.globals[self.KEY] = save_ptr

        save_ptr = self.state.globals[self.KEY]
        return self.inline_call(strtok_r, s, delim, save_ptr).ret_expr
